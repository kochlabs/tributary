package decode

import (
	"encoding/binary"
	"net/netip"
	"time"

	"nfa/internal/flow"
)

// sFlow v5 (sflow.org/sflow_version_5.txt). Only flow samples are turned into
// records; counter samples are ignored.

type xdr struct {
	b   []byte
	err bool
}

func (x *xdr) u32() uint32 {
	if len(x.b) < 4 {
		x.err = true
		return 0
	}
	v := binary.BigEndian.Uint32(x.b)
	x.b = x.b[4:]
	return v
}

func (x *xdr) bytes(n int) []byte {
	if n < 0 || len(x.b) < n {
		x.err = true
		return nil
	}
	v := x.b[:n]
	x.b = x.b[n:]
	return v
}

// opaque reads n bytes padded to a 4-byte boundary.
func (x *xdr) opaque(n int) []byte {
	v := x.bytes(n)
	if pad := (4 - n%4) % 4; pad > 0 && !x.err {
		x.bytes(pad)
	}
	return v
}

func (x *xdr) addr() netip.Addr {
	switch x.u32() {
	case 1:
		if b := x.bytes(4); b != nil {
			return addr4(b)
		}
	case 2:
		if b := x.bytes(16); b != nil {
			return addr16(b)
		}
	}
	return netip.Addr{}
}

// SFlowAgent returns the agent address embedded in an sFlow datagram so the
// collector can attribute it correctly even behind NAT/relays.
func SFlowAgent(data []byte) netip.Addr {
	x := xdr{b: data}
	if x.u32() != 5 {
		return netip.Addr{}
	}
	return x.addr()
}

func decodeSFlow(data []byte, now time.Time, out []flow.Record) ([]flow.Record, Result, error) {
	res := Result{Type: flow.TypeSFlowV5}
	x := xdr{b: data}
	x.u32() // version
	agent := x.addr()
	res.ObservationID = x.u32() // sub-agent id
	res.Sequence = x.u32()
	x.u32() // uptime
	n := int(x.u32())
	if x.err || !agent.IsValid() {
		return out, res, ErrMalformed
	}
	for i := 0; i < n && !x.err; i++ {
		format := x.u32()
		length := int(x.u32())
		body := x.bytes(length)
		if x.err {
			break
		}
		if format>>12 != 0 { // enterprise-specific
			continue
		}
		switch format & 0xfff {
		case 1, 3:
			var ok bool
			out, ok = decodeFlowSample(body, format&0xfff == 3, agent, now, out)
			if ok {
				res.Flows++
			}
		}
	}
	if x.err {
		return out, res, ErrMalformed
	}
	return out, res, nil
}

func decodeFlowSample(b []byte, expanded bool, agent netip.Addr, now time.Time, out []flow.Record) ([]flow.Record, bool) {
	x := xdr{b: b}
	r := flow.Record{TimeReceived: now, TimeStart: now, TimeEnd: now, Type: flow.TypeSFlowV5, Exporter: agent, Packets: 1}
	x.u32() // sequence
	if expanded {
		x.u32() // source id type
		x.u32() // source id index
	} else {
		x.u32()
	}
	r.SamplingRate = x.u32()
	x.u32() // sample pool
	x.u32() // drops
	if expanded {
		x.u32()
		r.InIf = x.u32()
		x.u32()
		r.OutIf = x.u32()
	} else {
		r.InIf = x.u32() & 0x3fffffff
		r.OutIf = x.u32() & 0x3fffffff
	}
	records := int(x.u32())
	haveIP := false
	for i := 0; i < records && !x.err; i++ {
		format := x.u32()
		rb := xdr{b: x.bytes(int(x.u32()))}
		if x.err {
			break
		}
		if format>>12 != 0 {
			continue
		}
		switch format & 0xfff {
		case 1: // raw packet header
			proto := rb.u32()
			frameLen := rb.u32()
			rb.u32() // stripped
			hdr := rb.opaque(int(rb.u32()))
			if !rb.err {
				r.Bytes = uint64(frameLen)
				if proto == 1 && parseEthernet(&r, hdr) {
					haveIP = true
				}
			}
		case 3: // sampled IPv4
			r.Bytes = uint64(rb.u32())
			r.Proto = uint8(rb.u32())
			r.SrcAddr = addr4(rb.bytes(4))
			r.DstAddr = addr4(rb.bytes(4))
			r.SrcPort, r.DstPort = uint16(rb.u32()), uint16(rb.u32())
			r.TCPFlags = uint8(rb.u32())
			r.ToS = uint8(rb.u32())
			r.EType = flow.ETypeIPv4
			haveIP = !rb.err
		case 4: // sampled IPv6
			r.Bytes = uint64(rb.u32())
			r.Proto = uint8(rb.u32())
			if s, d := rb.bytes(16), rb.bytes(16); !rb.err {
				r.SrcAddr, r.DstAddr = addr16(s), addr16(d)
			}
			r.SrcPort, r.DstPort = uint16(rb.u32()), uint16(rb.u32())
			r.TCPFlags = uint8(rb.u32())
			rb.u32() // priority
			r.EType = flow.ETypeIPv6
			haveIP = !rb.err
		case 1001: // extended switch
			if v := rb.u32(); v != 0 {
				r.VLAN = uint16(v)
			}
		case 1002: // extended router
			r.NextHop = rb.addr()
			r.SrcMask = uint8(rb.u32())
			r.DstMask = uint8(rb.u32())
		case 1003: // extended gateway
			rb.addr() // next hop
			rb.u32()  // router AS
			src := rb.u32()
			rb.u32() // src peer AS
			if src != 0 {
				r.SrcAS = src
			}
			// Destination AS is the last AS of the first path segment.
			if segs := rb.u32(); segs > 0 && !rb.err {
				rb.u32() // segment type
				if l := rb.u32(); l > 0 && l < 256 {
					for j := uint32(0); j < l; j++ {
						r.DstAS = rb.u32()
					}
				}
			}
		}
	}
	if x.err || !haveIP {
		return out, false
	}
	r.Normalize()
	return append(out, r), true
}

// parseEthernet decodes an Ethernet frame header (with optional 802.1Q tags)
// followed by IPv4/IPv6 and TCP/UDP.
func parseEthernet(r *flow.Record, b []byte) bool {
	if len(b) < 14 {
		return false
	}
	r.DstMAC = uint64(binary.BigEndian.Uint16(b[0:]))<<32 | uint64(binary.BigEndian.Uint32(b[2:]))
	r.SrcMAC = uint64(binary.BigEndian.Uint16(b[6:]))<<32 | uint64(binary.BigEndian.Uint32(b[8:]))
	etype := binary.BigEndian.Uint16(b[12:])
	b = b[14:]
	for (etype == 0x8100 || etype == 0x88a8) && len(b) >= 4 {
		if r.VLAN == 0 {
			r.VLAN = binary.BigEndian.Uint16(b) & 0x0fff
		}
		etype = binary.BigEndian.Uint16(b[2:])
		b = b[4:]
	}
	var l4 []byte
	switch etype {
	case flow.ETypeIPv4:
		if len(b) < 20 {
			return false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return false
		}
		r.EType = flow.ETypeIPv4
		r.ToS = b[1]
		r.Proto = b[9]
		r.SrcAddr = addr4(b[12:])
		r.DstAddr = addr4(b[16:])
		if binary.BigEndian.Uint16(b[6:])&0x1fff == 0 { // first fragment only
			l4 = b[ihl:]
		}
	case flow.ETypeIPv6:
		if len(b) < 40 {
			return false
		}
		r.EType = flow.ETypeIPv6
		r.ToS = uint8(binary.BigEndian.Uint16(b) >> 4)
		r.Proto = b[6]
		r.SrcAddr = addr16(b[8:])
		r.DstAddr = addr16(b[24:])
		l4 = b[40:]
	default:
		return false
	}
	switch r.Proto {
	case 6:
		if len(l4) >= 14 {
			r.TCPFlags = l4[13]
		}
		fallthrough
	case 17, 132:
		if len(l4) >= 4 {
			r.SrcPort = binary.BigEndian.Uint16(l4)
			r.DstPort = binary.BigEndian.Uint16(l4[2:])
		}
	case 1, 58:
		if len(l4) >= 2 {
			r.DstPort = uint16(l4[0])<<8 | uint16(l4[1])
		}
	}
	return true
}
