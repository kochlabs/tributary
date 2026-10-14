// Package flowgen encodes flow records into NetFlow v5/v9, IPFIX and sFlow v5
// datagrams. It is used by tests and by the flowgen traffic simulator.
package flowgen

import (
	"encoding/binary"
	"net/netip"
	"time"

	"nfa/internal/flow"
)

type buf struct{ b []byte }

func (w *buf) u8(v uint8)   { w.b = append(w.b, v) }
func (w *buf) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *buf) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *buf) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *buf) ip4(a netip.Addr) {
	b := a.Unmap().As4()
	w.b = append(w.b, b[:]...)
}
func (w *buf) ip16(a netip.Addr) {
	b := a.As16()
	w.b = append(w.b, b[:]...)
}

// mac appends a 48-bit MAC address (IE 56, sourceMacAddress).
func (w *buf) mac(v uint64) {
	for i := 5; i >= 0; i-- {
		w.b = append(w.b, byte(v>>(8*i)))
	}
}

func (w *buf) pad4(start int) {
	for (len(w.b)-start)%4 != 0 {
		w.b = append(w.b, 0)
	}
}

// Exporter carries per-device encoder state (sequence numbers, boot time).
type Exporter struct {
	Addr     netip.Addr
	Boot     time.Time
	Sampling uint32
	Domain   uint32
	seq      uint32
	packets  int
}

func (e *Exporter) uptime(now time.Time) uint32 { return uint32(now.Sub(e.Boot).Milliseconds()) }
func (e *Exporter) rel(t time.Time) uint32      { return uint32(t.Sub(e.Boot).Milliseconds()) }

// V5 encodes up to 30 IPv4 records. Bytes/packets are divided by the sampling rate.
func (e *Exporter) V5(now time.Time, recs []flow.Record) []byte {
	if len(recs) > 30 {
		recs = recs[:30]
	}
	w := &buf{}
	w.u16(5)
	w.u16(uint16(len(recs)))
	w.u32(e.uptime(now))
	w.u32(uint32(now.Unix()))
	w.u32(uint32(now.Nanosecond()))
	w.u32(e.seq)
	w.u8(0)
	w.u8(0)
	w.u16(uint16(e.Sampling) | func() uint16 {
		if e.Sampling > 1 {
			return 1 << 14
		}
		return 0
	}())
	e.seq += uint32(len(recs))
	for _, r := range recs {
		w.ip4(r.SrcAddr)
		w.ip4(r.DstAddr)
		w.ip4(nh4(r.NextHop))
		w.u16(uint16(r.InIf))
		w.u16(uint16(r.OutIf))
		w.u32(uint32(r.Packets / uint64(max(e.Sampling, 1))))
		w.u32(uint32(r.Bytes / uint64(max(e.Sampling, 1))))
		w.u32(e.rel(r.TimeStart))
		w.u32(e.rel(r.TimeEnd))
		w.u16(r.SrcPort)
		w.u16(r.DstPort)
		w.u8(0)
		w.u8(r.TCPFlags)
		w.u8(r.Proto)
		w.u8(r.ToS)
		w.u16(uint16(r.SrcAS))
		w.u16(uint16(r.DstAS))
		w.u8(r.SrcMask)
		w.u8(r.DstMask)
		w.u16(0)
	}
	return w.b
}

func nh4(a netip.Addr) netip.Addr {
	if a.IsValid() && a.Unmap().Is4() {
		return a
	}
	return netip.IPv4Unspecified()
}

var v9Tmpl4 = [][2]uint16{{8, 4}, {12, 4}, {15, 4}, {10, 4}, {14, 4}, {2, 4}, {1, 8}, {22, 4}, {21, 4}, {7, 2}, {11, 2}, {6, 1}, {4, 1}, {5, 1}, {16, 4}, {17, 4}, {9, 1}, {13, 1}, {61, 1}, {58, 2}, {48, 1}, {56, 6}}
var v9Tmpl6 = [][2]uint16{{27, 16}, {28, 16}, {62, 16}, {10, 4}, {14, 4}, {2, 4}, {1, 8}, {22, 4}, {21, 4}, {7, 2}, {11, 2}, {6, 1}, {4, 1}, {5, 1}, {16, 4}, {17, 4}, {29, 1}, {30, 1}, {61, 1}, {58, 2}, {48, 1}, {56, 6}}

// V9 encodes records as NetFlow v9. Templates and the sampling options record
// are included every 20th packet (and in the first one).
func (e *Exporter) V9(now time.Time, recs []flow.Record) []byte {
	w := &buf{}
	w.u16(9)
	countAt := len(w.b)
	w.u16(0)
	w.u32(e.uptime(now))
	w.u32(uint32(now.Unix()))
	w.u32(e.seq)
	w.u32(e.Domain)
	e.seq++
	count := 0
	if e.packets%20 == 0 {
		// Template flowset
		start := len(w.b)
		w.u16(0)
		w.u16(0)
		for id, t := range [][][2]uint16{v9Tmpl4, v9Tmpl6} {
			w.u16(uint16(256 + id))
			w.u16(uint16(len(t)))
			for _, f := range t {
				w.u16(f[0])
				w.u16(f[1])
			}
			count++
		}
		binary.BigEndian.PutUint16(w.b[start+2:], uint16(len(w.b)-start))
		// Options template: scope System(1)/4, options SAMPLING_INTERVAL(34)/4, FLOW_SAMPLER_ID(48)/1
		start = len(w.b)
		w.u16(1)
		w.u16(0)
		w.u16(258)
		w.u16(4)
		w.u16(8)
		w.u16(1)
		w.u16(4)
		w.u16(34)
		w.u16(4)
		w.u16(48)
		w.u16(1)
		w.pad4(start)
		binary.BigEndian.PutUint16(w.b[start+2:], uint16(len(w.b)-start))
		// Options data
		start = len(w.b)
		w.u16(258)
		w.u16(0)
		w.u32(0)
		w.u32(max(e.Sampling, 1))
		w.u8(1)
		w.pad4(start)
		binary.BigEndian.PutUint16(w.b[start+2:], uint16(len(w.b)-start))
		count += 2
	}
	e.packets++
	for _, v6 := range []bool{false, true} {
		start := len(w.b)
		n := 0
		for _, r := range recs {
			if is6(r) != v6 {
				continue
			}
			if n == 0 {
				w.u16(256 + b2u(v6))
				w.u16(0)
			}
			n++
			if v6 {
				w.ip16(r.SrcAddr)
				w.ip16(r.DstAddr)
				w.ip16(nh6(r.NextHop))
			} else {
				w.ip4(r.SrcAddr)
				w.ip4(r.DstAddr)
				w.ip4(nh4(r.NextHop))
			}
			w.u32(r.InIf)
			w.u32(r.OutIf)
			w.u32(uint32(r.Packets / uint64(max(e.Sampling, 1))))
			w.u64(r.Bytes / uint64(max(e.Sampling, 1)))
			w.u32(e.rel(r.TimeStart))
			w.u32(e.rel(r.TimeEnd))
			w.u16(r.SrcPort)
			w.u16(r.DstPort)
			w.u8(r.TCPFlags)
			w.u8(r.Proto)
			w.u8(r.ToS)
			w.u32(r.SrcAS)
			w.u32(r.DstAS)
			w.u8(r.SrcMask)
			w.u8(r.DstMask)
			w.u8(r.Direction)
			w.u16(r.VLAN)
			w.u8(1)
			w.mac(r.SrcMAC)
		}
		if n > 0 {
			w.pad4(start)
			binary.BigEndian.PutUint16(w.b[start+2:], uint16(len(w.b)-start))
			count += n
		}
	}
	binary.BigEndian.PutUint16(w.b[countAt:], uint16(count))
	return w.b
}

func nh6(a netip.Addr) netip.Addr {
	if a.IsValid() && a.Is6() && !a.Is4In6() {
		return a
	}
	return netip.IPv6Unspecified()
}

func is6(r flow.Record) bool { return r.SrcAddr.Is6() && !r.SrcAddr.Is4In6() }

func b2u(b bool) uint16 {
	if b {
		return 1
	}
	return 0
}

var ipfixTmpl4 = [][2]uint16{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {6, 2}, {5, 1}, {10, 4}, {14, 4}, {1, 8}, {2, 8}, {152, 8}, {153, 8}, {16, 4}, {17, 4}, {9, 1}, {13, 1}, {15, 4}, {58, 2}, {61, 1}, {56, 6}}
var ipfixTmpl6 = [][2]uint16{{27, 16}, {28, 16}, {7, 2}, {11, 2}, {4, 1}, {6, 2}, {5, 1}, {10, 4}, {14, 4}, {1, 8}, {2, 8}, {152, 8}, {153, 8}, {16, 4}, {17, 4}, {29, 1}, {30, 1}, {62, 16}, {58, 2}, {61, 1}, {56, 6}}

// IPFIX encodes records as IPFIX with absolute millisecond timestamps.
func (e *Exporter) IPFIX(now time.Time, recs []flow.Record) []byte {
	w := &buf{}
	w.u16(10)
	w.u16(0)
	w.u32(uint32(now.Unix()))
	w.u32(e.seq)
	w.u32(e.Domain)
	if e.packets%20 == 0 {
		start := len(w.b)
		w.u16(2)
		w.u16(0)
		for id, t := range [][][2]uint16{ipfixTmpl4, ipfixTmpl6} {
			w.u16(uint16(300 + id))
			w.u16(uint16(len(t)))
			for _, f := range t {
				w.u16(f[0])
				w.u16(f[1])
			}
		}
		binary.BigEndian.PutUint16(w.b[start+2:], uint16(len(w.b)-start))
		// Options template 302: scope observationDomainId(149)/4, samplingPacketInterval(305)/4, samplingPacketSpace(306)/4
		start = len(w.b)
		w.u16(3)
		w.u16(0)
		w.u16(302)
		w.u16(3)
		w.u16(1)
		for _, f := range [][2]uint16{{149, 4}, {305, 4}, {306, 4}} {
			w.u16(f[0])
			w.u16(f[1])
		}
		binary.BigEndian.PutUint16(w.b[start+2:], uint16(len(w.b)-start))
		start = len(w.b)
		w.u16(302)
		w.u16(0)
		w.u32(e.Domain)
		w.u32(1)
		w.u32(max(e.Sampling, 1) - 1)
		binary.BigEndian.PutUint16(w.b[start+2:], uint16(len(w.b)-start))
	}
	e.packets++
	n := 0
	for _, v6 := range []bool{false, true} {
		start := len(w.b)
		c := 0
		for _, r := range recs {
			if is6(r) != v6 {
				continue
			}
			if c == 0 {
				w.u16(300 + b2u(v6))
				w.u16(0)
			}
			c++
			if v6 {
				w.ip16(r.SrcAddr)
				w.ip16(r.DstAddr)
			} else {
				w.ip4(r.SrcAddr)
				w.ip4(r.DstAddr)
			}
			w.u16(r.SrcPort)
			w.u16(r.DstPort)
			w.u8(r.Proto)
			w.u16(uint16(r.TCPFlags))
			w.u8(r.ToS)
			w.u32(r.InIf)
			w.u32(r.OutIf)
			w.u64(r.Bytes / uint64(max(e.Sampling, 1)))
			w.u64(r.Packets / uint64(max(e.Sampling, 1)))
			w.u64(uint64(r.TimeStart.UnixMilli()))
			w.u64(uint64(r.TimeEnd.UnixMilli()))
			w.u32(r.SrcAS)
			w.u32(r.DstAS)
			w.u8(r.SrcMask)
			w.u8(r.DstMask)
			if v6 {
				w.ip16(nh6(r.NextHop))
			} else {
				w.ip4(nh4(r.NextHop))
			}
			w.u16(r.VLAN)
			w.u8(r.Direction)
			w.mac(r.SrcMAC)
		}
		if c > 0 {
			binary.BigEndian.PutUint16(w.b[start+2:], uint16(len(w.b)-start))
			n += c
		}
	}
	e.seq += uint32(n)
	binary.BigEndian.PutUint16(w.b[2:], uint16(len(w.b)))
	return w.b
}

// SFlow encodes each record as one flow sample carrying a synthetic
// Ethernet/IP/L4 header. Each sample represents SamplingRate packets.
func (e *Exporter) SFlow(now time.Time, recs []flow.Record) []byte {
	w := &buf{}
	w.u32(5)
	w.u32(1)
	w.ip4(e.Addr)
	w.u32(0)
	w.u32(e.seq)
	w.u32(e.uptime(now))
	w.u32(uint32(len(recs)))
	e.seq++
	rate := max(e.Sampling, 1)
	for i, r := range recs {
		hdr := packetHeader(r)
		w.u32(1) // flow sample
		lenAt := len(w.b)
		w.u32(0)
		start := len(w.b)
		w.u32(uint32(e.packets + i))
		w.u32(r.InIf)
		w.u32(rate)
		w.u32(uint32(e.packets+i) * rate)
		w.u32(0)
		w.u32(r.InIf)
		w.u32(r.OutIf)
		w.u32(2) // records: raw header + extended switch
		// raw packet header
		w.u32(1)
		w.u32(uint32(16 + len(hdr) + (4-len(hdr)%4)%4))
		w.u32(1) // ethernet
		frame := uint32(r.Bytes / max(r.Packets, 1))
		w.u32(max(frame, uint32(len(hdr))))
		w.u32(4)
		w.u32(uint32(len(hdr)))
		w.b = append(w.b, hdr...)
		w.pad4(start)
		// extended switch
		w.u32(1001)
		w.u32(16)
		w.u32(uint32(r.VLAN))
		w.u32(0)
		w.u32(uint32(r.VLAN))
		w.u32(0)
		binary.BigEndian.PutUint32(w.b[lenAt:], uint32(len(w.b)-start))
	}
	e.packets += len(recs)
	return w.b
}

func packetHeader(r flow.Record) []byte {
	w := &buf{}
	w.b = append(w.b, 0x00, 0x1c, 0x73, 0x00, 0x00, 0x01, 0x00, 0x1c, 0x73, 0x00, 0x00, 0x02)
	if r.VLAN != 0 {
		w.u16(0x8100)
		w.u16(r.VLAN)
	}
	l4 := &buf{}
	switch r.Proto {
	case 6:
		l4.u16(r.SrcPort)
		l4.u16(r.DstPort)
		l4.u32(1)
		l4.u32(0)
		l4.u8(0x50)
		l4.u8(r.TCPFlags)
		l4.u16(65535)
		l4.u32(0)
	case 17:
		l4.u16(r.SrcPort)
		l4.u16(r.DstPort)
		l4.u16(8)
		l4.u16(0)
	default:
		l4.u16(r.DstPort)
		l4.u16(0)
	}
	if is6(r) {
		w.u16(flow.ETypeIPv6)
		w.u32(6<<28 | uint32(r.ToS)<<20)
		w.u16(uint16(len(l4.b)))
		w.u8(r.Proto)
		w.u8(64)
		w.ip16(r.SrcAddr)
		w.ip16(r.DstAddr)
	} else {
		w.u16(flow.ETypeIPv4)
		w.u8(0x45)
		w.u8(r.ToS)
		w.u16(uint16(20 + len(l4.b)))
		w.u32(0)
		w.u8(64)
		w.u8(r.Proto)
		w.u16(0)
		w.ip4(r.SrcAddr)
		w.ip4(r.DstAddr)
	}
	return append(w.b, l4.b...)
}
