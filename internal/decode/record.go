package decode

import (
	"encoding/binary"
	"net/netip"
	"time"

	"nfa/internal/flow"
)

// recState collects values that need post-processing once every field of a
// record has been seen (time bases, competing byte counters, sampling).
type recState struct {
	bytes, pkts            uint64
	haveBytes, havePkts    bool
	outBytes, outPkts      uint64
	initBytes, respBytes   uint64
	initPkts, respPkts     uint64
	firstMs, lastMs        uint64 // sysUpTime-relative (v9 21/22, IPFIX 21/22)
	haveFirst, haveLast    bool
	sysInitMs              uint64 // IPFIX 160
	startAbs, endAbs       time.Time
	sampler                uint32
	hasSampler             bool
	sampling               uint32
	srcVLAN, dstVLAN       uint16
	postSrcMAC, postDstMAC uint64
}

// readRecord walks one data record using template t and returns the number of
// bytes consumed, or -1 when the record is truncated.
func readRecord(t *template, b []byte, fn func(f field, v []byte)) int {
	off := 0
	for _, f := range t.fields {
		l := int(f.length)
		if f.length == varLen {
			if off >= len(b) {
				return -1
			}
			l = int(b[off])
			off++
			if l == 255 {
				if off+2 > len(b) {
					return -1
				}
				l = int(binary.BigEndian.Uint16(b[off:]))
				off += 2
			}
		}
		if off+l > len(b) {
			return -1
		}
		fn(f, b[off:off+l])
		off += l
	}
	return off
}

func applyField(r *flow.Record, st *recState, f field, v []byte) {
	if f.enterprise != 0 || len(v) == 0 {
		return
	}
	switch f.typ {
	case 1: // octetDeltaCount / IN_BYTES
		st.bytes, st.haveBytes = uintN(v), true
	case 85: // octetTotalCount
		if !st.haveBytes {
			st.bytes = uintN(v)
		}
	case 2: // packetDeltaCount / IN_PKTS
		st.pkts, st.havePkts = uintN(v), true
	case 86:
		if !st.havePkts {
			st.pkts = uintN(v)
		}
	case 23:
		st.outBytes = uintN(v)
	case 24:
		st.outPkts = uintN(v)
	case 231: // initiatorOctets (Cisco ASA NSEL etc.)
		st.initBytes = uintN(v)
	case 232:
		st.respBytes = uintN(v)
	case 298:
		st.initPkts = uintN(v)
	case 299:
		st.respPkts = uintN(v)
	case 4:
		r.Proto = uint8(uintN(v))
	case 5:
		r.ToS = uint8(uintN(v))
	case 6:
		r.TCPFlags = uint8(uintN(v)) // low byte; IPFIX may send 2 bytes
	case 7:
		r.SrcPort = uint16(uintN(v))
	case 11:
		r.DstPort = uint16(uintN(v))
	case 8:
		if len(v) == 4 {
			r.SrcAddr = addr4(v)
		}
	case 12:
		if len(v) == 4 {
			r.DstAddr = addr4(v)
		}
	case 27:
		if len(v) == 16 {
			r.SrcAddr = addr16(v)
		}
	case 28:
		if len(v) == 16 {
			r.DstAddr = addr16(v)
		}
	case 15, 18:
		if len(v) == 4 && (!r.NextHop.IsValid() || f.typ == 15) {
			r.NextHop = addr4(v)
		}
	case 62, 63:
		if len(v) == 16 && (!r.NextHop.IsValid() || f.typ == 62) {
			r.NextHop = addr16(v)
		}
	case 9, 29:
		r.SrcMask = uint8(uintN(v))
	case 13, 30:
		r.DstMask = uint8(uintN(v))
	case 10:
		r.InIf = uint32(uintN(v))
	case 14:
		r.OutIf = uint32(uintN(v))
	case 16:
		r.SrcAS = uint32(uintN(v))
	case 17:
		r.DstAS = uint32(uintN(v))
	case 22:
		st.firstMs, st.haveFirst = uintN(v), true
	case 21:
		st.lastMs, st.haveLast = uintN(v), true
	case 150:
		st.startAbs = time.Unix(int64(uintN(v)), 0)
	case 151:
		st.endAbs = time.Unix(int64(uintN(v)), 0)
	case 152:
		st.startAbs = time.UnixMilli(int64(uintN(v)))
	case 153:
		st.endAbs = time.UnixMilli(int64(uintN(v)))
	case 160:
		st.sysInitMs = uintN(v)
	case 34, 50, 305:
		st.sampling = uint32(uintN(v))
	case 48, 302:
		st.sampler, st.hasSampler = uint32(uintN(v)), true
	case 58:
		st.srcVLAN = uint16(uintN(v))
	case 59:
		st.dstVLAN = uint16(uintN(v))
	case 243:
		if st.srcVLAN == 0 {
			st.srcVLAN = uint16(uintN(v))
		}
	case 60:
		switch uintN(v) {
		case 4:
			r.EType = flow.ETypeIPv4
		case 6:
			r.EType = flow.ETypeIPv6
		}
	case 61:
		r.Direction = uint8(uintN(v))
	// MACs: 56/80 are as received (IN_SRC_MAC / IN_DST_MAC, IPFIX
	// source/destinationMacAddress); 81/57 are post-forwarding variants,
	// used only when the first pair is absent.
	case 56:
		if len(v) == 6 {
			r.SrcMAC = uintN(v)
		}
	case 80:
		if len(v) == 6 {
			r.DstMAC = uintN(v)
		}
	case 81:
		if len(v) == 6 {
			st.postSrcMAC = uintN(v)
		}
	case 57:
		if len(v) == 6 {
			st.postDstMAC = uintN(v)
		}
	case 32: // ICMP_TYPE: type<<8 | code, conventionally reported as dst port
		if r.DstPort == 0 {
			r.DstPort = uint16(uintN(v))
		}
	}
}

// finishRecord resolves times and counters. boot is the exporter's boot time
// (zero when unknown) and export is the packet's export timestamp.
func (d *Decoder) finishRecord(r *flow.Record, st *recState, exporter netip.Addr, domain uint32, boot, export time.Time) {
	switch {
	case st.haveBytes || st.bytes > 0:
		r.Bytes, r.Packets = st.bytes, st.pkts
	case st.initBytes+st.respBytes > 0:
		r.Bytes, r.Packets = st.initBytes+st.respBytes, st.initPkts+st.respPkts
	default:
		r.Bytes, r.Packets = st.outBytes, st.outPkts
	}
	if st.sysInitMs > 0 {
		boot = time.UnixMilli(int64(st.sysInitMs))
	}
	switch {
	case !st.startAbs.IsZero():
		r.TimeStart, r.TimeEnd = st.startAbs, st.endAbs
	case st.haveFirst && !boot.IsZero():
		r.TimeStart = boot.Add(time.Duration(st.firstMs) * time.Millisecond)
		r.TimeEnd = boot.Add(time.Duration(st.lastMs) * time.Millisecond)
	}
	// Exporters with broken clocks produce nonsense; fall back to export time.
	if r.TimeEnd.IsZero() || r.TimeEnd.After(export.Add(time.Hour)) || r.TimeEnd.Before(export.Add(-24*time.Hour)) {
		r.TimeStart, r.TimeEnd = export, export
	}
	if r.SrcMAC == 0 {
		r.SrcMAC = st.postSrcMAC
	}
	if r.DstMAC == 0 {
		r.DstMAC = st.postDstMAC
	}
	if st.srcVLAN != 0 {
		r.VLAN = st.srcVLAN
	} else {
		r.VLAN = st.dstVLAN
	}
	if st.sampling > 0 {
		r.SamplingRate = st.sampling
	} else {
		r.SamplingRate = d.sampling.lookup(exporter, domain, st.sampler, st.hasSampler)
	}
	r.Normalize()
}

// learnOptions extracts sampling configuration from an options data record.
func (d *Decoder) learnOptions(t *template, b []byte, exporter netip.Addr, domain uint32) int {
	var rate, sampler, interval, space, ifIndex uint64
	var ifName, ifDesc string
	n := readRecord(t, b, func(f field, v []byte) {
		if f.enterprise != 0 {
			return
		}
		switch f.typ {
		case 10:
			ifIndex = uintN(v)
		case 82:
			ifName = cstring(v)
		case 83:
			ifDesc = cstring(v)
		case 34, 50:
			rate = uintN(v)
		case 305:
			interval = uintN(v)
		case 306:
			space = uintN(v)
		case 48, 302:
			sampler = uintN(v)
		}
	})
	if rate == 0 && interval > 0 {
		// RFC 7014 systematic count-based sampling: select `interval` of every
		// `interval+space` packets.
		rate = (interval + space) / interval
	}
	if n > 0 && rate > 0 {
		if d.sampling.set(samplingKey{exporter, domain, uint32(sampler)}, uint32(rate)) && d.OnSampling != nil {
			d.OnSampling(exporter, uint32(rate), sampler == 0)
		}
	}
	if n > 0 && ifIndex > 0 && ifName != "" && d.OnInterface != nil {
		d.OnInterface(exporter, uint32(ifIndex), ifName, ifDesc)
	}
	return n
}

// decodeDataSet decodes all records of a data set.
func (d *Decoder) decodeDataSet(t *template, b []byte, ft flow.Type, exporter netip.Addr, domain uint32, boot, export, now time.Time, out []flow.Record) ([]flow.Record, int) {
	n := 0
	for len(b) >= t.minLen && t.minLen > 0 {
		if t.options {
			used := d.learnOptions(t, b, exporter, domain)
			if used <= 0 {
				break
			}
			b = b[used:]
			continue
		}
		r := flow.Record{TimeReceived: now, Type: ft, Exporter: exporter}
		var st recState
		used := readRecord(t, b, func(f field, v []byte) { applyField(&r, &st, f, v) })
		if used <= 0 {
			break
		}
		b = b[used:]
		d.finishRecord(&r, &st, exporter, domain, boot, export)
		if !r.SrcAddr.IsValid() && !r.DstAddr.IsValid() {
			continue // not an IP flow (e.g. pure L2 record)
		}
		out = append(out, r)
		n++
	}
	return out, n
}
