package decode

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/kochlabs/tributary/internal/flow"
)

const (
	v5HeaderLen = 24
	v5RecordLen = 48
)

func decodeV5(exporter netip.Addr, data []byte, now time.Time, out []flow.Record) ([]flow.Record, Result, error) {
	res := Result{Type: flow.TypeNetFlowV5}
	if len(data) < v5HeaderLen {
		return out, res, ErrShort
	}
	count := int(binary.BigEndian.Uint16(data[2:]))
	uptime := binary.BigEndian.Uint32(data[4:])
	secs := binary.BigEndian.Uint32(data[8:])
	nsecs := binary.BigEndian.Uint32(data[12:])
	res.Sequence = binary.BigEndian.Uint32(data[16:])
	sampling := uint32(binary.BigEndian.Uint16(data[22:]) & 0x3fff)

	if len(data) < v5HeaderLen+count*v5RecordLen {
		return out, res, ErrShort
	}
	boot := time.Unix(int64(secs), int64(nsecs)).Add(-time.Duration(uptime) * time.Millisecond)

	for i := 0; i < count; i++ {
		b := data[v5HeaderLen+i*v5RecordLen:]
		r := flow.Record{
			TimeReceived: now,
			Type:         flow.TypeNetFlowV5,
			Exporter:     exporter,
			SamplingRate: sampling,
			SrcAddr:      addr4(b[0:]),
			DstAddr:      addr4(b[4:]),
			NextHop:      addr4(b[8:]),
			InIf:         uint32(binary.BigEndian.Uint16(b[12:])),
			OutIf:        uint32(binary.BigEndian.Uint16(b[14:])),
			Packets:      uint64(binary.BigEndian.Uint32(b[16:])),
			Bytes:        uint64(binary.BigEndian.Uint32(b[20:])),
			TimeStart:    boot.Add(time.Duration(binary.BigEndian.Uint32(b[24:])) * time.Millisecond),
			TimeEnd:      boot.Add(time.Duration(binary.BigEndian.Uint32(b[28:])) * time.Millisecond),
			SrcPort:      binary.BigEndian.Uint16(b[32:]),
			DstPort:      binary.BigEndian.Uint16(b[34:]),
			TCPFlags:     b[37],
			Proto:        b[38],
			ToS:          b[39],
			SrcAS:        uint32(binary.BigEndian.Uint16(b[40:])),
			DstAS:        uint32(binary.BigEndian.Uint16(b[42:])),
			SrcMask:      b[44],
			DstMask:      b[45],
			EType:        flow.ETypeIPv4,
		}
		r.Normalize()
		out = append(out, r)
	}
	res.Flows = count
	return out, res, nil
}
