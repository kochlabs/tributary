package decode

import (
	"encoding/binary"
	"net/netip"
	"time"

	"nfa/internal/flow"
)

const v9HeaderLen = 20

func (d *Decoder) decodeV9(exporter netip.Addr, data []byte, now time.Time, out []flow.Record) ([]flow.Record, Result, error) {
	res := Result{Type: flow.TypeNetFlowV9}
	if len(data) < v9HeaderLen {
		return out, res, ErrShort
	}
	uptime := binary.BigEndian.Uint32(data[4:])
	secs := binary.BigEndian.Uint32(data[8:])
	res.Sequence = binary.BigEndian.Uint32(data[12:])
	domain := binary.BigEndian.Uint32(data[16:])
	res.ObservationID = domain
	export := time.Unix(int64(secs), 0)
	boot := export.Add(-time.Duration(uptime) * time.Millisecond)

	b := data[v9HeaderLen:]
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		length := int(binary.BigEndian.Uint16(b[2:]))
		if length < 4 || length > len(b) {
			return out, res, ErrMalformed
		}
		body := b[4:length]
		b = b[length:]
		switch {
		case id == 0 || id == 1:
			d.templateRefresh(exporter, now)
			n, err := d.parseV9Templates(exporter, domain, body, id == 1)
			res.Templates += n
			if err != nil {
				return out, res, err
			}
		case id >= 256:
			t := d.templates.get(tmplKey{exporter, 9, domain, id})
			if t == nil {
				res.MissingTmpl++
				continue
			}
			var n int
			out, n = d.decodeDataSet(t, body, flow.TypeNetFlowV9, exporter, domain, boot, export, now, out)
			res.Flows += n
		}
	}
	return out, res, nil
}

const ipfixHeaderLen = 16

func (d *Decoder) decodeIPFIX(exporter netip.Addr, data []byte, now time.Time, out []flow.Record) ([]flow.Record, Result, error) {
	res := Result{Type: flow.TypeIPFIX}
	if len(data) < ipfixHeaderLen {
		return out, res, ErrShort
	}
	msgLen := int(binary.BigEndian.Uint16(data[2:]))
	if msgLen < ipfixHeaderLen || msgLen > len(data) {
		return out, res, ErrMalformed
	}
	export := time.Unix(int64(binary.BigEndian.Uint32(data[4:])), 0)
	res.Sequence = binary.BigEndian.Uint32(data[8:])
	domain := binary.BigEndian.Uint32(data[12:])
	res.ObservationID = domain

	b := data[ipfixHeaderLen:msgLen]
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		length := int(binary.BigEndian.Uint16(b[2:]))
		if length < 4 || length > len(b) {
			return out, res, ErrMalformed
		}
		body := b[4:length]
		b = b[length:]
		switch {
		case id == 2 || id == 3:
			d.templateRefresh(exporter, now)
			n, err := d.parseIPFIXTemplates(exporter, domain, body, id == 3)
			res.Templates += n
			if err != nil {
				return out, res, err
			}
		case id >= 256:
			t := d.templates.get(tmplKey{exporter, 10, domain, id})
			if t == nil {
				res.MissingTmpl++
				continue
			}
			var n int
			// IPFIX has no header uptime; boot time comes from field 160 if present.
			out, n = d.decodeDataSet(t, body, flow.TypeIPFIX, exporter, domain, time.Time{}, export, now, out)
			res.Flows += n
		}
	}
	return out, res, nil
}
