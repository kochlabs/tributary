// Package decode turns NetFlow v5/v9, IPFIX and sFlow v5 datagrams into
// normalized flow records. A single Decoder is safe for concurrent use and
// keeps per-exporter template and sampling state.
package decode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/flow"
)

var (
	ErrShort      = errors.New("packet too short")
	ErrVersion    = errors.New("unsupported version")
	ErrNoTemplate = errors.New("data set references unknown template")
	ErrMalformed  = errors.New("malformed packet")
)

// Result describes what a datagram contained besides the flows themselves.
type Result struct {
	Type          flow.Type
	Flows         int
	Templates     int // templates learned from this packet
	MissingTmpl   int // data sets skipped because their template is unknown
	Sequence      uint32
	ObservationID uint32
}

// Decoder holds template and sampling state across packets.
type Decoder struct {
	templates *templateCache
	sampling  *samplingCache

	// OnInterface, if set, receives interface names announced in options
	// data (IE 82 interfaceName / 83 interfaceDescription keyed by ifIndex).
	OnInterface func(exporter netip.Addr, index uint32, name, description string)
	// OnSampling, if set, is called when an exporter announces a sampling
	// rate different from the one previously known.
	OnSampling func(exporter netip.Addr, rate uint32, systemWide bool)
}

// SeedSampling sets the sampling rate assumed for an exporter until it
// announces one, e.g. the last rate persisted before a restart. Without it,
// flows arriving before the exporter's options data would be undercounted.
func (d *Decoder) SeedSampling(exporter netip.Addr, rate uint32, systemWide bool) {
	d.sampling.seed(exporter, rate, systemWide)
}

func New() *Decoder {
	return &Decoder{templates: newTemplateCache(), sampling: newSamplingCache()}
}

// TemplateCount reports how many templates are cached for an exporter.
func (d *Decoder) TemplateCount(exporter netip.Addr) int {
	return d.templates.count(exporter)
}

// Sampling reports an exporter's current sampling rate and its source.
func (d *Decoder) Sampling(exporter netip.Addr) (uint32, SamplingSource) {
	return d.sampling.info(exporter)
}

// templateRefresh feeds the sampling lifetime and notifies when a rate is
// withdrawn (rate 0) so persisted state can be cleared.
func (d *Decoder) templateRefresh(exporter netip.Addr, now time.Time) {
	if d.sampling.templateSeen(exporter, now) && d.OnSampling != nil {
		d.OnSampling(exporter, 0, false)
	}
}

// Decode detects the protocol of a NetFlow/IPFIX/sFlow datagram and appends
// the decoded flows to out.
func (d *Decoder) Decode(exporter netip.Addr, data []byte, now time.Time, out []flow.Record) ([]flow.Record, Result, error) {
	if len(data) < 4 {
		return out, Result{}, ErrShort
	}
	switch binary.BigEndian.Uint16(data) {
	case 5:
		return decodeV5(exporter, data, now, out)
	case 9:
		return d.decodeV9(exporter, data, now, out)
	case 10:
		return d.decodeIPFIX(exporter, data, now, out)
	case 0:
		if binary.BigEndian.Uint32(data) == 5 {
			return decodeSFlow(data, now, out)
		}
	}
	return out, Result{}, fmt.Errorf("%w: %d", ErrVersion, binary.BigEndian.Uint16(data))
}

func addr4(b []byte) netip.Addr {
	if len(b) < 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(b[:4]))
}

func addr16(b []byte) netip.Addr {
	if len(b) < 16 {
		return netip.Addr{}
	}
	a := netip.AddrFrom16([16]byte(b[:16]))
	if a.Is4In6() {
		return a.Unmap()
	}
	return a
}

// uintN reads a big-endian unsigned integer of 1..8 bytes. Exporters are free
// to use reduced-size encoding, so field widths vary.
func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			b = b[:i]
			break
		}
	}
	return strings.TrimSpace(string(b))
}

func uintN(b []byte) uint64 {
	var v uint64
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}
