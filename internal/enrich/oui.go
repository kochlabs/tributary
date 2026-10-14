package enrich

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

// manuf.gz is Wireshark's manufacturer database, compiled from the public
// IEEE MA-L/MA-M/MA-S registries (refresh with `make oui`). Embedded so
// vendor names work without internet access.
//
//go:embed manuf.gz
var manufGz []byte

type ouiTable struct {
	by24, by28, by36 map[uint64]string
}

var (
	ouiOnce sync.Once
	oui     ouiTable
)

func loadOUI() {
	oui = ouiTable{by24: map[uint64]string{}, by28: map[uint64]string{}, by36: map[uint64]string{}}
	zr, err := gzip.NewReader(bytes.NewReader(manufGz))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		// Columns: prefix, short name, full name (optional).
		name := strings.TrimSpace(f[1])
		if len(f) >= 3 && strings.TrimSpace(f[2]) != "" {
			name = strings.TrimSpace(f[2])
		}
		prefix, bits := strings.TrimSpace(f[0]), 24
		if p, b, ok := strings.Cut(prefix, "/"); ok {
			prefix = p
			bits, _ = strconv.Atoi(b)
		}
		v, err := strconv.ParseUint(strings.ReplaceAll(prefix, ":", ""), 16, 64)
		if err != nil {
			continue
		}
		// Normalise to a 48-bit value, then keep the prefix bits.
		v <<= uint(48 - 4*len(strings.ReplaceAll(prefix, ":", "")))
		key := v >> uint(48-bits)
		switch bits {
		case 24:
			oui.by24[key] = name
		case 28:
			oui.by28[key] = name
		case 36:
			oui.by36[key] = name
		}
	}
}

// Vendor returns the registered manufacturer for a MAC (as a 48-bit
// number), the most specific registration first. Randomised ("locally
// administered") addresses, as used by phones for privacy, have none.
func Vendor(mac uint64) string {
	if mac == 0 {
		return ""
	}
	if mac&(0x02<<40) != 0 {
		return "Private (randomized) address"
	}
	ouiOnce.Do(loadOUI)
	if n, ok := oui.by36[mac>>12]; ok {
		return n
	}
	if n, ok := oui.by28[mac>>20]; ok {
		return n
	}
	return oui.by24[mac>>24]
}

// FormatMAC renders a 48-bit MAC as aa:bb:cc:dd:ee:ff.
func FormatMAC(mac uint64) string {
	b := make([]byte, 0, 17)
	for i := 5; i >= 0; i-- {
		x := byte(mac >> (8 * i))
		b = append(b, "0123456789abcdef"[x>>4], "0123456789abcdef"[x&15])
		if i > 0 {
			b = append(b, ':')
		}
	}
	return string(b)
}

// ParseMAC accepts aa:bb:cc:dd:ee:ff, aa-bb-..., or aabb.ccdd.eeff.
func ParseMAC(s string) (uint64, bool) {
	h := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(s))
	if len(h) != 12 {
		return 0, false
	}
	v, err := strconv.ParseUint(h, 16, 64)
	return v, err == nil
}
