package store

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type fieldKind int

const (
	kAddr fieldKind = iota
	kUint
	kProto
	kApp
	kEType
	kCountry
	kDirection
)

type filterField struct {
	kind   fieldKind
	cols   []string // OR-ed together (e.g. host = src or dst)
	max    uint64
	rollup bool // column exists in traffic_1m
}

// FilterFields lists every filter key the API accepts.
var FilterFields = map[string]filterField{
	"exporter":    {kind: kAddr, cols: []string{"exporter"}, rollup: true},
	"src":         {kind: kAddr, cols: []string{"src_addr"}},
	"dst":         {kind: kAddr, cols: []string{"dst_addr"}},
	"host":        {kind: kAddr, cols: []string{"src_addr", "dst_addr"}},
	"peer":        {kind: kAddr, cols: []string{"src_addr", "dst_addr"}}, // second host, to pin one conversation
	"nexthop":     {kind: kAddr, cols: []string{"next_hop"}},
	"port":        {kind: kUint, cols: []string{"src_port", "dst_port"}, max: 65535},
	"src_port":    {kind: kUint, cols: []string{"src_port"}, max: 65535},
	"dst_port":    {kind: kUint, cols: []string{"dst_port"}, max: 65535},
	"proto":       {kind: kProto, cols: []string{"proto"}, rollup: true},
	"app":         {kind: kApp},
	"in_if":       {kind: kUint, cols: []string{"in_if"}, max: 1<<32 - 1, rollup: true},
	"out_if":      {kind: kUint, cols: []string{"out_if"}, max: 1<<32 - 1, rollup: true},
	"iface":       {kind: kUint, cols: []string{"in_if", "out_if"}, max: 1<<32 - 1, rollup: true},
	"src_as":      {kind: kUint, cols: []string{"src_as"}, max: 1<<32 - 1},
	"dst_as":      {kind: kUint, cols: []string{"dst_as"}, max: 1<<32 - 1},
	"as":          {kind: kUint, cols: []string{"src_as", "dst_as"}, max: 1<<32 - 1},
	"vlan":        {kind: kUint, cols: []string{"vlan"}, max: 4095},
	"dscp":        {kind: kUint, cols: []string{"bitShiftRight(tos, 2)"}, max: 63},
	"flow_type":   {kind: kUint, cols: []string{"flow_type"}, max: 255},
	"etype":       {kind: kEType, cols: []string{"etype"}, rollup: true},
	"src_country": {kind: kCountry, cols: []string{"src_country"}},
	"dst_country": {kind: kCountry, cols: []string{"dst_country"}},
	"country":     {kind: kCountry, cols: []string{"src_country", "dst_country"}},
	"direction":   {kind: kDirection},
}

var protoByName = map[string]uint8{
	"icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "icmpv6": 58, "ospf": 89, "pim": 103, "vrrp": 112, "sctp": 132,
}

// Filter is a parsed, parameterized WHERE clause fragment.
type Filter struct {
	conds    []string
	args     []any
	rollupOK bool
}

// ParseFilter builds a filter from key → value pairs. A value is a comma
// separated list (OR-ed); a leading "!" negates the whole list. Keys are AND-ed.
func ParseFilter(params map[string]string) (*Filter, error) {
	f := &Filter{rollupOK: true}
	for key, raw := range params {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		def, ok := FilterFields[key]
		if !ok {
			continue
		}
		neg := strings.HasPrefix(raw, "!")
		raw = strings.TrimPrefix(raw, "!")
		var ors []string
		for _, v := range strings.Split(raw, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			cond, args, err := def.cond(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			ors = append(ors, cond)
			f.args = append(f.args, args...)
		}
		if len(ors) == 0 {
			continue
		}
		c := "(" + strings.Join(ors, " OR ") + ")"
		if neg {
			c = "NOT " + c
		}
		f.conds = append(f.conds, c)
		if !def.rollup {
			f.rollupOK = false
		}
	}
	return f, nil
}

func (d filterField) cond(v string) (string, []any, error) {
	var parts []string
	var args []any
	switch d.kind {
	case kAddr:
		lo, hi, err := addrRange(v)
		if err != nil {
			return "", nil, err
		}
		for _, c := range d.cols {
			if lo == hi {
				parts = append(parts, c+" = toIPv6(?)")
				args = append(args, lo)
			} else {
				parts = append(parts, c+" BETWEEN toIPv6(?) AND toIPv6(?)")
				args = append(args, lo, hi)
			}
		}
	case kUint, kProto:
		var n uint64
		var err error
		if p, ok := protoByName[strings.ToLower(v)]; ok && d.kind == kProto {
			n = uint64(p)
		} else if lo, hi, isRange := strings.Cut(v, "-"); isRange && d.kind == kUint {
			a, err1 := strconv.ParseUint(lo, 10, 64)
			b, err2 := strconv.ParseUint(hi, 10, 64)
			if err1 != nil || err2 != nil || a > b || b > d.max {
				return "", nil, fmt.Errorf("invalid range %q", v)
			}
			for _, c := range d.cols {
				parts = append(parts, c+" BETWEEN ? AND ?")
				args = append(args, a, b)
			}
			return "(" + strings.Join(parts, " OR ") + ")", args, nil
		} else if n, err = strconv.ParseUint(v, 10, 64); err != nil || (d.max > 0 && n > d.max) || (d.kind == kProto && n > 255) {
			return "", nil, fmt.Errorf("invalid value %q", v)
		}
		for _, c := range d.cols {
			parts = append(parts, c+" = ?")
			args = append(args, n)
		}
	case kEType:
		switch strings.ToLower(v) {
		case "ipv4", "4":
			parts, args = []string{"etype = ?"}, []any{0x0800}
		case "ipv6", "6":
			parts, args = []string{"etype = ?"}, []any{0x86dd}
		default:
			return "", nil, fmt.Errorf("invalid ip version %q", v)
		}
	case kDirection:
		c, err := directionCond(v)
		if err != nil {
			return "", nil, err
		}
		return c, nil, nil
	case kCountry:
		v = strings.ToUpper(v)
		if len(v) != 2 || v[0] < 'A' || v[0] > 'Z' || v[1] < 'A' || v[1] > 'Z' {
			return "", nil, fmt.Errorf("country must be a 2-letter ISO code, got %q", v)
		}
		for _, c := range d.cols {
			parts = append(parts, c+" = ?")
			args = append(args, v)
		}
	case kApp:
		// "6/443" or "tcp/443"
		ps, port, ok := strings.Cut(v, "/")
		if !ok {
			return "", nil, fmt.Errorf("app must be proto/port, got %q", v)
		}
		p, known := protoByName[strings.ToLower(ps)]
		if !known {
			n, err := strconv.ParseUint(ps, 10, 8)
			if err != nil {
				return "", nil, fmt.Errorf("invalid protocol %q", ps)
			}
			p = uint8(n)
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", nil, fmt.Errorf("invalid port %q", port)
		}
		return "(" + appExpr + " = ?)", []any{fmt.Sprintf("%d/%d", p, n)}, nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", args, nil
}

// addrRange converts an address or CIDR prefix to an inclusive IPv6 range,
// mapping IPv4 into ::ffff:0:0/96 to match how addresses are stored.
func addrRange(s string) (string, string, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return "", "", fmt.Errorf("invalid prefix %q", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return "", "", fmt.Errorf("invalid address %q", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = p.Masked()
	bits := p.Bits()
	addr := p.Addr()
	if addr.Is4() {
		addr = netip.AddrFrom16(addr.As16())
		bits += 96
	}
	lo := addr.As16()
	hi := lo
	for i := bits; i < 128; i++ {
		hi[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom16(lo).String(), netip.AddrFrom16(hi).String(), nil
}

func (f *Filter) where(timeCol string, from, to int64) (string, []any) {
	conds := append([]string{timeCol + " >= toDateTime(?)", timeCol + " < toDateTime(?)"}, f.conds...)
	return strings.Join(conds, " AND "), append([]any{from, to}, f.args...)
}
