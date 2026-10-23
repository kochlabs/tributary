// Package threat matches flow addresses against lists of known-bad
// addresses (threat feeds), keeping the lists up to date.
package threat

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Format describes how a feed lists its addresses.
type Format struct {
	Kind      string // text | csv | json
	Field     string // json: the field holding the address
	Column    int    // csv: 1-based column
	Delimiter string // csv
}

// Parse reads the prefixes in a feed. Single addresses become /32 or /128
// prefixes; entries that aren't addresses (headers, metadata) are skipped and
// counted.
func Parse(r io.Reader, f Format) (prefixes []netip.Prefix, skipped int, err error) {
	add := func(s string) {
		if p, ok := parsePrefix(s); ok {
			prefixes = append(prefixes, p)
		} else {
			skipped++
		}
	}
	switch f.Kind {
	case "", "text":
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
				continue
			}
			// The address is the first token: "1.2.3.0/24 ; SBL123",
			// "5.6.7.8 # comment", "9.9.9.9\tsomething".
			tok := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ';' || r == '#' || r == ',' })
			if len(tok) > 0 {
				add(tok[0])
			}
		}
		err = sc.Err()
	case "csv":
		cr := csv.NewReader(r)
		cr.Comment = '#'
		cr.FieldsPerRecord = -1
		cr.LazyQuotes = true
		cr.ReuseRecord = true
		if f.Delimiter == `\t` {
			cr.Comma = '\t'
		} else if f.Delimiter != "" {
			cr.Comma = []rune(f.Delimiter)[0]
		}
		for {
			rec, e := cr.Read()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, skipped, fmt.Errorf("CSV: %w", e)
			}
			if f.Column-1 < len(rec) {
				add(strings.TrimSpace(rec[f.Column-1]))
			} else {
				skipped++
			}
		}
	case "json":
		prefixes, skipped, err = parseJSON(r, f.Field)
	default:
		err = fmt.Errorf("unknown format %q", f.Kind)
	}
	if err == nil && len(prefixes) == 0 {
		err = errors.New("no addresses found: check the format settings")
	}
	return prefixes, skipped, err
}

// parseJSON accepts a JSON array (of objects or of strings) or one JSON
// object per line, taking the address from field.
func parseJSON(r io.Reader, field string) ([]netip.Prefix, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	var out []netip.Prefix
	skipped := 0
	take := func(v any) {
		var s string
		switch t := v.(type) {
		case string:
			s = t
		case map[string]any:
			s, _ = t[field].(string)
		}
		if p, ok := parsePrefix(s); ok {
			out = append(out, p)
		} else {
			skipped++
		}
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []any
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, 0, fmt.Errorf("JSON: %w", err)
		}
		for _, v := range arr {
			take(v)
		}
		return out, skipped, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var v any
		err := dec.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, skipped, fmt.Errorf("JSON: %w", err)
		}
		take(v)
	}
	return out, skipped, nil
}

func parsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}
