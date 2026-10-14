package store

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
)

// Private and special-use ranges are always local; administrators add their
// own public prefixes (e.g. an ISP-delegated IPv6 /56) via settings.
var defaultLocal = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
	"fc00::/7", "fe80::/10",
}

var localPrefixes atomic.Pointer[[]netip.Prefix]

func init() { SetLocalNetworks(nil) }

// SetLocalNetworks sets the extra prefixes treated as local, in addition to
// private ranges. Local/remote dimensions and the direction filter use them.
func SetLocalNetworks(extra []netip.Prefix) {
	var ps []netip.Prefix
	for _, s := range defaultLocal {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	ps = append(ps, extra...)
	localPrefixes.Store(&ps)
}

// isLocal returns a SQL boolean expression testing whether an IPv6 column (or
// lambda variable) lies in a local prefix. Bounds come from parsed prefixes,
// so the literals are safe to inline.
func isLocal(col string) string {
	ps := *localPrefixes.Load()
	conds := make([]string, 0, len(ps))
	for _, p := range ps {
		lo, hi, err := addrRange(p.String())
		if err != nil {
			continue
		}
		conds = append(conds, fmt.Sprintf("%s BETWEEN toIPv6('%s') AND toIPv6('%s')", col, lo, hi))
	}
	return "(" + strings.Join(conds, " OR ") + ")"
}

// localDimension resolves the local/remote-aware dimensions, which depend on
// the current local network list.
func localDimension(name string) (dimension, bool) {
	ls, ld := isLocal("src_addr"), isLocal("dst_addr")
	inbound := fmt.Sprintf("(%s AND NOT %s)", ld, ls)  // remote -> local (download)
	outbound := fmt.Sprintf("(%s AND NOT %s)", ls, ld) // local -> remote (upload)
	switch name {
	case "local_host":
		return dimension{ipstr(fmt.Sprintf("arrayJoin(arrayFilter(x -> %s, [src_addr, dst_addr]))", isLocal("x"))), false}, true
	case "remote_host":
		return dimension{ipstr(fmt.Sprintf("arrayJoin(arrayFilter(x -> NOT %s, [src_addr, dst_addr]))", isLocal("x"))), false}, true
	case "remote_as":
		return dimension{fmt.Sprintf("toString(multiIf(%s, src_as, %s, dst_as, 0))", inbound, outbound), false}, true
	case "remote_country":
		return dimension{fmt.Sprintf("multiIf(%s, src_country, %s, dst_country, '')", inbound, outbound), false}, true
	case "direction":
		return dimension{fmt.Sprintf("multiIf(%s, 'download', %s, 'upload', %s AND %s, 'internal', 'transit')", inbound, outbound, ls, ld), false}, true
	case "device":
		// The device's MAC when the exporter reports MACs, else the local IP.
		return dimension{fmt.Sprintf("if(device_mac != 0, lower(MACNumToString(device_mac)), multiIf(%s, %s, %s, %s, ''))",
			ls, ipstr("src_addr"), ld, ipstr("dst_addr")), false}, true
	case "conversation":
		// Local endpoint first so rows read "my device ⇄ remote".
		return dimension{fmt.Sprintf("multiIf(%s, concat(%s, ' ⇄ ', %s), %s, concat(%s, ' ⇄ ', %s), concat(%s, ' ⇄ ', %s))",
			inbound, ipstr("dst_addr"), ipstr("src_addr"),
			outbound, ipstr("src_addr"), ipstr("dst_addr"),
			ipstr("least(src_addr, dst_addr)"), ipstr("greatest(src_addr, dst_addr)")), false}, true
	}
	return dimension{}, false
}

// directionCond is the WHERE fragment for the "direction" filter.
func directionCond(v string) (string, error) {
	ls, ld := isLocal("src_addr"), isLocal("dst_addr")
	switch strings.ToLower(v) {
	case "download", "in", "inbound":
		return fmt.Sprintf("(%s AND NOT %s)", ld, ls), nil
	case "upload", "out", "outbound":
		return fmt.Sprintf("(%s AND NOT %s)", ls, ld), nil
	case "internal":
		return fmt.Sprintf("(%s AND %s)", ls, ld), nil
	case "transit":
		return fmt.Sprintf("(NOT %s AND NOT %s)", ls, ld), nil
	}
	return "", fmt.Errorf("direction must be download, upload, internal or transit, got %q", v)
}

// LookupDimensionExpr returns the SQL expression of a dimension ("" if unknown).
func LookupDimensionExpr(name string) (string, bool) {
	d, ok := LookupDimension(name)
	return d.expr, ok
}

// LookupDimension returns a static or local-aware dimension.
func LookupDimension(name string) (dimension, bool) {
	if d, ok := localDimension(name); ok {
		return d, true
	}
	d, ok := Dimensions[name]
	return d, ok
}

// spreadBuckets yields one (bucket, weight, first) tuple per time bucket a
// flow overlaps, weighting by overlap so a flow's bytes are spread across its
// duration instead of landing in the bucket it was received. Flows with
// implausible timestamps are treated as instantaneous at receive time.
func spreadBuckets(step int) string {
	valid := "(time_end >= time_start AND time_end - time_start <= 3600 AND time_end <= time_received + 120 AND time_received - time_end <= 3600)"
	s := fmt.Sprintf("toUInt32(if(%s, toUnixTimestamp(time_start), toUnixTimestamp(time_received)))", valid)
	e := fmt.Sprintf("toUInt32(if(%s, toUnixTimestamp(time_end), toUnixTimestamp(time_received)) + 1)", valid)
	return fmt.Sprintf(`arrayJoin(arrayMap((b, i) -> (b, (least(b + %[1]d, %[3]s) - greatest(b, %[2]s)) / (%[3]s - %[2]s), i = 1),
		range(intDiv(%[2]s, %[1]d) * %[1]d, %[3]s, %[1]d) AS bs, arrayEnumerate(bs)))`, step, s, e)
}

// LocalSuggestion is a candidate local prefix detected in "transit" traffic
// (flows where neither side is known to be local).
type LocalSuggestion struct {
	Prefix string `json:"prefix"`
	Hosts  uint64 `json:"hosts"`
	Peers  uint64 `json:"peers"`
	Bytes  uint64 `json:"bytes"`
}

type LocalSuggestions struct {
	TransitPct  float64           `json:"transitPct"`
	Suggestions []LocalSuggestion `json:"suggestions"`
}

// SuggestLocalNetworks looks at the last hour of transit traffic for IPv6
// /64s that behave like a site's own LAN: many distinct addresses (privacy
// addresses) each talking to many remote peers. Results are suggestions only.
func (s *Store) SuggestLocalNetworks(ctx context.Context) (*LocalSuggestions, error) {
	ls, ld := isLocal("src_addr"), isLocal("dst_addr")
	out := &LocalSuggestions{Suggestions: []LocalSuggestion{}}
	var transit, total uint64
	err := s.conn.QueryRow(ctx, fmt.Sprintf(`SELECT sumIf(bytes, NOT %s AND NOT %s), sum(bytes)
		FROM netflow.flows WHERE time_received >= now() - INTERVAL 1 HOUR`, ls, ld)).Scan(&transit, &total)
	if err != nil {
		return nil, err
	}
	if total > 0 {
		out.TransitPct = float64(transit) / float64(total) * 100
	}
	rows, err := s.conn.Query(ctx, fmt.Sprintf(`SELECT toString(IPv6CIDRToRange(e, 64).1) AS net, uniq(e) AS hosts, uniq(peer) AS peers, sum(bytes) AS b
		FROM (
			SELECT arrayJoin([(src_addr, dst_addr), (dst_addr, src_addr)]) AS pr, pr.1 AS e, pr.2 AS peer, bytes
			FROM netflow.flows
			WHERE time_received >= now() - INTERVAL 1 HOUR AND NOT %s AND NOT %s
		)
		WHERE NOT (e BETWEEN toIPv6('::ffff:0.0.0.0') AND toIPv6('::ffff:255.255.255.255'))
		GROUP BY net HAVING hosts >= 3 AND peers >= 5
		ORDER BY hosts * peers DESC LIMIT 5`, ls, ld))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sg LocalSuggestion
		if err := rows.Scan(&sg.Prefix, &sg.Hosts, &sg.Peers, &sg.Bytes); err != nil {
			return nil, err
		}
		sg.Prefix += "/64"
		out.Suggestions = append(out.Suggestions, sg)
	}
	// Keep only candidates comparable to the strongest one; CDN ranges with a
	// handful of addresses also show up in transit traffic.
	if len(out.Suggestions) > 0 {
		top := out.Suggestions[0].Peers
		kept := out.Suggestions[:0]
		for _, sg := range out.Suggestions {
			if sg.Peers >= 20 && sg.Peers*5 >= top {
				kept = append(kept, sg)
			}
		}
		out.Suggestions = kept
	}
	return out, rows.Err()
}
