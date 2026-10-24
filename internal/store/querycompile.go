package store

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/kochlabs/tributary/internal/query"
)

// Compiling queries (docs/design/QUERY-LANGUAGE.md): a parsed query becomes a
// Filter. Plain values of the classic filter fields go through the same
// conditions as ParseFilter, so a converted filter selects the same flows.

// Names resolves names in queries to what flows store.
type Names interface {
	// HostAddrs returns the addresses with a name (inventory, Tributary
	// names, reverse DNS), ignoring case; a trailing * matches a prefix.
	HostAddrs(name string) []netip.Addr
	// DeviceMACs returns the MACs of devices with a name.
	DeviceMACs(name string) []uint64
}

// MaxNameAddrs is how many addresses one name may stand for.
const MaxNameAddrs = 256

type qkind int

const (
	qClassic qkind = iota // plain values through FilterFields[legacy].cond
	qAddr                 // classic, plus names and a-b ranges
	qNumber               // classic, plus comparisons and [lo TO hi]
	qMAC
	qFlags
)

type unit int

const (
	unitPlain unit = iota
	unitSize
	unitDuration // milliseconds
)

type qfield struct {
	kind   qkind
	legacy string   // FilterFields key, for classic values
	exprs  []string // numeric and MAC fields: what to compare
	unit   unit
	max    uint64
	side   string // qAddr: "local" or "remote" restricts the side
	any    string // the condition for field:*, if allowed
	rollup bool
}

var durationExpr = "(toUnixTimestamp(time_end) - toUnixTimestamp(time_start)) * 1000"

// queryFields are the query's fields; aliases map onto them.
var queryFields = map[string]qfield{
	"host":           {kind: qAddr, legacy: "host"},
	"src":            {kind: qAddr, legacy: "src"},
	"dst":            {kind: qAddr, legacy: "dst"},
	"local":          {kind: qAddr, legacy: "host", side: "local"},
	"remote":         {kind: qAddr, legacy: "host", side: "remote"},
	"nexthop":        {kind: qAddr, legacy: "nexthop"},
	"exporter":       {kind: qAddr, legacy: "exporter", rollup: true},
	"port":           {kind: qNumber, legacy: "port", exprs: []string{"src_port", "dst_port"}, max: 65535},
	"src_port":       {kind: qNumber, legacy: "src_port", exprs: []string{"src_port"}, max: 65535},
	"dst_port":       {kind: qNumber, legacy: "dst_port", exprs: []string{"dst_port"}, max: 65535},
	"in_if":          {kind: qNumber, legacy: "in_if", exprs: []string{"in_if"}, max: 1<<32 - 1, rollup: true},
	"out_if":         {kind: qNumber, legacy: "out_if", exprs: []string{"out_if"}, max: 1<<32 - 1, rollup: true},
	"iface":          {kind: qNumber, legacy: "iface", exprs: []string{"in_if", "out_if"}, max: 1<<32 - 1, rollup: true},
	"as":             {kind: qNumber, legacy: "as", exprs: []string{"src_as", "dst_as"}, max: 1<<32 - 1, any: "(src_as != 0 OR dst_as != 0)"},
	"src_as":         {kind: qNumber, legacy: "src_as", exprs: []string{"src_as"}, max: 1<<32 - 1, any: "src_as != 0"},
	"dst_as":         {kind: qNumber, legacy: "dst_as", exprs: []string{"dst_as"}, max: 1<<32 - 1, any: "dst_as != 0"},
	"remote_as":      {kind: qNumber, exprs: []string{"remote_as"}, max: 1<<32 - 1},
	"vlan":           {kind: qNumber, legacy: "vlan", exprs: []string{"vlan"}, max: 4095, any: "vlan != 0"},
	"dscp":           {kind: qNumber, legacy: "dscp", exprs: []string{"bitShiftRight(tos, 2)"}, max: 63},
	"flow_type":      {kind: qNumber, legacy: "flow_type", exprs: []string{"flow_type"}, max: 255},
	"bytes":          {kind: qNumber, exprs: []string{"bytes"}, unit: unitSize, max: math.MaxUint64},
	"packets":        {kind: qNumber, exprs: []string{"packets"}, max: math.MaxUint64},
	"duration":       {kind: qNumber, exprs: []string{durationExpr}, unit: unitDuration, max: math.MaxUint32},
	"sampling":       {kind: qNumber, exprs: []string{"sampling_rate"}, max: math.MaxUint32},
	"proto":          {kind: qClassic, legacy: "proto", rollup: true},
	"app":            {kind: qClassic, legacy: "app"},
	"etype":          {kind: qClassic, legacy: "etype", rollup: true},
	"direction":      {kind: qClassic, legacy: "direction"},
	"country":        {kind: qClassic, legacy: "country", any: "(src_country != '' OR dst_country != '')"},
	"src_country":    {kind: qClassic, legacy: "src_country", any: "src_country != ''"},
	"dst_country":    {kind: qClassic, legacy: "dst_country", any: "dst_country != ''"},
	"remote_country": {kind: qClassic},
	"threat":         {kind: qClassic, legacy: "threat", any: "(src_threat != '' OR dst_threat != '')"},
	"device":         {kind: qClassic, legacy: "device", any: "device_mac != 0"},
	"mac":            {kind: qMAC, exprs: []string{"src_mac", "dst_mac"}, any: "(src_mac != 0 OR dst_mac != 0)"},
	"src_mac":        {kind: qMAC, exprs: []string{"src_mac"}, any: "src_mac != 0"},
	"dst_mac":        {kind: qMAC, exprs: []string{"dst_mac"}, any: "dst_mac != 0"},
	"flags":          {kind: qFlags, any: "tcp_flags != 0"},
}

// queryAliases are other names for fields. tcp.port and udp.port also set
// the protocol.
var queryAliases = map[string]string{
	"ip": "host", "addr": "host", "ip.addr": "host", "peer": "host",
	"ip.src": "src", "ip.dst": "dst",
	"tcp.port": "port", "udp.port": "port", "sport": "src_port", "dport": "dst_port",
	"eth.addr": "mac", "eth.src": "src_mac", "eth.dst": "dst_mac",
}

var aliasProto = map[string]uint8{"tcp.port": 6, "udp.port": 17}

var tcpFlags = map[string]uint8{"fin": 1, "syn": 2, "rst": 4, "psh": 8, "ack": 16, "urg": 32, "ece": 64, "cwr": 128}

// QueryFieldNames lists the query's fields and aliases, sorted.
func QueryFieldNames() []string {
	var out []string
	for k := range queryFields {
		out = append(out, k)
	}
	for k := range queryAliases {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type compiler struct {
	names    Names
	args     []any
	warnings []query.Warning
	rollupOK bool
}

// CompileQuery turns a parsed query into a filter. Names that match nothing
// match nothing, with a warning; anything else wrong is a *query.Error.
func CompileQuery(n query.Node, names Names) (*Filter, []query.Warning, error) {
	f := &Filter{rollupOK: true}
	if n == nil {
		return f, nil, nil
	}
	c := &compiler{names: names, rollupOK: true}
	// A top-level AND is kept as separate conditions, like ParseFilter's.
	items := []query.Node{n}
	if and, ok := n.(*query.And); ok {
		items = and.Items
	}
	for _, it := range items {
		cond, err := c.node(it)
		if err != nil {
			return nil, nil, err
		}
		f.conds = append(f.conds, cond)
	}
	f.args, f.rollupOK = c.args, c.rollupOK
	return f, c.warnings, nil
}

// And combines two filters (either may be nil).
func (f *Filter) And(g *Filter) *Filter {
	switch {
	case f == nil:
		return g
	case g == nil:
		return f
	}
	return &Filter{conds: append(slices.Clone(f.conds), g.conds...), args: append(slices.Clone(f.args), g.args...), rollupOK: f.rollupOK && g.rollupOK}
}

func (c *compiler) node(n query.Node) (string, error) {
	switch n := n.(type) {
	case *query.Or:
		return c.list(n.Items, " OR ")
	case *query.And:
		return c.list(n.Items, " AND ")
	case *query.Not:
		x, err := c.node(n.X)
		if err != nil {
			return "", err
		}
		return "NOT " + x, nil
	case *query.Term:
		return c.term(n)
	}
	return "", fmt.Errorf("unknown query node %T", n)
}

func (c *compiler) list(items []query.Node, op string) (string, error) {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		p, err := c.node(it)
		if err != nil {
			return "", err
		}
		parts = append(parts, p)
	}
	return "(" + strings.Join(parts, op) + ")", nil
}

func errAt(span query.Span, hint, format string, a ...any) error {
	return &query.Error{Msg: fmt.Sprintf(format, a...), Hint: hint, Span: span}
}

func (c *compiler) term(t *query.Term) (string, error) {
	name := strings.ToLower(t.Field)
	if name == "" {
		name = "host"
		if v := t.Match.Values[0]; !v.Quoted && isDigits(v.Text) {
			return "", errAt(v.Span, "use port:"+v.Text+" or dst_port:"+v.Text, "a number alone isn't a host")
		}
	}
	extra := ""
	if p, ok := aliasProto[name]; ok {
		extra = fmt.Sprintf(" AND proto = %d", p)
	}
	if a, ok := queryAliases[name]; ok {
		name = a
	}
	def, ok := queryFields[name]
	if !ok {
		hint := ""
		if s := closest(name, QueryFieldNames()); s != "" {
			hint = "did you mean " + s + "?"
		}
		return "", errAt(t.FieldSpan, hint, "unknown field %s", t.Field)
	}
	if !def.rollup {
		c.rollupOK = false
	}
	cond, err := c.match(t, name, def)
	if err != nil {
		return "", err
	}
	if extra != "" {
		cond = "(" + cond + extra + ")"
	}
	if t.Neg {
		cond = "NOT " + cond
	}
	return cond, nil
}

func (c *compiler) match(t *query.Term, name string, def qfield) (string, error) {
	m := t.Match
	switch m.Kind {
	case query.MatchAny:
		if def.any == "" {
			return "", errAt(t.Span(), "", "%s:* isn't supported", name)
		}
		return "(" + def.any + ")", nil
	case query.MatchCompare:
		if def.kind != qNumber {
			return "", errAt(m.Values[0].Span, "", "%s can't be compared with %s", name, m.Op)
		}
		n, err := c.number(m.Values[0], def, name)
		if err != nil {
			return "", err
		}
		return c.perExpr(def, func(e string) string { c.args = append(c.args, n); return e + " " + m.Op + " ?" }), nil
	case query.MatchRange:
		return c.rangeMatch(m, name, def)
	}
	parts := make([]string, 0, len(m.Values))
	for _, v := range m.Values {
		p, err := c.value(v, name, def)
		if err != nil {
			return "", err
		}
		parts = append(parts, p)
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

// perExpr ORs a condition over the field's expressions.
func (c *compiler) perExpr(def qfield, cond func(expr string) string) string {
	parts := make([]string, 0, len(def.exprs))
	for _, e := range def.exprs {
		parts = append(parts, cond(c.expr(e)))
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// expr expands the expressions that depend on local networks.
func (c *compiler) expr(e string) string {
	if e == "remote_as" {
		inbound, outbound := sides()
		return fmt.Sprintf("multiIf(%s, src_as, %s, dst_as, 0)", inbound, outbound)
	}
	return e
}

func sides() (inbound, outbound string) {
	ls, ld := isLocal("src_addr"), isLocal("dst_addr")
	return fmt.Sprintf("(%s AND NOT %s)", ld, ls), fmt.Sprintf("(%s AND NOT %s)", ls, ld)
}

func (c *compiler) rangeMatch(m query.Match, name string, def qfield) (string, error) {
	lo, hi := m.Values[0], m.Values[1]
	switch def.kind {
	case qNumber:
		var conds []string
		var a, b uint64
		var err error
		if !lo.Star {
			if a, err = c.number(lo, def, name); err != nil {
				return "", err
			}
		}
		if !hi.Star {
			if b, err = c.number(hi, def, name); err != nil {
				return "", err
			}
		}
		if !lo.Star && !hi.Star && a > b {
			return "", errAt(query.Span{Pos: lo.Span.Pos, Len: hi.Span.Pos + hi.Span.Len - lo.Span.Pos}, "", "the range is backwards")
		}
		for _, e := range def.exprs {
			e = c.expr(e)
			switch {
			case lo.Star && hi.Star:
				conds = append(conds, "1")
			case lo.Star:
				conds, c.args = append(conds, e+" <= ?"), append(c.args, b)
			case hi.Star:
				conds, c.args = append(conds, e+" >= ?"), append(c.args, a)
			default:
				conds, c.args = append(conds, e+" BETWEEN ? AND ?"), append(c.args, a, b)
			}
		}
		return "(" + strings.Join(conds, " OR ") + ")", nil
	case qAddr:
		if lo.Star || hi.Star {
			return "", errAt(m.Values[0].Span, "use a prefix such as 10.0.0.0/8", "address ranges need both ends")
		}
		return c.addrRange(lo.Text+"-"+hi.Text, lo.Span, name, def)
	}
	return "", errAt(lo.Span, "", "%s doesn't take a range", name)
}

func (c *compiler) value(v query.Value, name string, def qfield) (string, error) {
	switch def.kind {
	case qAddr:
		return c.addrValue(v, name, def)
	case qNumber:
		if def.legacy != "" && !strings.HasPrefix(strings.ToUpper(v.Text), "AS") {
			if cond, args, err := FilterFields[def.legacy].cond(v.Text); err == nil {
				c.args = append(c.args, args...)
				return cond, nil
			}
		}
		if lo, hi, ok := strings.Cut(v.Text, "-"); ok && def.unit == unitPlain {
			return c.rangeMatch(query.Match{Values: []query.Value{{Text: lo, Span: v.Span}, {Text: hi, Span: v.Span}}}, name, def)
		}
		n, err := c.number(v, def, name)
		if err != nil {
			return "", err
		}
		return c.perExpr(def, func(e string) string { c.args = append(c.args, n); return e + " = ?" }), nil
	case qMAC:
		mac, ok := query.ParseMAC(v.Text)
		if !ok {
			return "", errAt(v.Span, "such as aa:bb:cc:dd:ee:ff", "%s takes a MAC address", name)
		}
		return c.perExpr(def, func(e string) string { c.args = append(c.args, mac); return e + " = ?" }), nil
	case qFlags:
		bit, ok := tcpFlags[strings.ToLower(v.Text)]
		if !ok {
			return "", errAt(v.Span, "fin, syn, rst, psh, ack, urg, ece or cwr", "unknown TCP flag %s", v.Text)
		}
		c.args = append(c.args, bit)
		return "(proto = 6 AND bitAnd(tcp_flags, ?) != 0)", nil
	}
	// Classic fields.
	switch name {
	case "remote_country":
		cc := strings.ToUpper(v.Text)
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			return "", errAt(v.Span, "such as US or DE", "remote_country takes a 2-letter ISO code")
		}
		inbound, outbound := sides()
		c.args = append(c.args, cc)
		return fmt.Sprintf("(multiIf(%s, src_country, %s, dst_country, '') = ?)", inbound, outbound), nil
	case "device":
		if _, ok := query.ParseMAC(v.Text); !ok {
			if _, err := netip.ParseAddr(v.Text); err != nil {
				return c.deviceName(v)
			}
		}
	case "threat":
		if !knownThreatFeed(v.Text) {
			c.warn(v.Span, "", "no threat feed named %s", query.Quote(v.Text, false))
		}
	}
	cond, args, err := FilterFields[def.legacy].cond(v.Text)
	if err != nil {
		return "", errAt(v.Span, "", "%s: %s", name, strings.TrimPrefix(err.Error(), name+": "))
	}
	c.args = append(c.args, args...)
	return cond, nil
}

func (c *compiler) warn(span query.Span, hint, format string, a ...any) {
	c.warnings = append(c.warnings, query.Warning{Msg: fmt.Sprintf(format, a...), Hint: hint, Span: span})
}

func (c *compiler) addrValue(v query.Value, name string, def qfield) (string, error) {
	if query.IsNetworkValue(v.Text) && strings.Contains(v.Text, "-") {
		return c.addrRange(v.Text, v.Span, name, def)
	}
	if _, _, err := addrRange(v.Text); err == nil {
		if def.side == "" {
			cond, args, _ := FilterFields[def.legacy].cond(v.Text)
			c.args = append(c.args, args...)
			return cond, nil
		}
		lo, hi, _ := addrRange(v.Text)
		return c.sided(def, func(col string) string {
			c.args = append(c.args, lo, hi)
			return col + " BETWEEN toIPv6(?) AND toIPv6(?)"
		}), nil
	}
	if strings.ContainsAny(v.Text, "/") || (strings.Count(v.Text, ".") == 3 && isDigitsDots(v.Text)) {
		return "", errAt(v.Span, "", "%s: invalid address or prefix %s", name, v.Text)
	}
	// A name.
	var addrs []netip.Addr
	if c.names != nil {
		addrs = c.names.HostAddrs(v.Text)
	}
	if len(addrs) == 0 {
		c.warn(v.Span, "", "no host named %s", query.Quote(v.Text, false))
		return "0", nil
	}
	if len(addrs) > MaxNameAddrs {
		return "", errAt(v.Span, "use a prefix such as 10.0.0.0/24", "%s matches %d addresses", v.Text, len(addrs))
	}
	return c.sided(def, func(col string) string {
		ph := make([]string, len(addrs))
		for i, a := range addrs {
			ph[i] = "toIPv6(?)"
			c.args = append(c.args, a.String())
		}
		return col + " IN (" + strings.Join(ph, ", ") + ")"
	}), nil
}

// sided applies an address condition to the field's columns, restricted to
// the local or remote side if the field asks.
func (c *compiler) sided(def qfield, cond func(col string) string) string {
	cols := FilterFields[def.legacy].cols
	parts := make([]string, 0, len(cols))
	for _, col := range cols {
		p := cond(col)
		switch def.side {
		case "local":
			p = "(" + p + " AND " + isLocal(col) + ")"
		case "remote":
			p = "(" + p + " AND NOT " + isLocal(col) + ")"
		}
		parts = append(parts, p)
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func (c *compiler) addrRange(s string, span query.Span, name string, def qfield) (string, error) {
	a, b, _ := strings.Cut(s, "-")
	lo, err1 := netip.ParseAddr(a)
	hi, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil {
		return "", errAt(span, "", "%s: invalid address range %s", name, s)
	}
	m := func(x netip.Addr) netip.Addr {
		if x.Is4() {
			return netip.AddrFrom16(x.As16())
		}
		return x
	}
	lo, hi = m(lo), m(hi)
	if hi.Less(lo) {
		return "", errAt(span, "", "the range is backwards")
	}
	return c.sided(def, func(col string) string {
		c.args = append(c.args, lo.String(), hi.String())
		return col + " BETWEEN toIPv6(?) AND toIPv6(?)"
	}), nil
}

func (c *compiler) deviceName(v query.Value) (string, error) {
	var macs []uint64
	if c.names != nil {
		macs = c.names.DeviceMACs(v.Text)
	}
	if len(macs) == 0 {
		c.warn(v.Span, "", "no device named %s", query.Quote(v.Text, false))
		return "0", nil
	}
	if len(macs) > MaxNameAddrs {
		return "", errAt(v.Span, "", "%s matches %d devices", v.Text, len(macs))
	}
	ph := make([]string, len(macs))
	for i, m := range macs {
		ph[i] = "?"
		c.args = append(c.args, m)
	}
	return "(device_mac IN (" + strings.Join(ph, ", ") + "))", nil
}

// number reads a value in the field's unit.
func (c *compiler) number(v query.Value, def qfield, name string) (uint64, error) {
	var n uint64
	var ok bool
	switch def.unit {
	case unitSize:
		n, ok = parseSize(v.Text)
	case unitDuration:
		n, ok = parseDuration(v.Text)
	default:
		s := v.Text
		if strings.HasPrefix(strings.ToUpper(s), "AS") && strings.Contains(name, "as") {
			s = s[2:]
		}
		var err error
		n, err = strconv.ParseUint(s, 10, 64)
		ok = err == nil
	}
	if !ok {
		hint := map[unit]string{unitPlain: "a number", unitSize: "a size such as 100MB", unitDuration: "a duration such as 5m"}[def.unit]
		return 0, errAt(v.Span, "", "%s takes %s", name, hint)
	}
	if n > def.max {
		return 0, errAt(v.Span, "", "%s is at most %d", name, def.max)
	}
	return n, nil
}

var sizeUnits = map[string]float64{"": 1, "b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
	"k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12, "kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40}

var durationUnits = map[string]float64{"": 1000, "ms": 1, "s": 1000, "m": 60e3, "h": 3600e3, "d": 86400e3}

func parseUnit(s string, units map[string]float64) (uint64, bool) {
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i < 0 {
		i = len(s)
	}
	f, err := strconv.ParseFloat(s[:i], 64)
	mul, ok := units[strings.ToLower(s[i:])]
	if err != nil || !ok || f < 0 || f*mul > math.MaxUint64/2 {
		return 0, false
	}
	return uint64(math.Round(f * mul)), true
}

func parseSize(s string) (uint64, bool)     { return parseUnit(s, sizeUnits) }
func parseDuration(s string) (uint64, bool) { return parseUnit(s, durationUnits) }

func isDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func isDigitsDots(s string) bool { return strings.Trim(s, "0123456789.") == "" }

func knownThreatFeed(v string) bool {
	if v == "*" {
		return true
	}
	ids := *threatFeedIDs.Load()
	if _, ok := ids[strings.ToLower(v)]; ok {
		return true
	}
	for _, id := range ids {
		if id == v {
			return true
		}
	}
	return false
}

// closest suggests the candidate nearest s, if one is close enough.
func closest(s string, candidates []string) string {
	best, bestD := "", 3
	for _, c := range candidates {
		if d := editDistance(s, c); d < bestD {
			best, bestD = c, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// FiltersToQuery writes classic filters (field → comma-separated values,
// "!" negating) as a query that selects the same flows.
func FiltersToQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if _, ok := FilterFields[k]; ok && strings.TrimSpace(v) != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var terms []string
	for _, k := range keys {
		raw := strings.TrimSpace(params[k])
		neg := strings.HasPrefix(raw, "!")
		var vals []string
		for _, v := range strings.Split(strings.TrimPrefix(raw, "!"), ",") {
			if v = strings.TrimSpace(v); v != "" {
				vals = append(vals, query.Quote(v, false))
			}
		}
		if len(vals) == 0 {
			continue
		}
		t := k + ":" + vals[0]
		if len(vals) > 1 {
			t = k + ":(" + strings.Join(vals, " OR ") + ")"
		}
		if neg {
			t = "NOT " + t
		}
		terms = append(terms, t)
	}
	return strings.Join(terms, " AND ")
}
