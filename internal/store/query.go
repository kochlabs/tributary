package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

func ipstr(col string) string {
	return fmt.Sprintf("replaceRegexpOne(toString(%s), '^::ffff:', '')", col)
}

// appExpr identifies the application side of a flow: the well-known port if
// either side has one, else the lower port.
var appExpr = `concat(toString(proto), '/', toString(if(proto IN (6, 17, 132),
	multiIf(dst_port < 1024, dst_port, src_port < 1024, src_port, least(src_port, dst_port)), 0)))`

type dimension struct {
	expr   string
	rollup bool
}

// Dimensions are the group-by keys for top-N and series queries. Every
// expression yields a String so results share one shape.
var Dimensions = map[string]dimension{
	"exporter":     {ipstr("exporter"), true},
	"src_addr":     {ipstr("src_addr"), false},
	"dst_addr":     {ipstr("dst_addr"), false},
	"host":         {ipstr("arrayJoin([src_addr, dst_addr])"), false},
	"conversation": {"concat(" + ipstr("least(src_addr, dst_addr)") + ", ' ⇄ ', " + ipstr("greatest(src_addr, dst_addr)") + ")", false},
	"app":          {appExpr, false},
	"proto":        {"toString(proto)", true},
	"src_port":     {"toString(src_port)", false},
	"dst_port":     {"toString(dst_port)", false},
	"src_as":       {"toString(src_as)", false},
	"dst_as":       {"toString(dst_as)", false},
	"in_if":        {"concat(" + ipstr("exporter") + ", '|', toString(in_if))", true},
	"out_if":       {"concat(" + ipstr("exporter") + ", '|', toString(out_if))", true},
	"dscp":         {"toString(bitShiftRight(tos, 2))", false},
	"etype":        {"toString(etype)", true},
	"vlan":         {"toString(vlan)", false},
	"flow_type":    {"toString(flow_type)", false},
	"src_country":  {"src_country", false},
	"dst_country":  {"dst_country", false},
	"country":      {"arrayJoin(arrayFilter(c -> c != '', arrayDistinct([src_country, dst_country])))", false},
	// The threat feed listing either end (the source's first), and that
	// end's address.
	"threat":      {"if(src_threat != '', src_threat, dst_threat)", false}, // the feed's ID
	"threat_host": {"multiIf(src_threat != '', " + ipstr("src_addr") + ", dst_threat != '', " + ipstr("dst_addr") + ", '')", false},
}

type Query struct {
	From, To time.Time
	Filter   *Filter
	Metric   string // bps | pps | fps
	GroupBy  string
	Limit    int
}

type source struct {
	table, timeCol, flows string
	raw                   bool
}

var (
	rawSource    = source{"netflow.flows", "time_received", "count()", true}
	rollupSource = source{"netflow.traffic_1m", "ts", "sum(flows)", false}
)

// pick prefers the 1-minute rollup when the query only touches rollup columns
// and covers enough time that 1-minute resolution is sufficient.
func (q *Query) pick(dims ...string) source {
	if q.Filter != nil && !q.Filter.rollupOK {
		return rawSource
	}
	for _, d := range dims {
		if dd, _ := LookupDimension(d); d != "" && !dd.rollup {
			return rawSource
		}
	}
	if q.To.Sub(q.From) <= 3*time.Hour {
		return rawSource
	}
	return rollupSource
}

func (q *Query) where(src source) (string, []any) {
	f := q.Filter
	if f == nil {
		f = &Filter{}
	}
	return f.where(src.timeCol, q.From.Unix(), q.To.Unix())
}

func (q *Query) metricCol() string {
	switch q.Metric {
	case "pps":
		return "p"
	case "fps":
		return "f"
	}
	return "b"
}

var niceSteps = []int{10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400}

func pickStep(d time.Duration, raw bool) int {
	want := int(d.Seconds() / 240)
	for _, s := range niceSteps {
		if s >= want && (raw || s >= 60) {
			return s
		}
	}
	return 86400
}

type Series struct {
	Key    string    `json:"key"`
	Label  string    `json:"label"`
	Values []float64 `json:"values"`
	Total  float64   `json:"total"`
}

type TimeSeries struct {
	Step   int      `json:"step"`
	Metric string   `json:"metric"`
	Times  []int64  `json:"times"`
	Series []Series `json:"series"`
	Source string   `json:"source"`
}

const otherKey = "__other__"

// TimeSeries returns the traffic rate over time, optionally split by the top
// q.Limit values of q.GroupBy with the remainder folded into "Other".
func (s *Store) TimeSeries(ctx context.Context, q Query) (*TimeSeries, error) {
	var dim dimension
	if q.GroupBy != "" {
		var ok bool
		if dim, ok = LookupDimension(q.GroupBy); !ok {
			return nil, fmt.Errorf("unknown dimension %q", q.GroupBy)
		}
	}
	src := q.pick(q.GroupBy)
	step := pickStep(q.To.Sub(q.From), src.raw)
	from := q.From.Truncate(time.Duration(step) * time.Second)
	q.From = from

	// Raw flows are spread over their duration, so include flows received up
	// to an hour after the window that may have started inside it.
	wq := q
	if src.raw {
		wq.To = q.To.Add(time.Hour)
	}
	where, args := wq.where(src)
	group := "''"
	var keys []string
	if q.GroupBy != "" {
		top, err := s.TopN(ctx, Query{From: q.From, To: q.To, Filter: q.Filter, Metric: q.Metric, GroupBy: q.GroupBy, Limit: max(q.Limit, 1)})
		if err != nil {
			return nil, err
		}
		for _, r := range top.Rows {
			keys = append(keys, r.Key)
		}
		if len(keys) == 0 {
			keys = []string{""}
		}
		group = fmt.Sprintf("if(has(?, %s), %s, '%s')", dim.expr, dim.expr, otherKey)
		args = append([]any{keys}, args...)
	}
	var sql string
	if src.raw {
		sql = fmt.Sprintf(`SELECT toUInt32(tb.1) AS t, %s AS g, toUInt64(round(sum(bytes * tb.2))) AS b,
			toUInt64(round(sum(packets * tb.2))) AS p, toUInt64(sum(tb.3)) AS f
			FROM (SELECT *, %s AS tb FROM netflow.flows WHERE %s)
			WHERE t >= ? AND t < ? GROUP BY t, g ORDER BY t`, group, spreadBuckets(step), where)
		args = append(args, from.Unix(), q.To.Unix())
	} else {
		sql = fmt.Sprintf(`SELECT toUnixTimestamp(toStartOfInterval(%s, INTERVAL %d SECOND)) AS t, %s AS g,
			sum(bytes) AS b, sum(packets) AS p, %s AS f
			FROM %s WHERE %s GROUP BY t, g ORDER BY t`, src.timeCol, step, group, src.flows, src.table, where)
	}
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	n := int(q.To.Sub(from).Seconds())/step + 1
	ts := &TimeSeries{Step: step, Metric: q.Metric, Times: make([]int64, n), Source: src.table}
	for i := range ts.Times {
		ts.Times[i] = (from.Unix() + int64(i*step)) * 1000
	}
	byKey := map[string]*Series{}
	order := append([]string{}, keys...)
	if q.GroupBy == "" {
		order = []string{""}
	}
	col := q.metricCol()
	for rows.Next() {
		var t uint32
		var g string
		var b, p, f uint64
		if err := rows.Scan(&t, &g, &b, &p, &f); err != nil {
			return nil, err
		}
		idx := (int64(t) - from.Unix()) / int64(step)
		if idx < 0 || int(idx) >= n {
			continue
		}
		se := byKey[g]
		if se == nil {
			se = &Series{Key: g, Values: make([]float64, n)}
			byKey[g] = se
			if g == otherKey {
				order = append(order, g)
			}
		}
		var v float64
		switch col {
		case "b":
			v = float64(b) * 8 / float64(step)
		case "p":
			v = float64(p) / float64(step)
		default:
			v = float64(f) / float64(step)
		}
		se.Values[int(idx)] += v
		se.Total += v * float64(step)
	}
	for _, k := range order {
		if se := byKey[k]; se != nil {
			ts.Series = append(ts.Series, *se)
		} else if k != otherKey && (q.GroupBy == "" || k != "") {
			ts.Series = append(ts.Series, Series{Key: k, Values: make([]float64, n)})
		}
	}
	return ts, rows.Err()
}

type TopRow struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"` // secondary label (hostname, AS org, country)
	// Conversation endpoints, local side first.
	Ends    []Endpoint `json:"ends,omitempty"`
	Bytes   uint64     `json:"bytes"`
	Packets uint64     `json:"packets"`
	Flows   uint64     `json:"flows"`
	Rate    float64    `json:"rate"` // average of the selected metric over the range
	Pct     float64    `json:"pct"`
}

type Endpoint struct {
	Addr   string `json:"addr"`
	Name   string `json:"name"`   // hostname, or organisation for remote hosts without one
	Detail string `json:"detail"` // address and context
	Local  bool   `json:"local"`
}

type TopResult struct {
	Dimension string   `json:"dimension"`
	Metric    string   `json:"metric"`
	Rows      []TopRow `json:"rows"`
	Total     TopRow   `json:"total"`
	Source    string   `json:"source"`
}

func (s *Store) TopN(ctx context.Context, q Query) (*TopResult, error) {
	dim, ok := LookupDimension(q.GroupBy)
	if !ok {
		return nil, fmt.Errorf("unknown dimension %q", q.GroupBy)
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 10
	}
	src := q.pick(q.GroupBy)
	where, args := q.where(src)
	order := map[string]string{"b": "b", "p": "p", "f": "f"}[q.metricCol()]
	sql := fmt.Sprintf(`SELECT %s AS k, sum(bytes) AS b, sum(packets) AS p, %s AS f
		FROM %s WHERE %s GROUP BY k ORDER BY %s DESC LIMIT %d`, dim.expr, src.flows, src.table, where, order, q.Limit)
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	res := &TopResult{Dimension: q.GroupBy, Metric: q.Metric, Source: src.table}
	for rows.Next() {
		var r TopRow
		if err := rows.Scan(&r.Key, &r.Bytes, &r.Packets, &r.Flows); err != nil {
			return nil, err
		}
		res.Rows = append(res.Rows, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	totSQL := fmt.Sprintf(`SELECT sum(bytes), sum(packets), %s FROM %s WHERE %s`, src.flows, src.table, where)
	if err := s.conn.QueryRow(ctx, totSQL, args...).Scan(&res.Total.Bytes, &res.Total.Packets, &res.Total.Flows); err != nil {
		return nil, err
	}
	secs := q.To.Sub(q.From).Seconds()
	rate := func(r *TopRow) (float64, float64) {
		switch q.metricCol() {
		case "p":
			return float64(r.Packets) / secs, float64(r.Packets)
		case "f":
			return float64(r.Flows) / secs, float64(r.Flows)
		}
		return float64(r.Bytes) * 8 / secs, float64(r.Bytes)
	}
	_, total := rate(&res.Total)
	res.Total.Rate, _ = rate(&res.Total)
	res.Total.Pct = 100
	for i := range res.Rows {
		r := &res.Rows[i]
		var v float64
		r.Rate, v = rate(r)
		if total > 0 {
			r.Pct = v / total * 100
		}
	}
	return res, nil
}

type FlowRow struct {
	TimeReceived int64  `json:"timeReceived"`
	TimeStart    int64  `json:"timeStart"`
	TimeEnd      int64  `json:"timeEnd"`
	FlowType     uint8  `json:"flowType"`
	Exporter     string `json:"exporter"`
	Sampling     uint32 `json:"sampling"`
	InIf         uint32 `json:"inIf"`
	OutIf        uint32 `json:"outIf"`
	SrcAddr      string `json:"srcAddr"`
	DstAddr      string `json:"dstAddr"`
	NextHop      string `json:"nextHop"`
	SrcPort      uint16 `json:"srcPort"`
	DstPort      uint16 `json:"dstPort"`
	Proto        uint8  `json:"proto"`
	TCPFlags     uint8  `json:"tcpFlags"`
	ToS          uint8  `json:"tos"`
	SrcAS        uint32 `json:"srcAs"`
	DstAS        uint32 `json:"dstAs"`
	VLAN         uint16 `json:"vlan"`
	Bytes        uint64 `json:"bytes"`
	Packets      uint64 `json:"packets"`
	ExporterName string `json:"exporterName,omitempty"`
	SrcMAC       string `json:"srcMac,omitempty"`
	DstMAC       string `json:"dstMac,omitempty"`
	DeviceMAC    string `json:"deviceMac,omitempty"`
	SrcCountry   string `json:"srcCountry"`
	SrcThreat    string `json:"srcThreat,omitempty"`
	DstThreat    string `json:"dstThreat,omitempty"`
	DstCountry   string `json:"dstCountry"`
	SrcHost      string `json:"srcHost,omitempty"`
	DstHost      string `json:"dstHost,omitempty"`
	SrcASName    string `json:"srcAsName,omitempty"`
	DstASName    string `json:"dstAsName,omitempty"`
}

type FlowPage struct {
	Total uint64    `json:"total"`
	Rows  []FlowRow `json:"rows"`
}

var flowSorts = map[string]string{
	"time":    "time_received",
	"bytes":   "bytes",
	"packets": "packets",
	"src":     "src_addr",
	"dst":     "dst_addr",
	"dport":   "dst_port",
}

func (s *Store) Flows(ctx context.Context, q Query, sortBy string, desc bool, offset int) (*FlowPage, error) {
	col, ok := flowSorts[sortBy]
	if !ok {
		col = "time_received"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	if q.Limit <= 0 || q.Limit > 5000 {
		q.Limit = 100
	}
	where, args := q.where(rawSource)
	page := &FlowPage{}
	if err := s.conn.QueryRow(ctx, "SELECT count() FROM netflow.flows WHERE "+where, args...).Scan(&page.Total); err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`SELECT toUnixTimestamp(time_received), toUnixTimestamp(time_start), toUnixTimestamp(time_end), flow_type,
		%s, sampling_rate, in_if, out_if, %s, %s, %s, src_port, dst_port, proto, tcp_flags, tos, src_as, dst_as, vlan, bytes, packets, src_country, dst_country,
		if(src_mac = 0, '', lower(MACNumToString(src_mac))), if(dst_mac = 0, '', lower(MACNumToString(dst_mac))),
		if(device_mac = 0, '', lower(MACNumToString(device_mac))), src_threat, dst_threat
		FROM netflow.flows WHERE %s ORDER BY %s %s LIMIT %d OFFSET %d`,
		ipstr("exporter"), ipstr("src_addr"), ipstr("dst_addr"), ipstr("next_hop"), where, col, dir, q.Limit, max(offset, 0))
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page.Rows = []FlowRow{}
	for rows.Next() {
		var r FlowRow
		var tr, ts, te uint32
		if err := rows.Scan(&tr, &ts, &te, &r.FlowType, &r.Exporter, &r.Sampling, &r.InIf, &r.OutIf, &r.SrcAddr, &r.DstAddr, &r.NextHop,
			&r.SrcPort, &r.DstPort, &r.Proto, &r.TCPFlags, &r.ToS, &r.SrcAS, &r.DstAS, &r.VLAN, &r.Bytes, &r.Packets, &r.SrcCountry, &r.DstCountry,
			&r.SrcMAC, &r.DstMAC, &r.DeviceMAC, &r.SrcThreat, &r.DstThreat); err != nil {
			return nil, err
		}
		r.TimeReceived, r.TimeStart, r.TimeEnd = int64(tr)*1000, int64(ts)*1000, int64(te)*1000
		page.Rows = append(page.Rows, r)
	}
	return page, rows.Err()
}

type Summary struct {
	DownloadBytes uint64  `json:"downloadBytes"`
	UploadBytes   uint64  `json:"uploadBytes"`
	DownloadBps   float64 `json:"downloadBps"`
	UploadBps     float64 `json:"uploadBps"`
	PeakDownBps   float64 `json:"peakDownloadBps"`
	PeakUpBps     float64 `json:"peakUploadBps"`
	LocalHosts    uint64  `json:"localHosts"`
	RemoteHosts   uint64  `json:"remoteHosts"`
	Bytes         uint64  `json:"bytes"`
	Packets       uint64  `json:"packets"`
	Flows         uint64  `json:"flows"`
	Exporters     uint64  `json:"exporters"`
	SrcHosts      uint64  `json:"srcHosts"`
	DstHosts      uint64  `json:"dstHosts"`
	AvgBps        float64 `json:"avgBps"`
	PeakBps       float64 `json:"peakBps"`
	AvgPps        float64 `json:"avgPps"`
}

func (s *Store) Summary(ctx context.Context, q Query) (*Summary, error) {
	where, args := q.where(rawSource)
	var sum Summary
	in, _ := LookupDimensionExpr("direction")
	err := s.conn.QueryRow(ctx, fmt.Sprintf(`SELECT sum(bytes), sum(packets), count(), uniq(exporter), uniq(src_addr), uniq(dst_addr),
		sumIf(bytes, %[1]s = 'download'), sumIf(bytes, %[1]s = 'upload'),
		uniqArray(arrayFilter((a, l) -> l, [src_addr, dst_addr], [%[2]s, %[3]s])),
		uniqArray(arrayFilter((a, l) -> NOT l, [src_addr, dst_addr], [%[2]s, %[3]s]))
		FROM netflow.flows WHERE `+where, in, isLocal("src_addr"), isLocal("dst_addr")), args...).
		Scan(&sum.Bytes, &sum.Packets, &sum.Flows, &sum.Exporters, &sum.SrcHosts, &sum.DstHosts,
			&sum.DownloadBytes, &sum.UploadBytes, &sum.LocalHosts, &sum.RemoteHosts)
	if err != nil {
		return nil, err
	}
	// Peaks use 1-minute buckets with each flow spread over its duration.
	wq := q
	wq.To = q.To.Add(time.Hour)
	pwhere, pargs := wq.where(rawSource)
	pargs = append(pargs, q.From.Unix(), q.To.Unix())
	var peak, peakDown, peakUp float64
	err = s.conn.QueryRow(ctx, fmt.Sprintf(`SELECT max(b), max(d), max(u) FROM (
		SELECT tb.1 AS t, sum(bytes * tb.2) AS b, sumIf(bytes * tb.2, dir = 'download') AS d, sumIf(bytes * tb.2, dir = 'upload') AS u
		FROM (SELECT bytes, %s AS dir, %s AS tb FROM netflow.flows WHERE %s)
		WHERE t >= ? AND t < ? GROUP BY t)`, in, spreadBuckets(60), pwhere), pargs...).Scan(&peak, &peakDown, &peakUp)
	if err != nil {
		return nil, err
	}
	secs := q.To.Sub(q.From).Seconds()
	sum.AvgBps = float64(sum.Bytes) * 8 / secs
	sum.AvgPps = float64(sum.Packets) / secs
	sum.DownloadBps = float64(sum.DownloadBytes) * 8 / secs
	sum.UploadBps = float64(sum.UploadBytes) * 8 / secs
	sum.PeakBps, sum.PeakDownBps, sum.PeakUpBps = peak*8/60, peakDown*8/60, peakUp*8/60
	return &sum, nil
}

type InterfaceTraffic struct {
	Exporter string `json:"exporter"`
	Index    uint32 `json:"index"`
	InBytes  uint64 `json:"inBytes"`
	OutBytes uint64 `json:"outBytes"`
}

// Interfaces lists interfaces seen in [from, to) with their volume.
func (s *Store) Interfaces(ctx context.Context, exporter string, from, to time.Time) ([]InterfaceTraffic, error) {
	cond := " AND ts >= toDateTime(?) AND ts < toDateTime(?)"
	part := []any{from.Unix(), to.Unix()}
	if exporter != "" {
		lo, _, err := addrRange(exporter)
		if err != nil {
			return nil, err
		}
		cond += " AND exporter = toIPv6(?)"
		part = append(part, lo)
	}
	args := append(append([]any{}, part...), part...)
	sql := fmt.Sprintf(`SELECT %s AS e, i, sumIf(bytes, d = 0) AS inb, sumIf(bytes, d = 1) AS outb FROM (
		SELECT exporter, in_if AS i, 0 AS d, bytes FROM netflow.traffic_1m WHERE 1%s
		UNION ALL
		SELECT exporter, out_if AS i, 1 AS d, bytes FROM netflow.traffic_1m WHERE 1%s
	) WHERE i != 0 GROUP BY e, i ORDER BY e, i`, ipstr("exporter"), cond, cond)
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InterfaceTraffic{}
	for rows.Next() {
		var it InterfaceTraffic
		if err := rows.Scan(&it.Exporter, &it.Index, &it.InBytes, &it.OutBytes); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

type ExporterTraffic struct {
	Bytes    uint64 `json:"bytes"`
	Flows    uint64 `json:"flows"`
	LastSeen int64  `json:"lastSeen"`
}

// ExporterTraffic returns volume per exporter address in [from, to). LastSeen
// is the newest minute with flows in the past hour regardless of the window,
// so status reflects the exporter's current health.
func (s *Store) ExporterTraffic(ctx context.Context, from, to time.Time) (map[string]ExporterTraffic, error) {
	rows, err := s.conn.Query(ctx, fmt.Sprintf(`SELECT %s,
			sumIf(bytes, ts >= toDateTime(?) AND ts < toDateTime(?)),
			sumIf(flows, ts >= toDateTime(?) AND ts < toDateTime(?)),
			toUnixTimestamp(maxIf(ts, ts >= now() - INTERVAL 1 HOUR))
		FROM netflow.traffic_1m WHERE (ts >= toDateTime(?) AND ts < toDateTime(?)) OR ts >= now() - INTERVAL 1 HOUR
		GROUP BY exporter`, ipstr("exporter")),
		from.Unix(), to.Unix(), from.Unix(), to.Unix(), from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ExporterTraffic{}
	for rows.Next() {
		var k string
		var t ExporterTraffic
		var last uint32
		if err := rows.Scan(&k, &t.Bytes, &t.Flows, &last); err != nil {
			return nil, err
		}
		if last > 0 {
			t.LastSeen = int64(last) * 1000
		}
		out[k] = t
	}
	return out, rows.Err()
}

type TableStats struct {
	Table        string `json:"table"`
	Rows         uint64 `json:"rows"`
	BytesOnDisk  uint64 `json:"bytesOnDisk"`
	Uncompressed uint64 `json:"uncompressed"`
	Parts        uint64 `json:"parts"`
	Oldest       int64  `json:"oldest"`
	Newest       int64  `json:"newest"`
}

type DiskStats struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Free  uint64 `json:"free"`
	Total uint64 `json:"total"`
}

type DBStats struct {
	Version string       `json:"version"`
	Uptime  uint32       `json:"uptime"`
	Tables  []TableStats `json:"tables"`
	Disks   []DiskStats  `json:"disks"`
}

func (s *Store) Stats(ctx context.Context) (*DBStats, error) {
	st := &DBStats{}
	if err := s.conn.QueryRow(ctx, "SELECT version(), uptime()").Scan(&st.Version, &st.Uptime); err != nil {
		return nil, err
	}
	rows, err := s.conn.Query(ctx, `SELECT table, sum(rows), sum(bytes_on_disk), sum(data_uncompressed_bytes), count(),
		toUnixTimestamp(min(min_time)), toUnixTimestamp(max(max_time))
		FROM system.parts WHERE database = 'netflow' AND active GROUP BY table ORDER BY table`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t TableStats
		var oldest, newest uint32
		if err := rows.Scan(&t.Table, &t.Rows, &t.BytesOnDisk, &t.Uncompressed, &t.Parts, &oldest, &newest); err != nil {
			rows.Close()
			return nil, err
		}
		t.Oldest, t.Newest = int64(oldest)*1000, int64(newest)*1000
		st.Tables = append(st.Tables, t)
	}
	rows.Close()
	rows, err = s.conn.Query(ctx, "SELECT name, path, free_space, total_space FROM system.disks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d DiskStats
		if err := rows.Scan(&d.Name, &d.Path, &d.Free, &d.Total); err != nil {
			return nil, err
		}
		st.Disks = append(st.Disks, d)
	}
	sort.Slice(st.Tables, func(i, j int) bool { return strings.Compare(st.Tables[i].Table, st.Tables[j].Table) < 0 })
	return st, rows.Err()
}

// StorageRate describes how fast each table grows, measured from recent data,
// so the UI can estimate disk use for a given retention.
type StorageRate struct {
	Table       string  `json:"table"`
	BytesPerRow float64 `json:"bytesPerRow"`
	RowsPerDay  float64 `json:"rowsPerDay"`
	BytesNow    uint64  `json:"bytesNow"`
	SampleHours float64 `json:"sampleHours"` // how much history the rate is based on
}

type StorageEstimate struct {
	Tables    []StorageRate `json:"tables"`
	DiskFree  uint64        `json:"diskFree"`
	DiskTotal uint64        `json:"diskTotal"`
}

func (s *Store) StorageEstimate(ctx context.Context) (*StorageEstimate, error) {
	est := &StorageEstimate{}
	for _, t := range []struct{ table, col string }{{"flows", "time_received"}, {"traffic_1m", "ts"}} {
		r := StorageRate{Table: t.table}
		err := s.conn.QueryRow(ctx, `SELECT sum(bytes_on_disk), sum(rows) FROM system.parts
			WHERE database = 'netflow' AND table = ? AND active`, t.table).Scan(&r.BytesNow, new(uint64))
		if err != nil {
			return nil, err
		}
		var rows, total uint64
		var spanSecs int64
		// Rate over the last 24 hours, or over all data if there is less.
		q := fmt.Sprintf(`SELECT countIf(%[1]s >= now() - INTERVAL 1 DAY), count(),
			toInt64(least(86400, dateDiff('second', min(%[1]s), max(%[1]s)))) FROM netflow.%[2]s`, t.col, t.table)
		if err := s.conn.QueryRow(ctx, q).Scan(&rows, &total, &spanSecs); err != nil {
			return nil, err
		}
		if total > 0 {
			r.BytesPerRow = float64(r.BytesNow) / float64(total)
		}
		if spanSecs > 0 {
			r.RowsPerDay = float64(rows) * 86400 / float64(spanSecs)
			r.SampleHours = float64(spanSecs) / 3600
		}
		est.Tables = append(est.Tables, r)
	}
	err := s.conn.QueryRow(ctx, "SELECT free_space, total_space FROM system.disks WHERE name = 'default'").Scan(&est.DiskFree, &est.DiskTotal)
	return est, err
}

// DeviceTraffic returns bytes and flow count per device MAC in [from, to).
func (s *Store) DeviceTraffic(ctx context.Context, from, to time.Time) (map[uint64][2]uint64, error) {
	rows, err := s.conn.Query(ctx, `SELECT device_mac, sum(bytes), count() FROM netflow.flows
		WHERE time_received >= toDateTime(?) AND time_received < toDateTime(?) AND device_mac != 0 GROUP BY device_mac`,
		from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint64][2]uint64{}
	for rows.Next() {
		var mac, b, f uint64
		if err := rows.Scan(&mac, &b, &f); err != nil {
			return nil, err
		}
		out[mac] = [2]uint64{b, f}
	}
	return out, rows.Err()
}

// ThreatHit is how often a threat feed's addresses were seen.
type ThreatHit struct {
	Feed  string `json:"feed"`  // the feed's ID, as flows store it
	Hosts uint64 `json:"hosts"` // distinct listed addresses
	Flows uint64 `json:"flows"`
	Last  int64  `json:"last"` // ms
}

// ThreatHits counts flows to or from listed addresses since from, by feed.
func (s *Store) ThreatHits(ctx context.Context, from time.Time) ([]ThreatHit, error) {
	rows, err := s.conn.Query(ctx, `SELECT if(src_threat != '', src_threat, dst_threat) AS feed,
			uniq(if(src_threat != '', src_addr, dst_addr)), count(), toUnixTimestamp(max(time_received))
		FROM netflow.flows WHERE time_received >= toDateTime(?) AND (src_threat != '' OR dst_threat != '')
		GROUP BY feed ORDER BY feed`, from.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatHit{}
	for rows.Next() {
		var h ThreatHit
		var last uint32
		if err := rows.Scan(&h.Feed, &h.Hosts, &h.Flows, &last); err != nil {
			return nil, err
		}
		h.Last = int64(last) * 1000
		out = append(out, h)
	}
	return out, rows.Err()
}

// ThreatMatch is one host's traffic with a threat feed's addresses.
type ThreatMatch struct {
	Feed    string   // the feed's ID, as flows store it
	Host    string   // the side that isn't listed
	Remotes []string // listed addresses, up to 5
	Count   uint64   // distinct listed addresses
	Flows   uint64
	Bytes   uint64
	First   int64 // ms
	Last    int64 // ms
}

// ThreatMatches lists traffic with listed addresses since from, by feed and
// host, busiest first.
func (s *Store) ThreatMatches(ctx context.Context, from time.Time, limit int) ([]ThreatMatch, error) {
	rows, err := s.conn.Query(ctx, fmt.Sprintf(`SELECT feed, host, groupUniqArray(5)(remote), uniq(remote), count(), sum(bytes),
			toUnixTimestamp(min(time_received)), toUnixTimestamp(max(time_received))
		FROM (SELECT if(src_threat != '', src_threat, dst_threat) AS feed,
				%s AS host, %s AS remote, bytes, time_received
			FROM netflow.flows WHERE time_received >= toDateTime(?) AND (src_threat != '' OR dst_threat != ''))
		GROUP BY feed, host ORDER BY count() DESC LIMIT %d`,
		ipstr("if(src_threat != '', dst_addr, src_addr)"), ipstr("if(src_threat != '', src_addr, dst_addr)"), max(limit, 1)), from.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatMatch{}
	for rows.Next() {
		var m ThreatMatch
		var first, last uint32
		if err := rows.Scan(&m.Feed, &m.Host, &m.Remotes, &m.Count, &m.Flows, &m.Bytes, &first, &last); err != nil {
			return nil, err
		}
		m.First, m.Last = int64(first)*1000, int64(last)*1000
		out = append(out, m)
	}
	return out, rows.Err()
}

// ExposedService is a local host and port that remote hosts connect to.
type ExposedService struct {
	Addr    string `json:"addr"`
	Proto   uint8  `json:"proto"`
	Port    uint16 `json:"port"`
	Sources uint64 `json:"sources"` // distinct remote hosts
	Flows   uint64 `json:"flows"`
	Bytes   uint64 `json:"bytes"`
}

// Exposure lists local services that answered remote hosts in the query's
// range, by distinct remote hosts. It counts replies, so scans of closed
// ports don't: a local host sending from a service port to a remote one, for
// TCP with SYN and ACK set (the handshake's answer; when the exporter reports
// no flags, any reply), for UDP from a port below 1024 or one that answers
// several remote hosts, so a local client's own conversations don't count.
func (s *Store) Exposure(ctx context.Context, q Query, limit int) ([]ExposedService, error) {
	where, args := q.where(rawSource)
	ls, ld := isLocal("src_addr"), isLocal("dst_addr")
	sql := fmt.Sprintf(`SELECT %s AS a, proto, src_port, uniq(dst_addr) AS remotes, count() AS f, sum(bytes) AS b
		FROM netflow.flows
		WHERE %s AND %s AND NOT %s AND src_port < dst_port AND (
			(proto = 6 AND (tcp_flags = 0 OR bitAnd(tcp_flags, 18) = 18)) OR proto = 17)
		GROUP BY a, proto, src_port
		HAVING proto = 6 OR src_port < 1024 OR remotes >= 3
		ORDER BY remotes DESC, f DESC LIMIT %d`, ipstr("src_addr"), where, ls, ld, max(limit, 1))
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExposedService{}
	for rows.Next() {
		var e ExposedService
		if err := rows.Scan(&e.Addr, &e.Proto, &e.Port, &e.Sources, &e.Flows, &e.Bytes); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
