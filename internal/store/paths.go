package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// OtherKey is the node that collects everything outside a column's top N.
const OtherKey = "__other__"

// Dimensions that expand one flow into several rows (arrayJoin) would count
// its traffic more than once in a path, so they can't be path columns.
var pathExcluded = map[string]bool{"host": true, "country": true, "local_host": true, "remote_host": true}

type PathNode struct {
	Column  int     `json:"column"`
	Key     string  `json:"key"`
	Label   string  `json:"label"`
	Detail  string  `json:"detail,omitempty"`
	Bytes   uint64  `json:"bytes"`
	Packets uint64  `json:"packets"`
	Flows   uint64  `json:"flows"`
	Rate    float64 `json:"rate"`
}

type PathLink struct {
	Source  int     `json:"source"` // node indexes
	Target  int     `json:"target"`
	Bytes   uint64  `json:"bytes"`
	Packets uint64  `json:"packets"`
	Flows   uint64  `json:"flows"`
	Rate    float64 `json:"rate"`
}

type PathResult struct {
	Dimensions []string   `json:"dimensions"`
	Metric     string     `json:"metric"`
	Nodes      []PathNode `json:"nodes"`
	Links      []PathLink `json:"links"`
	Source     string     `json:"source"`
}

// PathDimension reports whether d can be a column of a traffic path.
func PathDimension(d string) bool {
	_, ok := LookupDimension(d)
	return ok && !pathExcluded[d]
}

// ValidPathDimensions checks a list of 2 or 3 distinct path dimensions.
func ValidPathDimensions(dims []string) error {
	if len(dims) < 2 || len(dims) > 3 {
		return fmt.Errorf("choose 2 or 3 dimensions")
	}
	seen := map[string]bool{}
	for _, d := range dims {
		if _, ok := LookupDimension(d); !ok {
			return fmt.Errorf("unknown dimension %q", d)
		}
		if pathExcluded[d] {
			return fmt.Errorf("dimension %q can't be used in a path: it counts each flow on both sides", d)
		}
		if seen[d] {
			return fmt.Errorf("dimension %q is used twice", d)
		}
		seen[d] = true
	}
	return nil
}

// Paths aggregates traffic over 2–3 dimensions for a Sankey diagram. Each
// column keeps its top `limit` values (ranked by the query metric over the
// whole selection, not just within the shown paths); the rest is folded into
// an OtherKey node per column.
func (s *Store) Paths(ctx context.Context, q Query, dims []string, limit int) (*PathResult, error) {
	if err := ValidPathDimensions(dims); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 25 {
		limit = 8
	}
	src := q.pick(dims...)
	where, wargs := q.where(src)
	flowRow := "1"
	if !src.raw {
		flowRow = "flows"
	}
	rank := map[string]string{"b": "sum(bytes)", "p": "sum(packets)", "f": "sum(" + flowRow + ")"}[q.metricCol()]

	var cols, keys, groups []string
	var args []any
	for i, d := range dims {
		dd, _ := LookupDimension(d)
		top := fmt.Sprintf(`(SELECT k FROM (SELECT %s AS k, %s AS v FROM %s WHERE %s GROUP BY k ORDER BY v DESC LIMIT %d))`,
			dd.expr, rank, src.table, where, limit)
		args = append(args, wargs...)
		cols = append(cols, fmt.Sprintf("if(k%[1]d IN %[2]s, k%[1]d, '%[3]s') AS c%[1]d", i, top, OtherKey))
		keys = append(keys, fmt.Sprintf("%s AS k%d", dd.expr, i))
		groups = append(groups, fmt.Sprintf("c%d", i))
	}
	args = append(args, wargs...)
	sql := fmt.Sprintf(`SELECT %s, sum(bytes), sum(packets), sum(fl)
		FROM (SELECT %s, bytes, packets, %s AS fl FROM %s WHERE %s)
		GROUP BY %s`,
		strings.Join(cols, ", "), strings.Join(keys, ", "), flowRow, src.table, where, strings.Join(groups, ", "))
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := &PathResult{Dimensions: dims, Metric: q.Metric, Source: src.table, Nodes: []PathNode{}, Links: []PathLink{}}
	type nodeKey struct {
		col int
		key string
	}
	nodeIdx := map[nodeKey]int{}
	node := func(col int, key string) int {
		k := nodeKey{col, key}
		if i, ok := nodeIdx[k]; ok {
			return i
		}
		nodeIdx[k] = len(res.Nodes)
		res.Nodes = append(res.Nodes, PathNode{Column: col, Key: key})
		return len(res.Nodes) - 1
	}
	linkIdx := map[[2]int]int{}
	for rows.Next() {
		ks := make([]string, len(dims))
		var b, p, f uint64
		dest := make([]any, 0, len(dims)+3)
		for i := range ks {
			dest = append(dest, &ks[i])
		}
		dest = append(dest, &b, &p, &f)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		prev := -1
		for col, k := range ks {
			n := node(col, k)
			nd := &res.Nodes[n]
			nd.Bytes, nd.Packets, nd.Flows = nd.Bytes+b, nd.Packets+p, nd.Flows+f
			if prev >= 0 {
				li, ok := linkIdx[[2]int{prev, n}]
				if !ok {
					li = len(res.Links)
					linkIdx[[2]int{prev, n}] = li
					res.Links = append(res.Links, PathLink{Source: prev, Target: n})
				}
				l := &res.Links[li]
				l.Bytes, l.Packets, l.Flows = l.Bytes+b, l.Packets+p, l.Flows+f
			}
			prev = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	secs := q.To.Sub(q.From).Seconds()
	rate := func(b, p, f uint64) float64 {
		switch q.metricCol() {
		case "p":
			return float64(p) / secs
		case "f":
			return float64(f) / secs
		}
		return float64(b) * 8 / secs
	}
	for i := range res.Nodes {
		n := &res.Nodes[i]
		n.Rate = rate(n.Bytes, n.Packets, n.Flows)
	}
	for i := range res.Links {
		l := &res.Links[i]
		l.Rate = rate(l.Bytes, l.Packets, l.Flows)
	}
	sortPathNodes(res)
	return res, nil
}

// sortPathNodes orders nodes by column, then size with "Other" last, and
// remaps link indexes, so the diagram stacks each column largest first.
func sortPathNodes(res *PathResult) {
	order := make([]int, len(res.Nodes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := res.Nodes[order[a]], res.Nodes[order[b]]
		if x.Column != y.Column {
			return x.Column < y.Column
		}
		if (x.Key == OtherKey) != (y.Key == OtherKey) {
			return y.Key == OtherKey
		}
		return x.Rate > y.Rate
	})
	remap := make([]int, len(order))
	nodes := make([]PathNode, len(order))
	for newI, oldI := range order {
		remap[oldI] = newI
		nodes[newI] = res.Nodes[oldI]
	}
	res.Nodes = nodes
	for i := range res.Links {
		res.Links[i].Source = remap[res.Links[i].Source]
		res.Links[i].Target = remap[res.Links[i].Target]
	}
	sort.SliceStable(res.Links, func(a, b int) bool { return res.Links[a].Rate > res.Links[b].Rate })
}
