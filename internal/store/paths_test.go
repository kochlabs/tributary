package store

import "testing"

func TestValidPathDimensions(t *testing.T) {
	for _, ok := range [][]string{{"device", "app"}, {"device", "app", "remote_as"}, {"in_if", "out_if"}} {
		if err := ValidPathDimensions(ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][]string{{"app"}, {"a", "b", "c", "d"}, {"app", "app"}, {"host", "app"}, {"nope", "app"}, {"device", "app", "proto", "vlan"}} {
		if ValidPathDimensions(bad) == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestSortPathNodes(t *testing.T) {
	res := &PathResult{
		Nodes: []PathNode{
			{Column: 1, Key: "b", Rate: 5},
			{Column: 0, Key: OtherKey, Rate: 50},
			{Column: 0, Key: "x", Rate: 10},
			{Column: 1, Key: "a", Rate: 9},
		},
		Links: []PathLink{{Source: 1, Target: 0, Rate: 5}, {Source: 2, Target: 3, Rate: 9}},
	}
	sortPathNodes(res)
	want := []string{"x", OtherKey, "a", "b"} // by column, largest first, Other last
	for i, k := range want {
		if res.Nodes[i].Key != k {
			t.Fatalf("order: %+v", res.Nodes)
		}
	}
	// Links keep pointing at the same nodes, largest first.
	if l := res.Links[0]; res.Nodes[l.Source].Key != "x" || res.Nodes[l.Target].Key != "a" {
		t.Fatalf("link 0: %+v", l)
	}
	if l := res.Links[1]; res.Nodes[l.Source].Key != OtherKey || res.Nodes[l.Target].Key != "b" {
		t.Fatalf("link 1: %+v", l)
	}
}
