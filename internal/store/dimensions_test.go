package store

import "testing"

func TestDimensionNames(t *testing.T) {
	names := DimensionNames()
	for _, n := range names {
		if _, ok := LookupDimension(n); !ok {
			t.Errorf("%s is listed but doesn't resolve", n)
		}
	}
	for _, n := range localDimensionNames {
		if _, ok := localDimension(n); !ok {
			t.Errorf("%s is not a local dimension", n)
		}
	}
	if len(names) < len(Dimensions)+5 {
		t.Fatalf("only %d names", len(names))
	}
}

func TestThreatFilter(t *testing.T) {
	f, err := ParseFilter(map[string]string{"threat": "*"})
	if err != nil || len(f.conds) != 1 || f.conds[0] != "((src_threat != '' OR dst_threat != ''))" || f.rollupOK {
		t.Fatalf("any: %+v %v", f, err)
	}
	f, err = ParseFilter(map[string]string{"threat": "!Tor exit nodes"})
	if err != nil || f.conds[0] != "NOT ((src_threat = ? OR dst_threat = ?))" || len(f.args) != 2 || f.args[0] != "Tor exit nodes" {
		t.Fatalf("not one feed: %+v %v", f, err)
	}
	for _, d := range []string{"threat", "threat_host"} {
		if dim, ok := LookupDimension(d); !ok || dim.rollup {
			t.Fatalf("%s: %+v", d, dim)
		}
	}
}
