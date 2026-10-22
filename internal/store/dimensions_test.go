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
