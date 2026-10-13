package collector

import "math"

func f64(b uint64) float64  { return math.Float64frombits(b) }
func bits(f float64) uint64 { return math.Float64bits(f) }
