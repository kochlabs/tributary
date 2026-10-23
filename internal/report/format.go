package report

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Number formats match the web UI (core/format.ts).

var siPrefixes = []string{"", "K", "M", "G", "T", "P"}

func si(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "–"
	}
	i, x := 0, math.Abs(v)
	for x >= 1000 && i < len(siPrefixes)-1 {
		x /= 1000
		i++
	}
	var s string
	switch {
	case i == 0 && x < 10 && x != math.Trunc(x):
		s = fmt.Sprintf("%.1f", x)
	case x >= 100 || i == 0:
		s = fmt.Sprintf("%.0f", x)
	default:
		s = fmt.Sprintf("%.1f", x)
	}
	if v < 0 {
		s = "-" + s
	}
	if siPrefixes[i] != "" {
		s += " " + siPrefixes[i]
	}
	return s
}

// Bits formats a rate in bits per second: "12.4 Mbps".
func Bits(v float64) string {
	s := si(v)
	if strings.HasSuffix(s, " K") || strings.HasSuffix(s, " M") || strings.HasSuffix(s, " G") || strings.HasSuffix(s, " T") || strings.HasSuffix(s, " P") {
		return s + "bps"
	}
	return s + " bps"
}

// Count formats a count: "1.5M".
func Count(v float64) string { return strings.Replace(si(v), " ", "", 1) }

// Bytes formats a volume in binary units: "1.3 GB".
func Bytes(v uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i, x := 0, float64(v)
	for x >= 1024 && i < len(units)-1 {
		x /= 1024
		i++
	}
	if x >= 100 || i == 0 {
		return fmt.Sprintf("%.0f %s", x, units[i])
	}
	return fmt.Sprintf("%.1f %s", x, units[i])
}

// Span describes a time range: "16 Oct 2026 14:00 – 23 Oct 2026 14:00 (7 days)".
func Span(from, to time.Time) string {
	d := to.Sub(from)
	var n string
	switch {
	case d >= 48*time.Hour:
		n = fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= 2*time.Hour:
		n = fmt.Sprintf("%.0f hours", d.Hours())
	default:
		n = fmt.Sprintf("%.0f minutes", d.Minutes())
	}
	const layout = "2 Jan 2006 15:04"
	return fmt.Sprintf("%s – %s (%s)", from.Format(layout), to.Format(layout), n)
}
