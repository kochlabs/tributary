package report

import (
	"time"

	"github.com/go-analyze/charts"
)

// Charts are drawn as PNG at about 250 dpi (the PDF library's SVG support
// is limited to paths), so pixel sizes here are 10 px per mm of page.
const pxPerMM = 10

var palette = []string{"#0079b8", "#00a1a1", "#f6a623", "#8f5bc2", "#e15a3d", "#5aa220", "#0095d3", "#d6449c", "#a67c2e", "#4d7cfe", "#c25700", "#2f9e8f"}

const otherColor = "#8c8c8c"

// makeTheme is a light theme with the given series colors.
func makeTheme(colors []charts.Color) charts.ColorPalette {
	return charts.MakeTheme(charts.ThemeOption{
		AxisStrokeColor:    charts.ColorFromHex("#cccccc"),
		AxisSplitLineColor: charts.ColorFromHex("#e8e8e8"),
		BackgroundColor:    charts.ColorWhite,
		TextColor:          charts.ColorFromHex("#565656"),
		SeriesColors:       colors,
	})
}

// Font sizes in chart pixels: 26 px is about 7.5 pt on the page.
func font(px float64) charts.FontStyle {
	return charts.FontStyle{FontSize: px, Font: charts.GetFont(charts.FontFamilyNotoSans), FontColor: charts.ColorFromHex("#565656")}
}

// seriesTheme colors series in order, with "Other" in grey.
func seriesTheme(labels []string) charts.ColorPalette {
	colors := make([]charts.Color, len(labels))
	for i, l := range labels {
		if l == "Other" {
			colors[i] = charts.ColorFromHex(otherColor)
		} else {
			colors[i] = charts.ColorFromHex(palette[i%len(palette)])
		}
	}
	return makeTheme(colors)
}

// trafficChart is a stacked area chart of the series over time, w×h mm.
func trafficChart(times []time.Time, series []Series, w, h float64) ([]byte, error) {
	if len(times) == 0 || len(series) == 0 {
		return nil, nil
	}
	values := make([][]float64, len(series))
	names := make([]string, len(series))
	for i, s := range series {
		values[i], names[i] = s.Values, s.Label
	}
	// Label day boundaries on multi-day ranges, otherwise every few hours;
	// the rest stay empty so labels never collide.
	labels := make([]string, len(times))
	span := times[len(times)-1].Sub(times[0])
	every := time.Duration(0)
	switch {
	case span > 20*24*time.Hour:
		every = 7 * 24 * time.Hour
	case span > 2*24*time.Hour:
		every = 24 * time.Hour
	case span > 12*time.Hour:
		every = 3 * time.Hour
	default:
		every = time.Hour
	}
	for i, t := range times {
		local := t.Truncate(every)
		if every >= 24*time.Hour {
			local = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
		}
		if i > 0 && local.Equal(t) || i == 0 && t.Equal(local) {
			if every >= 24*time.Hour {
				labels[i] = t.Format("Mon 2 Jan")
			} else {
				labels[i] = t.Format("15:04")
			}
		}
	}
	th := seriesTheme(names)
	opt := charts.LineChartOption{
		Theme:       th,
		Padding:     charts.Box{Top: 20, Right: 70, Bottom: 10, Left: 10},
		SeriesList:  charts.NewSeriesListLine(values),
		StackSeries: charts.Ptr(true),
		Symbol:      charts.Symbol{Shape: charts.SymbolNone},
		FillOpacity: 210,
		XAxis: charts.XAxisOption{
			Labels:         labels,
			BoundaryGap:    charts.Ptr(false),
			LabelFontStyle: font(24),
			LabelCount:     len(labels),
		},
		YAxis: []charts.YAxisOption{{
			LabelFontStyle: font(24),
			ValueFormatter: func(f float64) string { return Bits(f) },
		}},
		Legend: charts.LegendOption{
			SeriesNames: names,
			FontStyle:   font(24),
			Offset:      charts.OffsetStr{Top: "bottom"},
			Symbol:      charts.SymbolSquare,
		},
	}
	p := charts.NewPainter(charts.PainterOptions{OutputFormat: charts.ChartOutputPNG, Width: int(w * pxPerMM), Height: int(h * pxPerMM), Theme: th})
	if err := p.LineChart(opt); err != nil {
		return nil, err
	}
	return p.Bytes()
}

// doughnut shows shares of the rows' volume, w×h mm.
func doughnut(rows []Row, w, h float64) ([]byte, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	values := make([]float64, len(rows))
	names := make([]string, len(rows))
	for i, r := range rows {
		values[i], names[i] = float64(r.Bytes), r.Label
	}
	th := seriesTheme(names)
	opt := charts.DoughnutChartOption{
		Theme:        th,
		Padding:      charts.Box{Top: 10, Right: 10, Bottom: 10, Left: 10},
		SeriesList:   charts.NewSeriesListDoughnut(values),
		RadiusRing:   "45%",
		RadiusCenter: "28%",
		SegmentGap:   4,
		Legend:       charts.LegendOption{Show: charts.Ptr(false)},
	}
	for i := range opt.SeriesList {
		opt.SeriesList[i].Label.Show = charts.Ptr(false)
	}
	p := charts.NewPainter(charts.PainterOptions{OutputFormat: charts.ChartOutputPNG, Width: int(w * pxPerMM), Height: int(h * pxPerMM), Theme: th})
	if err := p.DoughnutChart(opt); err != nil {
		return nil, err
	}
	return p.Bytes()
}
