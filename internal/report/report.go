// Package report renders reports as PDF. It only lays out what it is given:
// the API gathers the data, with the same labels as the web UI.
package report

import (
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"codeberg.org/go-pdf/fpdf"
)

// Row is one line of a ranked table.
type Row struct {
	Label  string
	Detail string // secondary text, e.g. hostname or country
	Bytes  uint64
	Flows  uint64
	Rate   float64 // bits per second over the range
	Pct    float64 // share of the total

	LastSeen time.Time // exporters
	Status   string    // exporters: active | silent | idle
}

// Series is one layer of the traffic chart, in bits per second.
type Series struct {
	Label  string
	Values []float64
}

// Exporter is one row of the exporters table.
type Exporter struct {
	Name     string
	Addr     string
	Bytes    uint64
	Flows    uint64
	LastSeen time.Time
	Status   string // active | silent | idle
}

// Summary is the network summary report.
type Summary struct {
	Appliance string
	Version   string
	From, To  time.Time
	Generated time.Time

	DownloadBytes, UploadBytes     uint64
	DownloadBps, UploadBps         float64
	PeakDownloadBps, PeakUploadBps float64
	LocalHosts, RemoteHosts, Flows uint64
	Packets                        uint64

	// Traffic over time, by service (remote organization).
	Times   []time.Time
	Traffic []Series

	Devices, Services, Apps, Countries []Row

	// Threat feeds: matches by feed, listed hosts and who talked to them.
	ThreatFeedsEnabled int
	ThreatFeeds        []Row
	ThreatHosts        []Row
	ThreatTalkers      []Row

	Exporters []Exporter
}

//go:embed fonts/*.ttf.gz
var fontFS embed.FS

var fonts = sync.OnceValues(func() (map[string][]byte, error) {
	out := map[string][]byte{}
	for style, name := range map[string]string{"": "fonts/NotoSans-Medium.ttf.gz", "B": "fonts/NotoSans-Bold.ttf.gz"} {
		f, err := fontFS.Open(name)
		if err != nil {
			return nil, err
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(zr)
		f.Close()
		if err != nil {
			return nil, err
		}
		out[style] = b
	}
	return out, nil
})

// Page geometry, mm.
const (
	pageW    = 210.0
	margin   = 15.0
	contentW = pageW - 2*margin
	bottom   = 297.0 - 18
	rowH     = 5.6
)

type rgb struct{ r, g, b int }

var (
	ink     = rgb{33, 33, 33}
	muted   = rgb{115, 115, 115}
	accent  = rgb{0, 121, 184}
	rule    = rgb{221, 221, 221}
	zebra   = rgb{246, 248, 250}
	tileBg  = rgb{244, 247, 250}
	danger  = rgb{201, 33, 0}
	warning = rgb{173, 115, 0}
)

type doc struct {
	*fpdf.Fpdf
	title string
	imgs  int
}

func (d *doc) color(c rgb)                   { d.SetTextColor(c.r, c.g, c.b) }
func (d *doc) fill(c rgb)                    { d.SetFillColor(c.r, c.g, c.b) }
func (d *doc) draw(c rgb)                    { d.SetDrawColor(c.r, c.g, c.b) }
func (d *doc) font(style string, pt float64) { d.SetFont("noto", style, pt) }

// fit shortens s with an ellipsis to fit w mm in the current font.
func (d *doc) fit(s string, w float64) string {
	if d.GetStringWidth(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 1 && d.GetStringWidth(string(r)+"…") > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// need starts a new page unless h mm are left.
func (d *doc) need(h float64) bool {
	if d.GetY()+h > bottom {
		d.AddPage()
		return true
	}
	return false
}

func (d *doc) heading(s, hint string) {
	d.need(24)
	d.Ln(4)
	d.font("B", 12)
	d.color(ink)
	d.CellFormat(d.GetStringWidth(s)+2, 7, s, "", 0, "L", false, 0, "")
	if hint != "" {
		d.font("", 8)
		d.color(muted)
		d.CellFormat(0, 7.4, hint, "", 0, "L", false, 0, "")
	}
	d.Ln(8)
	d.draw(rule)
	d.SetLineWidth(0.2)
	d.Line(margin, d.GetY()-0.6, pageW-margin, d.GetY()-0.6)
	d.Ln(1.5)
}

func (d *doc) image(png []byte, x, y, w, h float64) {
	if png == nil {
		return
	}
	d.imgs++
	name := fmt.Sprintf("img%d", d.imgs)
	opt := fpdf.ImageOptions{ImageType: "PNG"}
	d.RegisterImageOptionsReader(name, opt, bytes.NewReader(png))
	d.ImageOptions(name, x, y, w, h, false, opt, 0, "")
}

// column of a table.
type column struct {
	title string
	w     float64 // mm; 0 = the rest
	align string  // L | R
	cell  func(Row) (string, rgb)
	// deco draws in the cell before the text and returns the width it used
	// (text is placed after it).
	deco func(r Row, i int, x, y float64) float64
}

// table draws rows at x, w mm wide, repeating the header after page breaks.
// A row's Detail is shown in grey under its label when detail is set.
func (d *doc) table(x0, tw float64, cols []column, rows []Row, detail bool, empty string) {
	widths := make([]float64, len(cols))
	rest := tw
	for i, c := range cols {
		widths[i] = c.w
		rest -= c.w
	}
	for i, c := range cols {
		if c.w == 0 {
			widths[i] = rest
		}
	}
	if len(rows) == 0 {
		d.SetX(x0)
		d.font("", 8.5)
		d.color(muted)
		d.CellFormat(tw, rowH, empty, "", 1, "L", false, 0, "")
		return
	}
	header := func() {
		d.font("B", 7.5)
		d.color(muted)
		d.SetX(x0)
		d.draw(rule)
		for i, c := range cols {
			d.CellFormat(widths[i], rowH, c.title, "B", 0, c.align, false, 0, "")
		}
		d.Ln(rowH + 0.4)
	}
	d.need(rowH * 3)
	header()
	for n, r := range rows {
		h := rowH
		if detail && r.Detail != "" {
			h = rowH + 3.4
		}
		if d.need(h) {
			header()
		}
		y := d.GetY()
		if n%2 == 1 {
			d.fill(zebra)
			d.Rect(x0, y, tw, h, "F")
		}
		x := x0
		for i, c := range cols {
			used := 0.0
			if c.deco != nil {
				used = c.deco(r, n, x, y)
			}
			text, col := c.cell(r)
			d.font("", 8.5)
			if i == 0 {
				d.font("B", 8.5)
			}
			d.color(col)
			d.SetXY(x+used, y)
			cw := widths[i] - used
			d.CellFormat(cw, rowH, d.fit(text, cw-1.5), "", 0, c.align, false, 0, "")
			if i == 0 && detail && r.Detail != "" {
				d.font("", 7)
				d.color(muted)
				d.SetXY(x+used, y+rowH-1.6)
				d.CellFormat(cw, 4, d.fit(r.Detail, cw-1.5), "", 0, "L", false, 0, "")
			}
			x += widths[i]
		}
		d.SetXY(x0, y+h)
	}
}

// shareCol shows the share as a bar and a percentage.
func shareCol(d *doc) column {
	return column{title: "Share", w: 36, align: "R",
		cell: func(r Row) (string, rgb) { return fmt.Sprintf("%.1f%%", r.Pct), muted },
		deco: func(r Row, _ int, x, y float64) float64 {
			d.fill(rgb{226, 232, 238})
			d.Rect(x+2, y+2, 20, 1.6, "F")
			d.fill(accent)
			d.Rect(x+2, y+2, 20*min(max(r.Pct, 0), 100)/100, 1.6, "F")
			return 0
		}}
}

// swatchCol adds a color swatch per row, matching a chart's series colors.
func swatchCol(d *doc, c column) column {
	c.deco = func(r Row, i int, x, y float64) float64 {
		col := hex(palette[i%len(palette)])
		if r.Label == "Other" {
			col = hex(otherColor)
		}
		d.fill(col)
		d.Rect(x, y+1.7, 2.2, 2.2, "F")
		return 3.4
	}
	return c
}

var (
	volCol  = column{title: "Volume", w: 22, align: "R", cell: func(r Row) (string, rgb) { return Bytes(r.Bytes), ink }}
	rateCol = column{title: "Avg rate", w: 24, align: "R", cell: func(r Row) (string, rgb) { return Bits(r.Rate), ink }}
	flowCol = column{title: "Flows", w: 20, align: "R", cell: func(r Row) (string, rgb) { return Count(float64(r.Flows)), ink }}
)

func labelCol(title string) column {
	return column{title: title, align: "L", cell: func(r Row) (string, rgb) { return r.Label, ink }}
}

// RenderSummary renders the network summary as PDF.
func RenderSummary(s *Summary) ([]byte, error) {
	f, err := fonts()
	if err != nil {
		return nil, err
	}
	d := &doc{Fpdf: fpdf.New("P", "mm", "A4", ""), title: "Network summary"}
	d.SetMargins(margin, margin, margin)
	d.SetAutoPageBreak(false, 0) // breaks are placed by hand, so tables can repeat headers
	d.AddUTF8FontFromBytes("noto", "", f[""])
	d.AddUTF8FontFromBytes("noto", "B", f["B"])
	d.SetTitle(s.Appliance+": "+d.title, true)
	d.SetCreator("Tributary "+s.Version, true)
	d.SetAuthor(s.Appliance, true)
	d.AliasNbPages("{nb}")
	d.SetFooterFunc(func() {
		d.SetY(-12)
		d.font("", 7)
		d.color(muted)
		d.CellFormat(contentW/2, 5, d.fit(s.Appliance+" · "+d.title+" · "+Span(s.From, s.To), contentW/2), "", 0, "L", false, 0, "")
		d.CellFormat(contentW/2, 5, fmt.Sprintf("Page %d of {nb}", d.PageNo()), "", 0, "R", false, 0, "")
	})
	d.AddPage()

	// Title block.
	d.font("B", 20)
	d.color(ink)
	d.CellFormat(0, 10, d.title, "", 1, "L", false, 0, "")
	d.font("", 9.5)
	d.color(muted)
	d.CellFormat(0, 5.5, s.Appliance+" · "+Span(s.From, s.To), "", 1, "L", false, 0, "")
	d.font("", 7.5)
	d.CellFormat(0, 4.5, "Generated "+s.Generated.Format("2 Jan 2006 15:04 MST")+" by Tributary "+s.Version, "", 1, "L", false, 0, "")
	d.Ln(4)

	// KPI tiles, three by two.
	tiles := []struct{ label, value, sub string }{
		{"Download", Bits(s.DownloadBps), "peak " + Bits(s.PeakDownloadBps) + " · " + Bytes(s.DownloadBytes)},
		{"Upload", Bits(s.UploadBps), "peak " + Bits(s.PeakUploadBps) + " · " + Bytes(s.UploadBytes)},
		{"Total volume", Bytes(s.DownloadBytes + s.UploadBytes), Count(float64(s.Packets)) + " packets"},
		{"Local addresses", Count(float64(s.LocalHosts)), "active in range"},
		{"Remote hosts", Count(float64(s.RemoteHosts)), "contacted"},
		{"Flows", Count(float64(s.Flows)), fmt.Sprintf("%d exporter%s", len(s.Exporters), plural(len(s.Exporters)))},
	}
	const gap, tileH = 4.0, 19.0
	tileW := (contentW - 2*gap) / 3
	y0 := d.GetY()
	for i, t := range tiles {
		x := margin + float64(i%3)*(tileW+gap)
		y := y0 + float64(i/3)*(tileH+gap)
		d.fill(tileBg)
		d.RoundedRect(x, y, tileW, tileH, 1.5, "1234", "F")
		d.SetXY(x+3, y+2.2)
		d.font("", 7.5)
		d.color(muted)
		d.CellFormat(tileW-6, 4, t.label, "", 2, "L", false, 0, "")
		d.SetX(x + 3)
		d.font("B", 14)
		d.color(ink)
		d.CellFormat(tileW-6, 7.5, t.value, "", 2, "L", false, 0, "")
		d.SetX(x + 3)
		d.font("", 7)
		d.color(muted)
		d.CellFormat(tileW-6, 4, d.fit(t.sub, tileW-6), "", 0, "L", false, 0, "")
	}
	d.SetXY(margin, y0+2*tileH+gap+2)

	// Traffic over time.
	d.heading("Traffic over time", "by service, bits per second")
	const chartH = 72.0
	png, err := trafficChart(s.Times, s.Traffic, contentW, chartH)
	if err != nil {
		return nil, fmt.Errorf("traffic chart: %w", err)
	}
	if png == nil {
		d.font("", 8.5)
		d.color(muted)
		d.CellFormat(0, rowH, "No traffic in this range.", "", 1, "L", false, 0, "")
	} else {
		d.need(chartH)
		d.image(png, margin, d.GetY(), contentW, chartH)
		d.SetY(d.GetY() + chartH + 2)
	}

	// Services: doughnut beside the table.
	d.heading("Top services", "remote networks by owner, both directions")
	if len(s.Services) > 0 {
		// The doughnut on the left; its legend is the table's swatches.
		const dw = 50.0
		d.need(dw)
		y := d.GetY()
		png, err := doughnut(s.Services, dw, dw)
		if err != nil {
			return nil, fmt.Errorf("services chart: %w", err)
		}
		d.image(png, margin, y, dw, dw)
		d.table(margin+dw+4, contentW-dw-4, []column{swatchCol(d, labelCol("Organization")), rateCol, volCol, shareCol(d)}, s.Services, true, "")
		d.SetY(max(d.GetY(), y+dw) + 1)
	} else {
		d.table(margin, contentW, nil, nil, false, "No traffic in this range.")
	}

	d.heading("Top devices", "local hosts by MAC address, both directions")
	d.table(margin, contentW, []column{labelCol("Device"), rateCol, volCol, shareCol(d)}, s.Devices, true, "No devices seen in this range.")

	d.heading("Applications", "well-known port of the flow")
	d.table(margin, contentW, []column{labelCol("Protocol / port"), rateCol, volCol, shareCol(d)}, s.Apps, false, "No traffic in this range.")

	d.heading("Remote countries", "where remote hosts are")
	d.table(margin, contentW, []column{labelCol("Country"), rateCol, volCol, shareCol(d)}, s.Countries, false, "No traffic in this range.")

	// Security.
	hint := fmt.Sprintf("%d threat feed%s enabled", s.ThreatFeedsEnabled, plural(s.ThreatFeedsEnabled))
	d.heading("Threat feed matches", hint)
	switch {
	case s.ThreatFeedsEnabled == 0:
		d.font("", 8.5)
		d.color(muted)
		d.CellFormat(0, rowH, "No threat feeds are enabled, so nothing was matched.", "", 1, "L", false, 0, "")
	case len(s.ThreatFeeds) == 0:
		d.font("", 8.5)
		d.color(muted)
		d.CellFormat(0, rowH, "No traffic with addresses on threat feeds in this range.", "", 1, "L", false, 0, "")
	default:
		d.table(margin, contentW, []column{labelCol("Feed"), flowCol, volCol}, s.ThreatFeeds, false, "")
		d.Ln(3)
		d.table(margin, contentW, []column{
			{title: "Listed host", align: "L", cell: func(r Row) (string, rgb) { return r.Label, danger }},
			flowCol, volCol,
		}, s.ThreatHosts, true, "")
		if len(s.ThreatTalkers) > 0 {
			d.Ln(3)
			d.table(margin, contentW, []column{labelCol("Local host talking to listed hosts"), flowCol, volCol}, s.ThreatTalkers, true, "")
		}
	}

	// Exporters.
	d.heading("Exporters", "devices sending flow records")
	var exp []Row
	for _, e := range s.Exporters {
		name, detail := e.Name, e.Addr
		if name == "" {
			name, detail = e.Addr, ""
		}
		exp = append(exp, Row{Label: name, Detail: detail, Bytes: e.Bytes, Flows: e.Flows, LastSeen: e.LastSeen, Status: e.Status})
	}
	d.table(margin, contentW, []column{
		labelCol("Exporter"),
		flowCol, volCol,
		{title: "Last seen", w: 30, align: "R", cell: func(r Row) (string, rgb) {
			if r.LastSeen.IsZero() {
				return "–", muted
			}
			return r.LastSeen.Format("2 Jan 15:04"), ink
		}},
		{title: "Status", w: 20, align: "R", cell: func(r Row) (string, rgb) {
			if c, ok := map[string]rgb{"active": accent, "silent": warning}[r.Status]; ok {
				return r.Status, c
			}
			return r.Status, muted
		}},
	}, exp, true, "No exporters.")

	if err := d.Error(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := d.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func hex(s string) rgb {
	var c rgb
	fmt.Sscanf(strings.TrimPrefix(s, "#"), "%02x%02x%02x", &c.r, &c.g, &c.b)
	return c
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
