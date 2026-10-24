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

	LastSeen  time.Time // exporters
	Status    string    // exporters: active | silent | idle
	Service   string    // exposure: protocol/port
	Sources   uint64    // exposure: distinct remote hosts
	FirstSeen time.Time // new devices
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

// Report is a report to render. Sections lists what to include, in page
// order (see config.ReportSections); only their data needs filling in.
type Report struct {
	Title     string
	Appliance string
	Version   string
	From, To  time.Time
	Generated time.Time
	Scope     string // the filters, described; empty for all traffic
	Sections  []string

	DownloadBytes, UploadBytes     uint64
	DownloadBps, UploadBps         float64
	PeakDownloadBps, PeakUploadBps float64
	LocalHosts, RemoteHosts, Flows uint64
	Packets                        uint64
	ExporterCount                  int

	// Traffic over time, by service (remote organization).
	Times   []time.Time
	Traffic []Series

	Devices, Services, Apps, Countries []Row

	// Threat feeds: matches by feed, listed hosts and who talked to them.
	ThreatFeedsEnabled int
	ThreatFeeds        []Row
	ThreatHosts        []Row
	ThreatTalkers      []Row

	// Exposure: local services reached from remote hosts (Label the host,
	// Detail its address, Service the port, Sources the remote hosts).
	Exposure []Row
	// NewDevices: devices first seen in the range.
	NewDevices []Row

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

var sectionTitles = map[string][2]string{
	"traffic":     {"Traffic over time", "by service, bits per second"},
	"services":    {"Top services", "remote networks by owner, both directions"},
	"devices":     {"Top devices", "local hosts by MAC address, both directions"},
	"apps":        {"Applications", "well-known port of the flow"},
	"countries":   {"Remote countries", "where remote hosts are"},
	"exposure":    {"Exposed services", "local hosts accepting connections from the internet"},
	"new_devices": {"New devices", "first seen in this period"},
	"exporters":   {"Exporters", "devices sending flow records"},
}

func (d *doc) note(s string) {
	d.font("", 8.5)
	d.color(muted)
	d.CellFormat(0, rowH, s, "", 1, "L", false, 0, "")
}

// Render renders a report as PDF.
func Render(s *Report) ([]byte, error) {
	f, err := fonts()
	if err != nil {
		return nil, err
	}
	d := &doc{Fpdf: fpdf.New("P", "mm", "A4", ""), title: s.Title}
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
		d.CellFormat(contentW*0.75, 5, d.fit(s.Appliance+" · "+d.title+" · "+Span(s.From, s.To), contentW*0.75), "", 0, "L", false, 0, "")
		d.CellFormat(contentW*0.25, 5, fmt.Sprintf("Page %d of {nb}", d.PageNo()), "", 0, "R", false, 0, "")
	})
	d.AddPage()

	// Title block.
	d.font("B", 20)
	d.color(ink)
	d.MultiCell(0, 9, d.title, "", "L", false)
	d.font("", 9.5)
	d.color(muted)
	d.CellFormat(0, 5.5, s.Appliance+" · "+Span(s.From, s.To), "", 1, "L", false, 0, "")
	if s.Scope != "" {
		d.font("B", 8.5)
		d.color(ink)
		d.CellFormat(0, 5, d.fit("Only traffic matching: "+s.Scope, contentW), "", 1, "L", false, 0, "")
	}
	d.font("", 7.5)
	d.color(muted)
	d.CellFormat(0, 4.5, "Generated "+s.Generated.Format("2 Jan 2006 15:04 MST")+" by Tributary "+s.Version, "", 1, "L", false, 0, "")
	d.Ln(4)

	for _, sec := range s.Sections {
		if t, ok := sectionTitles[sec]; ok {
			d.heading(t[0], t[1])
		}
		if err := d.section(sec, s); err != nil {
			return nil, err
		}
	}

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
