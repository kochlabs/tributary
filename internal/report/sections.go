package report

import (
	"fmt"
	"strings"
)

// section draws one section of s (its heading is already drawn).
func (d *doc) section(name string, s *Report) error {
	switch name {
	case "kpis":
		d.kpis(s)
	case "traffic":
		const chartH = 72.0
		png, err := trafficChart(s.Times, s.Traffic, contentW, chartH)
		if err != nil {
			return fmt.Errorf("traffic chart: %w", err)
		}
		if png == nil {
			d.note("No traffic in this period.")
			return nil
		}
		d.need(chartH)
		d.image(png, margin, d.GetY(), contentW, chartH)
		d.SetY(d.GetY() + chartH + 2)
	case "services":
		if len(s.Services) == 0 {
			d.note("No traffic in this period.")
			return nil
		}
		// The doughnut on the left; its legend is the table's swatches.
		const dw = 50.0
		d.need(dw)
		y := d.GetY()
		png, err := doughnut(s.Services, dw, dw)
		if err != nil {
			return fmt.Errorf("services chart: %w", err)
		}
		d.image(png, margin, y, dw, dw)
		d.table(margin+dw+4, contentW-dw-4, []column{swatchCol(d, labelCol("Organization")), rateCol, volCol, shareCol(d)}, s.Services, true, "")
		d.SetY(max(d.GetY(), y+dw) + 1)
	case "devices":
		d.table(margin, contentW, []column{labelCol("Device"), rateCol, volCol, shareCol(d)}, s.Devices, true, "No devices seen in this period.")
	case "apps":
		d.table(margin, contentW, []column{labelCol("Protocol / port"), rateCol, volCol, shareCol(d)}, s.Apps, false, "No traffic in this period.")
	case "countries":
		d.table(margin, contentW, []column{labelCol("Country"), rateCol, volCol, shareCol(d)}, s.Countries, false, "No traffic in this period.")
	case "threats":
		d.heading("Threat feed matches", fmt.Sprintf("%d threat feed%s enabled", s.ThreatFeedsEnabled, plural(s.ThreatFeedsEnabled)))
		switch {
		case s.ThreatFeedsEnabled == 0:
			d.note("No threat feeds are enabled, so nothing was matched.")
		case len(s.ThreatFeeds) == 0:
			d.note("No traffic with addresses on threat feeds in this period.")
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
	case "exposure":
		d.table(margin, contentW, []column{
			labelCol("Local host"),
			{title: "Service", w: 36, align: "L", cell: func(r Row) (string, rgb) { return r.Service, ink }},
			{title: "Remote sources", w: 28, align: "R", cell: func(r Row) (string, rgb) { return Count(float64(r.Sources)), ink }},
			flowCol, volCol,
		}, s.Exposure, true, "No connections from the internet to local hosts in this period.")
	case "new_devices":
		d.table(margin, contentW, []column{
			labelCol("Device"),
			{title: "First seen", w: 34, align: "R", cell: func(r Row) (string, rgb) { return r.FirstSeen.Format("2 Jan 15:04"), ink }},
		}, s.NewDevices, true, "No new devices in this period.")
	case "exporters":
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
	default:
		return fmt.Errorf("unknown section %q", name)
	}
	return nil
}

// kpis draws the headline figures as tiles, three by two.
func (d *doc) kpis(s *Report) {
	tiles := []struct{ label, value, sub string }{
		{"Download", Bits(s.DownloadBps), "peak " + Bits(s.PeakDownloadBps) + " · " + Bytes(s.DownloadBytes)},
		{"Upload", Bits(s.UploadBps), "peak " + Bits(s.PeakUploadBps) + " · " + Bytes(s.UploadBytes)},
		{"Total volume", Bytes(s.DownloadBytes + s.UploadBytes), Count(float64(s.Packets)) + " packets"},
		{"Local addresses", Count(float64(s.LocalHosts)), "active in period"},
		{"Remote hosts", Count(float64(s.RemoteHosts)), "contacted"},
		{"Flows", Count(float64(s.Flows)), fmt.Sprintf("%d exporter%s", s.ExporterCount, plural(s.ExporterCount))},
	}
	const gap, tileH = 4.0, 19.0
	tileW := (contentW - 2*gap) / 3
	d.need(2*tileH + gap)
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
}

// Describe lists filters for a report header: "exporter = 10.0.0.1 · threat = *".
func Describe(filters map[string]string, label func(string) string) string {
	var parts []string
	for _, k := range sortedKeys(filters) {
		v := filters[k]
		op := "="
		if strings.HasPrefix(v, "!") {
			op, v = "≠", v[1:]
		}
		parts = append(parts, label(k)+" "+op+" "+v)
	}
	return strings.Join(parts, " · ")
}
