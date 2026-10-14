import { Metric, TimeSeries, TopRow } from '../core/api';
import { rate } from '../core/format';
import { chartColors, ChartOption, OTHER_COLOR, PALETTE } from './chart';

function esc(s: string) {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
}

/** Stacked area (or line) chart over time. */
export function timeSeriesOption(ts: TimeSeries, opts: { stacked?: boolean; legend?: boolean } = {}): ChartOption {
  const c = chartColors();
  const stacked = opts.stacked ?? true;
  const metric = ts.metric as Metric;
  let colorIdx = 0;
  const series = ts.series.map((s) => {
    const isOther = s.key === '__other__';
    const color = isOther ? OTHER_COLOR : PALETTE[colorIdx++ % PALETTE.length];
    return {
      name: s.label || s.key || $localize`:@@options.total:Total`,
      id: s.key,
      type: 'line',
      stack: stacked ? 'total' : undefined,
      showSymbol: false,
      smooth: 0.2,
      sampling: 'lttb',
      lineStyle: { width: stacked ? 0.8 : 1.6 },
      areaStyle: stacked || ts.series.length === 1 ? { opacity: ts.series.length === 1 ? 0.25 : 0.75 } : undefined,
      color,
      emphasis: { focus: 'series' },
      data: s.values.map((v, i) => [ts.times[i], v]),
    };
  });
  const showLegend = (opts.legend ?? true) && ts.series.length > 1;
  return {
    animation: false,
    grid: { left: 12, right: 18, top: 16, bottom: showLegend ? 56 : 28, containLabel: true },
    tooltip: {
      trigger: 'axis',
      confine: true,
      backgroundColor: c.bg,
      borderColor: c.grid,
      textStyle: { color: c.text, fontSize: 12 },
      axisPointer: { type: 'line', lineStyle: { color: c.muted } },
      formatter: (params: any[]) => {
        if (!params.length) return '';
        const t = new Date(params[0].value[0]).toLocaleString();
        const rows = [...params]
          .sort((a, b) => b.value[1] - a.value[1])
          .filter((p) => p.value[1] > 0 || params.length === 1)
          .slice(0, 12)
          .map((p) => `<div style="display:flex;gap:12px;justify-content:space-between"><span>${p.marker}${esc(p.seriesName)}</span><b>${rate(p.value[1], metric)}</b></div>`)
          .join('');
        const total = params.reduce((s, p) => s + p.value[1], 0);
        const tot = params.length > 1 && stacked ? `<div style="border-top:1px solid ${c.grid};margin-top:4px;padding-top:4px;display:flex;justify-content:space-between"><span>${$localize`:@@options.total:Total`}</span><b>${rate(total, metric)}</b></div>` : '';
        return `<div style="min-width:220px"><div style="margin-bottom:4px;color:${c.muted}">${t}</div>${rows}${tot}</div>`;
      },
    },
    legend: showLegend
      ? { type: 'scroll', bottom: 0, icon: 'roundRect', itemWidth: 12, itemHeight: 8, textStyle: { color: c.text, fontSize: 11 } }
      : { show: false },
    xAxis: {
      type: 'time',
      axisLine: { lineStyle: { color: c.grid } },
      axisLabel: { color: c.muted, hideOverlap: true },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: c.muted, formatter: (v: number) => rate(v, metric) },
      splitLine: { lineStyle: { color: c.grid, type: 'dashed' } },
    },
    series,
  };
}

/** Donut chart of top rows plus an "Other" slice. */
export function donutOption(rows: TopRow[], total: TopRow, metric: Metric): ChartOption {
  const c = chartColors();
  const val = (r: TopRow) => (metric === 'pps' ? r.packets : metric === 'fps' ? r.flows : r.bytes);
  const data = rows.map((r, i) => ({ name: r.label, value: val(r), key: r.key, itemStyle: { color: PALETTE[i % PALETTE.length] } }));
  const rest = val(total) - data.reduce((s, d) => s + d.value, 0);
  if (rest > val(total) * 0.001) data.push({ name: $localize`:@@options.other:Other`, value: rest, key: '__other__', itemStyle: { color: OTHER_COLOR } });
  return {
    animation: false,
    tooltip: {
      trigger: 'item',
      confine: true,
      backgroundColor: c.bg,
      borderColor: c.grid,
      textStyle: { color: c.text, fontSize: 12 },
      formatter: (p: any) => `${p.marker}${esc(p.name)}<br/><b>${p.percent.toFixed(1)}%</b>`,
    },
    legend: { type: 'scroll', orient: 'vertical', right: 0, top: 'middle', icon: 'circle', itemWidth: 8, textStyle: { color: c.text, fontSize: 11, width: 150, overflow: 'truncate' } },
    series: [
      {
        type: 'pie',
        radius: ['52%', '80%'],
        center: ['30%', '50%'],
        avoidLabelOverlap: true,
        label: { show: false },
        itemStyle: { borderColor: c.bg, borderWidth: 2 },
        data,
      },
    ],
  };
}

/** Horizontal bars for a top-N list. */
export function barOption(rows: TopRow[], metric: Metric): ChartOption {
  const c = chartColors();
  const r = [...rows].reverse();
  return {
    animation: false,
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: 'item', backgroundColor: c.bg, borderColor: c.grid, textStyle: { color: c.text }, formatter: (p: any) => `${esc(p.name)}<br/><b>${rate(p.value, metric)}</b>` },
    xAxis: { type: 'value', axisLabel: { color: c.muted, formatter: (v: number) => rate(v, metric) }, splitLine: { lineStyle: { color: c.grid, type: 'dashed' } } },
    yAxis: { type: 'category', data: r.map((x) => x.label), axisLabel: { color: c.text, width: 180, overflow: 'truncate' }, axisLine: { lineStyle: { color: c.grid } } },
    series: [{ type: 'bar', data: r.map((x) => x.rate), itemStyle: { color: PALETTE[0], borderRadius: [0, 3, 3, 0] }, barMaxWidth: 18 }],
  };
}
