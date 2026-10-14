import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, Filters, Metric, TopRow } from '../core/api';
import { bytes, count, DIMENSIONS, dimLabel, drillFilter, FILTER_FIELDS, METRICS, rate } from '../core/format';
import { TimeRange } from '../core/time';
import { filtersFromParams, loader } from '../core/util';
import { Chart, OTHER_COLOR, PALETTE } from '../shared/chart';
import { FilterBar } from '../shared/filter-bar';
import { RangeBar } from '../shared/range-bar';
import { timeSeriesOption } from '../shared/options';

const FILTER_KEYS = FILTER_FIELDS.map((f) => f.id);

@Component({
  selector: 'nfa-explorer',
  imports: [ClarityModule, FormsModule, Chart, FilterBar, RangeBar],
  template: `
    <div class="page-header">
      <div>
        <h2>Traffic Explorer</h2>
        <p class="subtitle">Break traffic down by any dimension · {{ time.label() }}</p>
      </div>
      <div class="header-controls">
        <nfa-range-bar />
        <button class="btn btn-sm btn-outline" (click)="showFlows({})"><cds-icon shape="table"></cds-icon> Show matching flows</button>
      </div>
    </div>

    <div class="card toolbar">
      <div class="card-block">
        <nfa-filter-bar [(filters)]="filters" />
        <div class="controls">
          <label class="ctl">
            <span>Group by</span>
            <select class="clr-select" [ngModel]="groupBy()" (ngModelChange)="groupBy.set($event)" name="groupBy">
              <option value="">— none (total) —</option>
              @for (d of dims; track d.id) {
                <option [value]="d.id">{{ d.label }}</option>
              }
            </select>
          </label>
          <label class="ctl">
            <span>Series</span>
            <select class="clr-select" [ngModel]="limit()" (ngModelChange)="limit.set(+$event)" name="limit">
              @for (n of [5, 8, 10, 15, 20]; track n) {
                <option [value]="n">Top {{ n }}</option>
              }
            </select>
          </label>
          <div class="btn-group btn-sm" role="group" aria-label="Metric">
            @for (m of metrics; track m.id) {
              <button class="btn" [class.btn-primary]="metric() === m.id" [class.btn-outline]="metric() !== m.id" (click)="metric.set(m.id)">{{ m.label }}</button>
            }
          </div>
          <div class="btn-group btn-sm" role="group" aria-label="Chart style">
            <button class="btn" [class.btn-primary]="stacked()" [class.btn-outline]="!stacked()" (click)="stacked.set(true)">Stacked</button>
            <button class="btn" [class.btn-primary]="!stacked()" [class.btn-outline]="stacked()" (click)="stacked.set(false)">Lines</button>
          </div>
        </div>
      </div>
    </div>

    @if (series.error() || top.error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ series.error() || top.error() }}</span></div></div></div>
    }

    <div class="card">
      <div class="card-header">
        {{ groupBy() ? dimLabel(groupBy()) : 'Total traffic' }}
        @if (series.value(); as s) {
          <span class="card-hint">{{ s.step }}s resolution · {{ s.source === 'netflow.traffic_1m' ? '1-minute rollup' : 'raw flows' }} · drag to zoom</span>
        }
      </div>
      <div class="card-block">
        <nfa-chart [option]="chartOpt()" [loading]="series.loading()" [height]="340" [brushTime]="true" (timeSelect)="time.setCustom($event.from, $event.to)" (chartClick)="seriesClick($event)" />
      </div>
    </div>

    @if (groupBy()) {
      <clr-datagrid class="datagrid-compact" [clrDgLoading]="top.loading()">
        <clr-dg-column class="rank-col">#</clr-dg-column>
        <clr-dg-column [clrDgField]="'label'">{{ dimLabel(groupBy()) }}</clr-dg-column>
        <clr-dg-column [clrDgField]="'rate'" [clrDgSortOrder]="-1">Avg {{ metricName() }}</clr-dg-column>
        <clr-dg-column [clrDgField]="'bytes'">Bytes</clr-dg-column>
        <clr-dg-column [clrDgField]="'packets'">Packets</clr-dg-column>
        <clr-dg-column [clrDgField]="'flows'">Flows</clr-dg-column>
        <clr-dg-column [clrDgField]="'pct'">Share</clr-dg-column>

        <clr-dg-row *clrDgItems="let r of rows(); let i = index" [clrDgItem]="r">
          <clr-dg-action-overflow>
            <button class="action-item" (click)="addFilter(r, false)"><cds-icon shape="filter"></cds-icon> Filter on this</button>
            <button class="action-item" (click)="addFilter(r, true)"><cds-icon shape="times"></cds-icon> Exclude this</button>
            <button class="action-item" (click)="showFlowsFor(r)"><cds-icon shape="table"></cds-icon> Show flows</button>
          </clr-dg-action-overflow>
          <clr-dg-cell class="rank-col">{{ r.rank }}</clr-dg-cell>
          <clr-dg-cell><span class="swatch" [style.background]="r.color"></span><a href="#" (click)="$event.preventDefault(); addFilter(r, false)">{{ r.label.split(' ⇄ ')[0] }}</a>
            @if (r.label.includes(' ⇄ ')) {
              <div class="peer">⇄ {{ r.label.split(' ⇄ ')[1] }}</div>
            }
            @if (r.detail) {
              <div class="detail">{{ r.detail }}</div>
            }
          </clr-dg-cell>
          <clr-dg-cell class="num">{{ fmtRate(r.rate) }}</clr-dg-cell>
          <clr-dg-cell class="num">{{ fmtBytes(r.bytes) }}</clr-dg-cell>
          <clr-dg-cell class="num">{{ fmtCount(r.packets) }}</clr-dg-cell>
          <clr-dg-cell class="num">{{ fmtCount(r.flows) }}</clr-dg-cell>
          <clr-dg-cell class="num">
            <div class="share"><div class="bar"><div class="fill" [style.width.%]="r.pct" [style.background]="r.color"></div></div>{{ r.pct.toFixed(1) }}%</div>
          </clr-dg-cell>
        </clr-dg-row>
        <clr-dg-placeholder>No traffic matches the current filters.</clr-dg-placeholder>
        <clr-dg-footer>
          @if (top.value(); as t) {
            <span class="footer-summary">{{ fmtBytes(t.total.bytes) }} total · {{ fmtCount(t.total.flows) }} flows</span>
          }
          <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            {{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} rows
          } @else {
            No rows
          }
        </clr-dg-pagination>
        </clr-dg-footer>
      </clr-datagrid>
    }
  `,
  styles: `
    .toolbar { margin-top: 0; }
    .header-controls { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .header-controls .btn { margin: 0; }
    .controls { display: flex; flex-wrap: wrap; align-items: center; gap: 16px; margin-top: 10px; }
    .ctl { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; }
    .card-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
    .card-hint { font-size: 11px; font-weight: 400; color: var(--cds-alias-typography-color-300); }
    .swatch { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 6px; }
    .peer { margin-left: 15px; }
    .detail { font-size: 11px; color: var(--cds-alias-typography-color-300); margin-left: 15px; }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .rank-col { width: 40px; max-width: 48px; }
    .share { display: flex; align-items: center; gap: 6px; justify-content: flex-end; }
    .bar { width: 60px; height: 6px; background: var(--cds-alias-object-border-color); border-radius: 3px; overflow: hidden; }
    .fill { height: 100%; }
    clr-datagrid { margin-top: 12px; }
    .footer-summary { margin-right: auto; }
  `,
})
export class Explorer {
  readonly time = inject(TimeRange);
  private api = inject(Api);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  readonly dims = DIMENSIONS;
  readonly metrics = METRICS;
  readonly dimLabel = dimLabel;

  private qp = this.route.snapshot.queryParams as Record<string, string>;
  readonly filters = signal<Filters>(filtersFromParams(this.qp, FILTER_KEYS));
  readonly groupBy = signal<string>(this.qp['groupBy'] ?? 'app');
  readonly metric = signal<Metric>((this.qp['metric'] as Metric) ?? 'bps');
  readonly limit = signal<number>(+(this.qp['limit'] ?? 10));
  readonly stacked = signal<boolean>(this.qp['style'] !== 'lines');

  readonly series = loader(
    () => ({ w: this.time.window(), f: this.filters(), m: this.metric(), g: this.groupBy(), l: this.limit() }),
    (p) => this.api.timeseries(p.w, p.f, p.m, p.g, p.l),
  );
  readonly top = loader(
    () => (this.groupBy() ? { w: this.time.window(), f: this.filters(), m: this.metric(), g: this.groupBy() } : undefined),
    (p) => this.api.top(p.w, p.f, p.g, p.m, 100),
  );

  readonly chartOpt = computed(() => {
    const s = this.series.value();
    return s ? timeSeriesOption(s, { stacked: this.stacked() }) : null;
  });

  /** Table rows with colors matching their chart series. */
  readonly rows = computed(() => {
    const t = this.top.value();
    if (!t) return [];
    const colorByKey = new Map<string, string>();
    (this.series.value()?.series ?? []).filter((s) => s.key !== '__other__').forEach((s, i) => colorByKey.set(s.key, PALETTE[i % PALETTE.length]));
    return t.rows.map((r, i) => ({ ...r, rank: i + 1, color: colorByKey.get(r.key) ?? OTHER_COLOR }));
  });

  readonly metricName = computed(() => ({ bps: 'bits/s', pps: 'packets/s', fps: 'flows/s' })[this.metric()]);

  constructor() {
    // Keep the URL in sync so views can be bookmarked and shared.
    effect(() => {
      const qp: Record<string, string | null> = {};
      for (const k of FILTER_KEYS) qp[k] = this.filters()[k] || null;
      qp['groupBy'] = this.groupBy() || null;
      qp['metric'] = this.metric() === 'bps' ? null : this.metric();
      qp['limit'] = this.limit() === 10 ? null : String(this.limit());
      qp['style'] = this.stacked() ? null : 'lines';
      untracked(() => this.router.navigate([], { queryParams: qp, replaceUrl: true }));
    });
  }

  fmtRate(v: number) {
    return rate(v, this.metric());
  }
  fmtBytes = bytes;
  fmtCount = count;

  addFilter(r: TopRow, exclude: boolean) {
    const f = drillFilter(this.groupBy(), r.key);
    if (!f) return;
    const next = { ...this.filters() };
    for (const [k, v] of Object.entries(f)) next[k] = (exclude && k !== 'exporter' ? '!' : '') + v;
    this.filters.set(next);
  }

  seriesClick(ev: { seriesId?: string }) {
    if (this.groupBy() && ev.seriesId && ev.seriesId !== '__other__') this.addFilter({ key: ev.seriesId } as TopRow, false);
  }

  showFlowsFor(r: TopRow) {
    this.showFlows(drillFilter(this.groupBy(), r.key) ?? {});
  }

  showFlows(extra: Filters) {
    this.router.navigate(['/flows'], { queryParams: { ...this.filters(), ...extra } });
  }
}
