import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, Filters, Metric, TopRow } from '../core/api';
import { bytes, count, DIMENSIONS, dimLabel, drillFilter, FILTER_FIELDS, METRICS, rate } from '../core/format';
import { TimeRange } from '../core/time';
import { filtersFromParams, loader, trackByKey } from '../core/util';
import { Chart, OTHER_COLOR, PALETTE } from '../shared/chart';
import { FilterBar } from '../shared/filter-bar';
import { RangeBar } from '../shared/range-bar';
import { sankeyOption, timeSeriesOption } from '../shared/options';

const FILTER_KEYS = FILTER_FIELDS.map((f) => f.id);

// Dimensions that count a flow on both sides can't be path columns.
const PATH_EXCLUDED = new Set(['host', 'country', 'local_host', 'remote_host']);

function parsePathDims(v: string | undefined): string[] {
  const ids = new Set(DIMENSIONS.map((d) => d.id));
  const d = (v ?? '').split(',').filter((x, i, a) => ids.has(x) && !PATH_EXCLUDED.has(x) && a.indexOf(x) === i).slice(0, 3);
  return d.length >= 2 ? d : ['device', 'app', 'remote_as'];
}

@Component({
  selector: 'nfa-explorer',
  imports: [ClarityModule, FormsModule, Chart, FilterBar, RangeBar],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.explorer">Traffic Explorer</h2>
        <p class="subtitle" i18n="@@explorer.subtitle">Break traffic down by any dimension · {{ time.label() }}</p>
      </div>
      <div class="header-controls">
        <nfa-range-bar />
        <button class="btn btn-sm btn-outline" (click)="showFlows({})"><cds-icon shape="table"></cds-icon> <ng-container i18n="@@explorer.showMatchingFlows">Show matching flows</ng-container></button>
      </div>
    </div>

    <div class="card toolbar">
      <div class="card-block">
        <nfa-filter-bar [(filters)]="filters" />
        <div class="controls">
          <div class="btn-group btn-sm" role="group" aria-label="View" i18n-aria-label="@@explorer.view">
            <button class="btn" [class.btn-primary]="view() === 'chart'" [class.btn-outline]="view() !== 'chart'" (click)="view.set('chart')"><cds-icon shape="line-chart"></cds-icon> <ng-container i18n="@@explorer.viewChart">Chart</ng-container></button>
            <button class="btn" [class.btn-primary]="view() === 'paths'" [class.btn-outline]="view() !== 'paths'" (click)="view.set('paths')"><cds-icon shape="tree-view"></cds-icon> <ng-container i18n="@@explorer.viewPaths">Paths</ng-container></button>
          </div>
          @if (view() === 'paths') {
            @for (col of [0, 1, 2]; track col) {
              @if (col > 0) {
                <cds-icon shape="arrow" direction="right" class="path-arrow"></cds-icon>
              }
              <select class="clr-select path-dim" [attr.aria-label]="pathColumnLabel(col)" [ngModel]="pathDims()[col] ?? ''" (ngModelChange)="setPathDim(col, $event)" [name]="'path' + col">
                @if (col === 2) {
                  <option value="" i18n="@@explorer.pathNone">— none —</option>
                }
                @for (d of pathDimOptions; track d.id) {
                  <option [value]="d.id" [disabled]="pathDims().includes(d.id) && pathDims()[col] !== d.id">{{ d.label }}</option>
                }
              </select>
            }
            <label class="ctl">
              <span i18n="@@explorer.perColumn">Per column</span>
              <select class="clr-select" [ngModel]="limit()" (ngModelChange)="limit.set(+$event)" name="pathLimit">
                @for (n of [5, 8, 10, 12, 15]; track n) {
                  <option [value]="n" i18n="@@explorer.topN">Top {{ n }}</option>
                }
              </select>
            </label>
            <div class="btn-group btn-sm" role="group" aria-label="Metric" i18n-aria-label="@@explorer.metric">
              @for (m of metrics; track m.id) {
                <button class="btn" [class.btn-primary]="metric() === m.id" [class.btn-outline]="metric() !== m.id" (click)="metric.set(m.id)">{{ m.label }}</button>
              }
            </div>
            <div class="btn-group btn-sm" role="group" aria-label="Direction" i18n-aria-label="@@explorer.directionGroup">
              <button class="btn" [class.btn-primary]="!direction()" [class.btn-outline]="!!direction()" (click)="setDirection('')" i18n="@@explorer.dirBoth">Both</button>
              <button class="btn" [class.btn-primary]="direction() === 'download'" [class.btn-outline]="direction() !== 'download'" (click)="setDirection('download')" i18n="@@explorer.dirDownload">Download</button>
              <button class="btn" [class.btn-primary]="direction() === 'upload'" [class.btn-outline]="direction() !== 'upload'" (click)="setDirection('upload')" i18n="@@explorer.dirUpload">Upload</button>
            </div>
          } @else {
          <label class="ctl">
            <span i18n="@@explorer.groupBy">Group by</span>
            <select class="clr-select" [ngModel]="groupBy()" (ngModelChange)="groupBy.set($event)" name="groupBy">
              <option value="" i18n="@@explorer.groupByNone">— none (total) —</option>
              @for (d of dims; track d.id) {
                <option [value]="d.id">{{ d.label }}</option>
              }
            </select>
          </label>
          <label class="ctl">
            <span i18n="@@explorer.series">Series</span>
            <select class="clr-select" [ngModel]="limit()" (ngModelChange)="limit.set(+$event)" name="limit">
              @for (n of [5, 8, 10, 15, 20]; track n) {
                <option [value]="n" i18n="@@explorer.topN">Top {{ n }}</option>
              }
            </select>
          </label>
          <div class="btn-group btn-sm" role="group" aria-label="Metric" i18n-aria-label="@@explorer.metric">
            @for (m of metrics; track m.id) {
              <button class="btn" [class.btn-primary]="metric() === m.id" [class.btn-outline]="metric() !== m.id" (click)="metric.set(m.id)">{{ m.label }}</button>
            }
          </div>
          <div class="btn-group btn-sm" role="group" aria-label="Chart style" i18n-aria-label="@@explorer.chartStyle">
            <button class="btn" [class.btn-primary]="stacked()" [class.btn-outline]="!stacked()" (click)="stacked.set(true)" i18n="@@explorer.stacked">Stacked</button>
            <button class="btn" [class.btn-primary]="!stacked()" [class.btn-outline]="stacked()" (click)="stacked.set(false)" i18n="@@explorer.lines">Lines</button>
          </div>
          }
        </div>
      </div>
    </div>

    @if (series.error() || top.error() || paths.error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ series.error() || top.error() || paths.error() }}</span></div></div></div>
    }

    @if (view() === 'paths') {
      <div class="card">
        <div class="card-header">
          <span i18n="@@explorer.pathsTitle">Traffic paths</span>
          @if (paths.value(); as p) {
            <span class="card-hint" i18n="@@explorer.pathsHint">{{ sourceLabel(p.source) }} · click a node or path to filter on it</span>
          }
        </div>
        <div class="card-block">
          @if (paths.value()?.nodes?.length === 0 && !paths.loading()) {
            <p class="empty" i18n="@@explorer.noMatch">No traffic matches the current filters.</p>
          } @else {
            <nfa-chart [option]="pathOpt()" [loading]="paths.loading()" [height]="pathHeight()" (chartClick)="pathClick($event)" />
          }
        </div>
      </div>
    } @else {
    <div class="card">
      <div class="card-header">
        @if (groupBy()) {
          {{ dimLabel(groupBy()) }}
        } @else {
          <ng-container i18n="@@explorer.totalTraffic">Total traffic</ng-container>
        }
        @if (series.value(); as s) {
          <span class="card-hint" i18n="@@explorer.resolution">{{ s.step }}s resolution · {{ sourceLabel(s.source) }} · drag to zoom</span>
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
        <clr-dg-column [clrDgField]="'rate'" [clrDgSortOrder]="-1" i18n="@@explorer.col.avg">Avg {{ metricName() }}</clr-dg-column>
        <clr-dg-column [clrDgField]="'bytes'" i18n="@@explorer.col.bytes">Bytes</clr-dg-column>
        <clr-dg-column [clrDgField]="'packets'" i18n="@@explorer.col.packets">Packets</clr-dg-column>
        <clr-dg-column [clrDgField]="'flows'" i18n="@@explorer.col.flows">Flows</clr-dg-column>
        <clr-dg-column [clrDgField]="'pct'" i18n="@@explorer.col.share">Share</clr-dg-column>

        <clr-dg-row *clrDgItems="let r of rows(); let i = index; trackBy: byKey" [clrDgItem]="r">
          <clr-dg-action-overflow>
            <button class="action-item" (click)="addFilter(r, false)"><cds-icon shape="filter"></cds-icon> <ng-container i18n="@@explorer.filterOn">Filter on this</ng-container></button>
            <button class="action-item" (click)="addFilter(r, true)"><cds-icon shape="times"></cds-icon> <ng-container i18n="@@explorer.exclude">Exclude this</ng-container></button>
            <button class="action-item" (click)="showFlowsFor(r)"><cds-icon shape="table"></cds-icon> <ng-container i18n="@@explorer.showFlows">Show flows</ng-container></button>
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
        <clr-dg-placeholder i18n="@@explorer.noMatch">No traffic matches the current filters.</clr-dg-placeholder>
        <clr-dg-footer>
          @if (top.value(); as t) {
            <span class="footer-summary" i18n="@@explorer.totals">{{ fmtBytes(t.total.bytes) }} total · {{ fmtCount(t.total.flows) }} flows</span>
          }
          <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@explorer.footer">{{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} rows</ng-container>
          } @else {
            <ng-container i18n="@@explorer.empty">No rows</ng-container>
          }
        </clr-dg-pagination>
        </clr-dg-footer>
      </clr-datagrid>
    }
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
    .path-dim { max-width: 220px; }
    .path-arrow { color: var(--cds-alias-typography-color-300); margin: 0 -8px; }
    .empty { color: var(--cds-alias-typography-color-300); padding: 40px 0; text-align: center; }
    clr-datagrid { margin-top: 12px; }
    .footer-summary { margin-right: auto; }
  `,
})
export class Explorer {
  readonly byKey = trackByKey<{ key: string }>((r) => r.key);
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
  readonly view = signal<'chart' | 'paths'>(this.qp['view'] === 'paths' ? 'paths' : 'chart');
  readonly pathDims = signal<string[]>(parsePathDims(this.qp['path']));
  readonly pathDimOptions = DIMENSIONS.filter((d) => !PATH_EXCLUDED.has(d.id));
  readonly direction = computed(() => this.filters()['direction'] ?? '');

  readonly paths = loader(
    () => (this.view() === 'paths' ? { w: this.time.window(), f: this.filters(), m: this.metric(), d: this.pathDims(), l: this.limit() } : undefined),
    (p) => this.api.paths(p.w, p.f, p.d, p.m, p.l),
  );
  readonly pathOpt = computed(() => {
    const p = this.paths.value();
    return p ? sankeyOption(p) : null;
  });
  /** Tall enough that the busiest column's nodes stay readable. */
  readonly pathHeight = computed(() => {
    const counts = [0, 0, 0];
    for (const n of this.paths.value()?.nodes ?? []) counts[n.column]++;
    return Math.max(420, Math.max(...counts) * 52 + 40);
  });

  readonly series = loader(
    () => (this.view() === 'chart' ? { w: this.time.window(), f: this.filters(), m: this.metric(), g: this.groupBy(), l: this.limit() } : undefined),
    (p) => this.api.timeseries(p.w, p.f, p.m, p.g, p.l),
  );
  readonly top = loader(
    () => (this.view() === 'chart' && this.groupBy() ? { w: this.time.window(), f: this.filters(), m: this.metric(), g: this.groupBy() } : undefined),
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

  readonly metricName = computed(() => ({ bps: $localize`:@@explorer.unit.bps:bits/s`, pps: $localize`:@@explorer.unit.pps:packets/s`, fps: $localize`:@@explorer.unit.fps:flows/s` })[this.metric()]);

  sourceLabel(source: string) {
    return source === 'netflow.traffic_1m' ? $localize`:@@explorer.source.rollup:1-minute rollup` : $localize`:@@explorer.source.raw:raw flows`;
  }

  constructor() {
    // Keep the URL in sync so views can be bookmarked and shared.
    effect(() => {
      const qp: Record<string, string | null> = {};
      for (const k of FILTER_KEYS) qp[k] = this.filters()[k] || null;
      qp['groupBy'] = this.groupBy() || null;
      qp['metric'] = this.metric() === 'bps' ? null : this.metric();
      qp['limit'] = this.limit() === 10 ? null : String(this.limit());
      qp['style'] = this.stacked() ? null : 'lines';
      qp['view'] = this.view() === 'paths' ? 'paths' : null;
      qp['path'] = this.view() === 'paths' ? this.pathDims().join(',') : null;
      untracked(() => this.router.navigate([], { queryParams: qp, replaceUrl: true }));
    });
  }

  fmtRate(v: number) {
    return rate(v, this.metric());
  }
  fmtBytes = bytes;
  fmtCount = count;

  addFilter(r: TopRow, exclude: boolean) {
    const f = drillFilter(this.groupBy(), r.key, r.label);
    if (!f) return;
    const next = { ...this.filters() };
    for (const [k, v] of Object.entries(f)) next[k] = (exclude && k !== 'exporter' ? '!' : '') + v;
    this.filters.set(next);
  }

  seriesClick(ev: { seriesId?: string }) {
    if (this.groupBy() && ev.seriesId && ev.seriesId !== '__other__') this.addFilter({ key: ev.seriesId } as TopRow, false);
  }

  pathColumnLabel(col: number) {
    return [$localize`:@@explorer.pathFrom:From`, $localize`:@@explorer.pathThrough:Through`, $localize`:@@explorer.pathTo:To`][col];
  }

  setPathDim(col: number, id: string) {
    const d = [...this.pathDims()];
    if (id) d[col] = id;
    else d.splice(col, 1);
    this.pathDims.set(d.filter(Boolean));
  }

  setDirection(v: string) {
    const f = { ...this.filters() };
    if (v) f['direction'] = v;
    else delete f['direction'];
    this.filters.set(f);
  }

  /** Clicking a node filters on its value; a path filters on both ends. */
  pathClick(ev: { dataType?: string; data: unknown }) {
    const p = this.paths.value();
    const idx = (ev.data as { index?: number })?.index;
    if (!p || idx === undefined) return;
    const nodes = ev.dataType === 'edge' ? [p.nodes[p.links[idx].source], p.nodes[p.links[idx].target]] : [p.nodes[idx]];
    const next = { ...this.filters() };
    for (const n of nodes) {
      if (n.key === '__other__') continue;
      Object.assign(next, drillFilter(p.dimensions[n.column], n.key, n.label) ?? {});
    }
    this.filters.set(next);
  }

  showFlowsFor(r: TopRow) {
    this.showFlows(drillFilter(this.groupBy(), r.key, r.label) ?? {});
  }

  showFlows(extra: Filters) {
    this.router.navigate(['/flows'], { queryParams: { ...this.filters(), ...extra } });
  }
}
