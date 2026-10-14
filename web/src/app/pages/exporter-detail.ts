import { Component, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, Interface, Metric } from '../core/api';
import { Auth } from '../core/auth';
import { ago, bits, bytes, count, dateTime, METRICS, samplingLabel } from '../core/format';
import { TimeRange } from '../core/time';
import { loader, trackByKey } from '../core/util';
import { Chart } from '../shared/chart';
import { RangeBar } from '../shared/range-bar';
import { timeSeriesOption } from '../shared/options';

@Component({
  selector: 'nfa-exporter-detail',
  imports: [ClarityModule, FormsModule, Chart, RouterLink, RangeBar],
  template: `
    <div class="breadcrumb"><a routerLink="/exporters" i18n="@@nav.exporters">Exporters</a> / {{ exp()?.name || addr() }}</div>
    <div class="page-header">
      <div>
        <h2>
          <cds-icon shape="router" size="md"></cds-icon> {{ exp()?.name || addr() }}
          @if (exp(); as e) {
            <span class="badge" [class.badge-success]="e.status === 'active'" [class.badge-warning]="e.status === 'idle'" [class.badge-danger]="e.status === 'stale'" i18n="Exporter status@@exporterDetail.status">{e.status, select, active {active} idle {idle} stale {stale} other {{{ e.status }}}}</span>
          }
        </h2>
        <p class="subtitle">{{ addr() }}{{ exp()?.location ? ' · ' + exp()?.location : '' }}{{ exp()?.description ? ' · ' + exp()?.description : '' }}</p>
      </div>
      <div class="header-controls">
        <nfa-range-bar />
        <a class="btn btn-sm btn-outline" [routerLink]="['/explorer']" [queryParams]="{ exporter: addr(), groupBy: 'app' }"><cds-icon shape="line-chart"></cds-icon> <ng-container i18n="@@exporterDetail.analyze">Analyze traffic</ng-container></a>
      </div>
    </div>

    @if (exp(); as e) {
      <div class="kpis">
        <div class="kpi card"><div class="kpi-label" i18n="@@exporterDetail.kpi.flowsPerSec">Flows/s</div><div class="kpi-value">{{ e.live ? e.live.flowsPerSec.toFixed(1) : '–' }}</div><div class="kpi-sub" i18n="@@exporterDetail.kpi.live">live</div></div>
        <div class="kpi card"><div class="kpi-label" i18n="@@exporterDetail.kpi.throughput">Throughput</div><div class="kpi-value">{{ e.live ? fmtBits(e.live.bitsPerSec) : '–' }}</div><div class="kpi-sub" i18n="@@exporterDetail.kpi.liveCorrected">live, sampling-corrected</div></div>
        <div class="kpi card"><div class="kpi-label" i18n="@@exporterDetail.kpi.protocol">Protocol</div><div class="kpi-value small">{{ e.live?.types?.join(', ') || '–' }}</div><div class="kpi-sub" i18n="@@exporterDetail.kpi.templatesCached">{{ e.live?.templates ?? 0 }} templates cached</div></div>
        @let sl = sampling(e);
        <div class="kpi card"><div class="kpi-label" i18n="@@exporterDetail.kpi.sampling">Sampling</div><div class="kpi-value">{{ sl.rate }}</div><div class="kpi-sub" [title]="sl.hint">{{ sl.sourceLabel }}</div></div>
        <div class="kpi card"><div class="kpi-label" i18n="@@exporterDetail.kpi.lostErrors">Lost / errors</div><div class="kpi-value">{{ fmtCount(e.live?.lost ?? 0) }} / {{ fmtCount(e.live?.errors ?? 0) }}</div><div class="kpi-sub" i18n="@@exporterDetail.kpi.setsWithoutTemplate">{{ fmtCount(e.live?.missingTemplates ?? 0) }} sets w/o template</div></div>
        <div class="kpi card"><div class="kpi-label" i18n="@@exporterDetail.kpi.volume">Volume</div><div class="kpi-value">{{ fmtBytes(e.bytes) }}</div><div class="kpi-sub" i18n="@@exporterDetail.kpi.firstLastSeen">first seen {{ dt(e.firstSeen) }} · last {{ ago(e.live?.lastSeen ?? 0) }}</div></div>
      </div>
    }

    <div class="card">
      <div class="card-header">
        <ng-container i18n="@@exporterDetail.chartTitle">Traffic by input interface · {{ time.label() }}</ng-container>
        <div class="btn-group btn-sm" role="group">
          @for (m of metrics; track m.id) {
            <button class="btn" [class.btn-primary]="metric() === m.id" [class.btn-outline]="metric() !== m.id" (click)="metric.set(m.id)">{{ m.label }}</button>
          }
        </div>
      </div>
      <div class="card-block">
        <nfa-chart [option]="chartOpt()" [loading]="series.loading()" [height]="280" [brushTime]="true" (timeSelect)="time.setCustom($event.from, $event.to)" />
      </div>
    </div>

    <h3 class="section-title" i18n="@@exporterDetail.interfaces">Interfaces</h3>
    <p class="hint"><ng-container i18n="@@exporterDetail.interfacesSeen">Interfaces seen in {{ time.label().toLowerCase() }}.</ng-container> @if (auth.isAdmin()) {<ng-container i18n="@@exporterDetail.interfacesAdminHint">Name them to make reports readable; set the speed to see utilization.</ng-container>}</p>
    <clr-datagrid class="datagrid-compact" [clrDgLoading]="ifaces.loading()">
      <clr-dg-column [clrDgField]="'index'" [clrDgSortOrder]="1" i18n="@@exporterDetail.col.ifIndex">ifIndex</clr-dg-column>
      <clr-dg-column [clrDgField]="'name'" i18n="@@common.name">Name</clr-dg-column>
      <clr-dg-column i18n="@@common.description">Description</clr-dg-column>
      <clr-dg-column i18n="@@exporterDetail.col.speed">Speed</clr-dg-column>
      <clr-dg-column [clrDgField]="'inBytes'" i18n="Inbound traffic@@exporterDetail.col.in">In</clr-dg-column>
      <clr-dg-column [clrDgField]="'outBytes'" i18n="Outbound traffic@@exporterDetail.col.out">Out</clr-dg-column>
      <clr-dg-column i18n="@@exporterDetail.col.utilization">Avg utilization in / out</clr-dg-column>

      <clr-dg-row *clrDgItems="let i of ifaces.value() ?? []; trackBy: byIndex" [clrDgItem]="i">
        <clr-dg-action-overflow>
          <a class="action-item" [routerLink]="['/explorer']" [queryParams]="{ exporter: addr(), iface: i.index, groupBy: 'app' }" i18n="@@exporterDetail.analyze">Analyze traffic</a>
          @if (auth.isAdmin()) {
            <button class="action-item" (click)="editIf(i)" i18n="@@common.edit">Edit</button>
          }
        </clr-dg-action-overflow>
        <clr-dg-cell>{{ i.index }}</clr-dg-cell>
        <clr-dg-cell>{{ i.name || '–' }}</clr-dg-cell>
        <clr-dg-cell>{{ i.description }}</clr-dg-cell>
        <clr-dg-cell>@if (i.speed) { {{ fmtBits(i.speed) }} } @else {<ng-container i18n="@@exporterDetail.speedUnknown">unknown</ng-container>}</clr-dg-cell>
        <clr-dg-cell class="num">{{ fmtBytes(i.inBytes) }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ fmtBytes(i.outBytes) }}</clr-dg-cell>
        <clr-dg-cell>
          @if (i.speed) {
            <div class="util">
              <span class="u-lbl" i18n="Inbound@@exporterDetail.utilIn">in</span><span class="u-bar"><span [style.width.%]="util(i.inBytes, i.speed)"></span></span><span class="u-pct">{{ util(i.inBytes, i.speed).toFixed(1) }}%</span>
              <span class="u-lbl" i18n="Outbound@@exporterDetail.utilOut">out</span><span class="u-bar"><span [style.width.%]="util(i.outBytes, i.speed)"></span></span><span class="u-pct">{{ util(i.outBytes, i.speed).toFixed(1) }}%</span>
            </div>
          } @else {
            <span class="hint" i18n="@@exporterDetail.setSpeed">set speed</span>
          }
        </clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder i18n="@@exporterDetail.placeholder">No interfaces carried traffic in this time range.</clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@exporterDetail.footer">{{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} interfaces</ng-container>
          } @else {
            <ng-container i18n="@@exporterDetail.empty">No interfaces</ng-container>
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <clr-modal [(clrModalOpen)]="ifOpen" clrModalSize="md">
      <h3 class="modal-title" i18n="@@exporterDetail.ifTitle">Interface {{ ifForm.index }}</h3>
      <div class="modal-body">
        <form clrForm clrLayout="vertical" id="ifform" (ngSubmit)="saveIf()">
          <clr-input-container>
            <label i18n="@@common.name">Name</label>
            <input clrInput name="name" [(ngModel)]="ifForm.name" placeholder="e.g. Gi0/0/1" i18n-placeholder="@@exporterDetail.ifNamePlaceholder" maxlength="64" />
          </clr-input-container>
          <clr-input-container>
            <label i18n="@@common.description">Description</label>
            <input clrInput name="description" [(ngModel)]="ifForm.description" placeholder="e.g. Uplink to ISP-A" i18n-placeholder="@@exporterDetail.ifDescPlaceholder" maxlength="256" />
          </clr-input-container>
          <clr-select-container>
            <label i18n="@@exporterDetail.speed">Speed</label>
            <select clrSelect name="speed" [(ngModel)]="ifForm.speed">
              <option [ngValue]="0" i18n="@@exporterDetail.speedUnknownOption">Unknown</option>
              @for (s of speeds; track s.v) {
                <option [ngValue]="s.v">{{ s.l }}</option>
              }
            </select>
          </clr-select-container>
        </form>
        @if (ifError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ ifError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="ifOpen.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="submit" form="ifform" class="btn btn-primary" i18n="@@common.save">Save</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .breadcrumb { font-size: 12px; margin-bottom: 4px; }
    h2 cds-icon { vertical-align: -4px; }
    h2 .badge { vertical-align: 4px; }
    .card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
    .kpi-value.small { font-size: 16px; }
    .section-title { margin-top: 24px; }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 4px; }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .util { display: flex; align-items: center; gap: 6px; font-variant-numeric: tabular-nums; }
    .u-lbl { font-size: 11px; color: var(--cds-alias-typography-color-300); }
    .u-bar { width: 50px; height: 6px; border-radius: 3px; background: var(--cds-alias-object-border-color); overflow: hidden; display: inline-block; }
    .u-bar span { display: block; height: 100%; background: var(--cds-alias-status-info); }
    .header-controls { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .header-controls .btn { margin: 0; }
    .u-pct { width: 42px; text-align: right; margin-right: 8px; }
  `,
})
export class ExporterDetail {
  readonly byIndex = trackByKey<{ index: number }>((i) => i.index);
  readonly addr = input.required<string>();
  readonly time = inject(TimeRange);
  readonly auth = inject(Auth);
  private api = inject(Api);
  readonly metrics = METRICS;
  readonly metric = signal<Metric>('bps');

  readonly list = loader(() => this.time.window(), (w) => this.api.exporters(w));
  readonly exp = computed(() => this.list.value()?.find((e) => e.addr === this.addr()));
  readonly ifaces = loader(() => ({ a: this.addr(), w: this.time.window() }), (p) => this.api.interfaces(p.a, p.w));
  readonly series = loader(
    () => ({ w: this.time.window(), a: this.addr(), m: this.metric() }),
    (p) => this.api.timeseries(p.w, { exporter: p.a }, p.m, 'in_if', 10),
  );
  readonly chartOpt = computed(() => {
    const s = this.series.value();
    return s ? timeSeriesOption(s) : null;
  });

  readonly speeds = [
    { v: 10e6, l: '10 Mbps' }, { v: 100e6, l: '100 Mbps' }, { v: 1e9, l: '1 Gbps' }, { v: 2.5e9, l: '2.5 Gbps' }, { v: 10e9, l: '10 Gbps' },
    { v: 25e9, l: '25 Gbps' }, { v: 40e9, l: '40 Gbps' }, { v: 100e9, l: '100 Gbps' }, { v: 400e9, l: '400 Gbps' },
  ];
  readonly ifOpen = signal(false);
  ifForm = { index: 0, name: '', description: '', speed: 0 };
  readonly ifError = signal('');

  ago = ago;
  sampling = (e: { sampling: number; live: any }) => samplingLabel(e.sampling, e.live);
  dt = dateTime;
  fmtBits = bits;
  fmtBytes = bytes;
  fmtCount = count;

  // Average utilization over the selected window.
  util(b: number, speed: number) {
    const w = this.time.window();
    return Math.min(100, ((b * 8) / ((w.to - w.from) / 1000) / speed) * 100);
  }

  editIf(i: Interface) {
    this.ifForm = { index: i.index, name: i.name, description: i.description, speed: i.speed };
    this.ifError.set('');
    this.ifOpen.set(true);
  }

  async saveIf() {
    try {
      await this.api.updateInterface({ exporter: this.addr(), ...this.ifForm });
      this.ifOpen.set(false);
      this.ifaces.reload();
      this.series.reload();
    } catch (e) {
      this.ifError.set(errorMessage(e));
    }
  }
}
