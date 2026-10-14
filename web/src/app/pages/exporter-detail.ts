import { Component, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, Interface, Metric } from '../core/api';
import { Auth } from '../core/auth';
import { ago, bits, bytes, count, dateTime, METRICS, samplingLabel } from '../core/format';
import { TimeRange } from '../core/time';
import { loader } from '../core/util';
import { Chart } from '../shared/chart';
import { timeSeriesOption } from '../shared/options';

@Component({
  selector: 'nfa-exporter-detail',
  imports: [ClarityModule, FormsModule, Chart, RouterLink],
  template: `
    <div class="breadcrumb"><a routerLink="/exporters">Exporters</a> / {{ exp()?.name || addr() }}</div>
    <div class="page-header">
      <div>
        <h2>
          <cds-icon shape="router" size="md"></cds-icon> {{ exp()?.name || addr() }}
          @if (exp(); as e) {
            <span class="badge" [class.badge-success]="e.status === 'active'" [class.badge-warning]="e.status === 'idle'" [class.badge-danger]="e.status === 'stale'">{{ e.status }}</span>
          }
        </h2>
        <p class="subtitle">{{ addr() }}{{ exp()?.location ? ' · ' + exp()?.location : '' }}{{ exp()?.description ? ' · ' + exp()?.description : '' }}</p>
      </div>
      <a class="btn btn-sm btn-outline" [routerLink]="['/explorer']" [queryParams]="{ exporter: addr(), groupBy: 'app' }"><cds-icon shape="line-chart"></cds-icon> Analyze traffic</a>
    </div>

    @if (exp(); as e) {
      <div class="kpis">
        <div class="kpi card"><div class="kpi-label">Flows/s</div><div class="kpi-value">{{ e.live ? e.live.flowsPerSec.toFixed(1) : '–' }}</div><div class="kpi-sub">live</div></div>
        <div class="kpi card"><div class="kpi-label">Throughput</div><div class="kpi-value">{{ e.live ? fmtBits(e.live.bitsPerSec) : '–' }}</div><div class="kpi-sub">live, sampling-corrected</div></div>
        <div class="kpi card"><div class="kpi-label">Protocol</div><div class="kpi-value small">{{ e.live?.types?.join(', ') || '–' }}</div><div class="kpi-sub">{{ e.live?.templates ?? 0 }} templates cached</div></div>
        @let sl = sampling(e);
        <div class="kpi card"><div class="kpi-label">Sampling</div><div class="kpi-value">{{ sl.rate }}</div><div class="kpi-sub" [title]="sl.hint">{{ sl.source }}</div></div>
        <div class="kpi card"><div class="kpi-label">Lost / errors</div><div class="kpi-value">{{ fmtCount(e.live?.lost ?? 0) }} / {{ fmtCount(e.live?.errors ?? 0) }}</div><div class="kpi-sub">{{ fmtCount(e.live?.missingTemplates ?? 0) }} sets w/o template</div></div>
        <div class="kpi card"><div class="kpi-label">Last 24h</div><div class="kpi-value">{{ fmtBytes(e.bytes24h) }}</div><div class="kpi-sub">first seen {{ dt(e.firstSeen) }} · last {{ ago(e.live?.lastSeen ?? 0) }}</div></div>
      </div>
    }

    <div class="card">
      <div class="card-header">
        Traffic by input interface · {{ time.label() }}
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

    <h3 class="section-title">Interfaces</h3>
    <p class="hint">Interfaces seen in the last 24 hours. {{ auth.isAdmin() ? 'Name them to make reports readable; set the speed to see utilization.' : '' }}</p>
    <clr-datagrid class="datagrid-compact" [clrDgLoading]="ifaces.loading()">
      <clr-dg-column [clrDgField]="'index'" [clrDgSortOrder]="1">ifIndex</clr-dg-column>
      <clr-dg-column [clrDgField]="'name'">Name</clr-dg-column>
      <clr-dg-column>Description</clr-dg-column>
      <clr-dg-column>Speed</clr-dg-column>
      <clr-dg-column [clrDgField]="'inBytes24h'">In (24h)</clr-dg-column>
      <clr-dg-column [clrDgField]="'outBytes24h'">Out (24h)</clr-dg-column>
      <clr-dg-column>Avg utilization in / out</clr-dg-column>

      <clr-dg-row *clrDgItems="let i of ifaces.value() ?? []" [clrDgItem]="i">
        <clr-dg-action-overflow>
          <a class="action-item" [routerLink]="['/explorer']" [queryParams]="{ exporter: addr(), iface: i.index, groupBy: 'app' }">Analyze traffic</a>
          @if (auth.isAdmin()) {
            <button class="action-item" (click)="editIf(i)">Edit</button>
          }
        </clr-dg-action-overflow>
        <clr-dg-cell>{{ i.index }}</clr-dg-cell>
        <clr-dg-cell>{{ i.name || '–' }}</clr-dg-cell>
        <clr-dg-cell>{{ i.description }}</clr-dg-cell>
        <clr-dg-cell>{{ i.speed ? fmtBits(i.speed) : 'unknown' }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ fmtBytes(i.inBytes24h) }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ fmtBytes(i.outBytes24h) }}</clr-dg-cell>
        <clr-dg-cell>
          @if (i.speed) {
            <div class="util">
              <span class="u-lbl">in</span><span class="u-bar"><span [style.width.%]="util(i.inBytes24h, i.speed)"></span></span><span class="u-pct">{{ util(i.inBytes24h, i.speed).toFixed(1) }}%</span>
              <span class="u-lbl">out</span><span class="u-bar"><span [style.width.%]="util(i.outBytes24h, i.speed)"></span></span><span class="u-pct">{{ util(i.outBytes24h, i.speed).toFixed(1) }}%</span>
            </div>
          } @else {
            <span class="hint">set speed</span>
          }
        </clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder>No interfaces have carried traffic in the last 24 hours.</clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            {{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} interfaces
          } @else {
            No interfaces
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <clr-modal [(clrModalOpen)]="ifOpen" clrModalSize="md">
      <h3 class="modal-title">Interface {{ ifForm.index }}</h3>
      <div class="modal-body">
        <form clrForm clrLayout="vertical" id="ifform" (ngSubmit)="saveIf()">
          <clr-input-container>
            <label>Name</label>
            <input clrInput name="name" [(ngModel)]="ifForm.name" placeholder="e.g. Gi0/0/1" maxlength="64" />
          </clr-input-container>
          <clr-input-container>
            <label>Description</label>
            <input clrInput name="description" [(ngModel)]="ifForm.description" placeholder="e.g. Uplink to ISP-A" maxlength="256" />
          </clr-input-container>
          <clr-select-container>
            <label>Speed</label>
            <select clrSelect name="speed" [(ngModel)]="ifForm.speed">
              <option [ngValue]="0">Unknown</option>
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
        <button type="button" class="btn btn-outline" (click)="ifOpen.set(false)">Cancel</button>
        <button type="submit" form="ifform" class="btn btn-primary">Save</button>
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
    .u-pct { width: 42px; text-align: right; margin-right: 8px; }
  `,
})
export class ExporterDetail {
  readonly addr = input.required<string>();
  readonly time = inject(TimeRange);
  readonly auth = inject(Auth);
  private api = inject(Api);
  readonly metrics = METRICS;
  readonly metric = signal<Metric>('bps');

  readonly list = loader(() => ({ a: this.addr(), t: this.time.tick() }), () => this.api.exporters());
  readonly exp = computed(() => this.list.value()?.find((e) => e.addr === this.addr()));
  readonly ifaces = loader(() => this.addr(), (a) => this.api.interfaces(a));
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

  util(b: number, speed: number) {
    return Math.min(100, ((b * 8) / 86400 / speed) * 100);
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
