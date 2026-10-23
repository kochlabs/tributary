import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, Metric, TopRow } from '../core/api';
import { Auth } from '../core/auth';
import { bits, bytes, count, drillFilter, METRICS } from '../core/format';
import { TimeRange } from '../core/time';
import { loader } from '../core/util';
import { Chart } from '../shared/chart';
import { donutOption, timeSeriesOption } from '../shared/options';
import { ConversationTable } from '../shared/conversation-table';
import { RangeBar } from '../shared/range-bar';
import { TopTable } from '../shared/top-table';

interface Panel {
  dim: string;
  title: string;
  col: string;
  hint: string;
  donut?: boolean;
  wide?: boolean;
}

// Panels answer "which of my devices", "which services", "talking to whom":
// all oriented local → remote so download and upload don't split one answer.
const PANELS: Panel[] = [
  { dim: 'conversation', title: $localize`:@@dashboard.panel.conversations:Top Conversations`, col: '', hint: $localize`:@@dashboard.panel.conversationsHint:Who talks to whom, your device first`, wide: true },
  { dim: 'device', title: $localize`:@@dashboard.panel.devices:Top Devices`, col: $localize`:@@dashboard.panel.devicesCol:Device`, hint: $localize`:@@dashboard.panel.devicesHint:By MAC address, both directions` },
  { dim: 'remote_as', title: $localize`:@@dashboard.panel.services:Top Services`, col: $localize`:@@dashboard.panel.servicesCol:Organization`, hint: $localize`:@@dashboard.panel.servicesHint:Remote networks by owner`, donut: true },
  { dim: 'app', title: $localize`:@@dashboard.panel.apps:Applications`, col: $localize`:@@dashboard.panel.appsCol:Protocol / port`, hint: $localize`:@@dashboard.panel.appsHint:Well-known port of the flow` },
  { dim: 'remote_host', title: $localize`:@@dashboard.panel.remoteHosts:Top Remote Hosts`, col: $localize`:@@dashboard.panel.remoteHostsCol:Remote host`, hint: $localize`:@@dashboard.panel.remoteHostsHint:Internet endpoints` },
  { dim: 'remote_country', title: $localize`:@@dashboard.panel.countries:Remote Countries`, col: $localize`:@@dashboard.panel.countriesCol:Country`, hint: $localize`:@@dashboard.panel.countriesHint:Where remote endpoints are` },
];

const SERIES_BY = [
  { id: 'remote_as', label: $localize`:@@dashboard.seriesBy.service:Service` },
  { id: 'device', label: $localize`:@@dashboard.seriesBy.device:Device` },
  { id: 'direction', label: $localize`:@@dashboard.seriesBy.direction:Direction` },
  { id: 'app', label: $localize`:@@dashboard.seriesBy.app:Application` },
];

@Component({
  selector: 'nfa-dashboard',
  imports: [ClarityModule, FormsModule, Chart, TopTable, ConversationTable, RouterLink, RangeBar],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.dashboard">Dashboard</h2>
        <p class="subtitle" i18n="@@dashboard.subtitle">Network traffic overview · {{ time.label() }}</p>
      </div>
      <div class="header-controls">
        <nfa-range-bar />
        <div class="btn-group btn-sm" role="group" aria-label="Metric" i18n-aria-label="@@dashboard.metric">
          @for (m of metrics; track m.id) {
            <button class="btn" [class.btn-primary]="metric() === m.id" [class.btn-outline]="metric() !== m.id" (click)="metric.set(m.id)">{{ m.label }}</button>
          }
        </div>
      </div>
    </div>

    @if (suggest.value(); as sg) {
      @if (sg.transitPct > 30 && sg.suggestions.length && !dismissed()) {
        <div class="alert alert-warning" role="alert">
          <div class="alert-items">
            <div class="alert-item static">
              <div class="alert-icon-wrapper"><cds-icon class="alert-icon" shape="exclamation-triangle"></cds-icon></div>
              <div class="alert-text">
                <ng-container i18n="@@dashboard.transitWarning">{{ sg.transitPct.toFixed(0) }}% of traffic is between addresses the appliance doesn't recognise as yours, so it can't tell downloads from uploads or devices from remote hosts.</ng-container>
                @for (p of sg.suggestions; track p.prefix) {
                  <div class="suggest">
                    <ng-container i18n="@@dashboard.suggestion"><code>{{ p.prefix }}</code> looks like your network ({{ p.hosts }} addresses talking to {{ p.peers }} remote hosts).</ng-container>
                    @if (auth.isAdmin()) {
                      <button class="btn btn-sm btn-link" (click)="addLocal(p.prefix)" i18n="@@dashboard.addPrefix">Add {{ p.prefix }}</button>
                      @if (p.prefix.endsWith('/64')) {
                        <button class="btn btn-sm btn-link" (click)="addLocal(widen(p.prefix, 56))" title="ISPs commonly delegate a /56 and routers assign one /64 per VLAN" i18n-title="@@dashboard.widenHint" i18n="@@dashboard.addWiderPrefix">Add {{ widen(p.prefix, 56) }}</button>
                      }
                    } @else {
                      <ng-container i18n="@@dashboard.askAdminEnrichment">Ask an administrator to add it under Configuration → Local Networks.</ng-container>
                    }
                  </div>
                }
                @if (suggestError()) {
                  <div class="error-text">{{ suggestError() }}</div>
                }
              </div>
              <div class="alert-actions"><button class="btn btn-sm btn-link" (click)="dismissed.set(true)" i18n="@@dashboard.dismiss">Dismiss</button></div>
            </div>
          </div>
        </div>
      }
    }
    @if (summary.error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ summary.error() }}</span></div></div></div>
    }

    <div class="kpis">
      @for (k of kpis(); track k.label) {
        <div class="kpi card">
          <div class="kpi-label"><cds-icon [shape]="k.icon" [attr.direction]="k.dir"></cds-icon> {{ k.label }}</div>
          <div class="kpi-value">{{ k.value }}</div>
          <div class="kpi-sub">{{ k.sub }}</div>
        </div>
      }
    </div>

    <div class="card chart-card">
      <div class="card-header">
        <span>
          <ng-container i18n="Followed by a dropdown (Service, Device, ...)@@dashboard.trafficBy">Traffic by</ng-container>
          <select class="clr-select inline-select" [ngModel]="seriesBy()" (ngModelChange)="seriesBy.set($event)" aria-label="Split traffic by" i18n-aria-label="@@dashboard.splitBy">
            @for (o of seriesOptions; track o.id) {
              <option [value]="o.id">{{ o.label }}</option>
            }
          </select>
        </span>
        <span class="card-hint" i18n="@@dashboard.zoomHint">Drag across the chart to zoom in</span>
      </div>
      <div class="card-block">
        <nfa-chart [option]="seriesOpt()" [loading]="series.loading()" [height]="300" [brushTime]="true" (timeSelect)="time.setCustom($event.from, $event.to)" (chartClick)="seriesClick($event)" />
      </div>
    </div>

    <div class="panels">
      @for (p of panels; track p.dim; let i = $index) {
        <div class="card panel" [class.wide]="p.wide">
          <div class="card-header">
            <span>{{ p.title }} <span class="card-hint">{{ p.hint }}</span></span>
            <a class="card-link" [routerLink]="['/explorer']" [queryParams]="{ groupBy: p.dim, metric: metric() }"><ng-container i18n="@@dashboard.explore">Explore</ng-container> <cds-icon shape="angle" direction="right"></cds-icon></a>
          </div>
          <div class="card-block">
            @let res = tops[i].value();
            @if (tops[i].error()) {
              <div class="error-text">{{ tops[i].error() }}</div>
            } @else if (!res) {
              <div class="center"><span class="spinner spinner-md" i18n="@@dashboard.loading">Loading…</span></div>
            } @else {
              @if (p.donut && res.rows.length) {
                <nfa-chart [option]="donut(res.rows, res.total)" [height]="170" (chartClick)="donutClick(p.dim, $event)" />
              }
              @if (p.dim === 'conversation') {
                <nfa-conversation-table [rows]="res.rows" [metric]="metric()" (drill)="drill(p.dim, $event)" />
              } @else {
                <nfa-top-table [rows]="res.rows" [metric]="metric()" [title]="p.col" (drill)="drill(p.dim, $event)" />
              }
            }
          </div>
        </div>
      }
    </div>
  `,
  styles: `
    .chart-card { margin-top: 12px; }
    .header-controls { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .header-controls .btn-group { margin: 0; }
    .card-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
    .card-hint { font-size: 11px; font-weight: 400; color: var(--cds-alias-typography-color-300); margin-left: 6px; }
    .card-link { font-size: 12px; font-weight: 400; }
    .inline-select { font-weight: 600; margin-left: 4px; }
    .panels { display: grid; grid-template-columns: repeat(auto-fill, minmax(460px, 1fr)); gap: 12px; margin-top: 12px; }
    .panels .card { margin: 0; }
    .panel.wide { grid-column: 1 / -1; }
    .panel .card-block { padding-top: 6px; }
    .center { display: flex; justify-content: center; padding: 40px; }
    .error-text { color: var(--cds-alias-status-danger); padding: 4px 0; }
    .suggest { margin-top: 4px; }
    .suggest .btn { margin: 0 0 0 4px; }
    @media (max-width: 560px) { .panels { grid-template-columns: 1fr; } }
  `,
})
export class Dashboard {
  readonly time = inject(TimeRange);
  readonly auth = inject(Auth);
  private api = inject(Api);
  private router = inject(Router);
  readonly metrics = METRICS;
  readonly panels = PANELS;
  readonly seriesOptions = SERIES_BY;
  readonly metric = signal<Metric>('bps');
  readonly seriesBy = signal('remote_as');
  readonly dismissed = signal(false);
  readonly suggestError = signal('');

  readonly summary = loader(() => this.time.window(), (w) => this.api.summary(w, {}));
  readonly suggest = loader(() => this.time.tick(), () => this.api.localSuggestions());
  readonly series = loader(
    () => ({ w: this.time.window(), m: this.metric(), g: this.seriesBy() }),
    (p) => this.api.timeseries(p.w, {}, p.m, p.g, 8),
  );
  readonly tops = PANELS.map((p) =>
    loader(
      () => ({ w: this.time.window(), m: this.metric() }),
      (q) => this.api.top(q.w, {}, p.dim, q.m, p.wide ? 12 : 8),
    ),
  );

  readonly seriesOpt = computed(() => {
    const s = this.series.value();
    return s ? timeSeriesOption(s) : null;
  });

  readonly kpis = computed(() => {
    const s = this.summary.value();
    const dash = '–';
    return [
      { icon: 'arrow', dir: 'down', label: $localize`:@@dashboard.kpi.download:Download`, value: s ? bits(s.downloadBps) : dash, sub: s ? $localize`:@@dashboard.kpi.peak:peak ${bits(s.peakDownloadBps)}:peak: · ${bytes(s.downloadBytes)}:volume:` : '' },
      { icon: 'arrow', dir: 'up', label: $localize`:@@dashboard.kpi.upload:Upload`, value: s ? bits(s.uploadBps) : dash, sub: s ? $localize`:@@dashboard.kpi.peak:peak ${bits(s.peakUploadBps)}:peak: · ${bytes(s.uploadBytes)}:volume:` : '' },
      { icon: 'storage', label: $localize`:@@dashboard.kpi.volume:Total volume`, value: s ? bytes(s.bytes) : dash, sub: s ? $localize`:@@dashboard.kpi.volumeSub:${count(s.packets)}:packets: packets · avg ${bits(s.avgBps)}:avg:` : '' },
      { icon: 'host', label: $localize`:@@dashboard.kpi.local:Local addresses`, value: s ? count(s.localHosts) : dash, sub: $localize`:@@dashboard.kpi.localSub:active in range` },
      { icon: 'network-globe', label: $localize`:@@dashboard.kpi.remote:Remote hosts`, value: s ? count(s.remoteHosts) : dash, sub: $localize`:@@dashboard.kpi.remoteSub:contacted` },
      { icon: 'list', label: $localize`:@@dashboard.kpi.flows:Flows`, value: s ? count(s.flows) : dash, sub: s ? (s.exporters === 1 ? $localize`:@@dashboard.kpi.exporterOne:${s.exporters}:count: exporter` : $localize`:@@dashboard.kpi.exporterMany:${s.exporters}:count: exporters`) : '' },
    ];
  });

  donut(rows: TopRow[], total: TopRow) {
    return donutOption(rows, total, this.metric());
  }

  drill(dim: string, row: TopRow) {
    const f = drillFilter(dim, row.key);
    if (!f) return;
    const next = dim === 'device' || dim === 'local_host' ? 'remote_as' : dim === 'remote_as' || dim === 'app' ? 'device' : 'app';
    this.router.navigate(['/explorer'], { queryParams: { ...f, groupBy: next, metric: this.metric() } });
  }

  donutClick(dim: string, ev: { data: unknown }) {
    const key = (ev.data as { key?: string })?.key;
    if (key && key !== '__other__') this.drill(dim, { key } as TopRow);
  }

  seriesClick(ev: { seriesId?: string }) {
    if (ev.seriesId && ev.seriesId !== '__other__') this.drill(this.seriesBy(), { key: ev.seriesId } as TopRow);
  }

  widen(prefix: string, bits: number) {
    // Zero the address beyond `bits` (hextet granularity is enough for /56).
    const [addr] = prefix.split('/');
    const full = expand6(addr);
    const keepHextets = Math.floor(bits / 16);
    const rem = bits % 16;
    const out = full.map((h, i) => (i < keepHextets ? h : i === keepHextets && rem ? (parseInt(h, 16) & (0xffff << (16 - rem)) & 0xffff).toString(16) : '0'));
    return compress6(out) + '/' + bits;
  }

  async addLocal(prefix: string) {
    this.suggestError.set('');
    try {
      const st = await this.api.settings();
      if (!st.localNetworks.includes(prefix)) {
        await this.api.saveSettings({ ...st, localNetworks: [...st.localNetworks, prefix] });
      }
      this.time.refresh();
    } catch (e) {
      this.suggestError.set(errorMessage(e));
    }
  }
}

function expand6(a: string): string[] {
  const [head, tail = ''] = a.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const fill = a.includes('::') ? Array(8 - h.length - t.length).fill('0') : [];
  return [...h, ...fill, ...t].map((x) => parseInt(x || '0', 16).toString(16));
}

function compress6(h: string[]): string {
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (h[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && h[j] === '0') j++;
    if (j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  if (bestLen < 2) return h.join(':');
  return h.slice(0, best).join(':') + '::' + h.slice(best + bestLen).join(':');
}
