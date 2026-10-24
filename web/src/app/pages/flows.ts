import { NgFor } from '@angular/common';
import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ClarityModule, ClrDatagridStateInterface } from '@clr/angular';
import { Api, Filters, FlowRow } from '../core/api';
import { appPort, bytes, count, dateTime, FILTER_FIELDS, FLOW_TYPES, proto, serviceName, shortTime, tcpFlags } from '../core/format';
import { TimeRange } from '../core/time';
import { ExpandedRows, filtersFromParams, loader, trackByKey } from '../core/util';
import { FilterBar } from '../shared/filter-bar';
import { RangeBar } from '../shared/range-bar';

const FILTER_KEYS = [...FILTER_FIELDS.map((f) => f.id), 'q'];

@Component({
  selector: 'nfa-flows',
  imports: [ClarityModule, FilterBar, NgFor, RangeBar],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.flows">Flow Search</h2>
        <p class="subtitle" i18n="@@flows.subtitle">Individual flow records · {{ time.label() }}</p>
      </div>
      <div class="header-controls">
        <nfa-range-bar />
        <a class="btn btn-sm btn-outline" [href]="csvUrl()" download><cds-icon shape="download"></cds-icon> <ng-container i18n="@@flows.exportCsv">Export CSV</ng-container></a>
      </div>
    </div>

    <div class="card toolbar"><div class="card-block"><nfa-filter-bar [(filters)]="filters" /></div></div>

    @if (page.error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ page.error() }}</span></div></div></div>
    }

    <clr-datagrid class="datagrid-compact flows-grid" (clrDgRefresh)="refresh($event)" [clrDgLoading]="page.loading()">
      <clr-dg-column [clrDgField]="'time'" [clrDgSortOrder]="-1" i18n="@@flows.col.received">Received</clr-dg-column>
      <clr-dg-column i18n="@@flows.col.exporter">Exporter</clr-dg-column>
      <clr-dg-column [clrDgField]="'src'" i18n="@@flows.col.source">Source</clr-dg-column>
      <clr-dg-column [clrDgField]="'dst'" i18n="@@flows.col.destination">Destination</clr-dg-column>
      <clr-dg-column [clrDgField]="'dport'" i18n="@@flows.col.service">Service</clr-dg-column>
      <clr-dg-column [clrDgField]="'bytes'" i18n="@@flows.col.bytes">Bytes</clr-dg-column>
      <clr-dg-column [clrDgField]="'packets'" i18n="@@flows.col.packets">Packets</clr-dg-column>
      <clr-dg-column i18n="@@flows.col.duration">Duration</clr-dg-column>

      <clr-dg-row *ngFor="let f of rows(); trackBy: flowKey" [clrDgItem]="f" [clrDgExpanded]="expanded.has(key(f))" (clrDgExpandedChange)="expanded.set(key(f), $event)">
        <clr-dg-cell class="nowrap" [title]="dt(f.timeReceived)">{{ st(f.timeReceived) }}</clr-dg-cell>
        <clr-dg-cell><a href="#" (click)="$event.preventDefault(); filterOn('exporter', f.exporter)" [title]="f.exporter">{{ f.exporterName || f.exporter }}</a></clr-dg-cell>
        <clr-dg-cell>
          <div class="mono"><a href="#" (click)="$event.preventDefault(); filterOn('host', f.srcAddr)">{{ f.srcAddr }}</a>{{ f.srcPort ? ':' + f.srcPort : '' }}
            @if (f.srcCountry) {<span class="cc" [title]="f.srcAsName || ''">{{ f.srcCountry }}</span>}
            @if (f.srcThreat) {<span class="label label-danger threat" [title]="f.srcThreat">{{ listedLabel }}</span>}</div>
          @if (f.srcHost) {<div class="host" [title]="f.srcHost">{{ f.srcHost }}</div>}
        </clr-dg-cell>
        <clr-dg-cell>
          <div class="mono"><a href="#" (click)="$event.preventDefault(); filterOn('host', f.dstAddr)">{{ f.dstAddr }}</a>{{ f.dstPort ? ':' + f.dstPort : '' }}
            @if (f.dstCountry) {<span class="cc" [title]="f.dstAsName || ''">{{ f.dstCountry }}</span>}
            @if (f.dstThreat) {<span class="label label-danger threat" [title]="f.dstThreat">{{ listedLabel }}</span>}</div>
          @if (f.dstHost) {<div class="host" [title]="f.dstHost">{{ f.dstHost }}</div>}
        </clr-dg-cell>
        <clr-dg-cell class="nowrap">{{ service(f) }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ fmtBytes(f.bytes) }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ fmtCount(f.packets) }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ dur(f) }}</clr-dg-cell>

          <clr-dg-row-detail *clrIfExpanded>
            <div class="detail-grid">
              <div><span i18n="@@flows.detail.flowStart">Flow start</span>{{ dt(f.timeStart) }}</div>
              <div><span i18n="@@flows.detail.flowEnd">Flow end</span>{{ dt(f.timeEnd) }}</div>
              <div><span i18n="@@flows.interfaces">Interfaces (in → out)</span>ifIndex {{ f.inIf }} → {{ f.outIf }}</div>
              <div><span i18n="@@flows.detail.flowProtocol">Flow protocol</span>{{ flowType(f.flowType) }}</div>
              <div><span i18n="@@flows.detail.sampling">Sampling</span>1:{{ f.sampling }}</div>
              <div><span i18n="@@flows.detail.nextHop">Next hop</span>{{ f.nextHop }}</div>
              <div><span i18n="@@flows.detail.sourceHost">Source host</span>{{ f.srcHost || '–' }}</div>
              <div><span i18n="@@flows.detail.destinationHost">Destination host</span>{{ f.dstHost || '–' }}</div>
              <div><span i18n="@@flows.detail.sourceAs">Source AS</span>{{ f.srcAs ? 'AS' + f.srcAs + (f.srcAsName ? ' ' + f.srcAsName : '') : '–' }}</div>
              <div><span i18n="@@flows.detail.destinationAs">Destination AS</span>{{ f.dstAs ? 'AS' + f.dstAs + (f.dstAsName ? ' ' + f.dstAsName : '') : '–' }}</div>
              <div><span i18n="@@flows.detail.deviceMac">Device (MAC)</span>{{ f.deviceMac || '–' }}</div>
              <div><span i18n="@@flows.detail.srcDstMac">Source / destination MAC</span>{{ f.srcMac || '–' }} → {{ f.dstMac || '–' }}</div>
              <div><span i18n="@@flows.detail.sourceCountry">Source country</span>{{ f.srcCountry || '–' }}</div>
              <div><span i18n="@@flows.detail.destinationCountry">Destination country</span>{{ f.dstCountry || '–' }}</div>
              @if (f.srcThreat || f.dstThreat) {
                <div><span i18n="@@flows.detail.threat">Threat feed</span>{{ f.srcThreat || f.dstThreat }} ({{ f.srcThreat ? f.srcAddr : f.dstAddr }})</div>
              }
              <div><span i18n="@@flows.detail.dscpTos">DSCP / ToS</span>{{ dscp(f.tos) }} / 0x{{ f.tos.toString(16) }}</div>
              <div><span i18n="@@flows.detail.vlan">VLAN</span>@if (f.vlan) { {{ f.vlan }} } @else {<ng-container i18n="@@flows.untagged">untagged</ng-container>}</div>
              <div><span i18n="@@flows.detail.tcpFlags">TCP flags</span>{{ f.tcpFlags ? '0x' + f.tcpFlags.toString(16) + ' (' + flags(f.tcpFlags) + ')' : '–' }}</div>
              <div><span i18n="@@flows.detail.avgPacketSize">Avg packet size</span>{{ f.packets ? (f.bytes / f.packets).toFixed(0) + ' B' : '–' }}</div>
            </div>
          </clr-dg-row-detail>
      </clr-dg-row>

      <clr-dg-placeholder i18n="@@flows.placeholder">No flows match the current filters and time range.</clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #pagination [clrDgPageSize]="50" [clrDgTotalItems]="total()">
          <clr-dg-page-size [clrPageSizeOptions]="[25, 50, 100, 250, 500]" i18n="@@flows.perPage">Flows per page</clr-dg-page-size>
          @if (total()) {
            <ng-container i18n="Datagrid footer: first–last of total@@flows.footer">{{ pagination.firstItem + 1 }}–{{ pagination.lastItem + 1 }} of {{ total().toLocaleString() }} flows</ng-container>
          } @else {
            <ng-container i18n="@@flows.empty">No flows</ng-container>
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>
  `,
  styles: `
    .toolbar { margin-top: 0; }
    .header-controls { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .header-controls .btn { margin: 0; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; white-space: nowrap; }
    .nowrap { white-space: nowrap; }
    .cc { display: inline-block; margin-left: 6px; padding: 0 4px; font-size: 10px; line-height: 14px; border-radius: 3px; border: 1px solid var(--cds-alias-object-border-color); color: var(--cds-alias-typography-color-300); font-family: inherit; }
    .threat { margin-left: 6px; font-family: inherit; }
    .host { font-size: 11px; color: var(--cds-alias-typography-color-300); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .flows-grid { margin-top: 12px; }
    .detail-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px 24px; padding: 8px 0; }
    .detail-grid span { display: block; font-size: 11px; color: var(--cds-alias-typography-color-300); text-transform: uppercase; letter-spacing: .03em; }
  `,
})
export class Flows {
  readonly expanded = new ExpandedRows();
  key(f: FlowRow) {
    return `${f.timeReceived}|${f.exporter}|${f.srcAddr}|${f.srcPort}|${f.dstAddr}|${f.dstPort}|${f.proto}|${f.bytes}`;
  }
  readonly flowKey = (_: number, f: FlowRow) => this.key(f);
  readonly time = inject(TimeRange);
  private api = inject(Api);
  private route = inject(ActivatedRoute);
  private router = inject(Router);

  readonly filters = signal<Filters>(filtersFromParams(this.route.snapshot.queryParams as Record<string, string>, FILTER_KEYS));
  private state = signal<{ sort: string; desc: boolean; offset: number; limit: number } | undefined>(undefined);

  readonly page = loader(
    () => {
      const s = this.state();
      return s ? { w: this.time.window(), f: this.filters(), s } : undefined;
    },
    (p) => this.api.flows(p.w, p.f, { sort: p.s.sort, desc: p.s.desc, offset: p.s.offset, limit: p.s.limit }),
  );
  readonly rows = computed<FlowRow[]>(() => this.page.value()?.rows ?? []);
  readonly total = computed(() => this.page.value()?.total ?? 0);
  readonly csvUrl = computed(() => {
    const s = this.state();
    return this.api.flowsCsvUrl(this.time.window(), this.filters(), s?.sort, s?.desc);
  });

  proto = proto;
  flags = tcpFlags;
  dt = dateTime;
  st = shortTime;
  fmtBytes = bytes;
  fmtCount = count;
  readonly listedLabel = $localize`:Badge on an address listed by a threat feed@@flows.listed:listed`;

  constructor() {
    effect(() => {
      const qp: Record<string, string | null> = {};
      for (const k of FILTER_KEYS) qp[k] = this.filters()[k] || null;
      untracked(() => this.router.navigate([], { queryParams: qp, replaceUrl: true }));
    });
  }

  refresh(st: ClrDatagridStateInterface<FlowRow>) {
    const size = st.page?.size ?? 50;
    const current = st.page?.current ?? 1;
    this.state.set({
      sort: (st.sort?.by as string) ?? 'time',
      desc: st.sort ? !!st.sort.reverse : true,
      offset: (current - 1) * size,
      limit: size,
    });
  }

  filterOn(key: string, value: string) {
    this.filters.set({ ...this.filters(), [key]: value });
  }

  service(f: FlowRow) {
    const p = proto(f.proto);
    if (f.proto !== 6 && f.proto !== 17 && f.proto !== 132) return p;
    const port = appPort(f.srcPort, f.dstPort);
    const name = serviceName(port);
    return name ? `${name} (${p.toLowerCase()}/${port})` : `${p.toLowerCase()}/${port}`;
  }

  dscp(tos: number) {
    return tos >> 2;
  }

  flowType(t: number) {
    return FLOW_TYPES[t] ?? $localize`:@@flows.unknown:Unknown`;
  }

  dur(f: FlowRow) {
    const s = Math.max(0, (f.timeEnd - f.timeStart) / 1000);
    return s < 1 ? '<1s' : s < 120 ? `${s.toFixed(0)}s` : `${(s / 60).toFixed(1)}m`;
  }
}
