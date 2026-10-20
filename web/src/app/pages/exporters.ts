import { Component, DestroyRef, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, Exporter } from '../core/api';
import { Auth } from '../core/auth';
import { ago, bits, bytes, count, samplingLabel } from '../core/format';
import { TimeRange } from '../core/time';
import { loader, trackByKey } from '../core/util';
import { RangeBar } from '../shared/range-bar';

@Component({
  selector: 'nfa-exporters',
  imports: [ClarityModule, FormsModule, RouterLink, RangeBar],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.exporters">Exporters</h2>
        <p class="subtitle" i18n="@@exporters.subtitle">Routers, switches and firewalls sending flow data · {{ time.label() }}</p>
      </div>
      <nfa-range-bar />
    </div>

    @if (list.error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ list.error() }}</span></div></div></div>
    }

    <clr-datagrid class="datagrid-compact" [clrDgLoading]="list.loading() && !list.value()">
      <clr-dg-column [clrDgField]="'status'" i18n="@@exporters.col.status">Status</clr-dg-column>
      <clr-dg-column [clrDgField]="'name'" i18n="@@exporters.col.exporter">Exporter</clr-dg-column>
      <clr-dg-column i18n="@@exporters.col.protocol">Protocol</clr-dg-column>
      <clr-dg-column [clrDgSortBy]="byFps" i18n="@@exporters.col.flowsPerSec">Flows/s</clr-dg-column>
      <clr-dg-column [clrDgSortBy]="byBps" i18n="@@exporters.col.throughput">Throughput</clr-dg-column>
      <clr-dg-column i18n="@@exporters.col.sampling">Sampling</clr-dg-column>
      <clr-dg-column i18n="@@exporters.col.templates">Templates</clr-dg-column>
      <clr-dg-column [clrDgSortBy]="byLost" i18n="@@exporters.col.lostErrors">Lost / Errors</clr-dg-column>
      <clr-dg-column [clrDgField]="'bytes'" i18n="@@exporters.col.volume">Volume</clr-dg-column>
      <clr-dg-column i18n="@@exporters.col.lastSeen">Last seen</clr-dg-column>

      <clr-dg-row *clrDgItems="let e of list.value() ?? []; trackBy: byAddr" [clrDgItem]="e">
        <clr-dg-action-overflow>
          <a class="action-item" [routerLink]="['/exporters', e.addr]"><cds-icon shape="details"></cds-icon> <ng-container i18n="@@exporters.details">Details &amp; interfaces</ng-container></a>
          <a class="action-item" [routerLink]="['/explorer']" [queryParams]="{ exporter: e.addr, groupBy: 'in_if' }"><cds-icon shape="line-chart"></cds-icon> <ng-container i18n="@@exporters.analyze">Analyze traffic</ng-container></a>
          @if (auth.isAdmin()) {
            <button class="action-item" (click)="edit(e)"><cds-icon shape="pencil"></cds-icon> <ng-container i18n="@@common.edit">Edit</ng-container></button>
            <button class="action-item" (click)="confirmDelete.set(e)"><cds-icon shape="trash"></cds-icon> <ng-container i18n="@@common.remove">Remove</ng-container></button>
          }
        </clr-dg-action-overflow>
        <clr-dg-cell>
          <span class="badge" [class.badge-success]="e.status === 'active'" [class.badge-warning]="e.status === 'idle'" [class.badge-danger]="e.status === 'stale'" i18n="Exporter status@@exporters.status">{e.status, select, active {active} idle {idle} stale {stale} other {{{ e.status }}}}</span>
        </clr-dg-cell>
        <clr-dg-cell>
          <a [routerLink]="['/exporters', e.addr]" class="exp-name">{{ e.name || e.addr }}</a>
          @if (e.name) {
            <div class="sub mono">{{ e.addr }}</div>
          }
          @if (e.location) {
            <div class="sub">{{ e.location }}</div>
          }
          @if (e.snmp?.sysName) {
            <div class="sub" [title]="e.snmp?.sysDescr ?? ''"><ng-container i18n="@@exporters.snmpSysName">SNMP: {{ e.snmp?.sysName }}</ng-container>@if (e.snmp?.lastError) { <cds-icon shape="error-standard" class="bad-icon" [title]="e.snmp?.lastError ?? ''"></cds-icon>}</div>
          }
        </clr-dg-cell>
        <clr-dg-cell>
          @for (t of e.live?.types ?? []; track t) {
            <span class="label label-light-blue">{{ t }}</span>
          } @empty {
            <span class="sub">–</span>
          }
        </clr-dg-cell>
        <clr-dg-cell class="num">{{ e.live ? e.live.flowsPerSec.toFixed(1) : '–' }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ e.live ? fmtBits(e.live.bitsPerSec) : '–' }}</clr-dg-cell>
        <clr-dg-cell>
          @let sl = sampling(e);
          {{ sl.rate }}
          @if (sl.source) {
            <span class="label" [class.label-orange]="sl.source === 'override' || sl.source === 'remembered'" [title]="sl.hint">{{ sl.sourceLabel }}</span>
          }
        </clr-dg-cell>
        <clr-dg-cell class="num">{{ e.live?.templates ?? '–' }}</clr-dg-cell>
        <clr-dg-cell class="num">
          <span [class.warn]="(e.live?.lost ?? 0) > 0">{{ fmtCount(e.live?.lost ?? 0) }}</span> /
          <span [class.warn]="(e.live?.errors ?? 0) > 0" [title]="e.live?.lastError ?? ''">{{ fmtCount(e.live?.errors ?? 0) }}</span>
        </clr-dg-cell>
        <clr-dg-cell class="num">{{ fmtBytes(e.bytes) }}</clr-dg-cell>
        <clr-dg-cell>{{ ago(e.live?.lastSeen ?? 0) }}</clr-dg-cell>
      </clr-dg-row>

      <clr-dg-placeholder i18n="@@exporters.placeholder">
        No exporters yet. Point your devices' NetFlow/IPFIX export at this appliance on UDP 2055 / 4739, or sFlow on UDP 6343.
      </clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@exporters.footer">{{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} exporters</ng-container>
          } @else {
            <ng-container i18n="@@exporters.empty">No exporters</ng-container>
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <clr-modal [(clrModalOpen)]="editOpen" clrModalSize="md">
      <h3 class="modal-title" i18n="@@exporters.editTitle">Edit exporter {{ form.addr }}</h3>
      <div class="modal-body">
        <form clrForm clrLayout="vertical" id="expform" (ngSubmit)="save()">
          <clr-input-container>
            <label i18n="@@exporters.displayName">Display name</label>
            <input clrInput name="name" [(ngModel)]="form.name" placeholder="e.g. core-rtr-01" i18n-placeholder="@@exporters.namePlaceholder" maxlength="64" />
          </clr-input-container>
          <clr-input-container>
            <label i18n="@@exporters.location">Location</label>
            <input clrInput name="location" [(ngModel)]="form.location" placeholder="e.g. DC1 / Rack 12" i18n-placeholder="@@exporters.locationPlaceholder" maxlength="128" />
          </clr-input-container>
          <clr-textarea-container>
            <label i18n="@@common.description">Description</label>
            <textarea clrTextarea name="description" [(ngModel)]="form.description" rows="2" maxlength="512"></textarea>
          </clr-textarea-container>
          <clr-input-container>
            <label i18n="@@exporters.samplingOverride">Sampling rate override</label>
            <input clrInput type="number" min="0" name="sampling" [(ngModel)]="form.sampling" />
            <clr-control-helper i18n="@@exporters.samplingHelper">0 = use the rate announced by the device. Set N for 1:N sampling when the device doesn't export it.</clr-control-helper>
          </clr-input-container>
        </form>
        @if (formError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ formError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="editOpen.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="submit" form="expform" class="btn btn-primary" i18n="@@common.save">Save</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="!!confirmDelete()" (clrModalOpenChange)="!$event && confirmDelete.set(null)" clrModalSize="sm">
      <h3 class="modal-title" i18n="@@exporters.removeTitle">Remove exporter?</h3>
      <div class="modal-body">
        <p i18n="@@exporters.removeBody">This removes the name and interface labels for <b>{{ confirmDelete()?.name || confirmDelete()?.addr }}</b>. Stored flow data is kept. The exporter reappears if it sends flows again.</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmDelete.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="remove()" i18n="@@common.remove">Remove</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .sub { font-size: 11px; color: var(--cds-alias-typography-color-300); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .exp-name { font-weight: 600; }
    .warn { color: var(--cds-alias-status-danger); font-weight: 600; }
    .bad-icon { color: var(--cds-alias-status-danger); width: 12px; height: 12px; }
  `,
})
export class Exporters {
  readonly byAddr = trackByKey<{ addr: string }>((e) => e.addr);
  private api = inject(Api);
  readonly auth = inject(Auth);
  readonly time = inject(TimeRange);
  // Live counters refresh every 10s; volume follows the selected range.
  private tick = signal(0);
  readonly list = loader(() => ({ w: this.time.window(), t: this.tick() }), (p) => this.api.exporters(p.w));

  readonly editOpen = signal(false);
  readonly confirmDelete = signal<Exporter | null>(null);
  form = { addr: '', name: '', description: '', location: '', sampling: 0 };
  readonly formError = signal('');

  readonly byFps = { compare: (a: Exporter, b: Exporter) => (a.live?.flowsPerSec ?? 0) - (b.live?.flowsPerSec ?? 0) };
  readonly byBps = { compare: (a: Exporter, b: Exporter) => (a.live?.bitsPerSec ?? 0) - (b.live?.bitsPerSec ?? 0) };
  readonly byLost = { compare: (a: Exporter, b: Exporter) => (a.live?.lost ?? 0) - (b.live?.lost ?? 0) };

  ago = ago;
  sampling = (e: Exporter) => samplingLabel(e.sampling, e.live);
  fmtBits = bits;
  fmtBytes = bytes;
  fmtCount = count;

  constructor() {
    const id = setInterval(() => this.tick.update((t) => t + 1), 10_000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
  }

  edit(e: Exporter) {
    this.form = { addr: e.addr, name: e.name, description: e.description, location: e.location, sampling: e.sampling };
    this.formError.set('');
    this.editOpen.set(true);
  }

  async save() {
    try {
      await this.api.updateExporter({ ...this.form, sampling: Number(this.form.sampling) || 0 });
      this.editOpen.set(false);
      this.list.reload();
    } catch (e) {
      this.formError.set(errorMessage(e));
    }
  }

  async remove() {
    const e = this.confirmDelete();
    this.confirmDelete.set(null);
    if (!e) return;
    await this.api.deleteExporter(e.addr);
    this.list.reload();
  }
}
