import { NgFor } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, DeviceInfo, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { ago, bytes, dateTime } from '../core/format';
import { TimeRange } from '../core/time';
import { ExpandedRows, loader, trackByKey } from '../core/util';
import { RangeBar } from '../shared/range-bar';

const SOURCE_HINT: Record<string, string> = {
  name: $localize`:@@devices.sourceName:Named by an administrator`,
  dns: $localize`:@@devices.sourceDns:Reverse DNS of its IPv4 address`,
  vendor: $localize`:@@devices.sourceVendor:Manufacturer from the MAC address`,
  mac: $localize`:@@devices.sourceMac:No name known: rename it`,
};

@Component({
  selector: 'nfa-devices',
  imports: [ClarityModule, FormsModule, NgFor, RangeBar],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.devices">Devices</h2>
        <p class="subtitle" i18n="@@devices.subtitle">Local devices by MAC address, with every address they used · {{ time.label() }}</p>
      </div>
      <nfa-range-bar />
    </div>

    @if (list.error() || error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() || list.error() }}</span></div></div></div>
    }

    <clr-datagrid class="datagrid-compact" [clrDgLoading]="list.loading() && !list.value()">
      <clr-dg-column [clrDgField]="'name'" i18n="@@devices.col.device">Device</clr-dg-column>
      <clr-dg-column [clrDgField]="'mac'" i18n="@@devices.col.mac">MAC</clr-dg-column>
      <clr-dg-column [clrDgField]="'vendor'" i18n="@@devices.col.vendor">Vendor</clr-dg-column>
      <clr-dg-column i18n="@@devices.col.ipv4">IPv4</clr-dg-column>
      <clr-dg-column i18n="@@devices.col.ipv6">IPv6</clr-dg-column>
      <clr-dg-column [clrDgField]="'bytes'" [clrDgSortOrder]="-1" i18n="@@devices.col.traffic">Traffic</clr-dg-column>
      <clr-dg-column [clrDgField]="'lastSeen'" i18n="@@devices.col.lastSeen">Last seen</clr-dg-column>

      <clr-dg-row *clrDgItems="let d of list.value() ?? []; trackBy: byMac" [clrDgItem]="d" [clrDgExpanded]="expanded.has(d.mac)" (clrDgExpandedChange)="expanded.set(d.mac, $event)">
        <clr-dg-action-overflow>
          @if (auth.isAdmin()) {
            <button class="action-item" (click)="openRename(d)"><cds-icon shape="pencil"></cds-icon> <ng-container i18n="@@devices.rename">Rename</ng-container></button>
          }
          <button class="action-item" (click)="analyze(d)"><cds-icon shape="line-chart"></cds-icon> <ng-container i18n="@@devices.analyze">Analyze traffic</ng-container></button>
          <button class="action-item" (click)="flows(d)"><cds-icon shape="table"></cds-icon> <ng-container i18n="@@devices.showFlows">Show flows</ng-container></button>
        </clr-dg-action-overflow>
        <clr-dg-cell>
          <a href="#" (click)="$event.preventDefault(); analyze(d)" class="name">{{ d.name }}</a>
          <div class="sub" [title]="hint(d)">{{ hint(d) }}</div>
        </clr-dg-cell>
        <clr-dg-cell class="mono">{{ d.mac }}</clr-dg-cell>
        <clr-dg-cell>
          @if (d.randomized) {
            <span class="label" i18n="@@devices.privateMac">Private MAC</span>
          } @else {
            {{ d.vendor || '–' }}
          }
        </clr-dg-cell>
        <clr-dg-cell class="mono">{{ d.ipv4.join(', ') || '–' }}</clr-dg-cell>
        <clr-dg-cell [title]="d.ipv6.join('\\n')">@if (d.ipv6.length) {<ng-container i18n="@@devices.ipv6Count">{d.ipv6.length, plural, =1 {1 address} other {{{ d.ipv6.length }} addresses}}</ng-container>} @else {–}</clr-dg-cell>
        <clr-dg-cell class="num">{{ d.bytes ? fmtBytes(d.bytes) : '–' }}</clr-dg-cell>
        <clr-dg-cell [title]="dt(d.lastSeen)">{{ ago(d.lastSeen) }}</clr-dg-cell>

        <clr-dg-row-detail *clrIfExpanded>
          <div class="detail">
            <div><span i18n="@@devices.firstSeen">First seen</span>{{ dt(d.firstSeen) }}</div>
            <div><span i18n="@@devices.flowsInRange">Flows in range</span>{{ d.flows.toLocaleString() }}</div>
            <div class="ips">
              <span i18n="@@devices.addresses">Addresses</span>
              <table class="table table-compact table-noborder">
                <tbody>
                  <tr *ngFor="let ip of d.ips"><td class="mono">{{ ip.ip }}</td><td>{{ ago(ip.seen) }}</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </clr-dg-row-detail>
      </clr-dg-row>
      <clr-dg-placeholder i18n="@@devices.placeholderEnrichment">
        No devices yet. Devices are learned from exporters that report MAC addresses (e.g. UniFi gateways, sFlow switches). Make sure your local networks are set under Configuration → Local Networks.
      </clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@devices.footer">{{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} devices</ng-container>
          } @else {
            <ng-container i18n="@@devices.empty">No devices</ng-container>
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <p class="hint" i18n="@@devices.hint">
      A device is identified by the MAC address its traffic arrives from. Downloads are matched to devices through the addresses they used for uploads, which also groups rotating IPv6 privacy addresses. Phones and laptops often use a <b>private (randomized) MAC</b> per network, so they have no vendor: give them a name.
    </p>

    <clr-modal [clrModalOpen]="!!renaming()" (clrModalOpenChange)="!$event && renaming.set(null)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@devices.renameTitle">Rename device</h3>
      <div class="modal-body">
        <p class="mono">{{ renaming()?.mac }} · @if (renaming()?.vendor) { {{ renaming()?.vendor }} } @else {<ng-container i18n="@@devices.unknownVendor">unknown vendor</ng-container>}</p>
        <form clrForm clrLayout="vertical" id="renameform" (ngSubmit)="saveName()">
          <clr-input-container>
            <label i18n="@@common.name">Name</label>
            <input clrInput name="name" [(ngModel)]="newName" maxlength="64" placeholder="e.g. Living room TV" i18n-placeholder="@@devices.namePlaceholder" />
            <clr-control-helper i18n="@@devices.nameHelper">Leave empty to use the DNS or vendor name again.</clr-control-helper>
          </clr-input-container>
        </form>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="renaming.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="submit" form="renameform" class="btn btn-primary" i18n="@@common.save">Save</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .name { font-weight: 600; }
    .sub { font-size: 11px; color: var(--cds-alias-typography-color-300); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 12px; }
    .detail { display: grid; grid-template-columns: 200px 140px 1fr; gap: 16px; padding: 6px 0; }
    .detail span { display: block; font-size: 11px; color: var(--cds-alias-typography-color-300); text-transform: uppercase; }
    .detail table { margin: 0; max-width: 560px; }
    .detail td { padding: 1px 12px 1px 0; text-align: left; }
  `,
})
export class Devices {
  readonly byMac = trackByKey<DeviceInfo>((d) => d.mac);
  readonly expanded = new ExpandedRows();
  private api = inject(Api);
  private router = inject(Router);
  readonly auth = inject(Auth);
  readonly time = inject(TimeRange);
  readonly list = loader(() => this.time.window(), (w) => this.api.devices(w));
  readonly renaming = signal<DeviceInfo | null>(null);
  readonly error = signal('');
  newName = '';
  ago = ago;
  dt = dateTime;
  fmtBytes = bytes;

  hint(d: DeviceInfo) {
    return SOURCE_HINT[d.nameSource] ?? '';
  }

  openRename(d: DeviceInfo) {
    this.newName = d.customName;
    this.renaming.set(d);
  }

  async saveName() {
    const d = this.renaming();
    if (!d) return;
    try {
      await this.api.renameDevice(d.mac, this.newName);
      this.renaming.set(null);
      this.error.set('');
      this.list.reload();
    } catch (e) {
      this.error.set(errorMessage(e));
    }
  }

  analyze(d: DeviceInfo) {
    this.router.navigate(['/explorer'], { queryParams: { device: d.mac, groupBy: 'remote_as' } });
  }

  flows(d: DeviceInfo) {
    this.router.navigate(['/flows'], { queryParams: { device: d.mac } });
  }
}
