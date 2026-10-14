import { NgFor } from '@angular/common';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, DeviceInfo, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { ago, bytes, dateTime } from '../core/format';
import { loader } from '../core/util';

const SOURCE_HINT: Record<string, string> = {
  name: 'Named by an administrator',
  dns: 'Reverse DNS of its IPv4 address',
  vendor: 'Manufacturer from the MAC address',
  mac: 'No name known: rename it',
};

@Component({
  selector: 'nfa-devices',
  imports: [ClarityModule, FormsModule, NgFor],
  template: `
    <div class="page-header">
      <div>
        <h2>Devices</h2>
        <p class="subtitle">Local devices identified by MAC address, with every IPv4 and IPv6 address they used</p>
      </div>
      <button class="btn btn-link" (click)="list.reload()"><cds-icon shape="refresh"></cds-icon> Refresh</button>
    </div>

    @if (list.error() || error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() || list.error() }}</span></div></div></div>
    }

    <clr-datagrid class="datagrid-compact" [clrDgLoading]="list.loading() && !list.value()">
      <clr-dg-column [clrDgField]="'name'">Device</clr-dg-column>
      <clr-dg-column [clrDgField]="'mac'">MAC</clr-dg-column>
      <clr-dg-column [clrDgField]="'vendor'">Vendor</clr-dg-column>
      <clr-dg-column>IPv4</clr-dg-column>
      <clr-dg-column>IPv6</clr-dg-column>
      <clr-dg-column [clrDgField]="'bytes24h'" [clrDgSortOrder]="-1">Last 24h</clr-dg-column>
      <clr-dg-column [clrDgField]="'lastSeen'">Last seen</clr-dg-column>

      <clr-dg-row *clrDgItems="let d of list.value() ?? []" [clrDgItem]="d">
        <clr-dg-action-overflow>
          @if (auth.isAdmin()) {
            <button class="action-item" (click)="openRename(d)"><cds-icon shape="pencil"></cds-icon> Rename</button>
          }
          <button class="action-item" (click)="analyze(d)"><cds-icon shape="line-chart"></cds-icon> Analyze traffic</button>
          <button class="action-item" (click)="flows(d)"><cds-icon shape="table"></cds-icon> Show flows</button>
        </clr-dg-action-overflow>
        <clr-dg-cell>
          <a href="#" (click)="$event.preventDefault(); analyze(d)" class="name">{{ d.name }}</a>
          <div class="sub" [title]="hint(d)">{{ hint(d) }}</div>
        </clr-dg-cell>
        <clr-dg-cell class="mono">{{ d.mac }}</clr-dg-cell>
        <clr-dg-cell>
          @if (d.randomized) {
            <span class="label">Private MAC</span>
          } @else {
            {{ d.vendor || '–' }}
          }
        </clr-dg-cell>
        <clr-dg-cell class="mono">{{ d.ipv4.join(', ') || '–' }}</clr-dg-cell>
        <clr-dg-cell [title]="d.ipv6.join('\\n')">{{ d.ipv6.length ? d.ipv6.length + ' address' + (d.ipv6.length === 1 ? '' : 'es') : '–' }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ d.bytes24h ? fmtBytes(d.bytes24h) : '–' }}</clr-dg-cell>
        <clr-dg-cell [title]="dt(d.lastSeen)">{{ ago(d.lastSeen) }}</clr-dg-cell>

        <clr-dg-row-detail *clrIfExpanded>
          <div class="detail">
            <div><span>First seen</span>{{ dt(d.firstSeen) }}</div>
            <div><span>Flows (24h)</span>{{ d.flows24h }}</div>
            <div class="ips">
              <span>Addresses</span>
              <table class="table table-compact table-noborder">
                <tbody>
                  <tr *ngFor="let ip of d.ips"><td class="mono">{{ ip.ip }}</td><td>{{ ago(ip.seen) }}</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </clr-dg-row-detail>
      </clr-dg-row>
      <clr-dg-placeholder>
        No devices yet. Devices are learned from exporters that report MAC addresses (e.g. UniFi gateways, sFlow switches). Make sure your local networks are configured under Settings.
      </clr-dg-placeholder>
      <clr-dg-footer>{{ (list.value() ?? []).length }} devices</clr-dg-footer>
    </clr-datagrid>

    <p class="hint">
      A device is identified by the MAC address its traffic arrives from. Downloads are matched to devices through the addresses they used for uploads, which also groups rotating IPv6 privacy addresses. Phones and laptops often use a <b>private (randomized) MAC</b> per network, so they have no vendor: give them a name.
    </p>

    <clr-modal [clrModalOpen]="!!renaming()" (clrModalOpenChange)="!$event && renaming.set(null)" clrModalSize="md">
      <h3 class="modal-title">Rename device</h3>
      <div class="modal-body">
        <p class="mono">{{ renaming()?.mac }} · {{ renaming()?.vendor || 'unknown vendor' }}</p>
        <form clrForm clrLayout="vertical" id="renameform" (ngSubmit)="saveName()">
          <clr-input-container>
            <label>Name</label>
            <input clrInput name="name" [(ngModel)]="newName" maxlength="64" placeholder="e.g. Living room TV" />
            <clr-control-helper>Leave empty to use the DNS or vendor name again.</clr-control-helper>
          </clr-input-container>
        </form>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="renaming.set(null)">Cancel</button>
        <button type="submit" form="renameform" class="btn btn-primary">Save</button>
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
  private api = inject(Api);
  private router = inject(Router);
  readonly auth = inject(Auth);
  private tick = signal(0);
  readonly list = loader(() => this.tick(), () => this.api.devices());
  readonly renaming = signal<DeviceInfo | null>(null);
  readonly error = signal('');
  newName = '';
  ago = ago;
  dt = dateTime;
  fmtBytes = bytes;

  constructor() {
    const id = setInterval(() => this.tick.update((t) => t + 1), 30_000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
  }

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
