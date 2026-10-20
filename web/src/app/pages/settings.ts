import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, GeoStatus, Settings, StorageEstimate, StorageRate } from '../core/api';
import { prefixContains, validAddrOrPrefix } from '../core/cidr';
import { bytes, count, dateTime } from '../core/format';

@Component({
  selector: 'nfa-settings',
  imports: [ClarityModule, FormsModule, RouterLink],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.settings">Settings</h2>
        <p class="subtitle" i18n="@@settings.subtitle">Appliance configuration. Changes apply immediately.</p>
      </div>
    </div>

    @if (saved()) {
      <div class="alert alert-success" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text" i18n="@@settings.saved">Settings saved and applied.</span></div></div></div>
    }
    @if (error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
    }

    @if (s(); as s) {
      <form clrForm clrLayout="horizontal" clrLabelSize="4" (ngSubmit)="save()" class="settings-form">
        <div class="card">
          <div class="card-header" i18n="@@settings.general">General</div>
          <div class="card-block">
            <clr-input-container>
              <label i18n="@@settings.applianceName">Appliance name</label>
              <input clrInput name="name" [(ngModel)]="s.applianceName" required maxlength="64" />
              <clr-control-helper i18n="@@settings.applianceNameHelp">Shown in the header and on the sign-in page.</clr-control-helper>
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@settings.sessionLifetime">Session lifetime (hours)</label>
              <input clrInput type="number" name="session" [(ngModel)]="s.sessionHours" min="1" max="720" required />
            </clr-input-container>
          </div>
        </div>

        <div class="card">
          <div class="card-header" i18n="@@settings.flowCollection">Flow collection</div>
          <div class="card-block">
            <p class="hint" i18n="@@settings.flowCollectionHint">Every listener accepts NetFlow v5/v9, IPFIX and sFlow; the ports below match device defaults. Set 0 to disable a listener.</p>
            <clr-input-container>
              <label i18n="@@settings.netflowPort">NetFlow UDP port</label>
              <input clrInput type="number" name="nf" [(ngModel)]="s.netflowPort" min="0" max="65535" />
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@settings.ipfixPort">IPFIX UDP port</label>
              <input clrInput type="number" name="ipfix" [(ngModel)]="s.ipfixPort" min="0" max="65535" />
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@settings.sflowPort">sFlow UDP port</label>
              <input clrInput type="number" name="sflow" [(ngModel)]="s.sflowPort" min="0" max="65535" />
            </clr-input-container>
            <clr-textarea-container>
              <label i18n="@@settings.exporterAllowlist">Allowed exporters</label>
              <textarea clrTextarea name="allowlist" rows="3" [ngModel]="allowText()" (ngModelChange)="allowText.set($event)" placeholder="Empty: accept flows from any source" i18n-placeholder="@@settings.allowlistPlaceholder"></textarea>
              <clr-control-helper i18n="@@settings.allowlistHelp">One IP address or CIDR prefix per line. When set, datagrams from any other source are dropped before decoding and listed on System Health. Leave empty to accept every source.</clr-control-helper>
            </clr-textarea-container>
            <div class="allow-actions">
              <button type="button" class="btn btn-sm btn-link" (click)="addActiveExporters()" i18n="@@settings.addActiveExporters">Add active exporters</button>
              @if (allowInvalid().length) {
                <span class="warn-text" i18n="@@settings.allowlistInvalid">Not an IP address or CIDR prefix: {{ allowInvalid().join(', ') }}</span>
              } @else if (lockedOut().length) {
                <span class="warn-text" i18n="@@settings.allowlistLockout">These exporters sent flows in the last hour and would be dropped: {{ lockedOut().join(', ') }}</span>
              }
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header" i18n="@@settings.dataRetention">Data retention</div>
          <div class="card-block">
            <p class="hint" i18n="@@settings.dataRetentionHint">Raw flows power flow search and host-level reports. The 1-minute rollup keeps interface, exporter and protocol trends for long-range charts at a fraction of the size.</p>
            <clr-input-container>
              <label i18n="@@settings.rawFlowsDays">Raw flows (days)</label>
              <input clrInput type="number" name="raw" [(ngModel)]="s.rawRetentionDays" min="1" max="3650" required />
              @if (rate('flows'); as r) {
                <clr-control-helper i18n="@@settings.rawFlowsEstimate">≈ {{ size(r, s.rawRetentionDays) }} at the current rate ({{ count(r.rowsPerDay) }} flows/day)</clr-control-helper>
              }
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@settings.rollupDays">1-minute rollup (days)</label>
              <input clrInput type="number" name="rollup" [(ngModel)]="s.rollupRetentionDays" min="1" max="3650" required />
              @if (rate('traffic_1m'); as r) {
                <clr-control-helper i18n="@@settings.rollupEstimate">≈ {{ size(r, s.rollupRetentionDays) }} at the current rate</clr-control-helper>
              }
            </clr-input-container>
            @if (storage(); as st) {
              @let total = totalEstimate(s.rawRetentionDays, s.rollupRetentionDays);
              @let budget = st.diskFree + current();
              <div class="estimate" [class.over]="total > budget * 0.75">
                <ng-container i18n="@@settings.totalEstimate">Estimated total <b>{{ fmtBytes(total) }}</b> of {{ fmtBytes(budget) }} available for flow data
                ({{ fmtBytes(st.diskFree) }} free on a {{ fmtBytes(st.diskTotal) }} disk).</ng-container>
                @if (total > budget * 0.75) {
                  <br /><ng-container i18n="@@settings.tooLittleSpace">That leaves too little working space; ClickHouse needs about 25% free to merge data. Lower retention or grow the disk.</ng-container>
                }
                @if (sampleHours() < 24) {
                  <br /><span class="muted" i18n="@@settings.estimateSample">Based on {{ sampleHours().toFixed(1) }} hours of data; the estimate firms up after a full day.</span>
                }
              </div>
            }
          </div>
        </div>

        <div class="card">
          <div class="card-header" i18n="@@settings.enrichment">Enrichment</div>
          <div class="card-block">
            <clr-toggle-container>
              <label i18n="@@settings.reverseDns">Reverse DNS</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="rdns" [(ngModel)]="s.reverseDns" />
                <label i18n="@@settings.reverseDnsToggle">Resolve hostnames for addresses in reports</label>
              </clr-toggle-wrapper>
              <clr-control-helper i18n="@@settings.reverseDnsHelp">Lookups use the appliance's system resolver and are cached for 6 hours. Disable on isolated networks.</clr-control-helper>
            </clr-toggle-container>
            <clr-textarea-container>
              <label i18n="@@settings.localNetworks">Local networks</label>
              <textarea clrTextarea name="localNetworks" rows="3" [ngModel]="localText()" (ngModelChange)="localText.set($event)" placeholder="2001:db8:1234::/56&#10;203.0.113.0/28"></textarea>
              <clr-control-helper i18n="@@settings.localNetworksHelp">One CIDR per line. Your own public ranges (e.g. your ISP-delegated IPv6 prefix). Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) are always local. Local addresses are never geolocated or assigned an AS.</clr-control-helper>
            </clr-textarea-container>
            <clr-textarea-container>
              <label i18n="@@settings.dnsResolvers">DNS resolvers</label>
              <textarea clrTextarea name="dnsServers" rows="2" [ngModel]="dnsText()" (ngModelChange)="dnsText.set($event)" placeholder="Leave empty to use the system resolvers" i18n-placeholder="@@settings.dnsResolversPlaceholder"></textarea>
              <clr-control-helper>
                <ng-container i18n="@@settings.dnsResolversHelp">One IP address per line (optionally <code>:port</code>), tried in order. Used for Tributary's own lookups: reverse DNS, GeoIP downloads and ASN lookups.
                Tip: your router/DHCP server usually knows local device names.</ng-container>
                @if (geo()?.systemDnsServers?.length) {
                  <ng-container i18n="@@settings.systemResolvers">System resolvers: {{ geo()!.systemDnsServers.join(', ') }}.</ng-container>
                }
              </clr-control-helper>
            </clr-textarea-container>
            <clr-toggle-container>
              <label i18n="@@settings.onlineAsn">Online ASN lookup</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="onlineasn" [(ngModel)]="s.onlineAsnLookup" />
                <label i18n="@@settings.onlineAsnToggle">Look up ASNs missing from the local database via RIPEstat</label>
              </clr-toggle-wrapper>
              <clr-control-helper i18n="@@settings.onlineAsnHelp">Queries stat.ripe.net once per /24 (IPv4) or /48 (IPv6) and caches results for 7 days.</clr-control-helper>
            </clr-toggle-container>
            <p class="hint sources">
              <ng-container i18n="@@settings.dataSourcesHint">GeoIP, ASN and MAC vendor databases are chosen under <a routerLink="/admin/data-sources">Data Sources</a>.</ng-container>
              @if (geo(); as g) {
                <ng-container i18n="@@settings.hostnameCache">Hostname cache: {{ g.rdnsCache }} entries.</ng-container>
              }
            </p>
          </div>
        </div>

        <div class="actions">
          <button type="submit" class="btn btn-primary" [clrLoading]="busy()" i18n="@@settings.saveSettings">Save settings</button>
          <button type="button" class="btn btn-outline" (click)="load()" i18n="@@common.revert">Revert</button>
        </div>
      </form>
    }
  `,
  styles: `
    .allow-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin: 4px 0 0; }
    .allow-actions .btn { margin: 0; }
    .warn-text { font-size: 12px; color: var(--cds-alias-status-danger); }
    .settings-form { max-width: 820px; }
    .settings-form .card:first-child { margin-top: 0; }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 0; }
    .actions { margin-top: 16px; }
    .estimate { margin: 16px 0 4px; padding: 10px 12px; font-size: 13px; border-radius: 4px; border: 1px solid var(--cds-alias-object-border-color); background: var(--cds-alias-object-container-background-tint, transparent); }
    .estimate.over { border-color: var(--cds-alias-status-danger); }
    .muted { color: var(--cds-alias-typography-color-300); font-size: 12px; }

    .sources { margin-top: 18px; }
  `,
})
export class SettingsPage {
  private api = inject(Api);
  readonly s = signal<Settings | null>(null);
  readonly busy = signal(false);
  readonly saved = signal(false);
  readonly error = signal('');
  readonly geo = signal<GeoStatus | null>(null);
  readonly storage = signal<StorageEstimate | null>(null);
  fmtBytes = bytes;
  count = count;
  readonly localText = signal('');
  readonly dnsText = signal('');
  readonly allowText = signal('');
  /** Exporters that sent flows in the last hour, to warn before locking them out. */
  readonly activeExporters = signal<string[]>([]);
  private allowEntries = computed(() => this.allowText().split(/[\s,]+/).map((x) => x.trim()).filter(Boolean));
  readonly allowInvalid = computed(() => this.allowEntries().filter((e) => !validAddrOrPrefix(e)));
  readonly lockedOut = computed(() => {
    const list = this.allowEntries();
    if (!list.length) return [];
    return this.activeExporters().filter((a) => !list.some((e) => prefixContains(e, a)));
  });
  dt = dateTime;

  constructor() {
    this.load();
  }

  async load() {
    this.saved.set(false);
    this.error.set('');
    try {
      const st = await this.api.settings();
      this.s.set(st);
      this.localText.set((st.localNetworks ?? []).join('\n'));
      this.dnsText.set((st.dnsServers ?? []).join('\n'));
      this.allowText.set((st.exporterAllowlist ?? []).join('\n'));
      const now = Date.now();
      this.api.exporters({ from: now - 3600e3, to: now }).then((list) => this.activeExporters.set(list.filter((e) => e.flows > 0).map((e) => e.addr)), () => {});
      this.geo.set(await this.api.geo());
      this.storage.set(await this.api.storageEstimate());
    } catch (e) {
      this.error.set(errorMessage(e));
    }
  }

  async save() {
    const cur = this.s();
    if (!cur) return;
    this.busy.set(true);
    this.saved.set(false);
    this.error.set('');
    const n = (v: unknown) => Number(v) || 0;
    try {
      this.s.set(
        await this.api.saveSettings({
          ...cur,
          dnsServers: this.dnsText().split(/[\s,]+/).map((x) => x.trim()).filter(Boolean),
          localNetworks: this.localText().split(/[\s,]+/).map((x) => x.trim()).filter(Boolean),
          exporterAllowlist: this.allowEntries(),
          sessionHours: n(cur.sessionHours),
          netflowPort: n(cur.netflowPort),
          ipfixPort: n(cur.ipfixPort),
          sflowPort: n(cur.sflowPort),
          rawRetentionDays: n(cur.rawRetentionDays),
          rollupRetentionDays: n(cur.rollupRetentionDays),
        }),
      );
      this.saved.set(true);
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  addActiveExporters() {
    const have = this.allowEntries();
    const add = this.activeExporters().filter((a) => !have.some((e) => prefixContains(e, a)));
    this.allowText.set([...have, ...add].join('\n'));
  }

  rate(table: string): StorageRate | undefined {
    const r = this.storage()?.tables.find((t) => t.table === table);
    return r && r.rowsPerDay > 0 ? r : undefined;
  }

  size(r: StorageRate, days: number) {
    return bytes(r.rowsPerDay * r.bytesPerRow * (Number(days) || 0));
  }

  totalEstimate(rawDays: number, rollupDays: number) {
    const raw = this.rate('flows');
    const roll = this.rate('traffic_1m');
    return (raw ? raw.rowsPerDay * raw.bytesPerRow * (Number(rawDays) || 0) : 0) + (roll ? roll.rowsPerDay * roll.bytesPerRow * (Number(rollupDays) || 0) : 0);
  }

  /** Space flow data occupies now; it is reusable under a new retention. */
  current() {
    return (this.storage()?.tables ?? []).reduce((a, t) => a + t.bytesNow, 0);
  }

  sampleHours() {
    return this.rate('flows')?.sampleHours ?? 0;
  }
}
