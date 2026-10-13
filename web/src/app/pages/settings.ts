import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, GeoStatus, Settings } from '../core/api';
import { dateTime } from '../core/format';

@Component({
  selector: 'nfa-settings',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2>Settings</h2>
        <p class="subtitle">Appliance configuration. Changes apply immediately.</p>
      </div>
    </div>

    @if (saved()) {
      <div class="alert alert-success" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">Settings saved and applied.</span></div></div></div>
    }
    @if (error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
    }

    @if (s(); as s) {
      <form clrForm clrLayout="horizontal" clrLabelSize="4" (ngSubmit)="save()" class="settings-form">
        <div class="card">
          <div class="card-header">General</div>
          <div class="card-block">
            <clr-input-container>
              <label>Appliance name</label>
              <input clrInput name="name" [(ngModel)]="s.applianceName" required maxlength="64" />
              <clr-control-helper>Shown in the header and on the sign-in page.</clr-control-helper>
            </clr-input-container>
            <clr-input-container>
              <label>Session lifetime (hours)</label>
              <input clrInput type="number" name="session" [(ngModel)]="s.sessionHours" min="1" max="720" required />
            </clr-input-container>
          </div>
        </div>

        <div class="card">
          <div class="card-header">Flow collection</div>
          <div class="card-block">
            <p class="hint">Every listener accepts NetFlow v5/v9, IPFIX and sFlow; the ports below match device defaults. Set 0 to disable a listener.</p>
            <clr-input-container>
              <label>NetFlow UDP port</label>
              <input clrInput type="number" name="nf" [(ngModel)]="s.netflowPort" min="0" max="65535" />
            </clr-input-container>
            <clr-input-container>
              <label>IPFIX UDP port</label>
              <input clrInput type="number" name="ipfix" [(ngModel)]="s.ipfixPort" min="0" max="65535" />
            </clr-input-container>
            <clr-input-container>
              <label>sFlow UDP port</label>
              <input clrInput type="number" name="sflow" [(ngModel)]="s.sflowPort" min="0" max="65535" />
            </clr-input-container>
          </div>
        </div>

        <div class="card">
          <div class="card-header">Data retention</div>
          <div class="card-block">
            <p class="hint">Raw flows power flow search and host-level reports. The 1-minute rollup keeps interface, exporter and protocol trends for long-range charts at a fraction of the size.</p>
            <clr-input-container>
              <label>Raw flows (days)</label>
              <input clrInput type="number" name="raw" [(ngModel)]="s.rawRetentionDays" min="1" max="3650" required />
            </clr-input-container>
            <clr-input-container>
              <label>1-minute rollup (days)</label>
              <input clrInput type="number" name="rollup" [(ngModel)]="s.rollupRetentionDays" min="1" max="3650" required />
            </clr-input-container>
          </div>
        </div>

        <div class="card">
          <div class="card-header">Enrichment</div>
          <div class="card-block">
            <clr-toggle-container>
              <label>Reverse DNS</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="rdns" [(ngModel)]="s.reverseDns" />
                <label>Resolve hostnames for addresses in reports</label>
              </clr-toggle-wrapper>
              <clr-control-helper>Lookups use the appliance's system resolver and are cached for 6 hours. Disable on isolated networks.</clr-control-helper>
            </clr-toggle-container>
            <clr-textarea-container>
              <label>Local networks</label>
              <textarea clrTextarea name="localNetworks" rows="3" [ngModel]="localText()" (ngModelChange)="localText.set($event)" placeholder="2001:db8:1234::/56&#10;203.0.113.0/28"></textarea>
              <clr-control-helper>One CIDR per line. Your own public ranges (e.g. your ISP-delegated IPv6 prefix). Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) are always local. Local addresses are never geolocated or assigned an AS.</clr-control-helper>
            </clr-textarea-container>
            <clr-textarea-container>
              <label>DNS resolvers</label>
              <textarea clrTextarea name="dnsServers" rows="2" [ngModel]="dnsText()" (ngModelChange)="dnsText.set($event)" placeholder="Leave empty to use the system resolvers"></textarea>
              <clr-control-helper>
                One IP address per line (optionally <code>:port</code>), tried in order. Used for Tributary's own lookups: reverse DNS, GeoIP downloads and ASN lookups.
                Tip: your router/DHCP server usually knows local device names.
                @if (geo()?.systemDnsServers?.length) {
                  System resolvers: {{ geo()!.systemDnsServers.join(', ') }}.
                }
              </clr-control-helper>
            </clr-textarea-container>
            <clr-toggle-container>
              <label>Online ASN lookup</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="onlineasn" [(ngModel)]="s.onlineAsnLookup" />
                <label>Look up ASNs missing from the local database via RIPEstat</label>
              </clr-toggle-wrapper>
              <clr-control-helper>Queries stat.ripe.net once per /24 (IPv4) or /48 (IPv6) and caches results for 7 days.</clr-control-helper>
            </clr-toggle-container>
            <clr-toggle-container>
              <label>GeoIP / ASN updates</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="geoauto" [(ngModel)]="s.geoAutoUpdate" />
                <label>Download DB-IP Lite databases monthly</label>
              </clr-toggle-wrapper>
              <clr-control-helper>For MaxMind GeoLite2/GeoIP2, copy GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb into the appliance's geoip directory; they take precedence.</clr-control-helper>
            </clr-toggle-container>
            @if (geo(); as g) {
              <table class="table table-compact table-noborder geo-table">
                <tbody>
                  <tr><td>Country database</td><td>{{ g.geo.country || 'not installed' }}{{ g.geo.countryBuilt ? ' · built ' + dt(g.geo.countryBuilt) : '' }}</td></tr>
                  <tr><td>ASN database</td><td>{{ g.geo.asn || 'not installed' }}{{ g.geo.asnBuilt ? ' · built ' + dt(g.geo.asnBuilt) : '' }}</td></tr>
                  <tr><td>Last update</td><td>{{ g.geo.lastUpdate || '–' }}</td></tr>
                  <tr><td>Hostname cache</td><td>{{ g.rdnsCache }} entries</td></tr>
                </tbody>
              </table>
              @if (g.geo.attribution) {
                <p class="hint"><a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a> (CC BY 4.0)</p>
              }
            }
            <button type="button" class="btn btn-sm btn-outline" (click)="updateGeo()" [clrLoading]="geoBusy()">Update GeoIP databases now</button>
          </div>
        </div>

        <div class="actions">
          <button type="submit" class="btn btn-primary" [clrLoading]="busy()">Save settings</button>
          <button type="button" class="btn btn-outline" (click)="load()">Revert</button>
        </div>
      </form>
    }
  `,
  styles: `
    .settings-form { max-width: 820px; }
    .settings-form .card:first-child { margin-top: 0; }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 0; }
    .actions { margin-top: 16px; }
    .geo-table { max-width: 640px; margin: 12px 0; }
    .geo-table td { text-align: left; padding: 2px 0; }
    .geo-table td:first-child { width: 180px; color: var(--cds-alias-typography-color-300); }
  `,
})
export class SettingsPage {
  private api = inject(Api);
  readonly s = signal<Settings | null>(null);
  readonly busy = signal(false);
  readonly saved = signal(false);
  readonly error = signal('');
  readonly geo = signal<GeoStatus | null>(null);
  readonly localText = signal('');
  readonly dnsText = signal('');
  readonly geoBusy = signal(false);
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
      this.geo.set(await this.api.geo());
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

  async updateGeo() {
    this.geoBusy.set(true);
    try {
      await this.api.updateGeo();
      // The download runs in the background; poll until it reports a result.
      const before = this.geo()?.geo.lastUpdate;
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const g = await this.api.geo();
        this.geo.set(g);
        if (g.geo.lastUpdate !== before) break;
      }
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.geoBusy.set(false);
    }
  }
}
