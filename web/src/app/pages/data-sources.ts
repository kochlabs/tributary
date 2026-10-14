import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, Enrichment, errorMessage, GeoStatus } from '../core/api';
import { count, dateTime } from '../core/format';

const GEO_SOURCES = [
  { id: 'dbip-lite', label: 'DB-IP Lite (free)', help: 'Country and ASN databases from db-ip.com, downloaded monthly. Free under CC BY 4.0, which requires the attribution shown below.' },
  { id: 'maxmind', label: 'MaxMind account', help: 'GeoLite2 (free with an account) or GeoIP2 (commercial) editions, downloaded with your account ID and license key. Switching to another source deletes the stored key.' },
  { id: 'urls', label: 'Download URLs', help: 'Any MaxMind-format (.mmdb) databases you are licensed for, such as a DB-IP subscription. Plain, .gz and .tar.gz downloads are accepted. Switching to another source deletes the stored URLs.' },
  { id: 'files', label: 'Files on the appliance', help: 'Databases kept up to date by another tool, such as MaxMind geoipupdate. Reloaded automatically when the files change.' },
] as const;

const OUI_SOURCES = [
  { id: 'ieee', label: 'IEEE registry', help: 'The default. Downloads the MA-L, MA-M and MA-S registries from the IEEE Registration Authority weekly: the authoritative, most current source.' },
  { id: 'url', label: 'Download URL', help: 'An IEEE registry CSV (or a Wireshark-format manuf file) from your own mirror, optionally gzipped. Useful when the appliance cannot reach the IEEE.' },
  { id: 'file', label: 'File on the appliance', help: 'An IEEE registry CSV (or a Wireshark-format manuf file), optionally gzipped. Reloaded automatically when it changes.' },
] as const;

@Component({
  selector: 'nfa-data-sources',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2>Data Sources</h2>
        <p class="subtitle">Where IP geolocation, AS and MAC vendor data comes from</p>
      </div>
    </div>

    @if (saved()) {
      <div class="alert alert-success" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">Saved. New sources are loaded in the background.</span></div></div></div>
    }
    @if (error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
    }

    @if (e(); as e) {
      <form clrForm clrLayout="horizontal" clrLabelSize="3" (ngSubmit)="save()" class="ds-form">
        <div class="card">
          <div class="card-header">IP geolocation and AS numbers</div>
          <div class="card-block">
            @if (st(); as g) {
              <table class="table table-compact table-noborder status">
                <tbody>
                  <tr><td>Country database</td><td>{{ g.geo.country || 'not installed' }}@if (g.geo.countryType) { <span class="muted">&nbsp;· {{ g.geo.countryType }}</span> }{{ g.geo.countryBuilt ? ' · built ' + dt(g.geo.countryBuilt) : '' }}@if (g.geo.countryKept) { <span class="label label-warning">previous source, until the new database loads</span> }</td></tr>
                  <tr><td>ASN database</td><td>{{ g.geo.asn || 'not installed' }}@if (g.geo.asnType) { <span class="muted">&nbsp;· {{ g.geo.asnType }}</span> }{{ g.geo.asnBuilt ? ' · built ' + dt(g.geo.asnBuilt) : '' }}@if (g.geo.asnKept) { <span class="label label-warning">previous source, until the new database loads</span> }</td></tr>
                  <tr><td>Last update</td><td [class.bad]="g.geo.lastUpdate.includes('failed')">{{ g.geo.lastUpdate || '–' }}</td></tr>
                </tbody>
              </table>
            }

            <clr-radio-container>
              <label>Source</label>
              @for (o of geoSources; track o.id) {
                <clr-radio-wrapper>
                  <input type="radio" clrRadio name="geoSource" [value]="o.id" [(ngModel)]="e.geoSource" />
                  <label>{{ o.label }}</label>
                </clr-radio-wrapper>
              }
              <clr-control-helper>{{ geoHelp(e.geoSource) }}</clr-control-helper>
            </clr-radio-container>

            @switch (e.geoSource) {
              @case ('maxmind') {
                <clr-input-container>
                  <label>Account ID</label>
                  <input clrInput name="mmAccount" [(ngModel)]="e.maxmindAccountId" autocomplete="off" />
                </clr-input-container>
                <clr-password-container>
                  <label>License key</label>
                  <input clrPassword name="mmKey" [(ngModel)]="licenseKey" autocomplete="new-password" [placeholder]="e.hasLicenseKey ? 'Stored · leave empty to keep' : ''" />
                  <clr-control-helper>Create one under <i>Manage license keys</i> in your MaxMind account. Stored encrypted.</clr-control-helper>
                </clr-password-container>
                <clr-select-container>
                  <label>Country edition</label>
                  <select clrSelect name="mmCountry" [(ngModel)]="e.maxmindCountryEdition">
                    @for (ed of countryEditions; track ed) { <option [value]="ed">{{ ed }}</option> }
                  </select>
                  <clr-control-helper>GeoLite2 editions are free; GeoIP2 editions need a subscription.</clr-control-helper>
                </clr-select-container>
                <clr-select-container>
                  <label>ASN edition</label>
                  <select clrSelect name="mmAsn" [(ngModel)]="e.maxmindAsnEdition">
                    @for (ed of asnEditions; track ed) { <option [value]="ed">{{ ed }}</option> }
                  </select>
                </clr-select-container>
              }
              @case ('urls') {
                <clr-input-container>
                  <label>Country database URL</label>
                  <input clrInput name="cUrl" [(ngModel)]="countryUrl" autocomplete="off" [placeholder]="e.geoCountryHost ? 'Stored (' + e.geoCountryHost + ') · leave empty to keep' : 'https://…'" />
                  <clr-control-helper>Download links often contain a license key, so they are stored encrypted and not shown again.</clr-control-helper>
                </clr-input-container>
                <clr-input-container>
                  <label>ASN database URL</label>
                  <input clrInput name="aUrl" [(ngModel)]="asnUrl" autocomplete="off" [disabled]="clearAsnUrl" [placeholder]="e.geoAsnHost ? 'Stored (' + e.geoAsnHost + ') · leave empty to keep' : 'Optional'" />
                </clr-input-container>
                @if (e.geoAsnHost) {
                  <clr-checkbox-container>
                    <label></label>
                    <clr-checkbox-wrapper>
                      <input type="checkbox" clrCheckbox name="clearAsn" [(ngModel)]="clearAsnUrl" />
                      <label>Remove the stored ASN URL</label>
                    </clr-checkbox-wrapper>
                  </clr-checkbox-container>
                }
              }
              @case ('files') {
                <clr-input-container>
                  <label>Country database file</label>
                  <input clrInput name="cFile" [(ngModel)]="e.geoCountryFile" placeholder="/var/lib/GeoIP/GeoIP2-Country.mmdb" />
                </clr-input-container>
                <clr-input-container>
                  <label>ASN database file</label>
                  <input clrInput name="aFile" [(ngModel)]="e.geoAsnFile" placeholder="/var/lib/GeoIP/GeoLite2-ASN.mmdb (optional)" />
                  <clr-control-helper>Absolute paths readable by the <code>nfa</code> user. Paths under /home are not accessible to the service.</clr-control-helper>
                </clr-input-container>
              }
            }

            @if (st()?.geo?.attributions?.length) {
              <p class="attrib">
                @for (a of st()!.geo.attributions; track a.text) {
                  <span><a [href]="a.url" target="_blank" rel="noopener">{{ a.text }}</a>{{ a.license ? ' (' + a.license + ')' : '' }}</span>
                }
              </p>
            }
            <button type="button" class="btn btn-sm btn-outline" (click)="update('geo')" [clrLoading]="busyGeo()" [disabled]="dirty()" [title]="dirty() ? 'Save your changes first' : ''">{{ e.geoSource === 'files' ? 'Reload now' : 'Update now' }}</button>
          </div>
        </div>

        <div class="card">
          <div class="card-header">MAC address vendors</div>
          <div class="card-block">
            @if (st(); as g) {
              <table class="table table-compact table-noborder status">
                <tbody>
                  <tr><td>Loaded from</td><td>{{ g.vendors.location }}</td></tr>
                  <tr><td>Entries</td><td>{{ fmtCount(g.vendors.entries) }}{{ g.vendors.updated ? ' · updated ' + dt(g.vendors.updated) : '' }}</td></tr>
                  <tr><td>Last update</td><td [class.bad]="g.vendors.lastUpdate.includes('failed')">{{ g.vendors.lastUpdate || '–' }}</td></tr>
                </tbody>
              </table>
            }
            <clr-radio-container>
              <label>Source</label>
              @for (o of ouiSources; track o.id) {
                <clr-radio-wrapper>
                  <input type="radio" clrRadio name="ouiSource" [value]="o.id" [(ngModel)]="e.ouiSource" />
                  <label>{{ o.label }}</label>
                </clr-radio-wrapper>
              }
              <clr-control-helper>{{ ouiHelp(e.ouiSource) }}</clr-control-helper>
            </clr-radio-container>
            @if (e.ouiSource === 'url') {
              <clr-input-container>
                <label>Download URL</label>
                <input clrInput name="ouiUrl" [(ngModel)]="e.ouiUrl" placeholder="https://mirror.example.com/oui.csv" />
              </clr-input-container>
            }
            @if (e.ouiSource === 'file') {
              <clr-input-container>
                <label>File</label>
                <input clrInput name="ouiFile" [(ngModel)]="e.ouiFile" placeholder="/srv/oui/oui.csv" />
                <clr-control-helper>An absolute path readable by the <code>nfa</code> user.</clr-control-helper>
              </clr-input-container>
            }
            @if (savedOui()) {
              <button type="button" class="btn btn-sm btn-outline" (click)="update('oui')" [clrLoading]="busyOui()" [disabled]="dirty()" [title]="dirty() ? 'Save your changes first' : ''">{{ e.ouiSource === 'file' ? 'Reload now' : 'Update now' }}</button>
            }
          </div>
        </div>

        <div class="card">
          <div class="card-header">Updates</div>
          <div class="card-block">
            <clr-toggle-container>
              <label>Automatic updates</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="auto" [(ngModel)]="e.autoUpdate" />
                <label>Keep downloaded databases current</label>
              </clr-toggle-wrapper>
              <clr-control-helper>DB-IP Lite is refreshed monthly; MaxMind, URL and IEEE downloads weekly. Files on the appliance are always reloaded when they change.</clr-control-helper>
            </clr-toggle-container>
          </div>
        </div>

        <div class="actions">
          <button type="submit" class="btn btn-primary" [clrLoading]="busy()" [disabled]="!dirty()">Save</button>
          <button type="button" class="btn btn-outline" (click)="load()" [disabled]="!dirty()">Revert</button>
          @if (error()) {
            <span class="save-error"><cds-icon shape="error-standard"></cds-icon> {{ error() }}</span>
          } @else if (dirty()) {
            <span class="unsaved"><cds-icon shape="exclamation-circle"></cds-icon> Unsaved changes. Saving switches to the selected sources and downloads them right away.</span>
          }
        </div>
      </form>
    }
  `,
  styles: `
    .ds-form { max-width: 880px; }
    .ds-form .card:first-child { margin-top: 0; }
    .status { max-width: 760px; margin: 0 0 8px; }
    .status td { text-align: left; padding: 2px 0; border: 0; }
    .status td:first-child { width: 170px; color: var(--cds-alias-typography-color-300); }
    .muted { color: var(--cds-alias-typography-color-300); }
    .bad { color: var(--cds-alias-status-danger); }
    .attrib { font-size: 12px; color: var(--cds-alias-typography-color-300); margin: 16px 0 8px; }
    .attrib span + span::before { content: ' · '; }
    .actions { margin-top: 16px; display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
    .save-error { font-size: 13px; color: var(--cds-alias-status-danger); margin-left: 8px; }
    .unsaved { font-size: 13px; color: var(--cds-alias-status-warning-shade, #8c5c00); margin-left: 8px; }
  `,
})
export class DataSources {
  private api = inject(Api);
  readonly e = signal<Enrichment | null>(null);
  readonly st = signal<GeoStatus | null>(null);
  readonly busy = signal(false);
  readonly busyGeo = signal(false);
  readonly busyOui = signal(false);
  readonly saved = signal(false);
  readonly error = signal('');
  readonly geoSources = GEO_SOURCES;
  readonly ouiSources = OUI_SOURCES;
  readonly countryEditions = ['GeoLite2-Country', 'GeoLite2-City', 'GeoIP2-Country', 'GeoIP2-City', 'GeoIP2-Enterprise'];
  readonly asnEditions = ['GeoLite2-ASN', 'GeoIP2-ISP'];
  // Write-only fields, kept out of the loaded record.
  licenseKey = '';
  countryUrl = '';
  asnUrl = '';
  clearAsnUrl = false;
  dt = dateTime;
  fmtCount = count;
  // Snapshot of the stored record, to tell unsaved edits apart.
  private savedJson = '';
  readonly savedOui = signal('');

  dirty() {
    const e = this.e();
    return !!e && (JSON.stringify(e) !== this.savedJson || !!this.licenseKey || !!this.countryUrl || !!this.asnUrl || this.clearAsnUrl);
  }

  private setSaved(e: Enrichment) {
    this.e.set(e);
    this.savedJson = JSON.stringify(e);
    this.savedOui.set(e.ouiSource);
  }

  constructor() {
    this.load();
  }

  geoHelp(id: string) {
    return GEO_SOURCES.find((o) => o.id === id)?.help ?? '';
  }

  ouiHelp(id: string) {
    return OUI_SOURCES.find((o) => o.id === id)?.help ?? '';
  }

  async load() {
    this.saved.set(false);
    this.error.set('');
    this.licenseKey = this.countryUrl = this.asnUrl = '';
    this.clearAsnUrl = false;
    try {
      const [e, st] = await Promise.all([this.api.enrichment(), this.api.geo()]);
      this.setSaved(e);
      this.st.set(st);
    } catch (err) {
      this.error.set(errorMessage(err));
    }
  }

  async save() {
    const e = this.e();
    if (!e) return;
    this.busy.set(true);
    this.saved.set(false);
    this.error.set('');
    const before = this.st();
    try {
      // hasLicenseKey and the URL hosts are read-only; the API rejects them.
      const { hasLicenseKey, geoCountryHost, geoAsnHost, ...stored } = e;
      const out = await this.api.saveEnrichment({
        ...stored,
        maxmindLicenseKey: this.licenseKey.trim(),
        geoCountryUrl: this.countryUrl.trim(),
        geoAsnUrl: this.clearAsnUrl ? '' : this.asnUrl.trim(),
        clearGeoAsnUrl: this.clearAsnUrl,
      });
      this.setSaved(out);
      this.licenseKey = this.countryUrl = this.asnUrl = '';
      this.clearAsnUrl = false;
      this.saved.set(true);
      await this.waitForChange(before, 30);
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  async update(which: 'geo' | 'oui') {
    const flag = which === 'geo' ? this.busyGeo : this.busyOui;
    flag.set(true);
    this.error.set('');
    try {
      const before = this.st();
      await (which === 'geo' ? this.api.updateGeo() : this.api.updateVendors());
      await this.waitForChange(before, 90);
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      flag.set(false);
    }
  }

  // Loading and downloads run in the background; poll until the status
  // reports a new result (or give up after a while).
  private async waitForChange(before: GeoStatus | null, seconds: number) {
    for (let i = 0; i < seconds / 2; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const st = await this.api.geo();
      this.st.set(st);
      if (
        st.geo.lastUpdate !== before?.geo.lastUpdate ||
        st.vendors.lastUpdate !== before?.vendors.lastUpdate ||
        st.geo.country !== before?.geo.country ||
        st.vendors.location !== before?.vendors.location
      )
        return;
    }
  }
}
