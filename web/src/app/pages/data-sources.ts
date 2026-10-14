import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, Enrichment, errorMessage, GeoStatus } from '../core/api';
import { count, dateTime } from '../core/format';

const GEO_SOURCES = [
  { id: 'dbip-lite', label: $localize`:@@dataSources.geo.dbipLabel:DB-IP Lite (free)`, help: $localize`:@@dataSources.geo.dbipHelp:Country and ASN databases from db-ip.com, downloaded monthly. Free under CC BY 4.0, which requires the attribution shown below.` },
  { id: 'maxmind', label: $localize`:@@dataSources.geo.maxmindLabel:MaxMind account`, help: $localize`:@@dataSources.geo.maxmindHelp:GeoLite2 (free with an account) or GeoIP2 (commercial) editions, downloaded with your account ID and license key. Switching to another source deletes the stored key.` },
  { id: 'urls', label: $localize`:@@dataSources.geo.urlsLabel:Download URLs`, help: $localize`:@@dataSources.geo.urlsHelp:Any MaxMind-format (.mmdb) databases you are licensed for, such as a DB-IP subscription. Plain, .gz and .tar.gz downloads are accepted. Switching to another source deletes the stored URLs.` },
  { id: 'files', label: $localize`:@@dataSources.geo.filesLabel:Files on the appliance`, help: $localize`:@@dataSources.geo.filesHelp:Databases kept up to date by another tool, such as MaxMind geoipupdate. Reloaded automatically when the files change.` },
] as const;

const OUI_SOURCES = [
  { id: 'ieee', label: $localize`:@@dataSources.oui.ieeeLabel:IEEE registry`, help: $localize`:@@dataSources.oui.ieeeHelp:The default. Downloads the MA-L, MA-M and MA-S registries from the IEEE Registration Authority weekly: the authoritative, most current source.` },
  { id: 'url', label: $localize`:@@dataSources.downloadUrl:Download URL`, help: $localize`:@@dataSources.oui.urlHelp:An IEEE registry CSV (or a Wireshark-format manuf file) from your own mirror, optionally gzipped. Useful when the appliance cannot reach the IEEE.` },
  { id: 'file', label: $localize`:@@dataSources.oui.fileLabel:File on the appliance`, help: $localize`:@@dataSources.oui.fileHelp:An IEEE registry CSV (or a Wireshark-format manuf file), optionally gzipped. Reloaded automatically when it changes.` },
] as const;

@Component({
  selector: 'nfa-data-sources',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.dataSources">Data Sources</h2>
        <p class="subtitle" i18n="@@dataSources.subtitle">Where IP geolocation, AS and MAC vendor data comes from</p>
      </div>
    </div>

    @if (saved()) {
      <div class="alert alert-success" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text" i18n="@@dataSources.saved">Saved. New sources are loaded in the background.</span></div></div></div>
    }
    @if (error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
    }

    @if (e(); as e) {
      <form clrForm clrLayout="horizontal" clrLabelSize="3" (ngSubmit)="save()" class="ds-form">
        <div class="card">
          <div class="card-header" i18n="@@dataSources.geoTitle">IP geolocation and AS numbers</div>
          <div class="card-block">
            @if (st(); as g) {
              <table class="table table-compact table-noborder status">
                <tbody>
                  <tr><td i18n="@@dataSources.countryDatabase">Country database</td><td>@if (g.geo.country) {<ng-container>{{ g.geo.country }}</ng-container>} @else {<ng-container i18n="@@dataSources.notInstalled">not installed</ng-container>}@if (g.geo.countryType) { <span class="muted">&nbsp;· {{ g.geo.countryType }}</span> }@if (g.geo.countryBuilt) {<ng-container i18n="@@dataSources.built"> · built {{ dt(g.geo.countryBuilt) }}</ng-container>}@if (g.geo.countryKept) { <span class="label label-warning" i18n="@@dataSources.previousSource">previous source, until the new database loads</span> }</td></tr>
                  <tr><td i18n="@@dataSources.asnDatabase">ASN database</td><td>@if (g.geo.asn) {<ng-container>{{ g.geo.asn }}</ng-container>} @else {<ng-container i18n="@@dataSources.notInstalled">not installed</ng-container>}@if (g.geo.asnType) { <span class="muted">&nbsp;· {{ g.geo.asnType }}</span> }@if (g.geo.asnBuilt) {<ng-container i18n="@@dataSources.built"> · built {{ dt(g.geo.asnBuilt) }}</ng-container>}@if (g.geo.asnKept) { <span class="label label-warning" i18n="@@dataSources.previousSource">previous source, until the new database loads</span> }</td></tr>
                  <tr><td i18n="@@dataSources.lastUpdate">Last update</td><td [class.bad]="g.geo.lastUpdate.includes('failed')">{{ g.geo.lastUpdate || '–' }}</td></tr>
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
                  <label i18n="@@dataSources.accountId">Account ID</label>
                  <input clrInput name="mmAccount" [(ngModel)]="e.maxmindAccountId" autocomplete="off" />
                </clr-input-container>
                <clr-password-container>
                  <label i18n="@@dataSources.licenseKey">License key</label>
                  <input clrPassword name="mmKey" [(ngModel)]="licenseKey" autocomplete="new-password" [placeholder]="e.hasLicenseKey ? storedKeep : ''" />
                  <clr-control-helper i18n="@@dataSources.licenseKeyHelp">Create one under <i>Manage license keys</i> in your MaxMind account. Stored encrypted.</clr-control-helper>
                </clr-password-container>
                <clr-select-container>
                  <label i18n="@@dataSources.countryEdition">Country edition</label>
                  <select clrSelect name="mmCountry" [(ngModel)]="e.maxmindCountryEdition">
                    @for (ed of countryEditions; track ed) { <option [value]="ed">{{ ed }}</option> }
                  </select>
                  <clr-control-helper i18n="@@dataSources.editionHelp">GeoLite2 editions are free; GeoIP2 editions need a subscription.</clr-control-helper>
                </clr-select-container>
                <clr-select-container>
                  <label i18n="@@dataSources.asnEdition">ASN edition</label>
                  <select clrSelect name="mmAsn" [(ngModel)]="e.maxmindAsnEdition">
                    @for (ed of asnEditions; track ed) { <option [value]="ed">{{ ed }}</option> }
                  </select>
                </clr-select-container>
              }
              @case ('urls') {
                <clr-input-container>
                  <label i18n="@@dataSources.countryUrl">Country database URL</label>
                  <input clrInput name="cUrl" [(ngModel)]="countryUrl" autocomplete="off" [placeholder]="e.geoCountryHost ? storedHost(e.geoCountryHost) : 'https://…'" />
                  <clr-control-helper i18n="@@dataSources.urlHelp">Download links often contain a license key, so they are stored encrypted and not shown again.</clr-control-helper>
                </clr-input-container>
                <clr-input-container>
                  <label i18n="@@dataSources.asnUrl">ASN database URL</label>
                  <input clrInput name="aUrl" [(ngModel)]="asnUrl" autocomplete="off" [disabled]="clearAsnUrl" [placeholder]="e.geoAsnHost ? storedHost(e.geoAsnHost) : optional" />
                </clr-input-container>
                @if (e.geoAsnHost) {
                  <clr-checkbox-container>
                    <label></label>
                    <clr-checkbox-wrapper>
                      <input type="checkbox" clrCheckbox name="clearAsn" [(ngModel)]="clearAsnUrl" />
                      <label i18n="@@dataSources.removeAsnUrl">Remove the stored ASN URL</label>
                    </clr-checkbox-wrapper>
                  </clr-checkbox-container>
                }
              }
              @case ('files') {
                <clr-input-container>
                  <label i18n="@@dataSources.countryFile">Country database file</label>
                  <input clrInput name="cFile" [(ngModel)]="e.geoCountryFile" placeholder="/var/lib/GeoIP/GeoIP2-Country.mmdb" />
                </clr-input-container>
                <clr-input-container>
                  <label i18n="@@dataSources.asnFile">ASN database file</label>
                  <input clrInput name="aFile" [(ngModel)]="e.geoAsnFile" placeholder="/var/lib/GeoIP/GeoLite2-ASN.mmdb (optional)" i18n-placeholder="@@dataSources.asnFilePlaceholder" />
                  <clr-control-helper i18n="@@dataSources.filesHelp">Absolute paths readable by the <code>nfa</code> user. Paths under /home are not accessible to the service.</clr-control-helper>
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
            <button type="button" class="btn btn-sm btn-outline" (click)="update('geo')" [clrLoading]="busyGeo()" [disabled]="dirty()" [title]="dirty() ? saveFirst : ''">@if (e.geoSource === 'files') {<ng-container i18n="@@dataSources.reloadNow">Reload now</ng-container>} @else {<ng-container i18n="@@dataSources.updateNow">Update now</ng-container>}</button>
          </div>
        </div>

        <div class="card">
          <div class="card-header" i18n="@@dataSources.vendorsTitle">MAC address vendors</div>
          <div class="card-block">
            @if (st(); as g) {
              <table class="table table-compact table-noborder status">
                <tbody>
                  <tr><td i18n="@@dataSources.loadedFrom">Loaded from</td><td>{{ g.vendors.location }}</td></tr>
                  <tr><td i18n="@@dataSources.entries">Entries</td><td>{{ fmtCount(g.vendors.entries) }}@if (g.vendors.updated) {<ng-container i18n="@@dataSources.updated"> · updated {{ dt(g.vendors.updated) }}</ng-container>}</td></tr>
                  <tr><td i18n="@@dataSources.lastUpdate">Last update</td><td [class.bad]="g.vendors.lastUpdate.includes('failed')">{{ g.vendors.lastUpdate || '–' }}</td></tr>
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
                <label i18n="@@dataSources.downloadUrl">Download URL</label>
                <input clrInput name="ouiUrl" [(ngModel)]="e.ouiUrl" placeholder="https://mirror.example.com/oui.csv" />
              </clr-input-container>
            }
            @if (e.ouiSource === 'file') {
              <clr-input-container>
                <label i18n="@@dataSources.file">File</label>
                <input clrInput name="ouiFile" [(ngModel)]="e.ouiFile" placeholder="/srv/oui/oui.csv" />
                <clr-control-helper i18n="@@dataSources.fileHelp">An absolute path readable by the <code>nfa</code> user.</clr-control-helper>
              </clr-input-container>
            }
            @if (savedOui()) {
              <button type="button" class="btn btn-sm btn-outline" (click)="update('oui')" [clrLoading]="busyOui()" [disabled]="dirty()" [title]="dirty() ? saveFirst : ''">@if (e.ouiSource === 'file') {<ng-container i18n="@@dataSources.reloadNow">Reload now</ng-container>} @else {<ng-container i18n="@@dataSources.updateNow">Update now</ng-container>}</button>
            }
          </div>
        </div>

        <div class="card">
          <div class="card-header" i18n="@@dataSources.updates">Updates</div>
          <div class="card-block">
            <clr-toggle-container>
              <label i18n="@@dataSources.autoUpdate">Automatic updates</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="auto" [(ngModel)]="e.autoUpdate" />
                <label i18n="@@dataSources.autoUpdateToggle">Keep downloaded databases current</label>
              </clr-toggle-wrapper>
              <clr-control-helper i18n="@@dataSources.autoUpdateHelp">DB-IP Lite is refreshed monthly; MaxMind, URL and IEEE downloads weekly. Files on the appliance are always reloaded when they change.</clr-control-helper>
            </clr-toggle-container>
          </div>
        </div>

        <div class="actions">
          <button type="submit" class="btn btn-primary" [clrLoading]="busy()" [disabled]="!dirty()" i18n="@@common.save">Save</button>
          <button type="button" class="btn btn-outline" (click)="load()" [disabled]="!dirty()" i18n="@@common.revert">Revert</button>
          @if (error()) {
            <span class="save-error"><cds-icon shape="error-standard"></cds-icon> {{ error() }}</span>
          } @else if (dirty()) {
            <span class="unsaved"><cds-icon shape="exclamation-triangle"></cds-icon> <ng-container i18n="@@dataSources.unsaved">Unsaved changes. Saving switches to the selected sources and downloads them right away.</ng-container></span>
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
  readonly storedKeep = $localize`:@@dataSources.storedKeep:Stored · leave empty to keep`;
  readonly optional = $localize`:@@dataSources.optional:Optional`;
  readonly saveFirst = $localize`:@@dataSources.saveFirst:Save your changes first`;
  storedHost(host: string) {
    return $localize`:@@dataSources.storedHost:Stored (${host}:host:) · leave empty to keep`;
  }
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
