import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, Enrichment, errorMessage, GeoStatus, Settings } from '../core/api';
import { validAddrPort } from '../core/cidr';
import { count, dateTime } from '../core/format';
import { ListEditor, listValues } from '../shared/list-editor';

const GEO_SOURCES = [
  {
    id: 'dbip-lite',
    label: $localize`:@@dataSources.geo.dbipLabel:DB-IP Lite (free)`,
    help: $localize`:@@dataSources.geo.dbipHelp:Country and ASN databases from db-ip.com, downloaded monthly. Free under CC BY 4.0, which requires the attribution shown below.`,
  },
  {
    id: 'maxmind',
    label: $localize`:@@dataSources.geo.maxmindLabel:MaxMind account`,
    help: $localize`:@@dataSources.geo.maxmindHelp:GeoLite2 (free with an account) or GeoIP2 (commercial) editions, downloaded with your account ID and license key. Switching to another source deletes the stored key.`,
  },
  {
    id: 'urls',
    label: $localize`:@@dataSources.geo.urlsLabel:Download URLs`,
    help: $localize`:@@dataSources.geo.urlsHelp:Any MaxMind-format (.mmdb) databases you are licensed for, such as a DB-IP subscription. Plain, .gz and .tar.gz downloads are accepted. Switching to another source deletes the stored URLs.`,
  },
  {
    id: 'files',
    label: $localize`:@@dataSources.geo.filesLabel:Files on the appliance`,
    help: $localize`:@@dataSources.geo.filesHelp:Databases kept up to date by another tool, such as MaxMind geoipupdate. Reloaded automatically when the files change.`,
  },
] as const;

const OUI_SOURCES = [
  {
    id: 'ieee',
    label: $localize`:@@dataSources.oui.ieeeLabel:IEEE registry`,
    help: $localize`:@@dataSources.oui.ieeeHelp:The default. Downloads the MA-L, MA-M and MA-S registries from the IEEE Registration Authority weekly: the authoritative, most current source.`,
  },
  {
    id: 'url',
    label: $localize`:@@dataSources.downloadUrl:Download URL`,
    help: $localize`:@@dataSources.oui.urlHelp:An IEEE registry CSV (or a Wireshark-format manuf file) from your own mirror, optionally gzipped. Useful when the appliance cannot reach the IEEE.`,
  },
  {
    id: 'file',
    label: $localize`:@@dataSources.oui.fileLabel:File on the appliance`,
    help: $localize`:@@dataSources.oui.fileHelp:An IEEE registry CSV (or a Wireshark-format manuf file), optionally gzipped. Reloaded automatically when it changes.`,
  },
] as const;

type Tab = 'geo' | 'hostnames' | 'vendors';
const TABS: Tab[] = ['geo', 'hostnames', 'vendors'];

// The Enrichment fields each tab edits (autoUpdate applies to both downloads).
const GEO_KEYS = [
  'geoSource',
  'maxmindAccountId',
  'maxmindCountryEdition',
  'maxmindAsnEdition',
  'geoCountryFile',
  'geoAsnFile',
  'autoUpdate',
] as const;
const OUI_KEYS = ['ouiSource', 'ouiUrl', 'ouiFile', 'autoUpdate'] as const;

function pick<T extends object, K extends keyof T>(o: T, keys: readonly K[]): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const k of keys) out[k] = o[k];
  return out;
}

@Component({
  selector: 'nfa-enrichment',
  imports: [ClarityModule, FormsModule, ListEditor],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.enrichment">Enrichment</h2>
        <p class="subtitle" i18n="@@enrichment.subtitle2">
          Geolocation, AS numbers, hostnames and MAC vendors
        </p>
      </div>
    </div>

    @if (saved()) {
      <div class="alert alert-success" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text">
              @if (saved() === 'sources') {
                <ng-container i18n="@@dataSources.saved"
                  >Saved. New sources are loaded in the background.</ng-container
                >
              } @else {
                <ng-container i18n="@@enrichment.saved">Saved and applied.</ng-container>
              }
            </span>
          </div>
        </div>
      </div>
    }
    @if (error()) {
      <div class="alert alert-danger" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text">{{ error() }}</span>
          </div>
        </div>
      </div>
    }

    @if (e(); as e) {
      <clr-tabs>
        <clr-tab>
          <button clrTabLink (click)="setTab('geo')">
            <ng-container i18n="@@enrichment.tab.geo">Geolocation &amp; ASN</ng-container>
            @if (geoDirty()) {
              <span class="dot" title="Unsaved changes" i18n-title="@@enrichment.unsavedTab"
                >•</span
              >
            }
          </button>
          <clr-tab-content *clrIfActive="tab() === 'geo'">
            <form
              clrForm
              clrLayout="horizontal"
              clrLabelSize="3"
              (ngSubmit)="saveGeo()"
              class="ds-form"
            >
              @if (st(); as g) {
                <table class="table table-compact table-noborder status">
                  <tbody>
                    <tr>
                      <td i18n="@@dataSources.countryDatabase">Country database</td>
                      <td>
                        @if (g.geo.country) {
                          <ng-container>{{ g.geo.country }}</ng-container>
                        } @else {
                          <ng-container i18n="@@dataSources.notInstalled"
                            >not installed</ng-container
                          >
                        }
                        @if (g.geo.countryType) {
                          <span class="muted">&nbsp;· {{ g.geo.countryType }}</span>
                        }
                        @if (g.geo.countryBuilt) {
                          <ng-container i18n="@@dataSources.built">
                            · built {{ dt(g.geo.countryBuilt) }}</ng-container
                          >
                        }
                        @if (g.geo.countryKept) {
                          <span class="label label-warning" i18n="@@dataSources.previousSource"
                            >previous source, until the new database loads</span
                          >
                        }
                      </td>
                    </tr>
                    <tr>
                      <td i18n="@@dataSources.asnDatabase">ASN database</td>
                      <td>
                        @if (g.geo.asn) {
                          <ng-container>{{ g.geo.asn }}</ng-container>
                        } @else {
                          <ng-container i18n="@@dataSources.notInstalled"
                            >not installed</ng-container
                          >
                        }
                        @if (g.geo.asnType) {
                          <span class="muted">&nbsp;· {{ g.geo.asnType }}</span>
                        }
                        @if (g.geo.asnBuilt) {
                          <ng-container i18n="@@dataSources.built">
                            · built {{ dt(g.geo.asnBuilt) }}</ng-container
                          >
                        }
                        @if (g.geo.asnKept) {
                          <span class="label label-warning" i18n="@@dataSources.previousSource"
                            >previous source, until the new database loads</span
                          >
                        }
                      </td>
                    </tr>
                    <tr>
                      <td i18n="@@dataSources.lastUpdate">Last update</td>
                      <td [class.bad]="g.geo.lastUpdate.includes('failed')">
                        {{ g.geo.lastUpdate || '–' }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              }

              <clr-radio-container>
                <label>Source</label>
                @for (o of geoSources; track o.id) {
                  <clr-radio-wrapper>
                    <input
                      type="radio"
                      clrRadio
                      name="geoSource"
                      [value]="o.id"
                      [(ngModel)]="e.geoSource"
                    />
                    <label>{{ o.label }}</label>
                  </clr-radio-wrapper>
                }
                <clr-control-helper>{{ geoHelp(e.geoSource) }}</clr-control-helper>
              </clr-radio-container>

              @switch (e.geoSource) {
                @case ('maxmind') {
                  <clr-input-container>
                    <label i18n="@@dataSources.accountId">Account ID</label>
                    <input
                      clrInput
                      name="mmAccount"
                      [(ngModel)]="e.maxmindAccountId"
                      autocomplete="off"
                    />
                  </clr-input-container>
                  <clr-password-container>
                    <label i18n="@@dataSources.licenseKey">License key</label>
                    <input
                      clrPassword
                      name="mmKey"
                      [(ngModel)]="licenseKey"
                      autocomplete="new-password"
                      [placeholder]="e.hasLicenseKey ? storedKeep : ''"
                    />
                    <clr-control-helper i18n="@@dataSources.licenseKeyHelp"
                      >Create one under <i>Manage license keys</i> in your MaxMind account. Stored
                      encrypted.</clr-control-helper
                    >
                  </clr-password-container>
                  <clr-select-container>
                    <label i18n="@@dataSources.countryEdition">Country edition</label>
                    <select clrSelect name="mmCountry" [(ngModel)]="e.maxmindCountryEdition">
                      @for (ed of countryEditions; track ed) {
                        <option [value]="ed">{{ ed }}</option>
                      }
                    </select>
                    <clr-control-helper i18n="@@dataSources.editionHelp"
                      >GeoLite2 editions are free; GeoIP2 editions need a
                      subscription.</clr-control-helper
                    >
                  </clr-select-container>
                  <clr-select-container>
                    <label i18n="@@dataSources.asnEdition">ASN edition</label>
                    <select clrSelect name="mmAsn" [(ngModel)]="e.maxmindAsnEdition">
                      @for (ed of asnEditions; track ed) {
                        <option [value]="ed">{{ ed }}</option>
                      }
                    </select>
                  </clr-select-container>
                }
                @case ('urls') {
                  <clr-input-container>
                    <label i18n="@@dataSources.countryUrl">Country database URL</label>
                    <input
                      clrInput
                      name="cUrl"
                      [(ngModel)]="countryUrl"
                      autocomplete="off"
                      [placeholder]="e.geoCountryHost ? storedHost(e.geoCountryHost) : 'https://…'"
                    />
                    <clr-control-helper i18n="@@dataSources.urlHelp"
                      >Download links often contain a license key, so they are stored encrypted and
                      not shown again.</clr-control-helper
                    >
                  </clr-input-container>
                  <clr-input-container>
                    <label i18n="@@dataSources.asnUrl">ASN database URL</label>
                    <input
                      clrInput
                      name="aUrl"
                      [(ngModel)]="asnUrl"
                      autocomplete="off"
                      [disabled]="clearAsnUrl"
                      [placeholder]="e.geoAsnHost ? storedHost(e.geoAsnHost) : optional"
                    />
                  </clr-input-container>
                  @if (e.geoAsnHost) {
                    <clr-checkbox-container>
                      <label></label>
                      <clr-checkbox-wrapper>
                        <input
                          type="checkbox"
                          clrCheckbox
                          name="clearAsn"
                          [(ngModel)]="clearAsnUrl"
                        />
                        <label i18n="@@dataSources.removeAsnUrl">Remove the stored ASN URL</label>
                      </clr-checkbox-wrapper>
                    </clr-checkbox-container>
                  }
                }
                @case ('files') {
                  <clr-input-container>
                    <label i18n="@@dataSources.countryFile">Country database file</label>
                    <input
                      clrInput
                      name="cFile"
                      [(ngModel)]="e.geoCountryFile"
                      placeholder="/var/lib/GeoIP/GeoIP2-Country.mmdb"
                    />
                  </clr-input-container>
                  <clr-input-container>
                    <label i18n="@@dataSources.asnFile">ASN database file</label>
                    <input
                      clrInput
                      name="aFile"
                      [(ngModel)]="e.geoAsnFile"
                      placeholder="/var/lib/GeoIP/GeoLite2-ASN.mmdb (optional)"
                      i18n-placeholder="@@dataSources.asnFilePlaceholder"
                    />
                    <clr-control-helper i18n="@@dataSources.filesHelp"
                      >Absolute paths readable by the <code>nfa</code> user. Paths under /home are
                      not accessible to the service.</clr-control-helper
                    >
                  </clr-input-container>
                }
              }

              @if (st()?.geo?.attributions?.length) {
                <p class="attrib">
                  @for (a of st()!.geo.attributions; track a.text) {
                    <span
                      ><a [href]="a.url" target="_blank" rel="noopener">{{ a.text }}</a
                      >{{ a.license ? ' (' + a.license + ')' : '' }}</span
                    >
                  }
                </p>
              }
              <clr-toggle-container>
                <label i18n="@@settings.onlineAsn">Online ASN lookup</label>
                <clr-toggle-wrapper>
                  <input
                    type="checkbox"
                    clrToggle
                    name="onlineasn"
                    [(ngModel)]="lk.onlineAsnLookup"
                  />
                  <label i18n="@@settings.onlineAsnToggle"
                    >Look up ASNs missing from the local database via RIPEstat</label
                  >
                </clr-toggle-wrapper>
                <clr-control-helper i18n="@@settings.onlineAsnHelp"
                  >Queries stat.ripe.net once per /24 (IPv4) or /48 (IPv6) and caches results for 7
                  days.</clr-control-helper
                >
              </clr-toggle-container>
              <clr-toggle-container>
                <label i18n="@@dataSources.autoUpdate">Automatic updates</label>
                <clr-toggle-wrapper>
                  <input type="checkbox" clrToggle name="auto" [(ngModel)]="e.autoUpdate" />
                  <label i18n="@@dataSources.autoUpdateToggle"
                    >Keep downloaded databases current</label
                  >
                </clr-toggle-wrapper>
                <clr-control-helper i18n="@@dataSources.autoUpdateHelp"
                  >DB-IP Lite is refreshed monthly; MaxMind, URL and IEEE downloads weekly. Files on
                  the appliance are always reloaded when they change.</clr-control-helper
                >
              </clr-toggle-container>
              <div class="actions">
                <button
                  type="submit"
                  class="btn btn-primary"
                  [clrLoading]="busy()"
                  [disabled]="!geoDirty()"
                  i18n="@@common.save"
                >
                  Save
                </button>
                <button
                  type="button"
                  class="btn btn-outline"
                  (click)="revert('geo')"
                  [disabled]="!geoDirty()"
                  i18n="@@common.revert"
                >
                  Revert
                </button>
                <button
                  type="button"
                  class="btn btn-outline"
                  (click)="update('geo')"
                  [clrLoading]="busyGeo()"
                  [disabled]="geoDirty()"
                  [title]="geoDirty() ? saveFirst : ''"
                >
                  @if (e.geoSource === 'files') {
                    <ng-container i18n="@@dataSources.reloadNow">Reload now</ng-container>
                  } @else {
                    <ng-container i18n="@@dataSources.updateNow">Update now</ng-container>
                  }
                </button>
                @if (geoDirty()) {
                  <span class="unsaved"
                    ><cds-icon shape="exclamation-triangle"></cds-icon>
                    <ng-container i18n="@@enrichment.unsaved">Unsaved changes.</ng-container></span
                  >
                }
              </div>
            </form>
          </clr-tab-content>
        </clr-tab>
        <clr-tab>
          <button clrTabLink (click)="setTab('hostnames')">
            <ng-container i18n="@@enrichment.tab.hostnames">Hostnames</ng-container>
            @if (hostnamesDirty()) {
              <span class="dot" title="Unsaved changes" i18n-title="@@enrichment.unsavedTab"
                >•</span
              >
            }
          </button>
          <clr-tab-content *clrIfActive="tab() === 'hostnames'">
            <form
              clrForm
              clrLayout="horizontal"
              clrLabelSize="3"
              (ngSubmit)="saveHostnames()"
              class="ds-form"
            >
              <clr-toggle-container>
                <label i18n="@@enrichment.hostnames">Hostnames</label>
                <clr-toggle-wrapper>
                  <input type="checkbox" clrToggle name="rdns" [(ngModel)]="lk.reverseDns" />
                  <label i18n="@@settings.reverseDnsToggle"
                    >Resolve hostnames for addresses in reports</label
                  >
                </clr-toggle-wrapper>
                <clr-control-helper>
                  <ng-container i18n="@@enrichment.reverseDnsHelp"
                    >Cached for 6 hours. Disable on isolated networks.</ng-container
                  >
                  @if (st(); as g) {
                    <ng-container i18n="@@settings.hostnameCache"
                      >Hostname cache: {{ g.rdnsCache }} entries.</ng-container
                    >
                  }
                </clr-control-helper>
              </clr-toggle-container>
              <div class="clr-form-control clr-row">
                <label
                  class="clr-control-label clr-col-12 clr-col-md-3"
                  i18n="@@settings.dnsResolvers"
                  >DNS resolvers</label
                >
                <div class="clr-control-container clr-col-12 clr-col-md-9">
                  @if (!dnsList().length) {
                    <p class="empty">
                      <ng-container i18n="@@settings.dnsEmpty"
                        >None added: using the system resolvers</ng-container
                      >
                      @if (st()?.systemDnsServers?.length) {
                        ({{ st()!.systemDnsServers.join(', ') }})
                      }
                      .
                    </p>
                  }
                  <nfa-list-editor
                    [(items)]="dnsList"
                    [ordered]="true"
                    placeholder="192.168.1.1 or [2001:db8::53]:53"
                    label="DNS resolver"
                    i18n-label="@@settings.dnsResolverLabel"
                    [validate]="dnsError"
                  />
                  <span class="clr-subtext" i18n="@@settings.dnsResolversHelp2"
                    >IP addresses, optionally with a port, tried in order. Used for Tributary's own
                    lookups: reverse DNS, GeoIP downloads and ASN lookups. Tip: your router/DHCP
                    server usually knows local device names.</span
                  >
                </div>
              </div>
              <div class="actions">
                <button
                  type="submit"
                  class="btn btn-primary"
                  [clrLoading]="busy()"
                  [disabled]="!hostnamesDirty()"
                  i18n="@@common.save"
                >
                  Save
                </button>
                <button
                  type="button"
                  class="btn btn-outline"
                  (click)="revert('hostnames')"
                  [disabled]="!hostnamesDirty()"
                  i18n="@@common.revert"
                >
                  Revert
                </button>
                @if (hostnamesDirty()) {
                  <span class="unsaved"
                    ><cds-icon shape="exclamation-triangle"></cds-icon>
                    <ng-container i18n="@@enrichment.unsaved">Unsaved changes.</ng-container></span
                  >
                }
              </div>
            </form>
          </clr-tab-content>
        </clr-tab>
        <clr-tab>
          <button clrTabLink (click)="setTab('vendors')">
            <ng-container i18n="@@enrichment.tab.vendors">MAC Vendors</ng-container>
            @if (ouiDirty()) {
              <span class="dot" title="Unsaved changes" i18n-title="@@enrichment.unsavedTab"
                >•</span
              >
            }
          </button>
          <clr-tab-content *clrIfActive="tab() === 'vendors'">
            <form
              clrForm
              clrLayout="horizontal"
              clrLabelSize="3"
              (ngSubmit)="saveOui()"
              class="ds-form"
            >
              @if (st(); as g) {
                <table class="table table-compact table-noborder status">
                  <tbody>
                    <tr>
                      <td i18n="@@dataSources.loadedFrom">Loaded from</td>
                      <td>{{ g.vendors.location }}</td>
                    </tr>
                    <tr>
                      <td i18n="@@dataSources.entries">Entries</td>
                      <td>
                        {{ fmtCount(g.vendors.entries) }}
                        @if (g.vendors.updated) {
                          <ng-container i18n="@@dataSources.updated">
                            · updated {{ dt(g.vendors.updated) }}</ng-container
                          >
                        }
                      </td>
                    </tr>
                    <tr>
                      <td i18n="@@dataSources.lastUpdate">Last update</td>
                      <td [class.bad]="g.vendors.lastUpdate.includes('failed')">
                        {{ g.vendors.lastUpdate || '–' }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              }
              <clr-radio-container>
                <label>Source</label>
                @for (o of ouiSources; track o.id) {
                  <clr-radio-wrapper>
                    <input
                      type="radio"
                      clrRadio
                      name="ouiSource"
                      [value]="o.id"
                      [(ngModel)]="e.ouiSource"
                    />
                    <label>{{ o.label }}</label>
                  </clr-radio-wrapper>
                }
                <clr-control-helper>{{ ouiHelp(e.ouiSource) }}</clr-control-helper>
              </clr-radio-container>
              @if (e.ouiSource === 'url') {
                <clr-input-container>
                  <label i18n="@@dataSources.downloadUrl">Download URL</label>
                  <input
                    clrInput
                    name="ouiUrl"
                    [(ngModel)]="e.ouiUrl"
                    placeholder="https://mirror.example.com/oui.csv"
                  />
                </clr-input-container>
              }
              @if (e.ouiSource === 'file') {
                <clr-input-container>
                  <label i18n="@@dataSources.file">File</label>
                  <input
                    clrInput
                    name="ouiFile"
                    [(ngModel)]="e.ouiFile"
                    placeholder="/srv/oui/oui.csv"
                  />
                  <clr-control-helper i18n="@@dataSources.fileHelp"
                    >An absolute path readable by the <code>nfa</code> user.</clr-control-helper
                  >
                </clr-input-container>
              }
              <clr-toggle-container>
                <label i18n="@@dataSources.autoUpdate">Automatic updates</label>
                <clr-toggle-wrapper>
                  <input type="checkbox" clrToggle name="auto" [(ngModel)]="e.autoUpdate" />
                  <label i18n="@@dataSources.autoUpdateToggle"
                    >Keep downloaded databases current</label
                  >
                </clr-toggle-wrapper>
                <clr-control-helper i18n="@@dataSources.autoUpdateHelp"
                  >DB-IP Lite is refreshed monthly; MaxMind, URL and IEEE downloads weekly. Files on
                  the appliance are always reloaded when they change.</clr-control-helper
                >
              </clr-toggle-container>
              <div class="actions">
                <button
                  type="submit"
                  class="btn btn-primary"
                  [clrLoading]="busy()"
                  [disabled]="!ouiDirty()"
                  i18n="@@common.save"
                >
                  Save
                </button>
                <button
                  type="button"
                  class="btn btn-outline"
                  (click)="revert('oui')"
                  [disabled]="!ouiDirty()"
                  i18n="@@common.revert"
                >
                  Revert
                </button>
                @if (savedOui()) {
                  <button
                    type="button"
                    class="btn btn-outline"
                    (click)="update('oui')"
                    [clrLoading]="busyOui()"
                    [disabled]="ouiDirty()"
                    [title]="ouiDirty() ? saveFirst : ''"
                  >
                    @if (e.ouiSource === 'file') {
                      <ng-container i18n="@@dataSources.reloadNow">Reload now</ng-container>
                    } @else {
                      <ng-container i18n="@@dataSources.updateNow">Update now</ng-container>
                    }
                  </button>
                }
                @if (ouiDirty()) {
                  <span class="unsaved"
                    ><cds-icon shape="exclamation-triangle"></cds-icon>
                    <ng-container i18n="@@enrichment.unsaved">Unsaved changes.</ng-container></span
                  >
                }
              </div>
            </form>
          </clr-tab-content>
        </clr-tab>
      </clr-tabs>
    }
  `,
  styles: `
    .ds-form {
      max-width: 880px;
    }
    .empty {
      margin: 6px 0 4px;
      font-size: 13px;
      color: var(--cds-alias-typography-color-300);
    }
    .clr-subtext {
      display: block;
      margin-top: 6px;
    }
    .ds-form {
      padding-top: 12px;
    }
    .dot {
      margin-left: 4px;
      color: var(--cds-alias-status-warning);
    }
    .status {
      max-width: 760px;
      margin: 0 0 8px;
    }
    .status td {
      text-align: left;
      padding: 2px 0;
      border: 0;
    }
    .status td:first-child {
      width: 170px;
      color: var(--cds-alias-typography-color-300);
    }
    .muted {
      color: var(--cds-alias-typography-color-300);
    }
    .bad {
      color: var(--cds-alias-status-danger);
    }
    .attrib {
      font-size: 12px;
      color: var(--cds-alias-typography-color-300);
      margin: 16px 0 8px;
    }
    .attrib span + span::before {
      content: ' · ';
    }
    .actions {
      margin-top: 16px;
      display: flex;
      align-items: center;
      gap: 4px;
      flex-wrap: wrap;
    }
    .save-error {
      font-size: 13px;
      color: var(--cds-alias-status-danger);
      margin-left: 8px;
    }
    .unsaved {
      font-size: 13px;
      color: var(--cds-alias-status-warning-shade, #8c5c00);
      margin-left: 8px;
    }
  `,
})
export class EnrichmentPage {
  private api = inject(Api);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  readonly e = signal<Enrichment | null>(null);
  readonly st = signal<GeoStatus | null>(null);
  readonly busy = signal(false);
  readonly busyGeo = signal(false);
  readonly busyOui = signal(false);
  readonly saved = signal<'' | 'lookups' | 'sources'>('');
  readonly error = signal('');
  readonly dnsList = signal<string[]>([]);
  /** The tab, kept in the URL (?tab=) so links and notices can open it. */
  readonly tab = signal<Tab>('geo');
  /** Settings edited here (the rest are on the Settings page). */
  lk = { reverseDns: false, onlineAsnLookup: false };
  private savedSettings: Pick<Settings, 'reverseDns' | 'onlineAsnLookup' | 'dnsServers'> = {
    reverseDns: false,
    onlineAsnLookup: false,
    dnsServers: [],
  };
  readonly dnsError = (v: string) =>
    validAddrPort(v)
      ? null
      : $localize`:@@settings.notAddrPort:Not an IP address (optionally with :port)`;
  readonly geoSources = GEO_SOURCES;
  readonly ouiSources = OUI_SOURCES;
  readonly countryEditions = [
    'GeoLite2-Country',
    'GeoLite2-City',
    'GeoIP2-Country',
    'GeoIP2-City',
    'GeoIP2-Enterprise',
  ];
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
  // The stored record, to tell unsaved edits apart.
  private stored: Enrichment | null = null;
  readonly savedOui = signal('');

  constructor() {
    const t = this.route.snapshot.queryParamMap.get('tab') as Tab;
    if (TABS.includes(t)) this.tab.set(t);
    this.load();
  }

  setTab(t: Tab) {
    this.tab.set(t);
    this.saved.set('');
    this.error.set('');
    this.router.navigate([], { queryParams: { tab: t === 'geo' ? null : t }, replaceUrl: true });
  }

  private changed<K extends keyof Enrichment>(keys: readonly K[]) {
    const e = this.e();
    return (
      !!e &&
      !!this.stored &&
      JSON.stringify(pick(e, keys)) !== JSON.stringify(pick(this.stored, keys))
    );
  }

  geoDirty() {
    return (
      this.changed(GEO_KEYS) ||
      !!this.licenseKey ||
      !!this.countryUrl ||
      !!this.asnUrl ||
      this.clearAsnUrl ||
      this.lk.onlineAsnLookup !== this.savedSettings.onlineAsnLookup
    );
  }

  ouiDirty() {
    return this.changed(OUI_KEYS);
  }

  hostnamesDirty() {
    return (
      this.lk.reverseDns !== this.savedSettings.reverseDns ||
      JSON.stringify(listValues(this.dnsList())) !==
        JSON.stringify(this.savedSettings.dnsServers ?? [])
    );
  }

  private setSettings(s: Settings) {
    this.savedSettings = {
      reverseDns: s.reverseDns,
      onlineAsnLookup: s.onlineAsnLookup,
      dnsServers: s.dnsServers ?? [],
    };
  }

  /** Records a saved Enrichment, keeping unsaved edits to the fields in keep. */
  private setStored<K extends keyof Enrichment>(out: Enrichment, keep: readonly K[] = []) {
    const cur = this.e();
    this.stored = out;
    this.e.set(cur && keep.length ? { ...out, ...pick(cur, keep) } : { ...out });
    this.savedOui.set(out.ouiSource);
  }

  private clearSecrets() {
    this.licenseKey = this.countryUrl = this.asnUrl = '';
    this.clearAsnUrl = false;
  }

  geoHelp(id: string) {
    return GEO_SOURCES.find((o) => o.id === id)?.help ?? '';
  }

  ouiHelp(id: string) {
    return OUI_SOURCES.find((o) => o.id === id)?.help ?? '';
  }

  async load() {
    this.saved.set('');
    this.error.set('');
    this.clearSecrets();
    try {
      const [e, st, settings] = await Promise.all([
        this.api.enrichment(),
        this.api.geo(),
        this.api.settings(),
      ]);
      this.setStored(e);
      this.setSettings(settings);
      this.lk = { reverseDns: settings.reverseDns, onlineAsnLookup: settings.onlineAsnLookup };
      this.dnsList.set(settings.dnsServers ?? []);
      this.st.set(st);
    } catch (err) {
      this.error.set(errorMessage(err));
    }
  }

  /** Discards one tab's edits. */
  revert(t: 'geo' | 'oui' | 'hostnames') {
    const e = this.e();
    if (!e || !this.stored) return;
    this.error.set('');
    if (t === 'geo') {
      this.e.set({ ...e, ...pick(this.stored, GEO_KEYS) });
      this.clearSecrets();
      this.lk.onlineAsnLookup = this.savedSettings.onlineAsnLookup;
    } else if (t === 'oui') {
      this.e.set({ ...e, ...pick(this.stored, OUI_KEYS) });
    } else {
      this.lk.reverseDns = this.savedSettings.reverseDns;
      this.dnsList.set(this.savedSettings.dnsServers ?? []);
    }
  }

  private async run(fn: () => Promise<'' | 'lookups' | 'sources'>) {
    this.busy.set(true);
    this.saved.set('');
    this.error.set('');
    try {
      this.saved.set(await fn());
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  /** Saves the stored record with changes to keys (and, for geo, the secrets entered). */
  private async saveSources<K extends keyof Enrichment>(
    keys: readonly K[],
    keep: readonly (keyof Enrichment)[],
    secrets: boolean,
  ) {
    const e = this.e();
    if (!e || !this.stored) return;
    const before = this.st();
    // hasLicenseKey and the URL hosts are read-only; the API rejects them.
    const { hasLicenseKey, geoCountryHost, geoAsnHost, ...stored } = {
      ...this.stored,
      ...pick(e, keys),
    };
    const out = await this.api.saveEnrichment({
      ...stored,
      maxmindLicenseKey: secrets ? this.licenseKey.trim() : '',
      geoCountryUrl: secrets ? this.countryUrl.trim() : '',
      geoAsnUrl: secrets && !this.clearAsnUrl ? this.asnUrl.trim() : '',
      clearGeoAsnUrl: secrets && this.clearAsnUrl,
    });
    this.setStored(out, keep);
    if (secrets) this.clearSecrets();
    await this.waitForChange(before, 30);
  }

  saveGeo() {
    return this.run(async () => {
      if (this.lk.onlineAsnLookup !== this.savedSettings.onlineAsnLookup) {
        this.setSettings(
          await this.api.updateSettings({ onlineAsnLookup: this.lk.onlineAsnLookup }),
        );
      }
      if (
        !this.changed(GEO_KEYS) &&
        !this.licenseKey &&
        !this.countryUrl &&
        !this.asnUrl &&
        !this.clearAsnUrl
      )
        return 'lookups';
      await this.saveSources(GEO_KEYS, ['ouiSource', 'ouiUrl', 'ouiFile'], true);
      return 'sources';
    });
  }

  saveOui() {
    return this.run(async () => {
      await this.saveSources(
        OUI_KEYS,
        GEO_KEYS.filter((k) => k !== 'autoUpdate'),
        false,
      );
      return 'sources';
    });
  }

  saveHostnames() {
    const dns = listValues(this.dnsList());
    const bad = dns.filter((v) => this.dnsError(v));
    if (bad.length) {
      this.error.set(
        $localize`:@@settings.fixEntries:Fix the highlighted entries first: ${bad.join(', ')}:entries:`,
      );
      return;
    }
    return this.run(async () => {
      const s = await this.api.updateSettings({ reverseDns: this.lk.reverseDns, dnsServers: dns });
      this.setSettings(s);
      this.dnsList.set(s.dnsServers ?? []);
      return 'lookups';
    });
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
