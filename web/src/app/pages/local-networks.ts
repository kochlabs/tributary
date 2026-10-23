import { Component, inject, signal } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage } from '../core/api';
import { validAddrOrPrefix } from '../core/cidr';
import { count } from '../core/format';
import { loader } from '../core/util';
import { ListEditor, listValues } from '../shared/list-editor';

/** The networks that are "yours" (Configuration → Local Networks). */
@Component({
  selector: 'nfa-local-networks',
  imports: [ClarityModule, ListEditor],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.localNetworks">Local Networks</h2>
        <p class="subtitle" i18n="@@localNetworks.subtitle">
          Which addresses are yours: this decides download and upload, devices, local and remote
          hosts, and what is enriched and matched against threat feeds.
        </p>
      </div>
    </div>

    @if (saved()) {
      <div class="alert alert-success" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text" i18n="@@enrichment.saved">Saved and applied.</span>
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

    <div class="card">
      <div class="card-block">
        <div class="clr-form clr-form-horizontal">
          <div class="clr-form-control clr-row">
            <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@enrichment.prefixes"
              >Prefixes</label
            >
            <div class="clr-control-container clr-col-12 clr-col-md-9">
              @if (!list().length) {
                <p class="empty" i18n="@@settings.localNetworksEmpty">
                  None added: only private ranges are local.
                </p>
              }
              <nfa-list-editor
                [(items)]="list"
                placeholder="2001:db8:1234::/56"
                label="Local network"
                i18n-label="@@settings.localNetworkLabel"
                [validate]="cidrError"
              />
              <span class="clr-subtext" i18n="@@settings.localNetworksHelp2"
                >CIDR prefixes of your own public ranges (e.g. your ISP-delegated IPv6 prefix).
                Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) are always local. Local
                addresses are never geolocated or assigned an AS.</span
              >
            </div>
          </div>
        </div>

        @if (suggestions().length) {
          <div class="suggest">
            <div class="suggest-title" i18n="@@localNetworks.suggested">
              Suggested from recent traffic
            </div>
            @for (p of suggestions(); track p.prefix) {
              <div class="suggest-row">
                <code>{{ p.prefix }}</code>
                <span class="muted" i18n="@@localNetworks.suggestionDetail"
                  >{{ count(p.hosts) }} addresses talking to {{ count(p.peers) }} remote hosts</span
                >
                <button
                  type="button"
                  class="btn btn-sm btn-link"
                  (click)="add(p.prefix)"
                  i18n="@@localNetworks.add"
                >
                  Add
                </button>
              </div>
            }
          </div>
        }
      </div>
    </div>

    <div class="actions">
      <button
        type="button"
        class="btn btn-primary"
        (click)="save()"
        [clrLoading]="busy()"
        [disabled]="!dirty()"
        i18n="@@common.save"
      >
        Save
      </button>
      <button
        type="button"
        class="btn btn-outline"
        (click)="load()"
        [disabled]="!dirty()"
        i18n="@@common.revert"
      >
        Revert
      </button>
      @if (dirty()) {
        <span class="unsaved"
          ><cds-icon shape="exclamation-triangle"></cds-icon>
          <ng-container i18n="@@enrichment.unsaved">Unsaved changes.</ng-container></span
        >
      }
    </div>
  `,
  styles: `
    .card-block > .clr-form > .clr-form-control:first-child {
      margin-top: 0;
    }
    .card {
      max-width: 880px;
      margin-top: 0;
    }
    .alert {
      margin: 0 0 16px;
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
    .suggest {
      margin-top: 20px;
      padding-top: 12px;
      border-top: 1px solid var(--cds-alias-object-border-color);
    }
    .suggest-title {
      font-weight: 600;
      font-size: 13px;
      margin-bottom: 4px;
    }
    .suggest-row {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .suggest-row .btn {
      margin: 0;
    }
    .muted {
      font-size: 13px;
      color: var(--cds-alias-typography-color-300);
    }
    .actions {
      margin-top: 16px;
      display: flex;
      align-items: center;
      gap: 4px;
      flex-wrap: wrap;
    }
    .unsaved {
      font-size: 13px;
      color: var(--cds-alias-status-warning-shade, #8c5c00);
      margin-left: 8px;
    }
  `,
})
export class LocalNetworks {
  private api = inject(Api);
  readonly list = signal<string[]>([]);
  readonly busy = signal(false);
  readonly saved = signal(false);
  readonly error = signal('');
  readonly suggest = loader(
    () => true,
    () => this.api.localSuggestions(),
  );
  readonly cidrError = (v: string) =>
    validAddrOrPrefix(v) && v.includes('/')
      ? null
      : $localize`:@@settings.notCidr:Not a CIDR prefix, e.g. 2001:db8:1234::/56`;
  count = count;
  private savedJson = '';

  constructor() {
    this.load();
  }

  /** Suggestions not already in the list. */
  suggestions() {
    const have = new Set(listValues(this.list()));
    return (this.suggest.value()?.suggestions ?? []).filter((p) => !have.has(p.prefix));
  }

  dirty() {
    return JSON.stringify(listValues(this.list())) !== this.savedJson;
  }

  private set(nets: string[]) {
    this.list.set(nets ?? []);
    this.savedJson = JSON.stringify(listValues(this.list()));
  }

  async load() {
    this.saved.set(false);
    this.error.set('');
    try {
      this.set((await this.api.settings()).localNetworks);
    } catch (err) {
      this.error.set(errorMessage(err));
    }
  }

  add(prefix: string) {
    this.list.update((l) => [...l, prefix]);
  }

  async save() {
    const nets = listValues(this.list());
    const bad = nets.filter((v) => this.cidrError(v));
    if (bad.length) {
      this.error.set(
        $localize`:@@settings.fixEntries:Fix the highlighted entries first: ${bad.join(', ')}:entries:`,
      );
      return;
    }
    this.busy.set(true);
    this.saved.set(false);
    this.error.set('');
    try {
      this.set((await this.api.updateSettings({ localNetworks: nets })).localNetworks);
      this.saved.set(true);
      this.suggest.reload();
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}
