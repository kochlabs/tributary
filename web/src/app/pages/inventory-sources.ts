import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, InventorySource, InventoryTest } from '../core/api';
import { ago } from '../core/format';
import { loader, trackByKey } from '../core/util';

type SourceType = InventorySource['type'];

/** The inventory types Tributary can read; each has a card in the chooser and a connection section in the editor. */
const TYPES: { id: SourceType; label: string; description: string; name: string }[] = [
  {
    id: 'netbox',
    label: 'NetBox',
    description: $localize`:@@inventory.netboxDescription:Devices, virtual machines, addresses, MACs, services and prefixes from NetBox 4.2 or later, through its REST API.`,
    name: 'NetBox',
  },
];

const blank = (type: SourceType): Partial<InventorySource> => ({
  name: TYPES.find((t) => t.id === type)?.name ?? '',
  type,
  enabled: true,
  priority: 10,
  url: '',
  token: '',
  scopeSite: '',
  scopeTenant: '',
  scopeTag: '',
  intervalMin: 15,
  localTag: '',
});

/** Read-only connections to an inventory, such as NetBox (Configuration → Inventory Sources). */
@Component({
  selector: 'nfa-inventory-sources',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.inventorySources">Inventory Sources</h2>
        <p class="subtitle" i18n="@@inventory.subtitle2">
          Names, roles and documented services from your source of truth. Read-only.
        </p>
      </div>
    </div>

    @if (list.error() || pageError()) {
      <div class="alert alert-danger" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text">{{ pageError() || list.error() }}</span>
          </div>
        </div>
      </div>
    }
    @if (info()) {
      <div class="alert alert-success" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text">{{ info() }}</span>
          </div>
        </div>
      </div>
    }

    <div class="toolbar">
      <div>
        <button class="btn btn-primary" (click)="chooserOpen.set(true)">
          <cds-icon shape="plus"></cds-icon>
          <ng-container i18n="@@inventory.add">Add source</ng-container>
        </button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="openEdit(selected()!)">
          <cds-icon shape="pencil"></cds-icon>
          <ng-container i18n="@@inventory.edit">Edit</ng-container>
        </button>
        <button
          class="btn btn-outline"
          [disabled]="!selected()?.enabled"
          (click)="syncNow(selected()!)"
        >
          <cds-icon shape="sync"></cds-icon>
          <ng-container i18n="@@inventory.syncNow">Sync now</ng-container>
        </button>
        <button
          class="btn btn-outline"
          [disabled]="!selected()"
          (click)="confirmDelete.set(selected()!)"
        >
          <cds-icon shape="trash"></cds-icon>
          <ng-container i18n="@@inventory.delete">Delete</ng-container>
        </button>
      </div>
      <button
        class="btn btn-link btn-icon"
        (click)="list.reload()"
        aria-label="Refresh"
        i18n-aria-label="@@common.refresh"
      >
        <cds-icon shape="refresh"></cds-icon>
      </button>
    </div>

    <clr-datagrid
      class="datagrid-compact"
      clrDgSelectionType="single"
      [clrDgSelected]="selectedList()"
      (clrDgSelectedChange)="selectedId.set($event[0]?.id)"
      [clrDgLoading]="list.loading()"
    >
      <clr-dg-column i18n="@@inventory.name">Name</clr-dg-column>
      <clr-dg-column i18n="@@inventory.type">Type</clr-dg-column>
      <clr-dg-column i18n="@@inventory.url">Address</clr-dg-column>
      <clr-dg-column i18n="@@inventory.contents">Contents</clr-dg-column>
      <clr-dg-column i18n="@@inventory.synced">Synced</clr-dg-column>
      <clr-dg-column [clrDgSortOrder]="1" [clrDgField]="'priority'" i18n="@@inventory.priority"
        >Priority</clr-dg-column
      >
      <clr-dg-row *clrDgItems="let s of list.value() ?? []; trackBy: byId" [clrDgItem]="s">
        <clr-dg-cell
          >{{ s.name }}
          @if (!s.enabled) {
            <span class="label" i18n="@@inventory.disabled">disabled</span>
          }
        </clr-dg-cell>
        <clr-dg-cell>{{ typeLabel(s.type) }}</clr-dg-cell>
        <clr-dg-cell class="url"
          ><a [href]="s.url" target="_blank" rel="noopener">{{ s.url }}</a>
          @if (scope(s); as sc) {
            <div class="muted small">{{ sc }}</div>
          }
        </clr-dg-cell>
        <clr-dg-cell>
          @if (counts(s); as c) {
            <div class="counts">
              <div i18n="@@inventory.countObjects">
                {c.objects, plural, =1 {1 device} other {{{ c.objects }} devices}}
              </div>
              <div i18n="@@inventory.countAddrs">
                {c.addrs, plural, =1 {1 address} other {{{ c.addrs }} addresses}}
              </div>
              <div i18n="@@inventory.countMacs">
                {c.macs, plural, =1 {1 MAC} other {{{ c.macs }} MACs}}
              </div>
              <div i18n="@@inventory.countServices">
                {c.services, plural, =1 {1 service} other {{{ c.services }} services}}
              </div>
              <div i18n="@@inventory.countPrefixes">
                {c.prefixes, plural, =1 {1 prefix} other {{{ c.prefixes }} prefixes}}
              </div>
            </div>
          } @else {
            <span class="muted">–</span>
          }
        </clr-dg-cell>
        <clr-dg-cell>
          @if (s.lastError) {
            <span class="err" [title]="s.lastError"
              ><cds-icon shape="exclamation-triangle" status="danger"></cds-icon>
              {{ s.lastError }}</span
            >
            @if (s.lastSuccess) {
              <div class="muted small" i18n="@@inventory.usingLast">
                using the copy from {{ ago(s.lastSuccess) }}
              </div>
            }
          } @else if (s.lastSuccess) {
            {{ ago(s.lastSuccess) }}
          } @else {
            <span class="muted" i18n="@@inventory.pending">pending</span>
          }
        </clr-dg-cell>
        <clr-dg-cell>{{ s.priority }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder i18n="@@inventory.placeholder2"
        >No inventory sources. Add one to name devices there once and see those names
        here.</clr-dg-placeholder
      >
    </clr-datagrid>
    <p class="hint" i18n="@@inventory.hint2">
      Inventory names take precedence over names set in Tributary and over reverse DNS, for past
      traffic too. With several sources, the lowest priority number wins where they disagree.
      Sources are only read; Tributary never changes them.
    </p>

    <!-- Type chooser -->
    <clr-modal
      [clrModalOpen]="chooserOpen()"
      (clrModalOpenChange)="chooserOpen.set($event)"
      clrModalSize="lg"
    >
      <h3 class="modal-title" i18n="@@inventory.addTitle">Add inventory source</h3>
      <div class="modal-body">
        <div class="types">
          @for (t of types; track t.id) {
            <button class="type-card" (click)="openNew(t.id)">
              <h4>{{ t.label }}</h4>
              <p>{{ t.description }}</p>
            </button>
          }
        </div>
      </div>
      <div class="modal-footer">
        <button
          type="button"
          class="btn btn-outline"
          (click)="chooserOpen.set(false)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
      </div>
    </clr-modal>

    <!-- Source editor: common settings, then the type's connection -->
    <clr-modal
      [clrModalOpen]="!!editing()"
      (clrModalOpenChange)="!$event && editing.set(null)"
      clrModalSize="lg"
      [clrModalStaticBackdrop]="true"
    >
      <h3 class="modal-title">
        @if (editing()?.id) {
          <ng-container i18n="@@inventory.editTypeTitle"
            >Edit {{ typeLabel(editing()?.type) }} source</ng-container
          >
        } @else {
          <ng-container i18n="@@inventory.addTypeTitle"
            >Add {{ typeLabel(editing()?.type) }} source</ng-container
          >
        }
      </h3>
      <div class="modal-body">
        @if (editing(); as e) {
          <form clrForm clrLayout="horizontal" clrLabelSize="3" id="invform" (ngSubmit)="save()">
            <clr-input-container>
              <label i18n="@@inventory.name">Name</label>
              <input clrInput name="name" [(ngModel)]="e.name" required maxlength="64" />
              <clr-control-helper i18n="@@inventory.nameHelp"
                >Shown next to names and links that come from this source.</clr-control-helper
              >
            </clr-input-container>
            <clr-toggle-container>
              <label i18n="@@inventory.status">Status</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="enabled" [(ngModel)]="e.enabled" />
                <label i18n="@@inventory.enabled">Enabled</label>
              </clr-toggle-wrapper>
            </clr-toggle-container>

            <div class="section" i18n="@@inventory.connection">Connection</div>
            @switch (e.type) {
              @case ('netbox') {
                <clr-input-container>
                  <label i18n="@@inventory.url">Address</label>
                  <input
                    clrInput
                    name="url"
                    [(ngModel)]="e.url"
                    required
                    placeholder="https://netbox.example.com"
                    class="wide"
                    autocomplete="off"
                    spellcheck="false"
                  />
                  <clr-control-helper i18n="@@inventory.urlHelp"
                    >NetBox 4.2 or later. HTTPS certificates are checked against the system CAs and
                    those under Appliance → Certificates.</clr-control-helper
                  >
                </clr-input-container>
                <clr-password-container>
                  <label i18n="@@inventory.token">API token</label>
                  <input
                    clrPassword
                    name="token"
                    [(ngModel)]="e.token"
                    autocomplete="new-password"
                    [placeholder]="e.hasToken ? storedKeep : ''"
                    class="wide"
                  />
                  <clr-control-helper i18n="@@inventory.tokenHelp"
                    >A read-only token (in NetBox: Admin → API Tokens, without "Write enabled").
                    Stored encrypted.</clr-control-helper
                  >
                </clr-password-container>
                <div class="clr-form-control clr-row">
                  <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@inventory.scope"
                    >Scope</label
                  >
                  <div class="clr-control-container clr-col-12 clr-col-md-9 scope">
                    <input
                      class="clr-input"
                      name="site"
                      [(ngModel)]="e.scopeSite"
                      placeholder="site"
                      i18n-placeholder="@@inventory.site"
                      aria-label="Site"
                    />
                    <input
                      class="clr-input"
                      name="tenant"
                      [(ngModel)]="e.scopeTenant"
                      placeholder="tenant"
                      i18n-placeholder="@@inventory.tenant"
                      aria-label="Tenant"
                    />
                    <input
                      class="clr-input"
                      name="tag"
                      [(ngModel)]="e.scopeTag"
                      placeholder="tag"
                      i18n-placeholder="@@inventory.tag"
                      aria-label="Tag"
                    />
                    <span class="clr-subtext" i18n="@@inventory.scopeHelp"
                      >Optional slugs: only devices in this site, tenant or with this tag.</span
                    >
                  </div>
                </div>
                <clr-input-container>
                  <label i18n="@@inventory.localTag">Local prefixes</label>
                  <input
                    clrInput
                    name="localTag"
                    [(ngModel)]="e.localTag"
                    placeholder="tributary-local"
                  />
                  <clr-control-helper i18n="@@inventory.localTagHelp2"
                    >Optional tag: prefixes with it are added to Local Networks.</clr-control-helper
                  >
                </clr-input-container>
              }
            }

            <div class="section" i18n="@@inventory.syncSection">Sync</div>
            <clr-input-container>
              <label i18n="@@inventory.interval">Sync every</label>
              <input
                clrInput
                type="number"
                name="interval"
                [(ngModel)]="e.intervalMin"
                min="5"
                max="1440"
                class="short"
              />
              <clr-control-helper i18n="@@inventory.intervalHelp"
                >Minutes. Tributary keeps the last copy if the inventory is
                unreachable.</clr-control-helper
              >
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@inventory.priority">Priority</label>
              <input
                clrInput
                type="number"
                name="priority"
                [(ngModel)]="e.priority"
                min="0"
                max="1000"
                class="short"
              />
              <clr-control-helper i18n="@@inventory.priorityHelp"
                >With several sources, the lowest number wins when they
                disagree.</clr-control-helper
              >
            </clr-input-container>
          </form>
          @if (test(); as t) {
            @if (t.ok && t.result; as r) {
              <div
                class="alert alert-sm"
                [class.alert-success]="!r.writable && !r.warning"
                [class.alert-warning]="r.writable || r.warning"
                role="alert"
              >
                <div class="alert-items">
                  <div class="alert-item static">
                    <span class="alert-text">
                      <ng-container i18n="@@inventory.testOk"
                        >Found {{ r.counts.objects }} devices, {{ r.counts.addrs }} addresses,
                        {{ r.counts.macs }} MACs, {{ r.counts.services }} services and
                        {{ r.counts.prefixes }} prefixes</ng-container
                      >
                      @if (r.sample.length) {
                        , e.g. {{ r.sample.join(', ') }}
                      }
                      .
                      @if (r.writable) {
                        <div i18n="@@inventory.writable">
                          This token can write. Tributary only reads: use a read-only token.
                        </div>
                      }
                      @if (r.warning) {
                        <div>{{ r.warning }}</div>
                      }
                    </span>
                  </div>
                </div>
              </div>
            } @else {
              <div class="alert alert-danger alert-sm" role="alert">
                <div class="alert-items">
                  <div class="alert-item static">
                    <span class="alert-text">{{ t.error }}</span>
                  </div>
                </div>
              </div>
            }
          }
          @if (formError()) {
            <div class="alert alert-danger alert-sm" role="alert">
              <div class="alert-items">
                <div class="alert-item static">
                  <span class="alert-text">{{ formError() }}</span>
                </div>
              </div>
            </div>
          }
        }
      </div>
      <div class="modal-footer">
        <button
          type="button"
          class="btn btn-outline"
          (click)="runTest()"
          [clrLoading]="testing()"
          [disabled]="!canTest()"
          i18n="@@inventory.test"
        >
          Test
        </button>
        <button
          type="button"
          class="btn btn-outline"
          (click)="editing.set(null)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
        <button
          type="submit"
          form="invform"
          class="btn btn-primary"
          [clrLoading]="busy()"
          [disabled]="!editing()?.name || !editing()?.url"
          i18n="@@common.save"
        >
          Save
        </button>
      </div>
    </clr-modal>

    <clr-modal
      [clrModalOpen]="!!confirmDelete()"
      (clrModalOpenChange)="!$event && confirmDelete.set(null)"
      clrModalSize="md"
    >
      <h3 class="modal-title" i18n="@@inventory.deleteTitle">
        Delete {{ confirmDelete()?.name }}?
      </h3>
      <div class="modal-body">
        <p i18n="@@inventory.deleteText">
          Its names and context disappear from Tributary. The inventory itself is not touched.
        </p>
      </div>
      <div class="modal-footer">
        <button
          type="button"
          class="btn btn-outline"
          (click)="confirmDelete.set(null)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
        <button type="button" class="btn btn-danger" (click)="remove()" i18n="@@inventory.delete">
          Delete
        </button>
      </div>
    </clr-modal>
  `,
  styles: `
    .alert {
      margin: 0 0 16px;
    }
    .modal-body .alert {
      margin: 12px 0 0;
    }
    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .toolbar .btn {
      margin: 0 6px 0 0;
    }
    .url {
      word-break: break-all;
    }
    .err {
      color: var(--cds-alias-status-danger);
    }
    .muted {
      color: var(--cds-alias-typography-color-300);
    }
    .small {
      font-size: 12px;
    }
    .label {
      margin-left: 6px;
    }
    .hint {
      font-size: 12px;
      color: var(--cds-alias-typography-color-300);
      margin-top: 8px;
    }
    .types {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }
    .type-card {
      text-align: left;
      padding: 18px 20px;
      border: 1px solid var(--cds-alias-object-border-color);
      border-radius: 4px;
      background: var(--cds-alias-object-container-background);
      cursor: pointer;
      font: inherit;
      color: inherit;
    }
    .type-card:hover {
      border-color: var(--cds-alias-status-info);
    }
    .type-card h4 {
      margin: 0 0 6px;
    }
    .type-card p {
      margin: 0;
      font-size: 13px;
      color: var(--cds-alias-typography-color-300);
    }
    .section {
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-size: 12px;
      color: var(--cds-alias-typography-color-300);
      margin: 22px 0 0;
    }
    .scope {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }
    .scope .clr-input {
      width: 9rem;
    }
    .scope .clr-subtext {
      flex-basis: 100%;
    }
    input.wide {
      width: 26rem;
      max-width: 100%;
    }
    input.short {
      width: 6rem;
    }
    @media (max-width: 900px) {
      .types {
        grid-template-columns: 1fr;
      }
    }
  `,
})
export class InventorySources {
  readonly byId = trackByKey<{ id: number }>((s) => s.id);
  private api = inject(Api);
  readonly types = TYPES;
  readonly list = loader(
    () => true,
    () => this.api.inventorySources(),
  );
  readonly selectedId = signal<number | undefined>(undefined);
  readonly selected = computed(() => this.list.value()?.find((s) => s.id === this.selectedId()));
  readonly selectedList = computed(() => {
    const s = this.selected();
    return s ? [s] : [];
  });
  readonly chooserOpen = signal(false);
  readonly editing = signal<Partial<InventorySource> | null>(null);
  readonly confirmDelete = signal<InventorySource | null>(null);
  readonly test = signal<InventoryTest | null>(null);
  readonly busy = signal(false);
  readonly testing = signal(false);
  readonly formError = signal('');
  readonly pageError = signal('');
  readonly info = signal('');
  readonly storedKeep = $localize`:@@dataSources.storedKeep:Stored · leave empty to keep`;
  ago = ago;

  typeLabel(t?: string) {
    return TYPES.find((x) => x.id === t)?.label ?? t ?? '';
  }

  counts(s: InventorySource) {
    try {
      const c = JSON.parse(s.counts || '{}');
      return c.objects !== undefined ? c : null;
    } catch {
      return null;
    }
  }

  scope(s: InventorySource) {
    return [
      s.scopeSite && `site ${s.scopeSite}`,
      s.scopeTenant && `tenant ${s.scopeTenant}`,
      s.scopeTag && `tag ${s.scopeTag}`,
    ]
      .filter(Boolean)
      .join(' · ');
  }

  /** Whether the connection is complete enough to test, by type. */
  canTest() {
    const e = this.editing();
    if (!e) return false;
    switch (e.type) {
      case 'netbox':
        return !!e.url && (!!e.token || !!e.hasToken);
    }
    return false;
  }

  openNew(type: SourceType) {
    this.chooserOpen.set(false);
    this.editing.set(blank(type));
    this.test.set(null);
    this.formError.set('');
  }

  openEdit(s: InventorySource) {
    this.editing.set({ ...s, token: '' });
    this.test.set(null);
    this.formError.set('');
  }

  async runTest() {
    const e = this.editing();
    if (!e) return;
    this.testing.set(true);
    this.test.set(null);
    try {
      this.test.set(await this.api.testInventorySource(e));
    } catch (err) {
      this.test.set({ ok: false, error: errorMessage(err) });
    } finally {
      this.testing.set(false);
    }
  }

  async save() {
    const e = this.editing();
    if (!e) return;
    this.busy.set(true);
    this.formError.set('');
    try {
      const saved = await this.api.saveInventorySource(e);
      this.editing.set(null);
      this.selectedId.set(saved.id);
      this.flash(
        $localize`:@@inventory.saved:Saved. Syncing ${saved.name}:name: in the background.`,
      );
      this.list.reload();
      setTimeout(() => this.list.reload(), 4000);
    } catch (err) {
      this.formError.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  async syncNow(s: InventorySource) {
    try {
      await this.api.syncInventorySource(s.id);
      this.flash($localize`:@@inventory.syncing:Syncing ${s.name}:name:…`);
      setTimeout(() => this.list.reload(), 4000);
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
  }

  async remove() {
    const s = this.confirmDelete();
    this.confirmDelete.set(null);
    if (!s) return;
    try {
      await this.api.deleteInventorySource(s.id);
      this.selectedId.set(undefined);
      this.pageError.set('');
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
    this.list.reload();
  }

  private flash(msg: string) {
    this.info.set(msg);
    setTimeout(() => this.info.set(''), 5000);
  }
}
