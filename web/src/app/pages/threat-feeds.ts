import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, ThreatFeed } from '../core/api';
import { ago, count } from '../core/format';
import { loader, trackByKey } from '../core/util';

type TestResult = { ok: boolean; error?: string; entries?: number; skipped?: number; sample?: string[] };

const blank = (): Partial<ThreatFeed> => ({ name: '', url: '', format: 'text', field: '', column: 1, delimiter: ',', enabled: true, notify: true, intervalHours: 12 });

/** Lists of known-bad addresses that flows are matched against (Security → Threat Feeds). */
@Component({
  selector: 'nfa-threat-feeds',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.threatFeeds">Threat Feeds</h2>
        <p class="subtitle" i18n="@@feeds.subtitle">Lists of known-bad addresses. Flows to or from a listed address are tagged with the first feed listing it.</p>
      </div>
    </div>

    @if (list.error() || pageError()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ pageError() || list.error() }}</span></div></div></div>
    }
    @if (info()) {
      <div class="alert alert-success" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ info() }}</span></div></div></div>
    }

    <div class="toolbar">
      <div>
        <button class="btn btn-primary" (click)="openEdit()"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@feeds.add">Add feed</ng-container></button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="openEdit(selected())"><cds-icon shape="pencil"></cds-icon> <ng-container i18n="@@feeds.edit">Edit</ng-container></button>
        <div class="btn-group btn-outline">
          <button class="btn" [disabled]="!selected() || position() === 0 || moving()" (click)="move(true)"><cds-icon shape="arrow"></cds-icon> <ng-container i18n="@@feeds.moveUp">Move up</ng-container></button>
          <button class="btn" [disabled]="!selected() || position() === feedCount() - 1 || moving()" (click)="move(false)"><cds-icon shape="arrow" direction="down"></cds-icon> <ng-container i18n="@@feeds.moveDown">Move down</ng-container></button>
        </div>
        <button class="btn btn-outline" [disabled]="!selected()?.enabled" (click)="updateNow(selected()!)"><cds-icon shape="sync"></cds-icon> <ng-container i18n="@@feeds.updateNow">Update now</ng-container></button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="confirmDelete.set(selected()!)"><cds-icon shape="trash"></cds-icon> <ng-container i18n="@@feeds.delete">Delete</ng-container></button>
        @if (list.value()?.defaultsMissing) {
          <button class="btn btn-link" (click)="addDefaults()" i18n="@@feeds.addDefaults">Add default feeds ({{ list.value()?.defaultsMissing }})</button>
        }
      </div>
      <button class="btn btn-link btn-icon" (click)="list.reload()" aria-label="Refresh" i18n-aria-label="@@common.refresh"><cds-icon shape="refresh"></cds-icon></button>
    </div>

    <clr-datagrid class="datagrid-compact" clrDgSelectionType="single" [clrDgSelected]="selectedList()" (clrDgSelectedChange)="selectedId.set($event[0]?.id)" [clrDgLoading]="list.loading()">
      <clr-dg-column class="order-col" i18n="Column: position in the matching order@@feeds.order">#</clr-dg-column>
      <clr-dg-column class="toggle-col" i18n="@@feeds.enabled">Enabled</clr-dg-column>
      <clr-dg-column i18n="@@feeds.name">Name</clr-dg-column>
      <clr-dg-column i18n="@@feeds.source">Source</clr-dg-column>
      <clr-dg-column i18n="@@feeds.format">Format</clr-dg-column>
      <clr-dg-column i18n="@@feeds.entries">Entries</clr-dg-column>
      <clr-dg-column i18n="@@feeds.updated">Updated</clr-dg-column>
      <clr-dg-column i18n="@@feeds.notices">Notices</clr-dg-column>
      <clr-dg-row *clrDgItems="let f of list.value()?.feeds ?? []; trackBy: byId; let i = index" [clrDgItem]="f">
        <clr-dg-cell class="order-col">{{ i + 1 }}</clr-dg-cell>
        <clr-dg-cell class="toggle-col">
          <clr-toggle-wrapper>
            <input type="checkbox" clrToggle [ngModel]="f.enabled" (ngModelChange)="setEnabled(f, $event)" [name]="'en' + f.id" [attr.aria-label]="f.name" (click)="$event.stopPropagation()" />
          </clr-toggle-wrapper>
        </clr-dg-cell>
        <clr-dg-cell>{{ f.name }}</clr-dg-cell>
        <clr-dg-cell class="url" [title]="f.url">{{ f.url }}</clr-dg-cell>
        <clr-dg-cell>{{ formatLabel(f) }}</clr-dg-cell>
        <clr-dg-cell>{{ f.entries ? count(f.entries) : '–' }}</clr-dg-cell>
        <clr-dg-cell>
          @if (f.lastError) {
            <span class="err" [title]="f.lastError"><cds-icon shape="exclamation-triangle" status="danger"></cds-icon> {{ f.lastError }}</span>
          } @else if (f.lastSuccess) {
            {{ ago(f.lastSuccess) }}
          } @else if (f.enabled) {
            <span class="muted" i18n="@@feeds.pending">pending</span>
          } @else {
            <span class="muted">–</span>
          }
        </clr-dg-cell>
        <clr-dg-cell>@if (f.notify) {<cds-icon shape="bell"></cds-icon>} @else {<span class="muted" i18n="@@feeds.off">off</span>}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder i18n="@@feeds.placeholder">No threat feeds.</clr-dg-placeholder>
      <clr-dg-footer>
        <ng-container i18n="@@feeds.footer">{{ enabledCount() }} of {{ feedCount() }} enabled · {{ count(list.value()?.ranges ?? 0) }} address ranges matched</ng-container>
      </clr-dg-footer>
    </clr-datagrid>
    <p class="hint" i18n="@@feeds.hint">When several feeds list an address, flows record the first one: put the most specific feeds first. Only addresses outside your local networks are matched; private, reserved and documentation ranges never match.</p>

    <clr-modal [clrModalOpen]="!!editing()" (clrModalOpenChange)="!$event && editing.set(null)" clrModalSize="lg" [clrModalStaticBackdrop]="true">
      <h3 class="modal-title">{{ editing()?.id ? editTitle : addTitle }}</h3>
      <div class="modal-body">
        @if (editing(); as e) {
          <form clrForm clrLayout="horizontal" clrLabelSize="3" id="feedform" (ngSubmit)="save()">
            <clr-input-container>
              <label i18n="@@feeds.name">Name</label>
              <input clrInput name="name" [(ngModel)]="e.name" required maxlength="64" autocomplete="off" />
              <clr-control-helper i18n="@@feeds.nameHelp">Shown on flows and used in the threat filter.</clr-control-helper>
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@feeds.source">Source</label>
              <input clrInput name="url" [(ngModel)]="e.url" required placeholder="https://…" autocomplete="off" class="wide" />
              <clr-control-helper i18n="@@feeds.sourceHelp">An http(s) URL, or the absolute path of a file on the appliance. Gzip is detected.</clr-control-helper>
            </clr-input-container>
            <clr-select-container>
              <label i18n="@@feeds.format">Format</label>
              <select clrSelect name="format" [(ngModel)]="e.format">
                <option value="text" i18n="@@feeds.formatText">Text: an address or CIDR per line</option>
                <option value="csv" i18n="@@feeds.formatCsv">CSV: a column</option>
                <option value="json" i18n="@@feeds.formatJson">JSON: a field</option>
              </select>
              <clr-control-helper>
                @switch (e.format) {
                  @case ('csv') { <ng-container i18n="@@feeds.csvHelp">Lines starting with # are skipped, as are values that aren't addresses (such as a header).</ng-container> }
                  @case ('json') { <ng-container i18n="@@feeds.jsonHelp">A JSON array (of objects or of strings), or one object per line.</ng-container> }
                  @default { <ng-container i18n="@@feeds.textHelp">The first word of each line; comments start with #, ; or //.</ng-container> }
                }
              </clr-control-helper>
            </clr-select-container>
            @if (e.format === 'csv') {
              <clr-input-container>
                <label i18n="@@feeds.column">Column</label>
                <input clrInput type="number" name="column" [(ngModel)]="e.column" min="1" max="100" />
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@feeds.delimiter">Delimiter</label>
                <input clrInput name="delimiter" [(ngModel)]="e.delimiter" maxlength="2" class="short" />
                <clr-control-helper i18n="@@feeds.delimiterHelp">One character, or \\t for tab.</clr-control-helper>
              </clr-input-container>
            }
            @if (e.format === 'json') {
              <clr-input-container>
                <label i18n="@@feeds.field">Field</label>
                <input clrInput name="field" [(ngModel)]="e.field" placeholder="ip" autocomplete="off" />
                <clr-control-helper i18n="@@feeds.fieldHelp">The field holding the address (ignored for an array of strings).</clr-control-helper>
              </clr-input-container>
            }
            <clr-input-container>
              <label i18n="@@feeds.interval">Update every</label>
              <input clrInput type="number" name="interval" [(ngModel)]="e.intervalHours" min="1" max="720" class="short" />
              <clr-control-helper i18n="@@feeds.intervalHelp">Hours. Most feeds change a few times a day; please don't poll more often than the publisher asks.</clr-control-helper>
            </clr-input-container>
            <clr-checkbox-container>
              <label i18n="@@feeds.options">Options</label>
              <clr-checkbox-wrapper>
                <input type="checkbox" clrCheckbox name="enabled" [(ngModel)]="e.enabled" />
                <label i18n="@@feeds.enabledOption">Enabled</label>
              </clr-checkbox-wrapper>
              <clr-checkbox-wrapper>
                <input type="checkbox" clrCheckbox name="notify" [(ngModel)]="e.notify" />
                <label i18n="@@feeds.notifyOption">Show a notice when matched</label>
              </clr-checkbox-wrapper>
              <clr-control-helper i18n="@@feeds.notifyHelp">Turn off for informational lists, such as Tor exit nodes: matches are still tagged.</clr-control-helper>
            </clr-checkbox-container>
          </form>
          @if (test(); as t) {
            @if (t.ok) {
              <div class="alert alert-success alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">
                <ng-container i18n="@@feeds.testOk">Found {{ count(t.entries ?? 0) }} addresses or ranges ({{ t.skipped }} lines skipped), e.g. {{ t.sample?.join(', ') }}.</ng-container>
              </span></div></div></div>
            } @else {
              <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ t.error }}</span></div></div></div>
            }
          }
          @if (formError()) {
            <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ formError() }}</span></div></div></div>
          }
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="runTest()" [clrLoading]="testing()" [disabled]="!editing()?.url" i18n="@@feeds.test">Test</button>
        <button type="button" class="btn btn-outline" (click)="editing.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="submit" form="feedform" class="btn btn-primary" [clrLoading]="busy()" [disabled]="!editing()?.name || !editing()?.url" i18n="@@common.save">Save</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="!!confirmDelete()" (clrModalOpenChange)="!$event && confirmDelete.set(null)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@feeds.deleteTitle">Delete {{ confirmDelete()?.name }}?</h3>
      <div class="modal-body"><p i18n="@@feeds.deleteText">Its addresses stop being matched. Flows already tagged keep the tag.</p></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmDelete.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="remove()" i18n="@@feeds.delete">Delete</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .alert { margin: 0 0 16px; }
    .modal-body .alert { margin: 12px 0 0; }
    .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .toolbar .btn { margin: 0 6px 0 0; }
    .toggle-col { width: 80px; }
    .order-col { width: 40px; color: var(--cds-alias-typography-color-300); }
    .toolbar > div { display: flex; align-items: center; flex-wrap: wrap; }
    .toolbar .btn-group { margin: 0 6px 0 0; }
    .toolbar .btn-group .btn { margin: 0; }
    clr-toggle-wrapper { margin: 0; }
    .url { font-family: var(--cds-global-typography-monospace-font-family, monospace); font-size: 12px; word-break: break-all; }
    .err { color: var(--cds-alias-status-danger); }
    .muted { color: var(--cds-alias-typography-color-300); }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 8px; }
    input.wide { width: 28rem; max-width: 100%; }
    input.short { width: 5rem; }
  `,
})
export class ThreatFeeds {
  readonly byId = trackByKey<{ id: number }>((f) => f.id);
  private api = inject(Api);
  readonly list = loader(() => true, () => this.api.threatFeeds());
  // By id, so the selection survives reloads (e.g. while reordering).
  readonly selectedId = signal<number | undefined>(undefined);
  readonly position = computed(() => (this.list.value()?.feeds ?? []).findIndex((f) => f.id === this.selectedId()));
  readonly selected = computed(() => this.list.value()?.feeds[this.position()]);
  readonly moving = signal(false);
  readonly selectedList = computed(() => {
    const f = this.selected();
    return f ? [f] : [];
  });
  readonly editing = signal<Partial<ThreatFeed> | null>(null);
  readonly confirmDelete = signal<ThreatFeed | null>(null);
  readonly busy = signal(false);
  readonly testing = signal(false);
  readonly test = signal<TestResult | null>(null);
  readonly formError = signal('');
  readonly pageError = signal('');
  readonly info = signal('');
  readonly feedCount = computed(() => this.list.value()?.feeds.length ?? 0);
  readonly enabledCount = computed(() => this.list.value()?.feeds.filter((f) => f.enabled).length ?? 0);
  readonly addTitle = $localize`:@@feeds.addTitle:Add threat feed`;
  readonly editTitle = $localize`:@@feeds.editTitle:Edit threat feed`;
  count = count;
  ago = ago;

  formatLabel(f: ThreatFeed) {
    switch (f.format) {
      case 'csv':
        return $localize`:@@feeds.csvColumn:CSV, column ${f.column}:column:`;
      case 'json':
        return $localize`:@@feeds.jsonField:JSON, ${f.field}:field:`;
    }
    return $localize`:@@feeds.text:Text`;
  }

  openEdit(f?: ThreatFeed) {
    this.editing.set(f ? { ...f } : blank());
    this.test.set(null);
    this.formError.set('');
  }

  async runTest() {
    const e = this.editing();
    if (!e) return;
    this.testing.set(true);
    this.test.set(null);
    try {
      this.test.set(await this.api.testThreatFeed(e));
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
      await this.api.saveThreatFeed(e);
      this.editing.set(null);
      this.selectedId.set(undefined);
      this.list.reload();
    } catch (err) {
      this.formError.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  async setEnabled(f: ThreatFeed, enabled: boolean) {
    try {
      await this.api.saveThreatFeed({ ...f, enabled });
      this.pageError.set('');
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
    this.list.reload();
  }

  async move(up: boolean) {
    const f = this.selected();
    if (!f) return;
    this.moving.set(true);
    try {
      await this.api.moveThreatFeed(f.id, up);
      this.pageError.set('');
      this.list.reload();
    } catch (err) {
      this.pageError.set(errorMessage(err));
    } finally {
      this.moving.set(false);
    }
  }

  async updateNow(f: ThreatFeed) {
    try {
      await this.api.updateThreatFeed(f.id);
      this.flash($localize`:@@feeds.updating:Updating ${f.name}:name:…`);
      setTimeout(() => this.list.reload(), 3000);
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
  }

  async addDefaults() {
    try {
      const r = await this.api.addDefaultThreatFeeds();
      this.flash($localize`:@@feeds.defaultsAdded:Added ${r.added}:count: default feeds.`);
      this.list.reload();
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
  }

  async remove() {
    const f = this.confirmDelete();
    this.confirmDelete.set(null);
    if (!f) return;
    try {
      await this.api.deleteThreatFeed(f.id);
      this.selectedId.set(undefined);
      this.pageError.set('');
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
    this.list.reload();
  }

  private flash(msg: string) {
    this.info.set(msg);
    setTimeout(() => this.info.set(''), 4000);
  }
}
