import { Component, computed, effect, inject, input, model, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, Filters, QueryIssue } from '../core/api';
import { FILTER_FIELDS, filterLabel } from '../core/format';

/**
 * Editable list of filter chips bound to a Filters model, with a query box
 * (the "q" key, docs/design/QUERY-LANGUAGE.md) combined with them by AND.
 */
@Component({
  selector: 'nfa-filter-bar',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="filter-bar">
      <cds-icon shape="filter" class="filter-icon"></cds-icon>
      @for (f of entries(); track f[0]) {
        <span class="label label-blue filter-chip" [class.negated]="f[1].startsWith('!')">
          <button class="chip-edit" (click)="edit(f[0])" [title]="editTitle(f[0])">
            {{ label(f[0]) }}{{ f[1].startsWith('!') ? ' ≠ ' : ': ' }}<b>{{ f[1].replace('!', '') }}</b>
          </button>
          <button class="chip-x" (click)="remove(f[0])" [attr.aria-label]="removeLabel(f[0])"><cds-icon shape="times" size="12"></cds-icon></button>
        </span>
      }
      @if (!editing()) {
        <button class="btn btn-sm btn-link add-btn" (click)="startAdd()"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@filterBar.addFilter">Add filter</ng-container></button>
        @if (entries().length) {
          <button class="btn btn-sm btn-link" (click)="clear()" i18n="@@filterBar.clearAll">Clear all</button>
        }
      } @else {
        <form class="add-form" (ngSubmit)="apply()">
          <select class="clr-select" name="field" [(ngModel)]="field" aria-label="Filter field" i18n-aria-label="@@filterBar.field">
            @for (f of fields; track f.id) {
              <option [value]="f.id">{{ f.label }}</option>
            }
          </select>
          <label class="neg"><input type="checkbox" name="neg" [(ngModel)]="neg" /> <ng-container i18n="Checkbox negating a filter@@filterBar.not">not</ng-container></label>
          <input class="clr-input value-input" name="value" [(ngModel)]="value" [placeholder]="hint()" autofocus aria-label="Filter value" i18n-aria-label="@@filterBar.value" />
          <button class="btn btn-sm btn-primary" type="submit" [disabled]="!value.trim()" i18n="@@filterBar.apply">Apply</button>
          <button class="btn btn-sm btn-link" type="button" (click)="editing.set(false)" i18n="@@common.cancel">Cancel</button>
        </form>
      }
    </div>
    <div class="filter-help" i18n="@@filterBar.help">Comma-separate values to match any of them; CIDR prefixes and port ranges (8000-8100) are supported.</div>
    @if (query()) {
      <form class="query-form" (ngSubmit)="runQuery()">
        <cds-icon shape="search" class="filter-icon"></cds-icon>
        <input
          class="clr-input query-input"
          name="query"
          [(ngModel)]="queryText"
          (ngModelChange)="queryError.set(null)"
          placeholder="Query, e.g. host:nas AND NOT country:(US OR CA)"
          i18n-placeholder="@@filterBar.queryPlaceholder"
          aria-label="Query"
          i18n-aria-label="@@filterBar.query"
          spellcheck="false"
          autocomplete="off"
        />
        <button class="btn btn-sm btn-primary" type="submit" [disabled]="checking()" i18n="@@filterBar.run">Run</button>
        @if (filters()['q']) {
          <button class="btn btn-sm btn-link" type="button" (click)="clearQuery()" i18n="@@filterBar.clearQuery">Clear</button>
        }
      </form>
      @if (queryError(); as e) {
        <div class="query-issue error" role="alert">
          <code>{{ before(e) }}<mark>{{ marked(e) }}</mark>{{ after(e) }}</code>
          <div>{{ e.message }}@if (e.hint) {&nbsp;· {{ e.hint }}}</div>
        </div>
      }
      @if (!queryError()) {
        @for (wn of queryWarnings(); track $index) {
          <div class="query-issue warn">
            <cds-icon shape="exclamation-triangle" status="warning" size="14"></cds-icon>
            {{ wn.message }}@if (wn.hint) {&nbsp;· {{ wn.hint }}}<span class="muted nothing" i18n="@@filterBar.matchesNothing">(matches nothing)</span>
          </div>
        }
      }
    }
  `,
  styles: `
    .filter-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; min-height: 36px; }
    .filter-icon { color: var(--cds-alias-typography-color-300); }
    .filter-chip { display: inline-flex; align-items: center; gap: 2px; margin: 0; padding-right: 2px; }
    .filter-chip.negated { --clr-label-bg-color: #fde8e3; }
    .chip-edit, .chip-x { background: none; border: 0; padding: 0 2px; color: inherit; cursor: pointer; font: inherit; }
    .add-form { display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .value-input { width: 220px; }
    .neg { font-size: 12px; display: inline-flex; align-items: center; gap: 4px; }
    .filter-help { font-size: 11px; color: var(--cds-alias-typography-color-300); margin-top: 2px; }
    .add-btn { margin: 0; }
    .query-form { display: flex; align-items: center; gap: 6px; margin-top: 8px; }
    .query-input { flex: 1; font-family: var(--cds-global-typography-monospace-font-family, monospace); font-size: 13px; }
    .query-form .btn { margin: 0; }
    .query-issue { font-size: 12px; margin: 4px 0 0 22px; }
    .query-issue.error { color: var(--cds-alias-status-danger); }
    .query-issue code { display: block; white-space: pre-wrap; color: var(--cds-alias-typography-color-400); background: none; padding: 0; }
    .query-issue mark { background: none; color: var(--cds-alias-status-danger); text-decoration: underline wavy var(--cds-alias-status-danger); }
    .muted { color: var(--cds-alias-typography-color-300); }
    .nothing { margin-left: 4px; }
  `,
})
export class FilterBar {
  readonly filters = model<Filters>({});
  /** Show the query box (reports don't store queries yet). */
  readonly query = input(true);
  readonly fields = FILTER_FIELDS;
  readonly editing = signal(false);
  readonly entries = computed(() => Object.entries(this.filters()).filter(([k, v]) => !!v && k !== 'q'));
  private api = inject(Api);
  queryText = '';
  readonly checking = signal(false);
  readonly queryError = signal<QueryIssue | null>(null);
  readonly queryWarnings = signal<QueryIssue[]>([]);
  private checked = '';
  field = 'host';
  value = '';
  neg = false;
  label = filterLabel;

  editTitle(key: string) {
    return $localize`:@@filterBar.editTitle:Edit ${this.label(key)}:field:`;
  }

  removeLabel(key: string) {
    return $localize`:@@filterBar.removeLabel:Remove ${this.label(key)}:field: filter`;
  }

  hint() {
    return FILTER_FIELDS.find((f) => f.id === this.field)?.hint ?? '';
  }

  startAdd() {
    this.field = 'host';
    this.value = '';
    this.neg = false;
    this.editing.set(true);
  }

  edit(key: string) {
    const v = this.filters()[key] ?? '';
    this.field = key;
    this.neg = v.startsWith('!');
    this.value = v.replace(/^!/, '');
    this.editing.set(true);
  }

  apply() {
    const v = this.value.trim();
    if (!v) return;
    this.filters.set({ ...this.filters(), [this.field]: (this.neg ? '!' : '') + v });
    this.editing.set(false);
  }

  remove(key: string) {
    const f = { ...this.filters() };
    delete f[key];
    this.filters.set(f);
  }

  clear() {
    this.filters.set({});
  }

  constructor() {
    // A query from the URL (or set by a page) shows in the box, with its warnings.
    effect(() => {
      const q = this.filters()['q'] ?? '';
      if (q === this.checked) return;
      this.queryText = q;
      this.checked = q;
      this.queryWarnings.set([]);
      if (q) this.api.checkQuery(q).then((r) => this.queryWarnings.set(r.warnings));
    });
  }

  async runQuery() {
    const text = this.queryText.trim();
    if (!text) {
      this.clearQuery();
      return;
    }
    this.checking.set(true);
    const r = await this.api.checkQuery(text);
    this.checking.set(false);
    if (r.error) {
      this.queryError.set(r.error);
      return;
    }
    this.queryError.set(null);
    this.queryWarnings.set(r.warnings);
    this.checked = r.query ?? '';
    this.queryText = this.checked;
    this.filters.set({ ...this.filters(), q: this.checked });
  }

  clearQuery() {
    const f = { ...this.filters() };
    delete f['q'];
    this.queryText = '';
    this.queryError.set(null);
    this.queryWarnings.set([]);
    this.filters.set(f);
  }

  // The error's text, split around the part it is about.
  before = (e: QueryIssue) => this.queryText.slice(0, e.pos);
  marked = (e: QueryIssue) => this.queryText.slice(e.pos, e.pos + e.len) || ' ';
  after = (e: QueryIssue) => this.queryText.slice(e.pos + e.len);
}
