import { Component, computed, model, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Filters } from '../core/api';
import { FILTER_FIELDS, filterLabel } from '../core/format';

/** Editable list of filter chips bound to a Filters model. */
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
  `,
})
export class FilterBar {
  readonly filters = model<Filters>({});
  readonly fields = FILTER_FIELDS;
  readonly editing = signal(false);
  readonly entries = computed(() => Object.entries(this.filters()).filter(([, v]) => !!v));
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
}
