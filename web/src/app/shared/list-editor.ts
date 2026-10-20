import { Component, ElementRef, inject, input, model } from '@angular/core';
import { ClarityModule } from '@clr/angular';

/**
 * Edits a list of short values (addresses, prefixes) one per row, with a
 * remove button per row and "Add" below; optionally reorderable, for lists
 * where order matters. Empty rows are allowed while editing; callers drop
 * them when saving. `validate` returns an error message for a bad value.
 */
@Component({
  selector: 'nfa-list-editor',
  imports: [ClarityModule],
  template: `
    @for (v of items(); track $index; let i = $index, first = $first, last = $last) {
      @let err = v.trim() ? validate()(v.trim()) : null;
      <div class="row" [class.has-error]="!!err">
        @if (ordered()) {
          <span class="order">
            <button type="button" class="btn btn-icon btn-link btn-sm" [disabled]="first" (click)="move(i, -1)" [attr.aria-label]="moveUpLabel">
              <cds-icon shape="angle" direction="up"></cds-icon>
            </button>
            <button type="button" class="btn btn-icon btn-link btn-sm" [disabled]="last" (click)="move(i, 1)" [attr.aria-label]="moveDownLabel">
              <cds-icon shape="angle" direction="down"></cds-icon>
            </button>
          </span>
        }
        <input class="clr-input value" [value]="v" (input)="set(i, $any($event.target).value)" (keydown.enter)="$event.preventDefault(); add()"
          [placeholder]="placeholder()" [attr.aria-label]="label()" [attr.aria-invalid]="!!err" spellcheck="false" autocomplete="off" />
        <button type="button" class="btn btn-icon btn-link btn-sm remove" (click)="remove(i)" [attr.aria-label]="removeLabel">
          <cds-icon shape="times"></cds-icon>
        </button>
        @if (err) {
          <span class="err"><cds-icon shape="error-standard"></cds-icon> {{ err }}</span>
        }
      </div>
    }
    <button type="button" class="btn btn-link btn-sm add" (click)="add()"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@common.add">Add</ng-container></button>
  `,
  styles: `
    :host { display: block; }
    .row { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; margin-bottom: 2px; }
    .value { width: 100%; max-width: 30rem; flex: 1 1 18rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
    .has-error .value { border-bottom-color: var(--cds-alias-status-danger); }
    .order { display: inline-flex; }
    .order .btn, .remove { margin: 0; }
    .err { flex-basis: 100%; font-size: 12px; color: var(--cds-alias-status-danger); }
    .add { margin: 4px 0 0; padding-left: 0; }
  `,
})
export class ListEditor {
  readonly items = model.required<string[]>();
  readonly placeholder = input('');
  readonly label = input('');
  readonly ordered = input(false);
  readonly validate = input<(v: string) => string | null>(() => null);
  private el = inject<ElementRef<HTMLElement>>(ElementRef);

  readonly moveUpLabel = $localize`:@@listEditor.moveUp:Move up`;
  readonly moveDownLabel = $localize`:@@listEditor.moveDown:Move down`;
  readonly removeLabel = $localize`:@@listEditor.remove:Remove`;

  set(i: number, v: string) {
    this.items.update((l) => l.map((x, j) => (j === i ? v : x)));
  }

  remove(i: number) {
    this.items.update((l) => l.filter((_, j) => j !== i));
  }

  move(i: number, d: number) {
    this.items.update((l) => {
      const n = [...l];
      [n[i], n[i + d]] = [n[i + d], n[i]];
      return n;
    });
  }

  /** Adds an empty row (unless the last one is still empty) and focuses it. */
  add() {
    const l = this.items();
    if (!l.length || l[l.length - 1].trim()) this.items.set([...l, '']);
    setTimeout(() => {
      const inputs = this.el.nativeElement.querySelectorAll<HTMLInputElement>('input.value');
      inputs[inputs.length - 1]?.focus();
    });
  }
}

/** Non-empty, trimmed values of a list being edited. */
export function listValues(l: string[]): string[] {
  return l.map((x) => x.trim()).filter(Boolean);
}
