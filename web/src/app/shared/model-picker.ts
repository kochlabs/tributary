import {
  Component,
  computed,
  ElementRef,
  HostListener,
  inject,
  input,
  model,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';

export interface PickerModel {
  id: string;
  name?: string;
}

/** Most matches shown at once; typing narrows the rest. */
const SHOWN = 150;

/**
 * Picks a model from a long list: a search box where every word must match
 * (in any order, in the ID or the name), results grouped by the ID's prefix
 * ("openrouter/anthropic", "ollama"), and the keyboard.
 */
@Component({
  selector: 'nfa-model-picker',
  imports: [ClarityModule, FormsModule],
  template: `
    <button
      type="button"
      class="field"
      (click)="toggle()"
      [class.empty]="!value()"
      [attr.aria-expanded]="open()"
      aria-haspopup="listbox"
    >
      <span class="current">{{ value() || placeholder() }}</span>
      <cds-icon shape="angle" [attr.direction]="open() ? 'up' : 'down'" size="12"></cds-icon>
    </button>
    @if (open()) {
      <div class="panel" role="dialog">
        <input
          #search
          class="clr-input search"
          [ngModel]="filter()"
          (ngModelChange)="setFilter($event)"
          (keydown)="key($event)"
          placeholder="Search, e.g. haiku 5.5 or ollama qwen"
          i18n-placeholder="@@modelPicker.search"
          aria-label="Search models"
          i18n-aria-label="@@modelPicker.searchLabel"
          autocomplete="off"
          spellcheck="false"
        />
        <div class="list" role="listbox" #list>
          @for (g of groups(); track g.name) {
            @if (g.name) {
              <div class="group">{{ g.name }}</div>
            }
            @for (m of g.items; track m.id) {
              <div
                class="option"
                role="option"
                [class.active]="m.id === activeId()"
                [class.selected]="m.id === value()"
                [attr.aria-selected]="m.id === value()"
                [attr.data-id]="m.id"
                (mousedown)="$event.preventDefault()"
                (click)="pick(m.id)"
                (mouseenter)="activeId.set(m.id)"
              >
                <span class="short">{{ short(m.id) }}</span>
                @if (m.name && m.name !== short(m.id)) {
                  <span class="name">{{ m.name }}</span>
                }
                @if (m.id === value()) {
                  <cds-icon shape="check" size="14"></cds-icon>
                }
              </div>
            }
          } @empty {
            <div class="none" i18n="@@modelPicker.none">No model matches.</div>
          }
        </div>
        <div class="foot">
          @if (hidden() > 0) {
            <span i18n="@@modelPicker.more">{{ hidden() }} more: keep typing to narrow.</span>
          } @else {
            <span i18n="@@modelPicker.count">{{ total() }} of {{ models().length }} models</span>
          }
          @if (filter().trim() && !filter().trim().includes(' ') && !exact()) {
            <button
              type="button"
              class="btn btn-sm btn-link use"
              (click)="pick(filter().trim())"
              i18n="@@modelPicker.use"
            >
              Use “{{ filter().trim() }}” as the model ID
            </button>
          }
        </div>
      </div>
    }
  `,
  styles: `
    :host {
      display: inline-block;
      position: relative;
      width: 28rem;
      max-width: 100%;
    }
    .field {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      background: none;
      border: 0;
      border-bottom: 1px solid var(--cds-alias-object-interaction-border-color, #8c8c8c);
      padding: 2px 4px;
      height: 24px;
      cursor: pointer;
      color: inherit;
      font: inherit;
      text-align: left;
    }
    .field:focus {
      outline: none;
      border-bottom-color: var(--cds-alias-object-interaction-border-color-active, #0072a3);
    }
    .field.empty .current {
      color: var(--cds-alias-typography-color-200);
    }
    .current {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-family: var(--cds-global-typography-monospace-font-family, monospace);
      font-size: 13px;
    }
    .panel {
      position: absolute;
      z-index: 1000;
      top: 28px;
      left: 0;
      width: 34rem;
      max-width: 90vw;
      background: var(--cds-alias-object-overlay-background, #fff);
      color: var(--cds-alias-typography-color-400);
      border: 1px solid var(--cds-alias-object-border-color, #ccc);
      border-radius: 4px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.18);
      padding: 8px;
    }
    .search {
      width: 100%;
    }
    .list {
      max-height: 22rem;
      overflow-y: auto;
      margin-top: 6px;
    }
    .group {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--cds-alias-typography-color-300);
      padding: 8px 6px 2px;
      position: sticky;
      top: 0;
      background: var(--cds-alias-object-overlay-background, #fff);
    }
    .option {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 3px 6px;
      border-radius: 3px;
      cursor: pointer;
      font-size: 13px;
    }
    .option.active {
      background: var(--cds-alias-object-interaction-background-hover, #e8f1fb);
    }
    .option.selected {
      font-weight: 600;
    }
    .short {
      font-family: var(--cds-global-typography-monospace-font-family, monospace);
      white-space: nowrap;
    }
    .name {
      color: var(--cds-alias-typography-color-300);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .option cds-icon {
      margin-left: auto;
      color: var(--cds-alias-status-info, #0072a3);
    }
    .none {
      padding: 8px 6px;
      color: var(--cds-alias-typography-color-300);
      font-size: 13px;
    }
    .foot {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 6px;
      font-size: 12px;
      color: var(--cds-alias-typography-color-300);
    }
    .use {
      margin: 0;
      padding: 0;
      height: auto;
      line-height: inherit;
      text-transform: none;
    }
  `,
})
export class ModelPicker {
  readonly models = input<PickerModel[]>([]);
  readonly value = model<string>('');
  readonly placeholder = input($localize`:@@modelPicker.choose:Choose a model`);

  private el = inject(ElementRef<HTMLElement>);
  private search = viewChild<ElementRef<HTMLInputElement>>('search');
  private listEl = viewChild<ElementRef<HTMLElement>>('list');
  readonly open = signal(false);
  readonly filter = signal('');
  readonly activeId = signal('');

  /** Every word of the filter appears in the ID or the name, in any order. */
  private readonly matches = computed(() => {
    const words = this.filter().toLowerCase().split(/\s+/).filter(Boolean);
    return this.models().filter((m) => {
      const hay = (m.id + ' ' + (m.name ?? '')).toLowerCase();
      return words.every((w) => hay.includes(w));
    });
  });
  readonly total = computed(() => this.matches().length);
  readonly hidden = computed(() => Math.max(0, this.total() - SHOWN));
  readonly exact = computed(() => this.models().some((m) => m.id === this.filter().trim()));
  private readonly shown = computed(() => this.matches().slice(0, SHOWN));
  readonly groups = computed(() => {
    const out: { name: string; items: PickerModel[] }[] = [];
    const byName = new Map<string, PickerModel[]>();
    for (const m of [...this.shown()].sort((a, b) => a.id.localeCompare(b.id))) {
      const g = this.group(m.id);
      if (!byName.has(g)) {
        byName.set(g, []);
        out.push({ name: g, items: byName.get(g)! });
      }
      byName.get(g)!.push(m);
    }
    return out;
  });
  /** The options in display order, for the arrow keys. */
  private readonly flat = computed(() => this.groups().flatMap((g) => g.items));

  group = (id: string) => (id.includes('/') ? id.slice(0, id.lastIndexOf('/')) : '');
  short = (id: string) => (id.includes('/') ? id.slice(id.lastIndexOf('/') + 1) : id);

  toggle() {
    if (this.open()) {
      this.close();
      return;
    }
    this.filter.set('');
    this.activeId.set(this.value());
    this.open.set(true);
    setTimeout(() => {
      this.search()?.nativeElement.focus();
      this.scrollToActive();
    });
  }

  close() {
    this.open.set(false);
  }

  setFilter(v: string) {
    this.filter.set(v);
    this.activeId.set(this.flat()[0]?.id ?? '');
  }

  pick(id: string) {
    this.value.set(id);
    this.close();
  }

  key(ev: KeyboardEvent) {
    const list = this.flat();
    const i = list.findIndex((m) => m.id === this.activeId());
    switch (ev.key) {
      case 'ArrowDown':
      case 'ArrowUp': {
        ev.preventDefault();
        if (!list.length) return;
        const next = ev.key === 'ArrowDown' ? Math.min(list.length - 1, i + 1) : Math.max(0, i - 1);
        this.activeId.set(list[next].id);
        this.scrollToActive();
        return;
      }
      case 'Enter':
        ev.preventDefault();
        if (i >= 0) this.pick(list[i].id);
        else if (this.filter().trim()) this.pick(this.filter().trim());
        return;
      case 'Escape':
        ev.preventDefault();
        this.close();
        return;
    }
  }

  private scrollToActive() {
    setTimeout(() => {
      const id = this.activeId();
      const el = this.listEl()?.nativeElement.querySelector(`[data-id="${CSS.escape(id)}"]`);
      el?.scrollIntoView({ block: 'nearest' });
    });
  }

  @HostListener('document:mousedown', ['$event'])
  outside(ev: MouseEvent) {
    if (this.open() && !this.el.nativeElement.contains(ev.target as Node)) this.close();
  }
}
