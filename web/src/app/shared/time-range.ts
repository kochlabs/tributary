import { Component, effect, inject, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { PRESETS, TimeRange } from '../core/time';

function toLocalInput(ms: number) {
  const d = new Date(ms - new Date(ms).getTimezoneOffset() * 60000);
  return d.toISOString().slice(0, 16);
}

@Component({
  selector: 'nfa-time-range',
  imports: [ClarityModule, FormsModule],
  template: `
    <clr-dropdown class="time-dropdown">
      <button class="time-btn" clrDropdownTrigger aria-label="Select time range">
        <cds-icon shape="clock"></cds-icon>
        <span class="time-label">{{ time.label() }}</span>
        <cds-icon shape="angle" direction="down"></cds-icon>
      </button>
      <clr-dropdown-menu *clrIfOpen clrPosition="bottom-right">
        <h4 class="dropdown-header">Time range</h4>
        @for (p of presets; track p.id) {
          <button clrDropdownItem [class.active]="!time.custom() && time.preset() === p.id" (click)="time.setPreset(p.id)">{{ p.label }}</button>
        }
        <div class="dropdown-divider" role="separator"></div>
        <button clrDropdownItem (click)="openCustom()">Custom range…</button>
        <button clrDropdownItem (click)="time.autoRefresh.set(!time.autoRefresh())">
          <cds-icon [shape]="time.autoRefresh() ? 'check' : 'times'"></cds-icon> Auto-refresh (60s)
        </button>
      </clr-dropdown-menu>
    </clr-dropdown>
    <button class="nav-icon refresh-btn" (click)="time.refresh()" aria-label="Refresh" title="Refresh now">
      <cds-icon shape="refresh"></cds-icon>
    </button>

    <clr-modal [(clrModalOpen)]="customOpen" clrModalSize="md">
      <h3 class="modal-title">Custom time range</h3>
      <div class="modal-body">
        <form clrForm clrLayout="horizontal">
          <clr-input-container>
            <label>From</label>
            <input clrInput type="datetime-local" name="from" [(ngModel)]="from" />
          </clr-input-container>
          <clr-input-container>
            <label>To</label>
            <input clrInput type="datetime-local" name="to" [(ngModel)]="to" />
          </clr-input-container>
        </form>
        @if (err()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ err() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="customOpen.set(false)">Cancel</button>
        <button type="button" class="btn btn-primary" (click)="applyCustom()">Apply</button>
      </div>
    </clr-modal>
  `,
  styles: `
    :host { display: flex; align-items: center; color: #fafafa; }
    .time-btn { display: flex; align-items: center; gap: 6px; background: none; border: 0; color: #fafafa; cursor: pointer; padding: 0 12px; height: 100%; font: inherit; }
    .time-label { white-space: nowrap; }
    .refresh-btn { background: none; border: 0; color: #fafafa; cursor: pointer; padding: 0 12px; }
    .dropdown-item.active { font-weight: 600; }
    @media (max-width: 768px) { .time-label { display: none; } }
  `,
})
export class TimeRangePicker {
  readonly time = inject(TimeRange);
  readonly presets = PRESETS;
  readonly customOpen = signal(false);
  from = '';
  to = '';
  readonly err = signal('');

  constructor() {
    let first = true;
    effect(() => {
      this.time.customRequest();
      if (first) {
        first = false;
        return;
      }
      untracked(() => this.openCustom());
    });
  }

  openCustom() {
    const w = this.time.window();
    this.from = toLocalInput(w.from);
    this.to = toLocalInput(w.to);
    this.err.set('');
    this.customOpen.set(true);
  }

  applyCustom() {
    const f = new Date(this.from).getTime();
    const t = new Date(this.to).getTime();
    if (!isFinite(f) || !isFinite(t) || t <= f) {
      this.err.set('"To" must be after "From".');
      return;
    }
    this.time.setCustom(f, t);
    this.customOpen.set(false);
  }
}
