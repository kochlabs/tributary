import { Component, inject } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { PRESETS, TimeRange } from '../core/time';

/**
 * Inline time range selector for page headers. Shares state with the header
 * time picker; a drag-zoom shows up as a custom range with a reset button.
 */
@Component({
  selector: 'nfa-range-bar',
  imports: [ClarityModule],
  template: `
    <div class="range-bar">
      <div class="btn-group btn-sm" role="group" aria-label="Time range">
        @for (p of presets; track p.id) {
          <button class="btn" [class.btn-primary]="!time.custom() && time.preset() === p.id" [class.btn-outline]="time.custom() || time.preset() !== p.id" (click)="time.setPreset(p.id)" [title]="p.label">{{ p.id }}</button>
        }
        <button class="btn" [class.btn-primary]="!!time.custom()" [class.btn-outline]="!time.custom()" (click)="time.customRequest.update((n) => n + 1)" title="Choose start and end">Custom…</button>
      </div>
      @if (time.custom()) {
        <span class="custom">
          <cds-icon shape="zoom-in"></cds-icon> {{ time.label() }}
          <button class="btn btn-sm btn-link" (click)="time.setPreset(time.preset())">Reset zoom</button>
        </span>
      }
    </div>
  `,
  styles: `
    .range-bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .btn-group { margin: 0; }
    .btn-group .btn { text-transform: none; letter-spacing: normal; }
    .custom { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--cds-alias-typography-color-400); }
    .custom .btn { margin: 0; }
  `,
})
export class RangeBar {
  readonly time = inject(TimeRange);
  readonly presets = PRESETS;
}
