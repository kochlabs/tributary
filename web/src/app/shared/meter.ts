import { Component, computed, input } from '@angular/core';

/**
 * Labelled usage meter: name and exact value with percentage on one line,
 * an inset bar below. Turns amber/red at the given thresholds.
 */
@Component({
  selector: 'nfa-meter',
  template: `
    <div class="meter" role="meter" [attr.aria-valuenow]="pct()" aria-valuemin="0" aria-valuemax="100" [attr.aria-label]="label()">
      <div class="meter-text">
        <span class="meter-label">{{ label() }}</span>
        <span class="meter-value">{{ value() }} <b>{{ pct().toFixed(0) }}%</b></span>
      </div>
      <div class="meter-track"><div class="meter-fill" [class]="level()" [style.width.%]="pct()"></div></div>
    </div>
  `,
  styles: `
    .meter { margin: 4px 0 12px; }
    .meter-text { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; margin-bottom: 4px; }
    .meter-label { color: var(--cds-alias-typography-color-300); }
    .meter-value { font-variant-numeric: tabular-nums; text-align: right; }
    .meter-track { height: 8px; border-radius: 4px; background: var(--cds-alias-object-border-color); overflow: hidden; }
    .meter-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
    .ok { background: var(--cds-alias-status-success); }
    .warn { background: var(--cds-alias-status-warning); }
    .bad { background: var(--cds-alias-status-danger); }
  `,
})
export class Meter {
  readonly label = input.required<string>();
  readonly value = input('');
  readonly percent = input.required<number>();
  readonly warnAt = input(75);
  readonly badAt = input(90);
  readonly pct = computed(() => Math.max(0, Math.min(100, this.percent() || 0)));
  readonly level = computed(() => (this.pct() >= this.badAt() ? 'bad' : this.pct() >= this.warnAt() ? 'warn' : 'ok'));
}
