import { Component, computed, input, output } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { Metric, TopRow } from '../core/api';
import { bytes, count, rate } from '../core/format';
import { PALETTE } from './chart';

/** Compact ranked table with inline share bars, used on dashboard cards. */
@Component({
  selector: 'nfa-top-table',
  imports: [ClarityModule],
  template: `
    @if (rows().length) {
      <table class="table table-compact table-noborder top-table">
        <thead>
          <tr>
            <th class="left">{{ title() }}</th>
            <th class="num">{{ metricLabel() }}</th>
            <th class="num hide-sm" i18n="@@topTable.volume">Volume</th>
            <th class="share" i18n="@@topTable.share">Share</th>
          </tr>
        </thead>
        <tbody>
          @for (r of rows(); track r.key; let i = $index) {
            <tr (click)="drill.emit(r)" class="clickable" [title]="filterTitle(r)">
              <td class="left label-cell">
                <span class="swatch" [style.background]="color(i)"></span>
                <span class="label-text">
                  @if (r.label.includes(' ⇄ ')) {
                    <span class="truncate" [title]="r.label">{{ r.label.split(' ⇄ ')[0] }}</span>
                    <span class="truncate peer" [title]="r.label">⇄ {{ r.label.split(' ⇄ ')[1] }}</span>
                  } @else {
                    <span class="truncate" [title]="r.label">{{ r.label }}</span>
                  }
                  @if (r.detail) {
                    <span class="truncate detail" [title]="r.detail">{{ r.detail }}</span>
                  }
                </span>
              </td>
              <td class="num">{{ fmtRate(r.rate) }}</td>
              <td class="num hide-sm">{{ fmtVol(r) }}</td>
              <td class="share">
                <div class="bar"><div class="fill" [style.width.%]="(r.pct / maxPct()) * 100" [style.background]="color(i)"></div></div>
                <span class="pct">{{ r.pct.toFixed(1) }}%</span>
              </td>
            </tr>
          }
        </tbody>
      </table>
    } @else {
      <div class="empty" i18n="@@topTable.empty">No traffic in this time range.</div>
    }
  `,
  styles: `
    .top-table { margin: 0; width: 100%; table-layout: fixed; }
    .top-table th, .top-table td { padding-top: 4px; padding-bottom: 4px; }
    .left { text-align: left; }
    .num { text-align: right; width: 92px; white-space: nowrap; font-variant-numeric: tabular-nums; }
    .share { width: 132px; white-space: nowrap; text-align: right; }
    .label-cell { display: flex; align-items: center; gap: 6px; min-width: 0; }
    .label-text { display: flex; flex-direction: column; min-width: 0; }
    .peer { font-size: 12px; }
    .detail { font-size: 11px; color: var(--cds-alias-typography-color-300); line-height: 1.2; }
    .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .swatch { width: 8px; height: 8px; border-radius: 2px; flex: none; }
    .clickable { cursor: pointer; }
    .clickable:hover { background: var(--cds-alias-object-interaction-background-hover, rgba(0,0,0,.04)); }
    .bar { display: inline-block; width: 70px; height: 6px; background: var(--cds-alias-object-border-color); border-radius: 3px; overflow: hidden; vertical-align: middle; }
    .fill { height: 100%; border-radius: 3px; }
    .pct { display: inline-block; width: 44px; text-align: right; font-variant-numeric: tabular-nums; font-size: 11px; }
    .empty { padding: 24px; text-align: center; color: var(--cds-alias-typography-color-300); }
    @media (max-width: 600px) { .hide-sm { display: none; } }
  `,
})
export class TopTable {
  readonly rows = input<TopRow[]>([]);
  readonly metric = input<Metric>('bps');
  readonly title = input($localize`:@@common.name:Name`);
  readonly drill = output<TopRow>();
  readonly maxPct = computed(() => Math.max(1, ...this.rows().map((r) => r.pct)));
  readonly metricLabel = computed(() => ({ bps: $localize`:@@topTable.avgBps:Avg bps`, pps: $localize`:@@topTable.avgPps:Avg pps`, fps: $localize`:@@topTable.flowsPerSec:Flows/s` })[this.metric()]);

  filterTitle(r: TopRow) {
    return $localize`:@@topTable.filterOn:Filter on ${r.label}:label:`;
  }
  color(i: number) {
    return PALETTE[i % PALETTE.length];
  }
  fmtRate(v: number) {
    return rate(v, this.metric());
  }
  fmtVol(r: TopRow) {
    return this.metric() === 'pps' ? $localize`:@@topTable.pkts:${count(r.packets)}:count: pkts` : this.metric() === 'fps' ? $localize`:@@topTable.flows:${count(r.flows)}:count: flows` : bytes(r.bytes);
  }
}
