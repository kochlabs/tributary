import { Component, computed, input, output } from '@angular/core';
import { Metric, TopRow } from '../core/api';
import { bytes, count, rate } from '../core/format';
import { PALETTE } from './chart';

/** Full-width conversations table: device and remote endpoint in their own columns. */
@Component({
  selector: 'nfa-conversation-table',
  template: `
    @if (rows().length) {
      <table class="table table-compact table-noborder conv">
        <thead>
          <tr>
            <th class="left">Device</th>
            <th class="arrow"></th>
            <th class="left">Remote</th>
            <th class="num">{{ metricLabel() }}</th>
            <th class="num">Volume</th>
            <th class="share">Share</th>
          </tr>
        </thead>
        <tbody>
          @for (r of rows(); track r.key; let i = $index) {
            <tr class="clickable" (click)="drill.emit(r)" title="Analyze this conversation">
              @for (e of ends(r); track $index; let first = $first) {
                @if (!first) {
                  <td class="arrow">⇄</td>
                }
                <td class="left">
                  <div class="name">
                    @if (first) {
                      <span class="swatch" [style.background]="color(i)"></span>
                    }
                    <span class="truncate" [title]="e.name">{{ e.name }}</span>
                  </div>
                  @if (e.detail) {
                    <div class="detail truncate" [title]="e.detail">{{ e.detail }}</div>
                  }
                </td>
              }
              <td class="num">{{ fmtRate(r.rate) }}</td>
              <td class="num">{{ fmtVol(r) }}</td>
              <td class="share">
                <span class="bar"><span class="fill" [style.width.%]="(r.pct / maxPct()) * 100" [style.background]="color(i)"></span></span>
                <span class="pct">{{ r.pct.toFixed(1) }}%</span>
              </td>
            </tr>
          }
        </tbody>
      </table>
    } @else {
      <div class="empty">No conversations in this time range.</div>
    }
  `,
  styles: `
    .conv { margin: 0; width: 100%; table-layout: fixed; }
    .conv th, .conv td { padding-top: 5px; padding-bottom: 5px; vertical-align: top; }
    .left { text-align: left; }
    .arrow { width: 28px; text-align: center; color: var(--cds-alias-typography-color-300); }
    .num { width: 110px; text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
    .share { width: 140px; text-align: right; white-space: nowrap; }
    .name { display: flex; align-items: center; gap: 6px; min-width: 0; }
    .detail { font-size: 11px; color: var(--cds-alias-typography-color-300); margin-left: 14px; }
    .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
    .swatch { width: 8px; height: 8px; border-radius: 2px; flex: none; }
    .clickable { cursor: pointer; }
    .clickable:hover { background: var(--cds-alias-object-interaction-background-hover, rgba(0,0,0,.04)); }
    .bar { display: inline-block; width: 70px; height: 6px; background: var(--cds-alias-object-border-color); border-radius: 3px; overflow: hidden; vertical-align: middle; }
    .fill { display: block; height: 100%; }
    .pct { display: inline-block; width: 46px; text-align: right; font-size: 11px; font-variant-numeric: tabular-nums; }
    .empty { padding: 24px; text-align: center; color: var(--cds-alias-typography-color-300); }
  `,
})
export class ConversationTable {
  readonly rows = input<TopRow[]>([]);
  readonly metric = input<Metric>('bps');
  readonly drill = output<TopRow>();
  readonly maxPct = computed(() => Math.max(1, ...this.rows().map((r) => r.pct)));
  readonly metricLabel = computed(() => ({ bps: 'Avg bps', pps: 'Avg pps', fps: 'Flows/s' })[this.metric()]);

  ends(r: TopRow) {
    if (r.ends?.length === 2) return r.ends;
    const [a, b] = r.label.split(' ⇄ ');
    return [{ name: a ?? r.label, detail: '' }, { name: b ?? '', detail: '' }];
  }
  color(i: number) {
    return PALETTE[i % PALETTE.length];
  }
  fmtRate(v: number) {
    return rate(v, this.metric());
  }
  fmtVol(r: TopRow) {
    return this.metric() === 'pps' ? count(r.packets) + ' pkts' : this.metric() === 'fps' ? count(r.flows) + ' flows' : bytes(r.bytes);
  }
}
