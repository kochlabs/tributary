import { afterNextRender, Component, DestroyRef, effect, ElementRef, inject, input, output, viewChild } from '@angular/core';
import { BarChart, LineChart, PieChart, SankeyChart } from 'echarts/charts';
import {
  BrushComponent,
  GridComponent,
  LegendComponent,
  TitleComponent,
  ToolboxComponent,
  TooltipComponent,
} from 'echarts/components';
import * as echarts from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { Theme } from '../core/util';

echarts.use([LineChart, BarChart, PieChart, SankeyChart, GridComponent, TooltipComponent, LegendComponent, TitleComponent, BrushComponent, ToolboxComponent, CanvasRenderer]);

export type ChartOption = echarts.EChartsCoreOption;

/**
 * Thin ECharts wrapper. When `brushTime` is set, dragging horizontally across
 * the plot selects a time window and emits it via `timeSelect`.
 */
@Component({
  selector: 'nfa-chart',
  template: `<div #el class="nfa-chart" [style.height.px]="height()"></div>`,
  styles: `:host { display: block; position: relative; } .nfa-chart { width: 100%; }`,
})
export class Chart {
  readonly option = input.required<ChartOption | null>();
  readonly height = input(280);
  readonly loading = input(false);
  readonly brushTime = input(false);
  readonly chartClick = output<{ name: string; seriesName: string; data: unknown; seriesId?: string; dataType?: string }>();
  readonly timeSelect = output<{ from: number; to: number }>();

  private el = viewChild.required<ElementRef<HTMLDivElement>>('el');
  private theme = inject(Theme);
  private chart?: echarts.ECharts;

  constructor() {
    const destroy = inject(DestroyRef);
    afterNextRender(() => {
      this.init();
      const ro = new ResizeObserver(() => this.chart?.resize());
      ro.observe(this.el().nativeElement);
      destroy.onDestroy(() => {
        ro.disconnect();
        this.chart?.dispose();
      });
    });
    effect(() => {
      const opt = this.option();
      this.theme.mode(); // re-render on theme switch so colors are re-read
      if (this.chart && opt) this.render(opt);
    });
    effect(() => {
      const l = this.loading();
      if (!this.chart) return;
      if (l) this.chart.showLoading('default', { text: '', color: '#0072a3', maskColor: 'rgba(128,128,128,0.08)', lineWidth: 2, spinnerRadius: 12 });
      else this.chart.hideLoading();
    });
  }

  private init() {
    this.chart = echarts.init(this.el().nativeElement, undefined, { renderer: 'canvas' });
    this.chart.on('click', (p: any) => this.chartClick.emit({ name: p.name, seriesName: p.seriesName, data: p.data, seriesId: p.seriesId, dataType: p.dataType }));
    this.chart.on('brushEnd', (p: any) => {
      const range = p.areas?.[0]?.coordRange;
      if (range && range[1] - range[0] > 60_000) this.timeSelect.emit({ from: Math.round(range[0]), to: Math.round(range[1]) });
      this.chart?.dispatchAction({ type: 'brush', areas: [] });
    });
    const opt = this.option();
    if (opt) this.render(opt);
  }

  private render(opt: ChartOption) {
    const c = this.chart!;
    const full = { ...themed(), ...opt };
    if (this.brushTime()) {
      Object.assign(full, {
        brush: { xAxisIndex: 0, brushType: 'lineX', brushMode: 'single', transformable: false, brushStyle: { color: 'rgba(0,114,163,0.15)', borderColor: 'rgba(0,114,163,0.6)', borderWidth: 1 } },
        toolbox: { show: false },
      });
    }
    c.setOption(full, { notMerge: true });
    if (this.brushTime()) {
      c.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: 'lineX', brushMode: 'single' } });
    }
  }
}

function cssVar(name: string, fallback: string) {
  const v = getComputedStyle(document.body).getPropertyValue(name).trim();
  return v || fallback;
}

export function chartColors() {
  return {
    text: cssVar('--cds-alias-typography-color-400', '#454545'),
    muted: cssVar('--cds-alias-typography-color-300', '#666'),
    grid: cssVar('--cds-alias-object-border-color', '#ddd'),
    bg: cssVar('--cds-alias-object-container-background', '#fff'),
    font: cssVar('--cds-alias-typography-font-family', 'Clarity City, Avenir Next, sans-serif'),
  };
}

function themed(): ChartOption {
  const c = chartColors();
  return {
    backgroundColor: 'transparent',
    textStyle: { color: c.text, fontFamily: c.font },
    color: PALETTE,
  };
}

export const PALETTE = ['#0079b8', '#00a1a1', '#f6a623', '#8f5bc2', '#e15a3d', '#5aa220', '#0095d3', '#d6449c', '#a67c2e', '#4d7cfe', '#c25700', '#2f9e8f'];
export const OTHER_COLOR = '#8c8c8c';
