import { Component, DestroyRef, inject, signal } from '@angular/core';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage } from '../core/api';

const RANGES = [
  { id: '24h', label: $localize`:@@reports.range.day:Last 24 hours` },
  { id: '7d', label: $localize`:@@reports.range.week:Last 7 days` },
  { id: '30d', label: $localize`:@@reports.range.month:Last 30 days` },
];

/** Reports, rendered as PDF on the appliance and shown in the browser's viewer. */
@Component({
  selector: 'nfa-reports',
  imports: [ClarityModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.reports">Reports</h2>
        <p class="subtitle" i18n="@@reports.subtitle2">PDF reports, generated on the appliance.</p>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span i18n="@@reports.summary">Network summary</span>
        <div class="controls">
          <div class="btn-group btn-sm" role="group">
            @for (r of ranges; track r.id) {
              <button
                class="btn"
                [class.btn-primary]="range() === r.id"
                [class.btn-outline]="range() !== r.id"
                (click)="load(r.id)"
              >
                {{ r.label }}
              </button>
            }
          </div>
          <button class="btn btn-sm btn-outline" [disabled]="!blobUrl()" (click)="download()">
            <cds-icon shape="download"></cds-icon>
            <ng-container i18n="@@reports.download">Download PDF</ng-container>
          </button>
        </div>
      </div>
      <div class="card-block viewer">
        @if (loading()) {
          <div class="state">
            <span class="spinner spinner-md"></span>
            <span i18n="@@reports.generating"
              >Generating the report… longer ranges take a while.</span
            >
          </div>
        } @else if (error()) {
          <div class="state error"><cds-icon shape="error-standard"></cds-icon> {{ error() }}</div>
        } @else if (frameUrl(); as u) {
          <iframe [src]="u" title="Network summary" i18n-title="@@reports.summary"></iframe>
        }
      </div>
    </div>
  `,
  styles: `
    .card {
      margin-top: 0;
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .controls {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .controls .btn-group,
    .controls .btn {
      margin: 0;
    }
    .viewer {
      padding: 0;
      height: calc(100vh - 230px);
      min-height: 480px;
    }
    .state {
      height: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      color: var(--cds-alias-typography-color-300);
    }
    .state.error {
      color: var(--cds-alias-status-danger);
    }
    iframe {
      display: block;
      width: 100%;
      height: 100%;
      border: 0;
    }
  `,
})
export class Reports {
  private api = inject(Api);
  private sanitizer = inject(DomSanitizer);
  readonly ranges = RANGES;
  readonly range = signal('7d');
  readonly loading = signal(false);
  readonly error = signal('');
  readonly blobUrl = signal('');
  readonly frameUrl = signal<SafeResourceUrl | null>(null);
  private seq = 0;

  constructor() {
    this.load('7d');
    inject(DestroyRef).onDestroy(() => this.setBlob(''));
  }

  private setBlob(url: string) {
    if (this.blobUrl()) URL.revokeObjectURL(this.blobUrl());
    this.blobUrl.set(url);
    this.frameUrl.set(url ? this.sanitizer.bypassSecurityTrustResourceUrl(url) : null);
  }

  async load(range: string) {
    const my = ++this.seq;
    this.range.set(range);
    this.loading.set(true);
    this.error.set('');
    this.setBlob('');
    try {
      const blob = await this.api.summaryReport(range);
      if (my === this.seq) this.setBlob(URL.createObjectURL(blob));
    } catch (e) {
      if (my === this.seq) this.error.set(errorMessage(e));
    } finally {
      if (my === this.seq) this.loading.set(false);
    }
  }

  /** Saves the PDF already shown, without generating it again. */
  download() {
    const a = document.createElement('a');
    a.href = this.blobUrl();
    a.download = `tributary-summary-${this.range()}-${new Date().toISOString().slice(0, 10)}.pdf`;
    a.click();
  }
}
