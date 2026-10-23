import { Component } from '@angular/core';
import { ClarityModule } from '@clr/angular';

/** Reports: a placeholder for saved and scheduled reports. */
@Component({
  selector: 'nfa-reports',
  imports: [ClarityModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.reports">Reports</h2>
        <p class="subtitle" i18n="@@reports.subtitle">Saved and scheduled reports.</p>
      </div>
    </div>
    <div class="empty">
      <cds-icon shape="file-group" size="xl"></cds-icon>
      <p i18n="@@reports.empty">No reports yet. This is where saved and scheduled reports will live.</p>
    </div>
  `,
  styles: `
    .empty { display: flex; flex-direction: column; align-items: center; padding: 64px 16px; color: var(--cds-alias-typography-color-300); }
    .empty p { margin-top: 12px; }
  `,
})
export class Reports {}
