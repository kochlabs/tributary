import { Component, inject } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { Api } from '../core/api';
import { dateTime } from '../core/format';
import { loader, trackByKey } from '../core/util';

@Component({
  selector: 'nfa-audit',
  imports: [ClarityModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@audit.title">Audit Log</h2>
        <p class="subtitle" i18n="@@audit.subtitle">Sign-ins and configuration changes (most recent 500)</p>
      </div>
      <button class="btn btn-sm btn-outline" (click)="log.reload()"><cds-icon shape="refresh"></cds-icon> <ng-container i18n="@@common.refresh">Refresh</ng-container></button>
    </div>
    <clr-datagrid class="datagrid-compact" [clrDgLoading]="log.loading()">
      <clr-dg-column [clrDgField]="'ts'" [clrDgSortOrder]="-1" i18n="@@audit.col.time">Time</clr-dg-column>
      <clr-dg-column [clrDgField]="'username'" i18n="@@audit.col.user">User</clr-dg-column>
      <clr-dg-column [clrDgField]="'action'" i18n="@@audit.col.action">Action</clr-dg-column>
      <clr-dg-column [clrDgField]="'detail'" i18n="@@audit.col.detail">Detail</clr-dg-column>
      <clr-dg-row *clrDgItems="let e of log.value() ?? []; trackBy: byId" [clrDgItem]="e">
        <clr-dg-cell>{{ dt(e.ts) }}</clr-dg-cell>
        <clr-dg-cell>{{ e.username }}</clr-dg-cell>
        <clr-dg-cell><span class="label" [class.label-danger]="e.action.endsWith('failed')" [class.label-info]="!e.action.endsWith('failed')">{{ e.action }}</span></clr-dg-cell>
        <clr-dg-cell>{{ e.detail }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-footer>
        <clr-dg-pagination #p [clrDgPageSize]="50">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (p.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@audit.footer">{{ p.firstItem + 1 }}–{{ p.lastItem + 1 }} of {{ p.totalItems.toLocaleString() }} entries</ng-container>
          } @else {
            <ng-container i18n="@@audit.empty">No entries</ng-container>
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>
  `,
})
export class Audit {
  readonly byId = trackByKey<{ id: number }>((e) => e.id);
  private api = inject(Api);
  readonly log = loader(() => true, () => this.api.audit());
  dt = dateTime;
}
