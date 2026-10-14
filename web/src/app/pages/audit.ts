import { Component, inject } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { Api } from '../core/api';
import { dateTime } from '../core/format';
import { loader } from '../core/util';

@Component({
  selector: 'nfa-audit',
  imports: [ClarityModule],
  template: `
    <div class="page-header">
      <div>
        <h2>Audit Log</h2>
        <p class="subtitle">Sign-ins and configuration changes (most recent 500)</p>
      </div>
      <button class="btn btn-sm btn-outline" (click)="log.reload()"><cds-icon shape="refresh"></cds-icon> Refresh</button>
    </div>
    <clr-datagrid class="datagrid-compact" [clrDgLoading]="log.loading()">
      <clr-dg-column [clrDgField]="'ts'" [clrDgSortOrder]="-1">Time</clr-dg-column>
      <clr-dg-column [clrDgField]="'username'">User</clr-dg-column>
      <clr-dg-column [clrDgField]="'action'">Action</clr-dg-column>
      <clr-dg-column [clrDgField]="'detail'">Detail</clr-dg-column>
      <clr-dg-row *clrDgItems="let e of log.value() ?? []" [clrDgItem]="e">
        <clr-dg-cell>{{ dt(e.ts) }}</clr-dg-cell>
        <clr-dg-cell>{{ e.username }}</clr-dg-cell>
        <clr-dg-cell><span class="label" [class.label-danger]="e.action.endsWith('failed')" [class.label-info]="!e.action.endsWith('failed')">{{ e.action }}</span></clr-dg-cell>
        <clr-dg-cell>{{ e.detail }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-footer>
        <clr-dg-pagination #p [clrDgPageSize]="50">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]">Rows per page</clr-dg-page-size>
          @if (p.totalItems) {
            {{ p.firstItem + 1 }}–{{ p.lastItem + 1 }} of {{ p.totalItems.toLocaleString() }} entries
          } @else {
            No entries
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>
  `,
})
export class Audit {
  private api = inject(Api);
  readonly log = loader(() => true, () => this.api.audit());
  dt = dateTime;
}
