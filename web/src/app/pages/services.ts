import { Component, inject, signal } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, ServiceUnit } from '../core/api';
import { bytes, dateTime } from '../core/format';
import { loader, trackByKey } from '../core/util';

const OP_LABELS: Record<string, string> = { restart: 'Restart', start: 'Start', stop: 'Stop', enable: 'Enable on boot', disable: 'Disable on boot' };
// Operations that interrupt something and deserve a confirmation.
const DISRUPTIVE = new Set(['stop', 'disable', 'restart']);

@Component({
  selector: 'nfa-services',
  imports: [ClarityModule],
  template: `
    <div class="page-header">
      <div>
        <h2>Services</h2>
        <p class="subtitle">System services relevant to the appliance</p>
      </div>
      <button class="btn btn-link" (click)="list.reload()"><cds-icon shape="refresh"></cds-icon> Refresh</button>
    </div>

    @if (list.error() || actionError()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ actionError() || list.error() }}</span></div></div></div>
    }
    @if (actionOk()) {
      <div class="alert alert-success" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ actionOk() }}</span></div></div></div>
    }
    @if (list.value(); as v) {
      @if (!v.installed) {
        <div class="alert alert-warning" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">The admin helper isn't installed; services are read-only.</span></div></div></div>
      }
    }

    <clr-datagrid class="datagrid-compact" [clrDgLoading]="list.loading() || !!working()">
      <clr-dg-column [clrDgField]="'unit'" [clrDgSortOrder]="1">Unit</clr-dg-column>
      <clr-dg-column [clrDgField]="'description'">Description</clr-dg-column>
      <clr-dg-column [clrDgField]="'active'">State</clr-dg-column>
      <clr-dg-column>Since</clr-dg-column>
      <clr-dg-column>Memory</clr-dg-column>
      <clr-dg-column [clrDgField]="'onBoot'">On boot</clr-dg-column>

      <clr-dg-row *clrDgItems="let s of list.value()?.services ?? []; trackBy: byUnit" [clrDgItem]="s">
        @if (s.ops.length && list.value()?.installed) {
          <clr-dg-action-overflow>
            @for (op of s.ops; track op) {
              @if (applicable(s, op)) {
                <button class="action-item" (click)="ask(s, op)">{{ opLabel(op) }}</button>
              }
            }
          </clr-dg-action-overflow>
        }
        <clr-dg-cell class="unit">{{ s.unit }}</clr-dg-cell>
        <clr-dg-cell>{{ s.description }}</clr-dg-cell>
        <clr-dg-cell class="nowrap"><span class="dot" [class]="dotClass(s)"></span> {{ s.active }} ({{ s.sub }})</clr-dg-cell>
        <clr-dg-cell class="nowrap">{{ s.active === 'active' && s.since ? dt(s.since) : '–' }}</clr-dg-cell>
        <clr-dg-cell class="nowrap">{{ s.memory && s.memory < 1e15 ? fmtBytes(s.memory) : '–' }}</clr-dg-cell>
        <clr-dg-cell>{{ boot(s.onBoot) }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-footer>
        <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            {{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} services
          } @else {
            No services
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <clr-modal [clrModalOpen]="!!pending()" (clrModalOpenChange)="!$event && pending.set(null)" clrModalSize="md">
      <h3 class="modal-title">{{ opLabel(pending()?.op ?? '') }} {{ pending()?.unit }}?</h3>
      <div class="modal-body">
        <p>{{ warning() }}</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="pending.set(null)">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="run()">{{ opLabel(pending()?.op ?? '') }}</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .unit { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .nowrap { white-space: nowrap; }
    .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 4px; }
    .ok { background: var(--cds-alias-status-success); }
    .warn { background: var(--cds-alias-status-warning); }
    .bad { background: var(--cds-alias-status-danger); }
    .off { background: var(--cds-alias-status-neutral); }
  `,
})
export class Services {
  readonly byUnit = trackByKey<{ unit: string }>((s) => s.unit);
  private api = inject(Api);
  readonly list = loader(() => true, () => this.api.services());
  readonly pending = signal<{ unit: string; op: string } | null>(null);
  readonly working = signal('');
  readonly actionError = signal('');
  readonly actionOk = signal('');
  dt = dateTime;
  fmtBytes = bytes;

  opLabel(op: string) {
    return OP_LABELS[op] ?? op;
  }

  boot(s: string) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : '–';
  }

  dotClass(s: ServiceUnit) {
    if (s.active === 'active') return 'ok';
    if (s.active === 'failed') return 'bad';
    if (s.active === 'activating' || s.active === 'deactivating' || s.active === 'reloading') return 'warn';
    return 'off';
  }

  // Hide operations that wouldn't change anything (e.g. "Start" on a running unit).
  applicable(s: ServiceUnit, op: string) {
    const running = s.active === 'active' || s.active === 'activating';
    switch (op) {
      case 'start':
        return !running;
      case 'stop':
      case 'restart':
        return running || op === 'restart';
      case 'enable':
        return s.onBoot !== 'enabled';
      case 'disable':
        return s.onBoot === 'enabled';
    }
    return true;
  }

  warning() {
    const p = this.pending();
    if (!p) return '';
    if (p.unit === 'ssh.service' && (p.op === 'stop' || p.op === 'disable')) return 'You will not be able to log in to the appliance over SSH until it is started again from this page.';
    if (p.unit === 'clickhouse-server.service') return 'Flow storage and all reports are unavailable while the database is down; flows received meanwhile are dropped.';
    if (p.unit === 'systemd-timesyncd.service') return 'The clock stops synchronising while the service is down.';
    return `This ${p.op === 'disable' ? 'changes whether the service starts at boot' : 'interrupts the service briefly'}.`;
  }

  ask(s: ServiceUnit, op: string) {
    this.actionError.set('');
    this.actionOk.set('');
    if (DISRUPTIVE.has(op)) this.pending.set({ unit: s.unit, op });
    else {
      this.pending.set({ unit: s.unit, op });
      this.run();
    }
  }

  async run() {
    const p = this.pending();
    this.pending.set(null);
    if (!p) return;
    this.working.set(p.unit);
    try {
      const r = await this.api.serviceAction(p.unit, p.op);
      this.actionOk.set(r.message || `${p.unit}: ${p.op} done`);
    } catch (e) {
      this.actionError.set(errorMessage(e));
    } finally {
      this.working.set('');
      this.list.reload();
    }
  }
}
