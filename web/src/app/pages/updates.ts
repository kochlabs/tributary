import { Component, computed, DestroyRef, ElementRef, inject, signal, viewChild } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, UpdateStatus } from '../core/api';
import { dateTime } from '../core/format';
import { trackByKey } from '../core/util';

@Component({
  selector: 'nfa-updates',
  imports: [ClarityModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.updates">Updates</h2>
        <p class="subtitle"><ng-container i18n="@@updates.subtitle">Operating system packages</ng-container>{{ st()?.os ? ' · ' + st()!.os : '' }}</p>
      </div>
    </div>

    @if (error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
    }
    @if (st(); as s) {
      @if (!s.installed) {
        <div class="alert alert-warning" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text" i18n="@@updates.notInstalled">The update helper isn't installed on this system. Re-run <code>deploy/install.sh</code> to enable updates from the UI.</span></div></div></div>
      }
      <div class="card">
        <div class="card-block">
          <table class="table table-noborder kv">
            <tbody>
              <tr><td i18n="@@updates.lastChecked">Last checked</td><td>{{ s.lastCheck ? dt(s.lastCheck) : neverLabel }}</td></tr>
              <tr>
                <td i18n="@@updates.available">Available</td>
                <td>
                  @if (busy()) {
                    <span class="spinner spinner-inline"></span> {{ busyText() }}
                  } @else if (s.upgradable.length === 0) {
                    <span class="dot ok"></span> <ng-container i18n="@@updates.upToDate">Up to date</ng-container>
                  } @else {
                    <span class="dot" [class.bad]="securityCount() > 0" [class.warn]="securityCount() === 0"></span>
                    <ng-container i18n="@@updates.count">{s.upgradable.length, plural, =1 {1 update} other {{{s.upgradable.length}} updates}}</ng-container>
                    @if (securityCount()) {
                      <span class="sec" i18n="@@updates.securityCount">({{ securityCount() }} security)</span>
                    }
                  }
                </td>
              </tr>
              <tr>
                <td i18n="@@updates.lastInstalled">Last installed</td>
                <td>
                  @if (s.lastInstall) {
                    {{ dt(s.lastInstall) }} ·
                    @if (s.lastInstallExit === 0) {
                      <span class="dot ok"></span> <ng-container i18n="@@updates.succeeded">Succeeded</ng-container>
                    } @else {
                      <span class="dot bad"></span> <ng-container i18n="@@updates.failed">Failed (exit {{ s.lastInstallExit }})</ng-container>
                    }
                  } @else {
                    <ng-container i18n="@@updates.never">Never</ng-container>
                  }
                </td>
              </tr>
              @if (s.rebootRequired) {
                <tr><td i18n="@@updates.restart">Restart</td><td><span class="dot warn"></span> <ng-container i18n="@@updates.rebootRequired">Required to finish installing updates (kernel {{ s.kernel }} is still running)</ng-container></td></tr>
              }
            </tbody>
          </table>
        </div>
        <div class="card-footer">
          <button class="btn btn-outline" (click)="request('check')" [disabled]="busy() || !s.installed"><cds-icon shape="refresh"></cds-icon> <ng-container i18n="@@updates.checkNow">Check now</ng-container></button>
          <button class="btn btn-primary" (click)="confirm.set('upgrade')" [disabled]="busy() || !s.installed || s.upgradable.length === 0"><cds-icon shape="download"></cds-icon> <ng-container i18n="@@updates.installUpdates">Install updates</ng-container></button>
          @if (s.rebootRequired) {
            <button class="btn btn-warning-outline" (click)="confirm.set('reboot')" [disabled]="busy()"><cds-icon shape="power"></cds-icon> <ng-container i18n="@@updates.restartAppliance">Restart appliance</ng-container></button>
          }
          <button class="btn btn-link" (click)="toggleOutput()">{{ showOutput() ? txt.hideOutput : txt.showOutput }}</button>
        </div>
      </div>

      @if (s.upgradable.length) {
        <h3 class="section-title" i18n="@@updates.availableUpdates">Available updates</h3>
        <clr-datagrid class="datagrid-compact">
          <clr-dg-column [clrDgField]="'name'" i18n="@@updates.col.package">Package</clr-dg-column>
          <clr-dg-column i18n="@@updates.col.installed">Installed</clr-dg-column>
          <clr-dg-column i18n="@@updates.col.available">Available</clr-dg-column>
          <clr-dg-column [clrDgField]="'suite'" i18n="@@updates.col.source">Source</clr-dg-column>
          <clr-dg-row *clrDgItems="let p of s.upgradable; trackBy: byName" [clrDgItem]="p">
            <clr-dg-cell>{{ p.name }} @if (p.security) {<span class="label label-danger" i18n="@@updates.securityLabel">security</span>}</clr-dg-cell>
            <clr-dg-cell class="mono">{{ p.from || '–' }}</clr-dg-cell>
            <clr-dg-cell class="mono">{{ p.version }}</clr-dg-cell>
            <clr-dg-cell>{{ p.suite }}</clr-dg-cell>
          </clr-dg-row>
          <clr-dg-footer>
          <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@updates.footer">{{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} packages</ng-container>
          } @else {
            <ng-container i18n="@@updates.noPackages">No packages</ng-container>
          }
        </clr-dg-pagination>
          </clr-dg-footer>
        </clr-datagrid>
      }

      @if (showOutput()) {
        <h3 class="section-title"><ng-container i18n="@@updates.output">Output</ng-container>{{ s.action ? ' · ' + s.action : '' }}{{ s.startedAt ? ' · ' + dt(s.startedAt) : '' }}</h3>
        <pre class="output" #out>{{ log() || txt.noOutput }}</pre>
      }
    } @else if (!error()) {
      <div class="center"><span class="spinner" i18n="@@updates.loading">Loading…</span></div>
    }

    <clr-modal [clrModalOpen]="!!confirm()" (clrModalOpenChange)="!$event && confirm.set(null)" clrModalSize="md">
      <h3 class="modal-title">{{ confirm() === 'reboot' ? txt.rebootTitle : txt.upgradeTitle }}</h3>
      <div class="modal-body">
        @if (confirm() === 'reboot') {
          <p i18n="@@updates.rebootBody">Flow collection and the web interface stop for a minute or two while the appliance restarts. Flows exported during the restart are lost.</p>
        } @else {
          <p i18n="@@updates.upgradeBody">Installs {{ st()?.upgradable?.length }} package update(s). Services such as the database may restart briefly, and a few seconds of flows can be lost.</p>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirm.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn" [class.btn-primary]="confirm() === 'upgrade'" [class.btn-warning]="confirm() === 'reboot'" (click)="request(confirm()!)">{{ confirm() === 'reboot' ? txt.restart : txt.install }}</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .card { margin-top: 0; }
    .kv { margin: 0; max-width: 900px; }
    .kv td { text-align: left; padding: 6px 0; border: 0; }
    .kv td:first-child { width: 260px; color: var(--cds-alias-typography-color-300); }
    .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin: 0 4px 0 2px; vertical-align: 0; }
    .ok { background: var(--cds-alias-status-success); }
    .warn { background: var(--cds-alias-status-warning); }
    .bad { background: var(--cds-alias-status-danger); }
    .sec { color: var(--cds-alias-status-danger); }
    .card-footer { display: flex; gap: 6px; flex-wrap: wrap; }
    .card-footer .btn { margin: 0; }
    .section-title { margin-top: 24px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .label { margin-left: 6px; }
    .output { max-height: 420px; overflow: auto; font-size: 12px; line-height: 1.45; padding: 12px; white-space: pre-wrap; word-break: break-all;
      background: var(--cds-alias-object-container-background-shade, #f4f4f4); border: 1px solid var(--cds-alias-object-border-color); border-radius: 4px; }
    .center { display: flex; justify-content: center; padding: 60px; }
  `,
})
export class Updates {
  readonly byName = trackByKey<{ name: string }>((p) => p.name);
  private api = inject(Api);
  readonly st = signal<UpdateStatus | null>(null);
  readonly error = signal('');
  readonly log = signal('');
  readonly showOutput = signal(false);
  readonly confirm = signal<'upgrade' | 'reboot' | null>(null);
  private logOffset = 0;
  private out = viewChild<ElementRef<HTMLPreElement>>('out');

  readonly busy = computed(() => {
    const s = this.st();
    return !!s && (s.state === 'running' || !!s.pending);
  });
  readonly busyText = computed(() => {
    const s = this.st();
    const a = s?.pending || s?.action;
    return a === 'upgrade' ? $localize`:@@updates.installing:Installing updates…` : a === 'reboot' ? $localize`:@@updates.restarting:Restarting…` : $localize`:@@updates.checking:Checking for updates…`;
  });
  readonly securityCount = computed(() => this.st()?.upgradable.filter((p) => p.security).length ?? 0);
  dt = dateTime;
  readonly neverLabel = $localize`:@@updates.never:Never`;
  readonly txt = {
    hideOutput: $localize`:@@updates.hideOutput:Hide output`,
    showOutput: $localize`:@@updates.showOutput:Show output`,
    noOutput: $localize`:@@updates.noOutput:No output yet.`,
    rebootTitle: $localize`:@@updates.rebootTitle:Restart the appliance?`,
    upgradeTitle: $localize`:@@updates.upgradeTitle:Install updates?`,
    restart: $localize`:@@updates.restart:Restart`,
    install: $localize`:@@updates.install:Install`,
  };

  constructor() {
    this.refresh();
    // Poll quickly while an action runs, slowly otherwise.
    let ticks = 0;
    const id = setInterval(() => {
      ticks++;
      if (this.busy() || ticks % 10 === 0) this.refresh();
    }, 2000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
  }

  async refresh() {
    try {
      const wasBusy = this.busy();
      this.st.set(await this.api.updates());
      this.error.set('');
      if (this.showOutput() || this.busy() || wasBusy) await this.pullLog();
    } catch (e) {
      this.error.set(errorMessage(e));
    }
  }

  async pullLog() {
    const r = await this.api.updatesLog(this.logOffset);
    if (r.offset < this.logOffset || this.logOffset === 0) this.log.set(r.text);
    else if (r.text) this.log.update((l) => l + r.text);
    this.logOffset = r.offset;
    queueMicrotask(() => {
      const el = this.out()?.nativeElement;
      if (el) el.scrollTop = el.scrollHeight;
    });
  }

  toggleOutput() {
    this.showOutput.update((v) => !v);
    if (this.showOutput()) {
      this.logOffset = 0;
      this.pullLog();
    }
  }

  async request(action: 'check' | 'upgrade' | 'reboot') {
    this.confirm.set(null);
    this.error.set('');
    try {
      await this.api.requestUpdate(action);
      this.logOffset = 0;
      this.log.set('');
      if (action !== 'check') this.showOutput.set(true);
      await this.refresh();
    } catch (e) {
      this.error.set(errorMessage(e));
    }
  }
}
