import { HttpEventType } from '@angular/common/http';
import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, BackupInfo, BackupJob, BackupManifest, errorMessage } from '../core/api';
import { bytes, count, dateTime } from '../core/format';
import { loader, trackByKey } from '../core/util';

@Component({
  selector: 'nfa-backup',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.backup">Backup &amp; Restore</h2>
        <p class="subtitle" i18n="@@backup.subtitle">Encrypted backups of the appliance configuration, optionally with flow history</p>
      </div>
    </div>

    @if (error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
    }

    @if (job(); as j) {
      @if (j.state === 'running' || restarting()) {
        <div class="alert alert-info" role="alert">
          <div class="alert-items"><div class="alert-item static">
            <span class="spinner spinner-inline"></span>
            <span class="alert-text">
              @if (restarting()) {
                <ng-container i18n="@@backup.restarting">Restore complete. Tributary is restarting with the restored configuration; you'll be asked to sign in again…</ng-container>
              } @else if (j.kind === 'backup') {
                <ng-container i18n="@@backup.creating">Creating backup: {{ phaseLabel(j.phase) }} · {{ fmtBytes(j.bytes) }} written</ng-container>
              } @else {
                <ng-container i18n="@@backup.restoring">Restoring: {{ phaseLabel(j.phase) }} · {{ fmtBytes(j.bytes) }} processed</ng-container>
              }
            </span>
          </div></div>
        </div>
      } @else if (j.state === 'failed') {
        <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">
          @if (j.kind === 'backup') {
            <ng-container i18n="@@backup.backupFailed">The backup failed: {{ j.error }}</ng-container>
          } @else {
            <ng-container i18n="@@backup.restoreFailed">The restore failed: {{ j.error }}. The configuration was not changed.</ng-container>
          }
        </span></div></div></div>
      }
    }

    <div class="card">
      <div class="card-header" i18n="@@backup.create">Create a backup</div>
      <div class="card-block">
        <p class="hint" i18n="@@backup.contents">A backup holds users and identity sources, all settings and data sources, exporter, interface and device names, certificates and the key that protects stored credentials. It is encrypted with a passphrase you choose: without it the backup can't be restored, so keep it somewhere safe.</p>
        <form clrForm clrLayout="horizontal" clrLabelSize="3" (ngSubmit)="create()">
          <clr-password-container>
            <label i18n="@@backup.passphrase">Passphrase</label>
            <input clrPassword name="pass" [(ngModel)]="pass" autocomplete="new-password" />
            <clr-control-helper i18n="@@backup.passphraseHelp">At least {{ minPass() }} characters.</clr-control-helper>
          </clr-password-container>
          <clr-password-container>
            <label i18n="@@backup.confirm">Confirm passphrase</label>
            <input clrPassword name="pass2" [(ngModel)]="pass2" autocomplete="new-password" />
          </clr-password-container>
          <clr-checkbox-container>
            <label i18n="@@backup.flowHistory">Flow history</label>
            <clr-checkbox-wrapper>
              <input type="checkbox" clrCheckbox name="flows" [(ngModel)]="includeFlows" [disabled]="!flowsFit()" />
              <label i18n="@@backup.includeFlows">Include flow history (about {{ fmtBytes(status.value()?.flowsBytes ?? 0) }})</label>
            </clr-checkbox-wrapper>
            <clr-control-helper>
              @if (flowsFit()) {
                <ng-container i18n="@@backup.flowsHelp">Large and slower to create; {{ fmtBytes(status.value()?.freeBytes ?? 0) }} free on the appliance. Without it, flows collected after the restore start a fresh history.</ng-container>
              } @else {
                <span class="warn" i18n="@@backup.flowsNoRoom">Not enough free disk space on the appliance for a backup with flow history.</span>
              }
            </clr-control-helper>
          </clr-checkbox-container>
          <div class="actions">
            <button type="submit" class="btn btn-primary" [disabled]="!canCreate()"><cds-icon shape="download"></cds-icon> <ng-container i18n="@@backup.createButton">Create backup</ng-container></button>
            @if (pass && pass2 && pass !== pass2) {
              <span class="warn" i18n="@@backup.mismatch">The passphrases don't match.</span>
            }
          </div>
        </form>
      </div>
    </div>

    <h3 class="section-title" i18n="@@backup.stored">Backups on this appliance</h3>
    <p class="hint" i18n="@@backup.storedHint">Download backups to keep them elsewhere: a backup on the appliance's own disk won't help if that disk fails.</p>
    <clr-datagrid class="datagrid-compact" [clrDgLoading]="status.loading() && !status.value()">
      <clr-dg-column [clrDgField]="'created'" [clrDgSortOrder]="-1" i18n="@@backup.col.created">Created</clr-dg-column>
      <clr-dg-column i18n="@@backup.col.contents">Contents</clr-dg-column>
      <clr-dg-column i18n="@@backup.col.source">Source</clr-dg-column>
      <clr-dg-column [clrDgField]="'size'" i18n="@@backup.col.size">Size</clr-dg-column>
      <clr-dg-row *clrDgItems="let b of status.value()?.backups ?? []; trackBy: byName" [clrDgItem]="b">
        <clr-dg-action-overflow>
          <a class="action-item" [href]="api.backupUrl(b.name)" download><cds-icon shape="download"></cds-icon> <ng-container i18n="@@backup.download">Download</ng-container></a>
          <button class="action-item" (click)="confirmDelete.set(b)"><cds-icon shape="trash"></cds-icon> <ng-container i18n="@@common.delete">Delete</ng-container></button>
        </clr-dg-action-overflow>
        <clr-dg-cell>
          <a [href]="api.backupUrl(b.name)" download>{{ dt(b.created) }}</a>
          <div class="sub mono">{{ b.name }}</div>
        </clr-dg-cell>
        <clr-dg-cell>
          @if (b.flows?.length) {
            <ng-container i18n="@@backup.withFlows">Configuration + flow history ({{ fmtCount(flowRows(b.flows)) }} flows)</ng-container>
          } @else {
            <ng-container i18n="@@backup.configOnly">Configuration</ng-container>
          }
        </clr-dg-cell>
        <clr-dg-cell>{{ b.hostname }} · {{ b.version }}</clr-dg-cell>
        <clr-dg-cell class="num">{{ fmtBytes(b.size) }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder i18n="@@backup.none">No backups yet.</clr-dg-placeholder>
    </clr-datagrid>

    <div class="card restore">
      <div class="card-header" i18n="@@backup.restore">Restore from a backup</div>
      <div class="card-block">
        <p class="hint" i18n="@@backup.restoreHint">Restoring replaces this appliance's configuration with the backup's (users, settings, names, certificates) and restarts Tributary; everyone is signed out. Use it to recover, or to move to a new appliance.</p>
        <div class="step">
          <span class="num-badge">1</span>
          <input type="file" accept=".tbk" (change)="pick($event)" [disabled]="busy()" />
          @if (uploadPct() !== null) {
            <span class="progress-text">
              @if (uploadPct()! < 100) {
                <ng-container i18n="@@backup.uploading">Uploading… {{ uploadPct() }}%</ng-container>
              } @else {
                <cds-icon shape="check"></cds-icon> <ng-container i18n="@@backup.uploaded">Uploaded</ng-container>
              }
            </span>
          }
        </div>
        @if (uploaded()) {
          <div class="step">
            <span class="num-badge">2</span>
            <input class="clr-input pass" type="password" name="rpass" [(ngModel)]="restorePass" placeholder="Backup passphrase" i18n-placeholder="@@backup.restorePassPlaceholder" autocomplete="off" (keyup.enter)="inspect()" />
            <button class="btn btn-sm btn-outline" (click)="inspect()" [disabled]="!restorePass || busy()" i18n="@@backup.check">Check backup</button>
          </div>
        }
        @if (manifest(); as m) {
          <div class="step manifest">
            <span class="num-badge">3</span>
            <div>
              <table class="table table-compact table-noborder kv">
                <tbody>
                  <tr><td i18n="@@backup.col.created">Created</td><td>{{ dt(m.created) }}</td></tr>
                  <tr><td i18n="@@backup.col.source">Source</td><td>{{ m.hostname }} · {{ m.version }}</td></tr>
                  <tr><td i18n="@@backup.col.contents">Contents</td><td>
                    @if (m.flows?.length) {
                      <ng-container i18n="@@backup.withFlows">Configuration + flow history ({{ fmtCount(flowRows(m.flows)) }} flows)</ng-container>
                    } @else {
                      <ng-container i18n="@@backup.configOnly">Configuration</ng-container>
                    }
                  </td></tr>
                </tbody>
              </table>
              @if (m.flows?.length) {
                <clr-checkbox-wrapper>
                  <input type="checkbox" clrCheckbox name="rflows" [(ngModel)]="restoreFlows" />
                  <label i18n="@@backup.restoreFlows">Also restore the flow history. This deletes all flow data currently on this appliance.</label>
                </clr-checkbox-wrapper>
              }
              <button class="btn btn-danger" (click)="confirmRestore.set(true)" [disabled]="busy()"><cds-icon shape="history"></cds-icon> <ng-container i18n="@@backup.restoreButton">Restore</ng-container></button>
            </div>
          </div>
        }
      </div>
    </div>

    <clr-modal [clrModalOpen]="!!confirmDelete()" (clrModalOpenChange)="!$event && confirmDelete.set(null)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@backup.deleteTitle">Delete this backup?</h3>
      <div class="modal-body"><p class="mono">{{ confirmDelete()?.name }}</p></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmDelete.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="remove()" i18n="@@common.delete">Delete</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="confirmRestore()" (clrModalOpenChange)="confirmRestore.set($event)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@backup.restoreTitle">Restore this backup?</h3>
      <div class="modal-body">
        <p i18n="@@backup.restoreWarning">The current configuration (users, identity sources, settings, names and certificates) will be replaced by the backup's, and Tributary will restart. Everyone will need to sign in again, with the accounts from the backup. The replaced files are kept on the appliance.</p>
        @if (restoreFlows) {
          <p class="warn" i18n="@@backup.restoreFlowsWarning">All flow data now on this appliance will be deleted and replaced by the backup's flow history.</p>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmRestore.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="restore()" i18n="@@backup.restoreButton">Restore</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .card:first-of-type { margin-top: 0; }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 0; max-width: 900px; }
    .actions { display: flex; align-items: center; gap: 12px; margin-top: 16px; }
    .actions .btn { margin: 0; }
    .warn { color: var(--cds-alias-status-danger); font-size: 13px; }
    .section-title { margin-top: 24px; }
    .sub { font-size: 11px; color: var(--cds-alias-typography-color-300); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .restore { margin-top: 24px; }
    .step { display: flex; align-items: flex-start; gap: 12px; margin: 12px 0; }
    .step .btn { margin: 0; }
    .num-badge { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 50%; flex: none;
      background: var(--cds-alias-object-interaction-background-selected, #e8f1f8); color: var(--cds-alias-typography-color-400); font-size: 12px; font-weight: 600; }
    .pass { width: 260px; }
    .progress-text { font-size: 13px; }
    .manifest .kv { margin: 0 0 8px; max-width: 560px; }
    .manifest .kv td { text-align: left; padding: 2px 12px 2px 0; border: 0; }
    .manifest .kv td:first-child { width: 120px; color: var(--cds-alias-typography-color-300); }
    .manifest .btn { margin-top: 12px; }
  `,
})
export class Backup {
  readonly api = inject(Api);
  readonly byName = trackByKey<BackupInfo>((b) => b.name);
  private tick = signal(0);
  readonly status = loader(() => this.tick(), () => this.api.backups());
  readonly error = signal('');
  readonly restarting = signal(false);
  readonly confirmDelete = signal<BackupInfo | null>(null);
  readonly confirmRestore = signal(false);
  readonly uploadPct = signal<number | null>(null);
  readonly uploaded = signal(false);
  readonly manifest = signal<BackupManifest | null>(null);
  readonly working = signal(false);

  pass = '';
  pass2 = '';
  includeFlows = false;
  restorePass = '';
  restoreFlows = false;

  readonly job = computed<BackupJob | null>(() => this.status.value()?.job ?? null);
  readonly minPass = computed(() => this.status.value()?.minPassphrase ?? 12);
  readonly busy = computed(() => this.working() || this.restarting() || this.job()?.state === 'running');
  readonly flowsFit = computed(() => {
    const s = this.status.value();
    return !!s && s.flowsBytes > 0 && s.freeBytes > s.flowsBytes * 1.5 + 200 * 1024 * 1024;
  });

  dt = dateTime;
  fmtBytes = bytes;
  fmtCount = count;

  constructor() {
    // Poll quickly while a job runs, slowly otherwise.
    let ticks = 0;
    const id = setInterval(() => {
      ticks++;
      if (this.restarting()) return;
      if (this.job()?.state === 'running' || ticks % 15 === 0) this.tick.update((t) => t + 1);
    }, 1000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
  }

  canCreate() {
    return !this.busy() && this.pass.length >= this.minPass() && this.pass === this.pass2;
  }

  phaseLabel(p: string) {
    if (p === 'config') return $localize`:@@backup.phase.config:configuration`;
    if (p === 'flows:prepare') return $localize`:@@backup.phase.prepare:preparing flow tables`;
    if (p.startsWith('flows:')) return $localize`:@@backup.phase.flows:flow table ${p.slice(6)}:table:`;
    if (p === 'finishing') return $localize`:@@backup.phase.finishing:finishing`;
    if (p === 'restarting') return $localize`:@@backup.phase.restarting:restarting`;
    return p;
  }

  flowRows(t: { rows: number }[] | undefined) {
    return (t ?? []).find((x) => (x as { table?: string }).table === 'flows')?.rows ?? 0;
  }

  async create() {
    this.error.set('');
    this.working.set(true);
    try {
      await this.api.createBackup(this.pass, this.includeFlows);
      this.pass = this.pass2 = '';
      this.tick.update((t) => t + 1);
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.working.set(false);
    }
  }

  async remove() {
    const b = this.confirmDelete();
    this.confirmDelete.set(null);
    if (!b) return;
    try {
      await this.api.deleteBackup(b.name);
      this.tick.update((t) => t + 1);
    } catch (e) {
      this.error.set(errorMessage(e));
    }
  }

  pick(ev: Event) {
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;
    this.error.set('');
    this.uploaded.set(false);
    this.manifest.set(null);
    this.restoreFlows = false;
    this.uploadPct.set(0);
    this.working.set(true);
    this.api.uploadRestore(file).subscribe({
      next: (e) => {
        if (e.type === HttpEventType.UploadProgress && e.total) this.uploadPct.set(Math.floor((e.loaded / e.total) * 100));
        if (e.type === HttpEventType.Response) {
          this.uploadPct.set(100);
          this.uploaded.set(true);
          this.working.set(false);
        }
      },
      error: (e) => {
        this.error.set(errorMessage(e));
        this.uploadPct.set(null);
        this.working.set(false);
      },
    });
  }

  async inspect() {
    this.error.set('');
    this.working.set(true);
    try {
      this.manifest.set(await this.api.inspectRestore(this.restorePass));
    } catch (e) {
      this.manifest.set(null);
      this.error.set(errorMessage(e));
    } finally {
      this.working.set(false);
    }
  }

  async restore() {
    this.confirmRestore.set(false);
    this.error.set('');
    this.working.set(true);
    try {
      await this.api.applyRestore(this.restorePass, this.restoreFlows);
      this.restorePass = '';
      await this.waitForRestart();
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.working.set(false);
    }
  }

  /** Follows the restore job, then waits for the restarted appliance. */
  private async waitForRestart() {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    for (;;) {
      await sleep(1000);
      let s;
      try {
        s = await this.api.backups();
      } catch {
        break; // the server went down to restart
      }
      this.status.value.set(s);
      if (s.job?.state === 'failed') return;
      if (s.job?.state === 'done' && s.job.phase === 'restarting') break;
    }
    this.restarting.set(true);
    await sleep(3000);
    for (let i = 0; i < 120; i++) {
      try {
        const r = await fetch('/healthz', { cache: 'no-store' });
        if (r.ok) break;
      } catch {
        // still restarting
      }
      await sleep(1000);
    }
    location.href = '/login';
  }
}
