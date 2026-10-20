import { Component, DestroyRef, inject, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, BackupSchedule, BackupScheduleStatus, DestinationTest, errorMessage } from '../core/api';
import { ago, bytes, dateTime } from '../core/format';

const WEEKDAYS = [0, 1, 2, 3, 4, 5, 6].map((d) => ({
  id: d,
  // 2023-01-01 was a Sunday.
  label: new Date(2023, 0, 1 + d).toLocaleDateString(undefined, { weekday: 'long' }),
}));

/** Scheduled backups and their off-appliance destination (Backup & Restore page). */
@Component({
  selector: 'nfa-backup-schedule',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="card">
      <div class="card-header">
        <span><cds-icon shape="calendar"></cds-icon> <ng-container i18n="@@sched.title">Scheduled backups</ng-container></span>
        @if (st(); as st) {
          <span class="card-hint">
            @if (st.running) {
              <span class="spinner spinner-inline"></span> <ng-container i18n="@@sched.running">Running: {{ phaseLabel(st.phase ?? '') }}</ng-container>
            } @else if (st.run.finished && !st.run.ok) {
              <span class="bad"><cds-icon shape="error-standard"></cds-icon> <ng-container i18n="@@sched.lastFailed">Last backup failed {{ ago(st.run.finished) }}</ng-container></span>
            } @else if (st.run.lastSuccess) {
              <span class="good"><cds-icon shape="check-circle"></cds-icon></span> <ng-container i18n="@@sched.lastOk">Last backup {{ ago(st.run.lastSuccess) }}</ng-container>
            }
            @if (st.next && !st.running) {
              <span i18n="@@sched.next"> · next {{ dt(st.next) }}</span>
            }
          </span>
        }
      </div>
      <div class="card-block">
        @if (s(); as s) {
          <p class="hint" i18n="@@sched.hint">Makes encrypted backups unattended and copies them off the appliance, keeping the newest ones at each place. Only this appliance's own scheduled backups are ever deleted.</p>
          <form clrForm clrLayout="horizontal" clrLabelSize="3" (ngSubmit)="save()">
            <clr-toggle-container>
              <label i18n="@@sched.enabled">Schedule</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="enabled" [(ngModel)]="s.enabled" />
                <label i18n="@@sched.enable">Make backups on a schedule</label>
              </clr-toggle-wrapper>
            </clr-toggle-container>
            <div class="clr-form-control clr-row">
              <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@sched.when">When</label>
              <div class="clr-col-12 clr-col-md-9 inline">
                <div class="clr-select-wrapper">
                  <select class="clr-select" name="freq" [(ngModel)]="s.frequency">
                    <option value="daily" i18n="@@sched.daily">Every day</option>
                    <option value="weekly" i18n="@@sched.weekly">Every week</option>
                  </select>
                </div>
                @if (s.frequency === 'weekly') {
                  <span i18n="@@sched.on">on</span>
                  <div class="clr-select-wrapper">
                    <select class="clr-select" name="weekday" [(ngModel)]="s.weekday">
                      @for (d of weekdays; track d.id) { <option [ngValue]="d.id">{{ d.label }}</option> }
                    </select>
                  </div>
                }
                <span i18n="@@sched.at">at</span>
                <input class="clr-input time" type="time" name="time" [(ngModel)]="s.time" required />
                <span class="sub" i18n="@@sched.localTime">appliance time</span>
              </div>
            </div>
            <clr-checkbox-container>
              <label i18n="@@backup.flowHistory">Flow history</label>
              <clr-checkbox-wrapper>
                <input type="checkbox" clrCheckbox name="flows" [(ngModel)]="s.includeFlows" />
                <label i18n="@@sched.includeFlows">Include flow history (large: needs room on the appliance and at the destination)</label>
              </clr-checkbox-wrapper>
            </clr-checkbox-container>

            <h5 class="section" i18n="@@sched.encryption">Encryption</h5>
            <div class="clr-form-control clr-row">
              <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@sched.encryptWith">Encrypt with</label>
              <div class="clr-col-12 clr-col-md-9">
                <div class="btn-group btn-sm" role="group">
                  <button type="button" class="btn" [class.btn-primary]="s.encryption === 'publickey'" [class.btn-outline]="s.encryption !== 'publickey'" (click)="s.encryption = 'publickey'" i18n="@@sched.publicKey">Public key (recommended)</button>
                  <button type="button" class="btn" [class.btn-primary]="s.encryption === 'passphrase'" [class.btn-outline]="s.encryption !== 'passphrase'" (click)="s.encryption = 'passphrase'" i18n="@@backup.passphrase">Passphrase</button>
                </div>
              </div>
            </div>
            @if (s.encryption === 'publickey') {
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@sched.publicKeys">Public keys</label>
                <div class="clr-control-container clr-col-12 clr-col-md-9">
                  <textarea class="clr-textarea keys mono" name="keys" [(ngModel)]="s.publicKeys" rows="2" spellcheck="false" placeholder="age1…"></textarea>
                  <span class="clr-subtext" i18n="@@sched.publicKeysHelp">One age public key per line. Create a key pair on your own computer with <code>age-keygen -o tributary-backup.key</code>, paste its public key (age1…) here and keep the key file offline. The appliance can then write backups but can't read them; restoring needs the key file.</span>
                </div>
              </div>
            } @else {
              <clr-password-container>
                <label i18n="@@backup.passphrase">Passphrase</label>
                <input clrPassword name="pass" [(ngModel)]="pass" autocomplete="new-password" [placeholder]="s.hasPassphrase ? stored : ''" />
                <clr-control-helper i18n="@@sched.passphraseHelp">At least {{ st()?.minPassphrase ?? 12 }} characters, stored encrypted on the appliance. Record it somewhere safe: restoring on a new appliance needs it.</clr-control-helper>
              </clr-password-container>
              @if (pass) {
                <clr-password-container>
                  <label i18n="@@backup.confirm">Confirm passphrase</label>
                  <input clrPassword name="pass2" [(ngModel)]="pass2" autocomplete="new-password" />
                </clr-password-container>
              }
            }

            <h5 class="section" i18n="@@sched.destination">Destination</h5>
            <div class="clr-form-control clr-row">
              <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@sched.copyTo">Copy to</label>
              <div class="clr-col-12 clr-col-md-9">
                <div class="btn-group btn-sm" role="group">
                  @for (t of types; track t.id) {
                    <button type="button" class="btn" [class.btn-primary]="s.destination.type === t.id" [class.btn-outline]="s.destination.type !== t.id" (click)="setType(t.id)">{{ t.label }}</button>
                  }
                </div>
              </div>
            </div>
            @let d = s.destination;
            @if (d.type === '') {
              <p class="warn-text indent" i18n="@@sched.localOnlyWarning">Backups stay on the appliance's own disk, which won't help if that disk fails. Choose a destination, or download backups regularly.</p>
            }
            @if (d.type === 'smb' || d.type === 'sftp') {
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@sched.server">Server</label>
                <div class="clr-col-12 clr-col-md-9 inline">
                  <input class="clr-input host" name="host" [(ngModel)]="d.host" [placeholder]="d.type === 'smb' ? 'nas.corp.example.com' : 'backup.example.com'" spellcheck="false" />
                  <span>:</span>
                  <input class="clr-input port" type="number" name="port" [(ngModel)]="d.port" [placeholder]="d.type === 'smb' ? '445' : '22'" min="1" max="65535" />
                </div>
              </div>
            }
            @if (d.type === 'smb') {
              <clr-input-container>
                <label i18n="@@sched.share">Share</label>
                <input clrInput name="share" [(ngModel)]="d.share" placeholder="Backups" />
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@sched.domain">Domain</label>
                <input clrInput name="domain" [(ngModel)]="d.domain" placeholder="CORP" i18n-placeholder="@@sched.domainPlaceholder" />
                <clr-control-helper i18n="@@sched.domainHelp">Optional; for a domain account</clr-control-helper>
              </clr-input-container>
            }
            @if (d.type === 'smb' || d.type === 'sftp') {
              <clr-input-container>
                <label i18n="@@sched.user">User name</label>
                <input clrInput name="user" [(ngModel)]="d.username" autocomplete="off" />
              </clr-input-container>
            }
            @if (d.type === 'sftp') {
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@sched.signInWith">Sign in with</label>
                <div class="clr-col-12 clr-col-md-9">
                  <div class="btn-group btn-sm" role="group">
                    <button type="button" class="btn" [class.btn-primary]="d.sftpAuth === 'key'" [class.btn-outline]="d.sftpAuth !== 'key'" (click)="d.sftpAuth = 'key'" i18n="@@sched.applianceKey">Appliance SSH key</button>
                    <button type="button" class="btn" [class.btn-primary]="d.sftpAuth === 'password'" [class.btn-outline]="d.sftpAuth !== 'password'" (click)="d.sftpAuth = 'password'" i18n="@@sched.password">Password</button>
                  </div>
                  @if (d.sftpAuth === 'key' && st()?.sshPublicKey; as pub) {
                    <div class="pubkey">
                      <span class="sub" i18n="@@sched.addKey">Add this line to the user's ~/.ssh/authorized_keys on the server:</span>
                      <div class="uri"><code>{{ pub }}</code> <button type="button" class="btn btn-link btn-sm" (click)="copy(pub)">{{ copied() ? copiedLabel : copyLabel }}</button></div>
                    </div>
                  }
                </div>
              </div>
            }
            @if (d.type === 'smb' || (d.type === 'sftp' && d.sftpAuth === 'password')) {
              <clr-password-container>
                <label i18n="@@sched.password">Password</label>
                <input clrPassword name="password" [(ngModel)]="d.password" autocomplete="new-password" [placeholder]="d.hasPassword ? stored : ''" />
              </clr-password-container>
            }
            @if (d.type === 's3') {
              <clr-input-container>
                <label i18n="@@sched.endpoint">Endpoint</label>
                <input clrInput name="endpoint" [(ngModel)]="d.endpoint" placeholder="https://minio.example.com:9000" class="wide" spellcheck="false" />
                <clr-control-helper i18n="@@sched.endpointHelp">Empty for Amazon S3. For other providers (MinIO, Wasabi, Backblaze B2, Cloudflare R2, Ceph…) their S3 endpoint.</clr-control-helper>
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@sched.region">Region</label>
                <input clrInput name="region" [(ngModel)]="d.region" placeholder="us-east-1" />
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@sched.bucket">Bucket</label>
                <input clrInput name="bucket" [(ngModel)]="d.bucket" spellcheck="false" />
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@sched.accessKey">Access key</label>
                <input clrInput name="accessKey" [(ngModel)]="d.accessKey" autocomplete="off" spellcheck="false" class="wide mono" />
              </clr-input-container>
              <clr-password-container>
                <label i18n="@@sched.secretKey">Secret key</label>
                <input clrPassword name="secretKey" [(ngModel)]="d.secretKey" autocomplete="new-password" [placeholder]="d.hasSecretKey ? stored : ''" />
              </clr-password-container>
              <clr-checkbox-container>
                <label></label>
                <clr-checkbox-wrapper>
                  <input type="checkbox" clrCheckbox name="pathStyle" [(ngModel)]="d.pathStyle" />
                  <label i18n="@@sched.pathStyle">Path-style requests (usually needed for MinIO and Ceph)</label>
                </clr-checkbox-wrapper>
              </clr-checkbox-container>
            }
            @if (d.type) {
              <clr-input-container>
                <label>@if (d.type === 's3') {<ng-container i18n="@@sched.prefix">Prefix</ng-container>} @else {<ng-container i18n="@@sched.folder">Folder</ng-container>}</label>
                <input clrInput name="path" [(ngModel)]="d.path" placeholder="tributary" class="wide" spellcheck="false" />
                <clr-control-helper i18n="@@sched.folderHelp">Created if missing. Several appliances can share it: each prunes only its own backups.</clr-control-helper>
              </clr-input-container>
            }
            @if (d.type === 'sftp') {
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@sched.hostKey">Host key</label>
                <div class="clr-col-12 clr-col-md-9 hostkey">
                  @if (d.hostKey) {
                    <span class="good"><cds-icon shape="lock"></cds-icon></span> <ng-container i18n="@@sched.hostKeyPinned">Confirmed: {{ hostKeyType(d.hostKey) }}</ng-container>
                  } @else {
                    <span class="sub" i18n="@@sched.hostKeyNone">Not confirmed yet: test the connection to see the server's key.</span>
                  }
                </div>
              </div>
            }
            @if (d.type) {
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-3"></label>
                <div class="clr-col-12 clr-col-md-9">
                  <button type="button" class="btn btn-outline btn-sm" (click)="test()" [clrLoading]="testing()"><cds-icon shape="play"></cds-icon> <ng-container i18n="@@sched.test">Test connection</ng-container></button>
                  @if (result(); as r) {
                    <div class="result" [class.bad]="!r.ok && !r.hostKey">
                      <span class="dot" [class.ok]="r.ok" [class.bad-dot]="!r.ok && !r.hostKey" [class.ask]="!!r.hostKey"></span> {{ r.message }}
                      @if (r.ok && r.backups) {
                        <span i18n="@@sched.existing">({{ r.backups }} of this appliance's backups already there)</span>
                      }
                      @if (r.hostKey) {
                        <div class="fp"><code>{{ r.fingerprint }}</code></div>
                        <p class="sub" i18n="@@sched.fingerprintHelp">Compare it with the server's own fingerprint (on the server: <code>ssh-keygen -lf {{ r.keyFile }}</code>) before trusting it.</p>
                        <button type="button" class="btn btn-sm btn-primary" (click)="trust(r)" i18n="@@sched.trustKey">Trust this key and test again</button>
                      }
                    </div>
                  }
                </div>
              </div>
            }

            <h5 class="section" i18n="@@sched.retention">Retention</h5>
            <div class="clr-form-control clr-row">
              <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@sched.keep">Keep</label>
              <div class="clr-col-12 clr-col-md-9 inline">
                @if (d.type) {
                  <input class="clr-input num" type="number" name="keepRemote" [(ngModel)]="s.keepRemote" min="1" max="1000" />
                  <span i18n="@@sched.atDestination">at the destination,</span>
                }
                <input class="clr-input num" type="number" name="keepLocal" [(ngModel)]="s.keepLocal" min="1" max="100" />
                <span i18n="@@sched.onAppliance">on this appliance (newest first)</span>
              </div>
            </div>

            @if (error()) {
              <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
            }
            @if (st()?.run; as run) {
              @if (run.finished && run.error) {
                <div class="alert alert-sm" [class.alert-danger]="!run.ok" [class.alert-warning]="run.ok" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">
                  {{ dt(run.finished) }}: {{ run.error }}
                </span></div></div></div>
              } @else if (run.ok && run.name) {
                <p class="sub last">
                  @if (run.copied) {
                    <ng-container i18n="@@sched.lastRunCopied">Last: {{ run.name }} · {{ fmtBytes(run.size ?? 0) }} · {{ dt(run.finished) }} · copied</ng-container>
                  } @else {
                    <ng-container i18n="@@sched.lastRun">Last: {{ run.name }} · {{ fmtBytes(run.size ?? 0) }} · {{ dt(run.finished) }}</ng-container>
                  }
                </p>
              }
            }
            <div class="actions">
              <button type="submit" class="btn btn-primary" [clrLoading]="saving()" [disabled]="pass !== '' && pass !== pass2" i18n="@@common.save">Save</button>
              <button type="button" class="btn btn-outline" (click)="runNow()" [disabled]="!canRun() || !!st()?.running" i18n="@@sched.runNow">Back up now</button>
              @if (pass && pass2 && pass !== pass2) {
                <span class="warn-text" i18n="@@backup.mismatch">The passphrases don't match.</span>
              }
            </div>
          </form>
        }
      </div>
    </div>
  `,
  styles: `
    .card-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .card-hint { font-size: 12px; font-weight: 400; color: var(--cds-alias-typography-color-300); }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 0; max-width: 900px; }
    .section { text-transform: uppercase; letter-spacing: 0.06em; font-size: 12px; color: var(--cds-alias-typography-color-300); margin: 22px 0 2px; }
    .inline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding-top: 2px; }
    .time { width: 7.5rem; }
    .host { width: 18rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .port { width: 5rem; }
    .num { width: 4.5rem; }
    .wide { width: 360px; }
    .keys { width: 100%; max-width: 560px; font-size: 12px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .sub { font-size: 12px; color: var(--cds-alias-typography-color-300); }
    .btn-group { margin: 0; }
    .pubkey { margin-top: 8px; }
    .uri { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .uri code { font-size: 11px; word-break: break-all; }
    .uri .btn { margin: 0; }
    .hostkey { padding-top: 6px; font-size: 13px; }
    .result { margin-top: 10px; font-size: 13px; max-width: 640px; }
    .result.bad { color: var(--cds-alias-status-danger); }
    .result .btn { margin: 6px 0 0; }
    .fp { margin: 6px 0 2px; }
    .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 4px; }
    .dot.ok { background: var(--cds-alias-status-success); }
    .dot.bad-dot { background: var(--cds-alias-status-danger); }
    .dot.ask { background: var(--cds-alias-status-warning); }
    .good { color: var(--cds-alias-status-success); }
    .bad { color: var(--cds-alias-status-danger); }
    .warn-text { font-size: 12px; color: var(--cds-alias-status-danger); }
    .indent { margin: 6px 0 0; }
    .last { margin: 14px 0 0; }
    .actions { display: flex; align-items: center; gap: 10px; margin-top: 18px; }
    .actions .btn { margin: 0; }
    @media (min-width: 768px) { .indent { margin-left: 25%; } }
  `,
})
export class BackupScheduleCard {
  private api = inject(Api);
  /** Emitted when a run finishes, so the page can refresh its backup list. */
  readonly changed = output<void>();
  readonly st = signal<BackupScheduleStatus | null>(null);
  readonly s = signal<BackupSchedule | null>(null);
  readonly error = signal('');
  readonly saving = signal(false);
  readonly testing = signal(false);
  readonly result = signal<DestinationTest | null>(null);
  readonly copied = signal(false);
  readonly weekdays = WEEKDAYS;
  readonly types: { id: BackupSchedule['destination']['type']; label: string }[] = [
    { id: '', label: $localize`:@@sched.thisAppliance:This appliance only` },
    { id: 'smb', label: 'SMB / CIFS' },
    { id: 's3', label: 'S3' },
    { id: 'sftp', label: 'SFTP' },
  ];
  readonly stored = $localize`:@@snmp.storedKeep:Stored · leave empty to keep`;
  readonly copyLabel = $localize`:@@identitySources.copy:Copy`;
  readonly copiedLabel = $localize`:@@identitySources.copied:Copied`;
  pass = '';
  pass2 = '';
  ago = ago;
  dt = dateTime;
  fmtBytes = bytes;
  private wasRunning = false;

  constructor() {
    this.load(true);
    const id = setInterval(() => this.load(false), 5000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
  }

  /** Refreshes the status; the form is replaced only on first load or after saving. */
  private async load(form: boolean) {
    try {
      const st = await this.api.backupSchedule();
      this.st.set(st);
      if (form || !this.s()) this.setForm(st);
      if (this.wasRunning && !st.running) this.changed.emit();
      this.wasRunning = !!st.running;
    } catch (e) {
      if (form) this.error.set(errorMessage(e));
    }
  }

  private setForm(st: BackupScheduleStatus) {
    const s = structuredClone(st.schedule);
    s.destination.port = s.destination.port || (null as unknown as number);
    this.s.set(s);
    this.pass = this.pass2 = '';
  }

  setType(t: BackupSchedule['destination']['type']) {
    const d = this.s()!.destination;
    if (d.type !== t) {
      d.type = t;
      d.port = null as unknown as number;
      this.result.set(null);
    }
  }

  hostKeyType(k: string) {
    return k.split(' ')[0];
  }

  canRun() {
    const st = this.st();
    return !!st && (st.schedule.encryption === 'publickey' ? !!st.schedule.publicKeys : !!st.schedule.hasPassphrase);
  }

  phaseLabel(p: string) {
    if (p === 'backup') return $localize`:@@sched.phaseBackup:making the backup`;
    if (p === 'copy') return $localize`:@@sched.phaseCopy:copying to the destination`;
    if (p === 'prune') return $localize`:@@sched.phasePrune:removing old backups`;
    return p;
  }

  private body(): BackupSchedule {
    const s = this.s()!;
    return { ...s, passphrase: this.pass, keepLocal: Number(s.keepLocal) || 0, keepRemote: Number(s.keepRemote) || 0, weekday: Number(s.weekday) || 0,
      destination: { ...s.destination, port: Number(s.destination.port) || 0 } };
  }

  async save() {
    this.saving.set(true);
    this.error.set('');
    try {
      const st = await this.api.saveBackupSchedule(this.body());
      this.st.set(st);
      this.setForm(st);
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.saving.set(false);
    }
  }

  async test() {
    this.testing.set(true);
    this.result.set(null);
    try {
      this.result.set(await this.api.testBackupDestination(this.body()));
    } catch (e) {
      this.result.set({ ok: false, message: errorMessage(e), backups: 0 });
    } finally {
      this.testing.set(false);
    }
  }

  /** Pins the SFTP host key just shown and tests with it. */
  trust(r: DestinationTest) {
    this.s()!.destination.hostKey = r.hostKey!;
    this.test();
  }

  async runNow() {
    this.error.set('');
    try {
      await this.api.runBackupSchedule();
      this.wasRunning = true;
      await this.load(false);
    } catch (e) {
      this.error.set(errorMessage(e));
    }
  }

  async copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 2000);
    } catch {
      /* clipboard unavailable: the key is selectable */
    }
  }
}
