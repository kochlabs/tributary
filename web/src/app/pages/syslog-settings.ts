import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, SyslogConfig, SyslogStatus, SyslogTarget } from '../core/api';
import { count, dateTime } from '../core/format';

const FACILITIES: { id: number; label: string }[] = [
  { id: 4, label: 'auth (4)' },
  { id: 10, label: 'authpriv (10)' },
  { id: 13, label: 'log audit (13)' },
  { id: 1, label: 'user (1)' },
  ...[16, 17, 18, 19, 20, 21, 22, 23].map((id) => ({ id, label: `local${id - 16} (${id})` })),
];

/** Forwarding of the audit log to syslog servers (Audit Log page). */
@Component({
  selector: 'nfa-syslog-settings',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="card">
      <div class="card-header">
        <span><cds-icon shape="upload"></cds-icon> <ng-container i18n="@@syslog.title">Forward to syslog</ng-container></span>
        @if (status(); as st) {
          @if (saved()?.enabled) {
            <span class="card-hint" i18n="@@syslog.counters">{{ fmtCount(st.sent) }} sent · {{ fmtCount(st.dropped) }} dropped</span>
          }
        }
      </div>
      <div class="card-block">
        @if (c(); as c) {
          <p class="hint" i18n="@@syslog.hint">Sends every audit entry (sign-ins, failed sign-ins, configuration changes) to your syslog servers as it happens, for SIEM and compliance. Messages that can't be delivered are counted as dropped.</p>
          <clr-toggle-wrapper class="enable">
            <input type="checkbox" clrToggle name="syslogOn" [(ngModel)]="c.enabled" />
            <label i18n="@@syslog.enable">Forward the audit log</label>
          </clr-toggle-wrapper>

          <table class="table table-compact table-noborder targets">
            <thead>
              <tr><th class="left" i18n="@@syslog.server">Server</th><th class="left" i18n="@@syslog.transport">Transport</th><th></th></tr>
            </thead>
            <tbody>
              @for (t of c.targets; track $index; let i = $index) {
                <tr>
                  <td><input class="clr-input addr" [(ngModel)]="t.address" [name]="'addr' + i" placeholder="syslog.example.com" spellcheck="false" autocomplete="off" /></td>
                  <td>
                    <div class="btn-group btn-sm" role="group">
                      @for (tr of transports; track tr) {
                        <button type="button" class="btn" [class.btn-primary]="t.transport === tr" [class.btn-outline]="t.transport !== tr" (click)="t.transport = tr">{{ tr.toUpperCase() }}</button>
                      }
                    </div>
                    @if (!hasPort(t.address)) {
                      <span class="port" i18n="@@syslog.defaultPort">port {{ t.transport === 'tls' ? 6514 : 514 }}</span>
                    }
                  </td>
                  <td><button type="button" class="btn btn-icon btn-link btn-sm" (click)="remove(i)" aria-label="Remove" i18n-aria-label="@@listEditor.remove"><cds-icon shape="times"></cds-icon></button></td>
                </tr>
              }
            </tbody>
          </table>
          @if (c.targets.length < 4) {
            <button type="button" class="btn btn-link btn-sm add" (click)="add()"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@syslog.addServer">Add server</ng-container></button>
          }
          <p class="hint" i18n="@@syslog.tlsHint">TLS verifies the server's certificate against the system CAs and the trusted CAs on the Certificates page.</p>

          <div class="opts">
            <label>
              <span i18n="@@syslog.format">Format</span>
              <select class="clr-select" [(ngModel)]="c.format" name="fmt">
                <option value="rfc5424" i18n="@@syslog.rfc5424">RFC 5424 (recommended)</option>
                <option value="rfc3164" i18n="@@syslog.rfc3164">RFC 3164 (BSD, older collectors)</option>
              </select>
            </label>
            <label>
              <span i18n="@@syslog.facility">Facility</span>
              <select class="clr-select" [(ngModel)]="c.facility" name="fac">
                @for (f of facilities; track f.id) {
                  <option [ngValue]="f.id">{{ f.label }}</option>
                }
              </select>
            </label>
          </div>

          @if (results(); as rs) {
            <ul class="results">
              @for (r of rs; track r.address) {
                <li [class.ok]="r.ok" [class.bad]="!r.ok">
                  <cds-icon [shape]="r.ok ? 'check' : 'error-standard'"></cds-icon>
                  {{ r.address }}:
                  @if (r.ok) {
                    <ng-container i18n="@@syslog.testSent">test message sent</ng-container>
                  } @else {
                    {{ r.error }}
                  }
                </li>
              }
            </ul>
          }
          @if (status()?.lastError; as e) {
            <p class="bad small" i18n="@@syslog.lastError">Last delivery error ({{ dt(status()!.lastErrorAt!) }}): {{ e }}</p>
          }
          @if (error()) {
            <p class="bad small">{{ error() }}</p>
          }
          @if (ok()) {
            <p class="ok small" i18n="@@syslog.saved">Saved.</p>
          }
          <div class="actions">
            <button type="button" class="btn btn-primary btn-sm" (click)="save()" [disabled]="busy()" i18n="@@common.save">Save</button>
            <button type="button" class="btn btn-outline btn-sm" (click)="test()" [disabled]="busy() || !hasTargets()" i18n="@@syslog.test">Send test message</button>
          </div>
        }
      </div>
    </div>
  `,
  styles: `
    .card { margin-top: 0; margin-bottom: 16px; }
    .card-header { display: flex; justify-content: space-between; align-items: center; }
    .card-hint { font-size: 12px; font-weight: 400; color: var(--cds-alias-typography-color-300); }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 0; max-width: 900px; }
    .enable { margin: 8px 0 4px; }
    .targets { max-width: 760px; margin: 8px 0 0; }
    .targets th, .targets td { border: 0; padding: 4px 8px 4px 0; vertical-align: middle; }
    .left { text-align: left; }
    .addr { width: 22rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
    .btn-group { margin: 0; }
    .port { white-space: nowrap; font-size: 11px; color: var(--cds-alias-typography-color-300); margin-left: 8px; }
    .add { margin: 0; padding-left: 0; }
    .opts { display: flex; gap: 24px; flex-wrap: wrap; margin: 8px 0 12px; }
    .opts label { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; }
    .results { list-style: none; padding: 0; margin: 0 0 8px; font-size: 13px; }
    .ok { color: var(--cds-alias-status-success); }
    .bad { color: var(--cds-alias-status-danger); }
    .small { font-size: 13px; margin: 0 0 8px; }
    .actions { display: flex; gap: 8px; }
    .actions .btn { margin: 0; }
  `,
})
export class SyslogSettings {
  private api = inject(Api);
  readonly c = signal<SyslogConfig | null>(null);
  readonly saved = signal<SyslogConfig | null>(null);
  readonly status = signal<SyslogStatus | null>(null);
  readonly results = signal<{ address: string; ok: boolean; error?: string }[] | null>(null);
  readonly error = signal('');
  readonly ok = signal(false);
  readonly busy = signal(false);
  readonly transports: SyslogTarget['transport'][] = ['udp', 'tcp', 'tls'];
  readonly facilities = FACILITIES;
  dt = dateTime;
  fmtCount = count;

  constructor() {
    this.api.syslog().then(
      (r) => this.load(r),
      (e) => this.error.set(errorMessage(e)),
    );
  }

  private load(r: { config: SyslogConfig; status: SyslogStatus }) {
    this.saved.set(r.config);
    this.c.set(structuredClone(r.config));
    this.status.set(r.status);
  }

  /** Whether an address names a port (host:port or [v6]:port). */
  hasPort(a: string) {
    a = a.trim();
    return /^\[.*\]:\d+$/.test(a) || (/:\d+$/.test(a) && a.split(':').length === 2);
  }

  hasTargets() {
    return (this.c()?.targets ?? []).some((t) => t.address.trim());
  }

  add() {
    this.c()!.targets.push({ address: '', transport: 'udp' });
  }

  remove(i: number) {
    this.c()!.targets.splice(i, 1);
  }

  private clean(): SyslogConfig {
    const c = this.c()!;
    return { ...c, targets: c.targets.filter((t) => t.address.trim()) };
  }

  async save() {
    this.busy.set(true);
    this.error.set('');
    this.ok.set(false);
    try {
      this.load(await this.api.saveSyslog(this.clean()));
      this.ok.set(true);
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  async test() {
    this.busy.set(true);
    this.error.set('');
    this.results.set(null);
    try {
      this.results.set(await this.api.testSyslog(this.clean()));
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }
}
