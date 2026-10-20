import { Component, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, SnmpSettings } from '../core/api';
import { ago, dateTime } from '../core/format';

/** SNMP polling settings and status for one exporter (exporter detail page). */
@Component({
  selector: 'nfa-snmp-settings',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="card">
      <div class="card-header">
        <span><cds-icon shape="network-switch"></cds-icon> SNMP</span>
        @if (saved()?.version && saved()?.status; as st) {
          <span class="card-hint">
            @if (st.lastError) {
              <span class="bad"><cds-icon shape="error-standard"></cds-icon> <ng-container i18n="@@snmp.pollFailed">last poll failed {{ ago(st.lastPoll) }}</ng-container></span>
            } @else if (st.lastPoll) {
              <ng-container i18n="@@snmp.lastPoll">{{ st.sysName || '–' }} · {{ st.interfaces }} interfaces · polled {{ ago(st.lastPoll) }}</ng-container>
            } @else {
              <ng-container i18n="@@snmp.notPolled">not polled yet</ng-container>
            }
          </span>
        }
      </div>
      <div class="card-block">
        @if (s(); as s) {
          <p class="hint" i18n="@@snmp.hint">Polls the device every 15 minutes for interface names, descriptions (ifAlias) and speeds. Names and speeds you set yourself always take precedence; SNMP replaces names learned from flow data.</p>
          <div class="grid">
            <label i18n="@@snmp.version">Version</label>
            <div class="btn-group btn-sm" role="group">
              <button type="button" class="btn" [class.btn-primary]="!s.version" [class.btn-outline]="!!s.version" (click)="s.version = ''" i18n="@@snmp.off">Off</button>
              <button type="button" class="btn" [class.btn-primary]="s.version === '2c'" [class.btn-outline]="s.version !== '2c'" (click)="s.version = '2c'">v2c</button>
              <button type="button" class="btn" [class.btn-primary]="s.version === '3'" [class.btn-outline]="s.version !== '3'" (click)="s.version = '3'">v3</button>
            </div>
            @if (s.version) {
              <label i18n="@@snmp.agent">Agent</label>
              <div class="inline">
                <input class="clr-input host" [(ngModel)]="s.host" name="snmpHost" [placeholder]="addr()" spellcheck="false" />
                <span>:</span>
                <input class="clr-input port" type="number" [(ngModel)]="s.port" name="snmpPort" placeholder="161" min="1" max="65535" />
                <span class="sub" i18n="@@snmp.agentHelp">empty: the exporter's address</span>
              </div>
            }
            @if (s.version === '2c') {
              <label i18n="@@snmp.community">Community</label>
              <input class="clr-input" type="password" [(ngModel)]="community" name="snmpCommunity" autocomplete="new-password"
                [placeholder]="s.hasCommunity ? storedKeep : ''" />
            }
            @if (s.version === '3') {
              <label i18n="@@snmp.user">User</label>
              <input class="clr-input" [(ngModel)]="s.user" name="snmpUser" autocomplete="off" spellcheck="false" />
              <label i18n="@@snmp.auth">Authentication</label>
              <div class="inline">
                <select class="clr-select" [(ngModel)]="s.authProto" name="snmpAuth">
                  <option value="" i18n="@@snmp.none">None</option>
                  @for (a of authProtos; track a) { <option [value]="a">{{ a }}</option> }
                </select>
                @if (s.authProto) {
                  <input class="clr-input" type="password" [(ngModel)]="authPass" name="snmpAuthPass" autocomplete="new-password"
                    [placeholder]="s.hasAuthPass ? storedKeep : passphrase" />
                }
              </div>
              <label i18n="@@snmp.privacy">Privacy</label>
              <div class="inline">
                <select class="clr-select" [(ngModel)]="s.privProto" name="snmpPriv" [disabled]="!s.authProto">
                  <option value="" i18n="@@snmp.none">None</option>
                  @for (p of privProtos; track p) { <option [value]="p">{{ p }}</option> }
                </select>
                @if (s.privProto) {
                  <input class="clr-input" type="password" [(ngModel)]="privPass" name="snmpPrivPass" autocomplete="new-password"
                    [placeholder]="s.hasPrivPass ? storedKeep : passphrase" />
                }
              </div>
            }
          </div>
          @if (saved()?.status?.lastError; as e) {
            <p class="bad small">{{ e }}</p>
          }
          @if (saved()?.status?.sysDescr; as d) {
            <p class="sub small">{{ d }}</p>
          }
          @if (error()) {
            <p class="bad small">{{ error() }}</p>
          }
          <div class="actions">
            <button type="button" class="btn btn-primary btn-sm" (click)="save()" [disabled]="busy()" i18n="@@common.save">Save</button>
            @if (saved()?.version) {
              <button type="button" class="btn btn-outline btn-sm" (click)="poll()" [clrLoading]="busy()" i18n="@@snmp.pollNow">Poll now</button>
            }
          </div>
        }
      </div>
    </div>
  `,
  styles: `
    .card-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .card-hint { font-size: 12px; font-weight: 400; color: var(--cds-alias-typography-color-300); }
    .hint { font-size: 12px; color: var(--cds-alias-typography-color-300); margin-top: 0; }
    .grid { display: grid; grid-template-columns: 140px 1fr; gap: 10px 16px; align-items: center; max-width: 720px; font-size: 13px; }
    .grid label { color: var(--cds-alias-typography-color-400); font-weight: 600; }
    .inline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .host { width: 16rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .port { width: 5rem; }
    .inline input[type=password], .grid > input { width: 16rem; }
    .btn-group { margin: 0; }
    .sub { font-size: 11px; color: var(--cds-alias-typography-color-300); }
    .bad { color: var(--cds-alias-status-danger); }
    .small { font-size: 13px; margin: 10px 0 0; }
    .actions { display: flex; gap: 8px; margin-top: 14px; }
    .actions .btn { margin: 0; }
  `,
})
export class SnmpSettingsCard {
  readonly addr = input.required<string>();
  /** Emitted after a poll so the page can reload interfaces. */
  readonly polled = output<void>();
  private api = inject(Api);
  readonly s = signal<SnmpSettings | null>(null);
  readonly saved = signal<SnmpSettings | null>(null);
  readonly error = signal('');
  readonly busy = signal(false);
  readonly authProtos = ['SHA', 'SHA256', 'SHA512', 'MD5'];
  readonly privProtos = ['AES', 'AES256', 'DES'];
  readonly storedKeep = $localize`:@@snmp.storedKeep:Stored · leave empty to keep`;
  readonly passphrase = $localize`:@@snmp.passphrase:Passphrase (8+ characters)`;
  community = '';
  authPass = '';
  privPass = '';
  ago = ago;
  dt = dateTime;

  ngOnInit() {
    this.api.snmp(this.addr()).then(
      (v) => this.set(v),
      (e) => this.error.set(errorMessage(e)),
    );
  }

  private set(v: SnmpSettings) {
    this.saved.set(v);
    this.s.set({ ...v, port: v.port || (null as unknown as number) });
    this.community = this.authPass = this.privPass = '';
  }

  async save() {
    const s = this.s()!;
    this.busy.set(true);
    this.error.set('');
    try {
      this.set(
        await this.api.saveSnmp(this.addr(), {
          version: s.version, host: s.host ?? '', port: Number(s.port) || 0, user: s.user ?? '',
          authProto: s.authProto ?? '', privProto: s.privProto ?? '',
          community: this.community, authPass: this.authPass, privPass: this.privPass,
        }),
      );
      if (this.s()?.version) await this.poll();
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  async poll() {
    this.busy.set(true);
    this.error.set('');
    try {
      this.saved.set(await this.api.pollSnmp(this.addr()));
      this.polled.emit();
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }
}
