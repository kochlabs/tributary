import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, EmailConfig, errorMessage } from '../core/api';

const PORTS: Record<EmailConfig['security'], number> = { starttls: 587, tls: 465, none: 25 };

/** The SMTP server the appliance sends mail through (Configuration → Email). */
@Component({
  selector: 'nfa-email',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.email">Email</h2>
        <p class="subtitle" i18n="@@email.subtitle">
          The mail server the appliance sends reports and alerts through.
        </p>
      </div>
    </div>

    @if (saved()) {
      <div class="alert alert-success" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text" i18n="@@email.saved">Saved.</span>
          </div>
        </div>
      </div>
    }
    @if (error()) {
      <div class="alert alert-danger" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text">{{ error() }}</span>
          </div>
        </div>
      </div>
    }

    @if (c(); as c) {
      <form clrForm clrLayout="horizontal" clrLabelSize="3" (ngSubmit)="save()" class="em-form">
        <div class="card">
          <div class="card-header" i18n="@@email.server">SMTP server</div>
          <div class="card-block">
            <clr-toggle-container>
              <label i18n="@@email.sending">Sending</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="enabled" [(ngModel)]="c.enabled" />
                <label i18n="@@email.enable">Send email from the appliance</label>
              </clr-toggle-wrapper>
              <clr-control-helper i18n="@@email.enableHelp"
                >While off, nothing is sent; you can still send a test message.</clr-control-helper
              >
            </clr-toggle-container>
            <clr-input-container>
              <label i18n="@@email.host">Server</label>
              <input
                clrInput
                name="host"
                [(ngModel)]="c.host"
                placeholder="smtp.example.com"
                autocomplete="off"
                spellcheck="false"
              />
            </clr-input-container>
            <clr-select-container>
              <label i18n="@@email.security">Security</label>
              <select
                clrSelect
                name="security"
                [ngModel]="c.security"
                (ngModelChange)="setSecurity($event)"
              >
                <option value="starttls" i18n="@@email.starttls">
                  STARTTLS (usually port 587)
                </option>
                <option value="tls" i18n="@@email.tls">TLS (usually port 465)</option>
                <option value="none" i18n="@@email.none">
                  None: a relay on a trusted network (usually port 25)
                </option>
              </select>
              <clr-control-helper>
                @if (c.security === 'none') {
                  <ng-container i18n="@@email.noneHelp"
                    >Mail is sent unencrypted, and without signing in.</ng-container
                  >
                } @else {
                  <ng-container i18n="@@email.securityHelp"
                    >The server's certificate is checked against the system CAs and those under
                    Appliance → Certificates.</ng-container
                  >
                }
              </clr-control-helper>
            </clr-select-container>
            <clr-input-container>
              <label i18n="@@email.port">Port</label>
              <input
                clrInput
                type="number"
                name="port"
                [(ngModel)]="c.port"
                min="1"
                max="65535"
                class="short"
              />
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@email.username">Username</label>
              <input
                clrInput
                name="username"
                [(ngModel)]="c.username"
                autocomplete="off"
                spellcheck="false"
                [disabled]="c.security === 'none'"
              />
              <clr-control-helper i18n="@@email.usernameHelp"
                >Leave empty if the server accepts mail without signing in.</clr-control-helper
              >
            </clr-input-container>
            @if (c.username && c.security !== 'none') {
              <clr-password-container>
                <label i18n="@@email.password">Password</label>
                <input
                  clrPassword
                  name="password"
                  [(ngModel)]="password"
                  autocomplete="new-password"
                  [placeholder]="c.hasPassword ? storedKeep : ''"
                />
                <clr-control-helper i18n="@@email.passwordHelp"
                  >Stored encrypted. For Microsoft 365 or Google, use an app
                  password.</clr-control-helper
                >
              </clr-password-container>
            }
            <clr-input-container>
              <label i18n="@@email.from">Sender</label>
              <input
                clrInput
                name="from"
                [(ngModel)]="c.from"
                placeholder="Tributary <tributary@example.com>"
                autocomplete="off"
                spellcheck="false"
                class="wide"
              />
              <clr-control-helper i18n="@@email.fromHelp"
                >An address the server lets this account send as, optionally with a
                name.</clr-control-helper
              >
            </clr-input-container>
          </div>
        </div>

        <div class="card">
          <div class="card-header" i18n="@@email.testTitle">Test</div>
          <div class="card-block">
            <div class="test-row">
              <input
                class="clr-input wide"
                name="testTo"
                [(ngModel)]="testTo"
                placeholder="you@example.com"
                aria-label="Recipient"
                i18n-aria-label="@@email.recipient"
                autocomplete="off"
              />
              <button
                type="button"
                class="btn btn-outline"
                (click)="test()"
                [clrLoading]="testing()"
                [disabled]="!testTo.trim() || !c.host || !c.from"
                i18n="@@email.sendTest"
              >
                Send test message
              </button>
            </div>
            <p class="hint" i18n="@@email.testHelp">Uses the settings above, saved or not.</p>
            @if (testResult(); as t) {
              @if (t.ok) {
                <div class="result ok">
                  <cds-icon shape="check-circle" status="success"></cds-icon>
                  <ng-container i18n="@@email.testOk"
                    >Sent. Check the inbox (and the spam folder).</ng-container
                  >
                </div>
              } @else {
                <div class="result bad">
                  <cds-icon shape="error-standard" status="danger"></cds-icon> {{ t.error }}
                </div>
              }
            }
          </div>
        </div>

        <div class="actions">
          <button
            type="submit"
            class="btn btn-primary"
            [clrLoading]="busy()"
            [disabled]="!dirty()"
            i18n="@@common.save"
          >
            Save
          </button>
          <button
            type="button"
            class="btn btn-outline"
            (click)="load()"
            [disabled]="!dirty()"
            i18n="@@common.revert"
          >
            Revert
          </button>
          @if (dirty()) {
            <span class="unsaved"
              ><cds-icon shape="exclamation-triangle"></cds-icon>
              <ng-container i18n="@@enrichment.unsaved">Unsaved changes.</ng-container></span
            >
          }
        </div>
      </form>
    }
  `,
  styles: `
    .em-form {
      max-width: 880px;
    }
    .em-form .card:first-child {
      margin-top: 0;
    }
    .alert {
      margin: 0 0 16px;
      max-width: 880px;
    }
    input.wide {
      width: 24rem;
      max-width: 100%;
    }
    input.short {
      width: 6rem;
    }
    .test-row {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .test-row .btn {
      margin: 0;
    }
    .hint {
      font-size: 12px;
      color: var(--cds-alias-typography-color-300);
      margin-top: 6px;
    }
    .result {
      margin-top: 10px;
      font-size: 13px;
      display: flex;
      align-items: flex-start;
      gap: 6px;
    }
    .result.bad {
      color: var(--cds-alias-status-danger);
      word-break: break-word;
    }
    .actions {
      margin-top: 16px;
      display: flex;
      align-items: center;
      gap: 4px;
      flex-wrap: wrap;
    }
    .unsaved {
      font-size: 13px;
      color: var(--cds-alias-status-warning-shade, #8c5c00);
      margin-left: 8px;
    }
  `,
})
export class EmailPage {
  private api = inject(Api);
  readonly c = signal<EmailConfig | null>(null);
  readonly busy = signal(false);
  readonly testing = signal(false);
  readonly saved = signal(false);
  readonly error = signal('');
  readonly testResult = signal<{ ok: boolean; error?: string } | null>(null);
  readonly storedKeep = $localize`:@@dataSources.storedKeep:Stored · leave empty to keep`;
  password = '';
  testTo = '';
  private savedJson = '';

  constructor() {
    this.load();
  }

  dirty() {
    const c = this.c();
    return !!c && (JSON.stringify(c) !== this.savedJson || !!this.password);
  }

  private set(c: EmailConfig) {
    this.c.set(c);
    this.savedJson = JSON.stringify(c);
    this.password = '';
  }

  /** Switching security moves a default port along with it. */
  setSecurity(sec: EmailConfig['security']) {
    const c = this.c();
    if (!c) return;
    if (Object.values(PORTS).includes(c.port)) c.port = PORTS[sec];
    c.security = sec;
    if (sec === 'none') c.username = '';
  }

  private form(): EmailConfig {
    return { ...this.c()!, password: this.password };
  }

  async load() {
    this.saved.set(false);
    this.error.set('');
    try {
      this.set(await this.api.email());
    } catch (err) {
      this.error.set(errorMessage(err));
    }
  }

  async save() {
    this.busy.set(true);
    this.saved.set(false);
    this.error.set('');
    try {
      this.set(await this.api.saveEmail(this.form()));
      this.saved.set(true);
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  async test() {
    this.testing.set(true);
    this.testResult.set(null);
    try {
      this.testResult.set(await this.api.testEmail(this.form(), this.testTo));
    } catch (err) {
      this.testResult.set({ ok: false, error: errorMessage(err) });
    } finally {
      this.testing.set(false);
    }
  }
}
