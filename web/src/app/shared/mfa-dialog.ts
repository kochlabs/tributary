import { Component, inject, model, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, MfaSetup } from '../core/api';
import { Auth } from '../core/auth';

/** Turn two-factor authentication on or off for the signed-in user. */
@Component({
  selector: 'nfa-mfa-dialog',
  imports: [ClarityModule, FormsModule],
  template: `
    <clr-modal [clrModalOpen]="open()" (clrModalOpenChange)="close($event)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@mfa.title">Two-factor authentication</h3>
      <div class="modal-body">
        @if (status(); as st) {
          @if (!st.available) {
            <p i18n="@@mfa.ssoAccount">Your account signs in through single sign-on; two-factor authentication is handled by your identity provider.</p>
          } @else if (codes().length) {
            <p i18n="@@mfa.recoveryIntro">Two-factor authentication is on. Save these recovery codes somewhere safe: each one signs you in once if you lose your device. They won't be shown again.</p>
            <ul class="recovery">
              @for (c of codes(); track c) {
                <li><code>{{ c }}</code></li>
              }
            </ul>
          } @else if (setup(); as su) {
            <p i18n="@@mfa.scan">Scan this code with an authenticator app, then enter the 6-digit code it shows.</p>
            <img class="qr" [src]="su.qr" alt="QR code for your authenticator app" i18n-alt="@@login.qrAlt" />
            <details class="manual"><summary i18n="@@login.manualEntry">Can't scan? Enter this key instead</summary><code>{{ su.secret }}</code></details>
            <input class="clr-input code" [(ngModel)]="code" name="mfaCode" inputmode="numeric" autocomplete="one-time-code" placeholder="123 456" (keyup.enter)="confirm()" />
          } @else if (st.enabled) {
            <p><cds-icon shape="check-circle" class="on"></cds-icon> <ng-container i18n="@@mfa.on">On. Sign-ins ask for a code from your authenticator app.</ng-container></p>
            <p class="sub" i18n="@@mfa.recoveryLeft">{{ st.recoveryLeft }} recovery codes left.</p>
            @if (st.required) {
              <p class="sub" i18n="@@mfa.requiredNote">Required for administrators on this appliance, so it can't be turned off. To move to a new device, ask another administrator to reset it, then set it up again.</p>
            } @else {
              <p class="sub" i18n="@@mfa.offPrompt">To turn it off, enter a current code (or a recovery code):</p>
              <input class="clr-input code" [(ngModel)]="code" name="mfaOff" inputmode="numeric" autocomplete="one-time-code" placeholder="123 456" />
            }
          } @else {
            <p i18n="@@mfa.offIntro">Protect your account with a code from an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden…) in addition to your password.</p>
          }
        }
        @if (error()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        @if (status(); as st) {
          @if (st.available && !codes().length) {
            @if (setup()) {
              <button type="button" class="btn btn-primary" (click)="confirm()" [clrLoading]="busy()" [disabled]="!code.trim()" i18n="@@mfa.turnOn">Turn on</button>
            } @else if (!st.enabled) {
              <button type="button" class="btn btn-primary" (click)="start()" [clrLoading]="busy()" i18n="@@mfa.setUp">Set up</button>
            } @else if (!st.required) {
              <button type="button" class="btn btn-danger" (click)="disable()" [clrLoading]="busy()" [disabled]="!code.trim()" i18n="@@mfa.turnOff">Turn off</button>
            }
          }
        }
        <button type="button" class="btn btn-outline" (click)="close(false)">@if (codes().length) {<ng-container i18n="@@mfa.saved">I've saved them</ng-container>} @else {<ng-container i18n="@@common.close">Close</ng-container>}</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .code { width: 12rem; font-size: 18px; letter-spacing: .15em; text-align: center; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .qr { display: block; width: 180px; height: 180px; margin: 0 0 8px; image-rendering: pixelated; background: #fff; padding: 6px; border-radius: 4px; }
    .manual { font-size: 12px; margin-bottom: 12px; }
    .manual code { display: block; word-break: break-all; margin-top: 4px; }
    .recovery { columns: 2; list-style: none; padding: 0; }
    .sub { font-size: 13px; color: var(--cds-alias-typography-color-300); }
    .on { color: var(--cds-alias-status-success); }
  `,
})
export class MfaDialog {
  readonly open = model(false);
  private api = inject(Api);
  private auth = inject(Auth);
  readonly status = signal<{ available: boolean; enabled: boolean; recoveryLeft: number; required: boolean } | null>(null);
  readonly setup = signal<MfaSetup | null>(null);
  readonly codes = signal<string[]>([]);
  readonly error = signal('');
  readonly busy = signal(false);
  code = '';

  async load() {
    this.setup.set(null);
    this.codes.set([]);
    this.error.set('');
    this.code = '';
    try {
      this.status.set(await this.api.mfaStatus());
    } catch (e) {
      this.error.set(errorMessage(e));
    }
  }

  private async run(f: () => Promise<void>) {
    this.busy.set(true);
    this.error.set('');
    try {
      await f();
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  start() {
    return this.run(async () => this.setup.set(await this.api.mfaSetup()));
  }

  confirm() {
    return this.run(async () => {
      const r = await this.api.mfaSetupConfirm(this.code);
      this.setup.set(null);
      this.codes.set(r.recoveryCodes);
      this.status.set(await this.api.mfaStatus());
      const u = this.auth.user();
      if (u) this.auth.user.set({ ...u, mfa: true });
    });
  }

  disable() {
    return this.run(async () => {
      await this.api.mfaDisable(this.code);
      this.code = '';
      this.status.set(await this.api.mfaStatus());
      const u = this.auth.user();
      if (u) this.auth.user.set({ ...u, mfa: false });
    });
  }

  close(open: boolean) {
    if (!open) {
      this.open.set(false);
      this.setup.set(null);
      this.codes.set([]);
    }
  }
}
