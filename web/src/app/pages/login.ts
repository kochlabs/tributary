import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { languageName, setLanguageCookie } from '../core/language';

@Component({
  selector: 'nfa-login',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="login-wrapper">
      <form class="login" (ngSubmit)="submit()">
        <section class="title">
          <div class="brand">
            <img class="logo light-only" src="brand/mark.png" alt="" />
            <img class="logo dark-only" src="brand/mark-light.png" alt="" />
            @if (name() === 'Tributary') {
              <h1 class="clr-sr-only">Tributary</h1>
              <img class="wordmark light-only" src="brand/wordmark.png" alt="Tributary" />
              <img class="wordmark dark-only" src="brand/wordmark-light.png" alt="Tributary" />
            } @else {
              <span class="name">{{ name() }}</span>
            }
          </div>
          <h5 class="hint" i18n="@@login.tagline">Network Flow Analytics</h5>
        </section>
        <div class="login-group">
          <clr-input-container>
            <label class="clr-sr-only" i18n="@@login.username">Username</label>
            <input type="text" name="username" clrInput placeholder="Username" i18n-placeholder="@@login.username" [(ngModel)]="username" autocomplete="username" required autofocus />
          </clr-input-container>
          <clr-password-container>
            <label class="clr-sr-only" i18n="@@login.password">Password</label>
            <input type="password" name="password" clrPassword placeholder="Password" i18n-placeholder="@@login.password" [(ngModel)]="password" autocomplete="current-password" required />
          </clr-password-container>
          @if (error()) {
            <div class="error active">{{ error() }}</div>
          }
          <button type="submit" class="btn btn-primary" [clrLoading]="busy()" [disabled]="!username || !password" i18n="@@login.title">Sign in</button>
          @if (sso().length) {
            <div class="divider"><span i18n="Separator between password sign-in and SSO buttons@@login.or">or</span></div>
            @for (s of sso(); track s.id) {
              <a class="btn btn-outline sso-btn" [href]="ssoHref(s.id)"><cds-icon shape="login"></cds-icon> <ng-container i18n="@@login.signInWith">Sign in with {{ s.name }}</ng-container></a>
            }
          }
        </div>
        <div class="version" i18n="@@login.version">Version {{ version() }}</div>
        @if (languages().length > 1) {
          <div class="language">
            <cds-icon shape="network-globe"></cds-icon>
            <select class="clr-select" aria-label="Language" i18n-aria-label="@@shell.language" (change)="setLanguage($any($event.target).value)">
              @for (l of languages(); track l.code) {
                <option [value]="l.code" [selected]="l.code === language()" [attr.lang]="l.code">{{ l.name }}</option>
              }
            </select>
          </div>
        }
      </form>
    </div>
  `,
  styles: `
    .login-wrapper { background: #02060c url('/brand/login-background.webp') right center / cover no-repeat; }
    /* Clarity centres the login column; span it so the brand lines up with the form's left edge. */
    .title { align-self: stretch; text-align: left; }
    .brand { display: flex; align-items: center; gap: 14px; }
    .logo, .wordmark { height: 48px; width: auto; display: block; }
    .name { line-height: 48px; }
    .dark-only { display: none; }
    :host-context([cds-theme='dark']) .dark-only { display: block; }
    :host-context([cds-theme='dark']) .light-only { display: none; }
    .divider { display: flex; align-items: center; gap: 12px; margin: 18px 0 6px; font-size: 12px; color: var(--cds-alias-typography-color-300); }
    .divider::before, .divider::after { content: ''; flex: 1; border-top: 1px solid var(--cds-alias-object-border-color); }
    .sso-btn { margin: 6px 0 0; width: 100%; max-width: none; }
    .language { margin-top: 12px; display: flex; align-items: center; gap: 6px; font-size: 12px; }
    .version { margin-top: 24px; font-size: 11px; color: var(--cds-alias-typography-color-300); }
  `,
})
export class Login {
  setLanguage(code: string) {
    setLanguageCookie(code);
    location.reload();
  }

  private auth = inject(Auth);
  private api = inject(Api);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  readonly name = signal('Tributary');
  readonly version = signal('');
  readonly languages = signal<{ code: string; name: string }[]>([]);
  readonly language = signal('');
  readonly sso = signal<{ id: number; name: string }[]>([]);
  readonly error = signal('');
  readonly busy = signal(false);
  username = '';
  password = '';

  constructor() {
    this.api.publicInfo().then((i) => {
      this.name.set(i.name);
      this.version.set(i.version);
      this.languages.set((i.languages ?? []).map((code) => ({ code, name: languageName(code) })));
      this.language.set(i.language ?? '');
      this.sso.set(i.sso ?? []);
    });
    const ssoError = this.route.snapshot.queryParamMap.get('sso_error');
    if (ssoError) this.error.set(ssoError);
  }

  async submit() {
    this.busy.set(true);
    this.error.set('');
    try {
      await this.auth.login(this.username, this.password);
      const next = this.route.snapshot.queryParamMap.get('next');
      this.router.navigateByUrl(next && next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard');
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  ssoHref(id: number) {
    const next = this.route.snapshot.queryParamMap.get('next');
    return `/api/auth/sso/${id}/start` + (next && next.startsWith('/') && !next.startsWith('//') ? `?next=${encodeURIComponent(next)}` : '');
  }
}
