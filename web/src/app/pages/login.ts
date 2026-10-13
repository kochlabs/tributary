import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';

@Component({
  selector: 'nfa-login',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="login-wrapper">
      <form class="login" (ngSubmit)="submit()">
        <section class="title">
          <svg class="logo" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="6" fill="#0072a3"/><path d="M5 8.5c6.5 0 8 7.5 15 7.5M5 16h15M5 23.5c6.5 0 8-7.5 15-7.5" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/><path d="M20 16h7" fill="none" stroke="#fff" stroke-width="3.6" stroke-linecap="round"/></svg>
          <h3 class="welcome">Welcome to</h3>
          {{ name() }}
          <h5 class="hint">Network flow analytics</h5>
        </section>
        <div class="login-group">
          <clr-input-container>
            <label class="clr-sr-only">Username</label>
            <input type="text" name="username" clrInput placeholder="Username" [(ngModel)]="username" autocomplete="username" required autofocus />
          </clr-input-container>
          <clr-password-container>
            <label class="clr-sr-only">Password</label>
            <input type="password" name="password" clrPassword placeholder="Password" [(ngModel)]="password" autocomplete="current-password" required />
          </clr-password-container>
          @if (error()) {
            <div class="error active">{{ error() }}</div>
          }
          <button type="submit" class="btn btn-primary" [clrLoading]="busy()" [disabled]="!username || !password">Sign in</button>
        </div>
        <div class="version">Version {{ version() }}</div>
      </form>
    </div>
  `,
  styles: `
    .logo { width: 48px; height: 48px; display: block; margin-bottom: 16px; }
    .version { margin-top: 24px; font-size: 11px; color: var(--cds-alias-typography-color-300); }
  `,
})
export class Login {
  private auth = inject(Auth);
  private api = inject(Api);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  readonly name = signal('Tributary');
  readonly version = signal('');
  readonly error = signal('');
  readonly busy = signal(false);
  username = '';
  password = '';

  constructor() {
    this.api.publicInfo().then((i) => {
      this.name.set(i.name);
      this.version.set(i.version);
    });
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
}
