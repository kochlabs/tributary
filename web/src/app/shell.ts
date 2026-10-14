import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, Attribution, errorMessage, Notice } from './core/api';
import { Auth } from './core/auth';
import { readPref, writePref } from './core/time';
import { Theme } from './core/util';
import { languageName, setLanguageCookie } from './core/language';
import { NoticeText, noticeActionLabel } from './shared/notice-text';
import { TimeRangePicker } from './shared/time-range';

@Component({
  selector: 'nfa-shell',
  imports: [ClarityModule, RouterOutlet, RouterLink, RouterLinkActive, TimeRangePicker, FormsModule, NoticeText],
  template: `
    <div class="main-container">
      @if (visibleNotices().length) {
        <clr-alerts>
          @for (n of visibleNotices(); track n.id) {
            <clr-alert [clrAlertType]="n.level" [clrAlertAppLevel]="true" [clrAlertClosable]="n.dismissible" (clrAlertClosedChange)="$event && dismiss(n)">
              <clr-alert-item>
                <span class="alert-text"><nfa-notice-text [notice]="n" /></span>
                @if (n.action) {
                  <div class="alert-actions">
                    <button class="btn alert-action" (click)="router.navigateByUrl(n.action.route)">{{ actionLabel(n) }}</button>
                  </div>
                }
              </clr-alert-item>
            </clr-alert>
          }
        </clr-alerts>
      }
      <header class="header header-6">
        <div class="branding">
          <a routerLink="/dashboard" class="nav-link">
            <img class="logo" src="brand/mark-light.png" alt="" />
            @if (name() === 'Tributary') {
              <img class="wordmark" src="brand/wordmark-light.png" alt="Tributary" />
            } @else {
              <span class="title">{{ name() }}</span>
            }
          </a>
        </div>
        <div class="header-actions">
          <nfa-time-range class="header-nav-item" />
          <clr-dropdown>
            <button class="nav-text user-btn" clrDropdownTrigger aria-label="User menu" i18n-aria-label="@@shell.userMenu">
              <cds-icon shape="user"></cds-icon>
              <span class="user-name">{{ auth.user()?.username }}</span>
              <cds-icon shape="angle" direction="down"></cds-icon>
            </button>
            <clr-dropdown-menu *clrIfOpen clrPosition="bottom-right">
              <h4 class="dropdown-header">{{ auth.user()?.fullName || auth.user()?.username }} · {{ auth.user()?.role }}</h4>
              <button clrDropdownItem (click)="theme.toggle()">
                <cds-icon [shape]="theme.mode() === 'dark' ? 'sun' : 'moon'"></cds-icon>
                @if (theme.mode() === 'dark') {
                  <ng-container i18n="@@shell.lightTheme">Light theme</ng-container>
                } @else {
                  <ng-container i18n="@@shell.darkTheme">Dark theme</ng-container>
                }
              </button>
              <button clrDropdownItem (click)="openPassword()"><cds-icon shape="lock"></cds-icon> <ng-container i18n="@@shell.changePassword">Change password</ng-container></button>
              <button clrDropdownItem (click)="openAbout()"><cds-icon shape="info-circle"></cds-icon> <ng-container i18n="@@shell.about">About</ng-container></button>
              @if (languages().length > 1) {
                <div class="dropdown-divider" role="separator"></div>
                <h4 class="dropdown-header" i18n="@@shell.language">Language</h4>
                @for (l of languages(); track l.code) {
                  <button clrDropdownItem [class.active]="l.code === language()" (click)="setLanguage(l.code)" [attr.lang]="l.code">
                    <cds-icon [shape]="l.code === language() ? 'check' : 'network-globe'"></cds-icon> {{ l.name }}
                  </button>
                }
              }
              <div class="dropdown-divider" role="separator"></div>
              <button clrDropdownItem (click)="logout()"><cds-icon shape="logout"></cds-icon> <ng-container i18n="@@shell.logout">Log out</ng-container></button>
            </clr-dropdown-menu>
          </clr-dropdown>
        </div>
      </header>
      <div class="content-container">
        <clr-vertical-nav [clrVerticalNavCollapsible]="true" [(clrVerticalNavCollapsed)]="navCollapsed">
          <a clrVerticalNavLink routerLink="/dashboard" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="dashboard"></cds-icon><ng-container i18n="@@nav.dashboard">Dashboard</ng-container></a>
          <a clrVerticalNavLink routerLink="/explorer" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="line-chart"></cds-icon><ng-container i18n="@@nav.explorer">Traffic Explorer</ng-container></a>
          <a clrVerticalNavLink routerLink="/flows" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="table"></cds-icon><ng-container i18n="@@nav.flows">Flow Search</ng-container></a>
          <a clrVerticalNavLink routerLink="/devices" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="devices"></cds-icon><ng-container i18n="@@nav.devices">Devices</ng-container></a>
          <a clrVerticalNavLink routerLink="/exporters" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="router"></cds-icon><ng-container i18n="@@nav.exporters">Exporters</ng-container></a>
          <a clrVerticalNavLink routerLink="/system" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="host"></cds-icon><ng-container i18n="@@nav.system">System Health</ng-container></a>
          @if (auth.isAdmin()) {
            <clr-vertical-nav-group routerLinkActive="active" [clrVerticalNavGroupExpanded]="true">
              <cds-icon clrVerticalNavIcon shape="cog"></cds-icon>
              <ng-container i18n="@@shell.administration">Administration</ng-container>
              <clr-vertical-nav-group-children>
                <a clrVerticalNavLink routerLink="/admin/settings" routerLinkActive="active" i18n="@@nav.settings">Settings</a>
                <a clrVerticalNavLink routerLink="/admin/users" routerLinkActive="active" i18n="@@nav.users">Users</a>
                <a clrVerticalNavLink routerLink="/admin/identity-sources" routerLinkActive="active" i18n="@@nav.identitySources">Identity Sources</a>
                <a clrVerticalNavLink routerLink="/admin/data-sources" routerLinkActive="active" i18n="@@nav.dataSources">Data Sources</a>
                <a clrVerticalNavLink routerLink="/admin/certificates" routerLinkActive="active" i18n="@@nav.certificates">Certificates</a>
                <a clrVerticalNavLink routerLink="/admin/services" routerLinkActive="active" i18n="@@nav.services">Services</a>
                <a clrVerticalNavLink routerLink="/admin/time" routerLinkActive="active" i18n="@@nav.time">Time</a>
                <a clrVerticalNavLink routerLink="/admin/updates" routerLinkActive="active" i18n="@@nav.updates">Updates</a>
                <a clrVerticalNavLink routerLink="/admin/audit" routerLinkActive="active" i18n="@@nav.audit">Audit Log</a>
              </clr-vertical-nav-group-children>
            </clr-vertical-nav-group>
          }
        </clr-vertical-nav>
        <main class="content-area">
          <router-outlet />
        </main>
      </div>
    </div>

    <clr-modal [(clrModalOpen)]="pwOpen" clrModalSize="md">
      <h3 class="modal-title" i18n="@@shell.changePassword">Change password</h3>
      <div class="modal-body">
        <form clrForm clrLayout="vertical" id="pwform" (ngSubmit)="changePassword()">
          <clr-password-container>
            <label i18n="@@shell.currentPassword">Current password</label>
            <input clrPassword name="cur" [(ngModel)]="pwCurrent" autocomplete="current-password" required />
          </clr-password-container>
          <clr-password-container>
            <label i18n="@@shell.newPassword">New password</label>
            <input clrPassword name="new" [(ngModel)]="pwNew" autocomplete="new-password" required minlength="8" />
            <clr-control-helper i18n="@@shell.passwordHint">At least 8 characters.</clr-control-helper>
          </clr-password-container>
          <clr-password-container>
            <label i18n="@@shell.confirmPassword">Confirm new password</label>
            <input clrPassword name="confirm" [(ngModel)]="pwConfirm" autocomplete="new-password" required />
          </clr-password-container>
        </form>
        @if (pwError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ pwError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="pwOpen.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="submit" form="pwform" class="btn btn-primary" [clrLoading]="pwBusy()" i18n="@@shell.changePassword">Change password</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="aboutOpen()" (clrModalOpenChange)="aboutOpen.set($event)" clrModalSize="md">
      <h3 class="modal-title"><img class="about-logo" src="brand/mark.png" alt="" /> Tributary</h3>
      <div class="modal-body about">
        <p class="ver" i18n="@@shell.version">Version {{ version() }}</p>
        <p>
          <ng-container i18n="@@shell.license">Tributary is free software, licensed under the
          <a href="LICENSE.txt" target="_blank" rel="noopener">GNU Affero General Public License v3.0</a> or later.</ng-container>
          @if (source()) {
            <ng-container i18n="@@shell.sourceCode"><a [href]="source()" target="_blank" rel="noopener">Source code</a> is available to everyone who uses it.</ng-container>
          }
        </p>
        @if (attributions().length) {
          <h4 i18n="@@shell.data">Data</h4>
          <ul class="list-unstyled">
            @for (a of attributions(); track a.text) {
              <li><a [href]="a.url" target="_blank" rel="noopener">{{ a.text }}</a>{{ a.license ? ' (' + a.license + ')' : '' }}</li>
            }
          </ul>
        }
        <h4 i18n="@@shell.openSource">Open-source components</h4>
        <p>
          <a href="THIRD_PARTY_NOTICES.txt" target="_blank" rel="noopener" i18n="@@shell.serverComponents">Server components</a> ·
          <a href="3rdpartylicenses.txt" target="_blank" rel="noopener" i18n="@@shell.webComponents">Web interface components</a>
        </p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-primary" (click)="aboutOpen.set(false)" i18n="@@common.close">Close</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .about-logo { height: 24px; vertical-align: -4px; margin-right: 6px; }
    .about h4 { margin-top: 16px; font-size: 14px; }
    .about .ver { color: var(--cds-alias-typography-color-300); margin-top: 0; }
    .branding .nav-link { display: flex; align-items: center; gap: 10px; }
    .logo { height: 26px; width: auto; }
    .wordmark { height: 26px; width: auto; }
    .title { white-space: nowrap; }
    .user-btn { display: flex; align-items: center; gap: 6px; background: none; border: 0; color: inherit; cursor: pointer; padding: 0 16px; height: 100%; font: inherit; }
    .header-actions { align-items: stretch; }
    .content-area { padding: 18px 24px 32px; }
    @media (max-width: 768px) { .user-name { display: none; } .content-area { padding: 12px; } }
  `,
})
export class Shell {
  readonly auth = inject(Auth);
  readonly theme = inject(Theme);
  private api = inject(Api);
  readonly router = inject(Router);
  readonly name = signal('Tributary');
  navCollapsed = false;

  readonly pwOpen = signal(false);
  pwCurrent = '';
  pwNew = '';
  pwConfirm = '';
  readonly pwError = signal('');
  readonly pwBusy = signal(false);

  readonly notices = signal<Notice[]>([]);
  private readonly dismissed = signal<string[]>(this.loadDismissed());
  readonly visibleNotices = computed(() => this.notices().filter((n) => !n.dismissible || !this.dismissed().includes(n.id)));

  readonly aboutOpen = signal(false);
  readonly version = signal('');
  readonly source = signal('');
  readonly attributions = signal<Attribution[]>([]);

  constructor() {
    this.loadNotices();
    const id = setInterval(() => this.loadNotices(), 60_000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
    this.api.publicInfo().then((i) => {
      this.languages.set((i.languages ?? []).map((code) => ({ code, name: languageName(code) })));
      this.language.set(i.language ?? '');
      this.name.set(i.name);
      this.version.set(i.version);
      this.source.set(i.source);
      document.title = i.name;
    });
  }

  private loadDismissed(): string[] {
    try {
      return JSON.parse(readPref('nfa.dismissedNotices', '[]'));
    } catch {
      return [];
    }
  }

  async loadNotices() {
    try {
      const list = await this.api.notices();
      if (!Array.isArray(list)) return;
      this.notices.set(list);
      // Forget dismissals of conditions that have cleared.
      const ids = new Set(list.map((n) => n.id));
      const kept = this.dismissed().filter((d) => ids.has(d));
      if (kept.length !== this.dismissed().length) {
        this.dismissed.set(kept);
        writePref('nfa.dismissedNotices', JSON.stringify(kept));
      }
    } catch {
      // Keep the last known notices; the session may have expired.
    }
  }

  dismiss(n: Notice) {
    const d = [...this.dismissed(), n.id];
    this.dismissed.set(d);
    writePref('nfa.dismissedNotices', JSON.stringify(d));
  }

  async logout() {
    await this.auth.logout();
    this.router.navigate(['/login']);
  }

  readonly languages = signal<{ code: string; name: string }[]>([]);
  readonly language = signal('');

  /** Switches the UI language: the server serves the matching build. */
  setLanguage(code: string) {
    setLanguageCookie(code);
    location.reload();
  }

  actionLabel = noticeActionLabel;

  async openAbout() {
    this.aboutOpen.set(true);
    try {
      const g = await this.api.geo();
      this.attributions.set(g.geo.attributions);
    } catch {
      this.attributions.set([]);
    }
  }

  openPassword() {
    this.pwCurrent = this.pwNew = this.pwConfirm = '';
    this.pwError.set('');
    this.pwOpen.set(true);
  }

  async changePassword() {
    if (this.pwNew !== this.pwConfirm) {
      this.pwError.set($localize`:@@shell.passwordMismatch:New passwords do not match.`);
      return;
    }
    this.pwBusy.set(true);
    try {
      await this.api.changePassword(this.pwCurrent, this.pwNew);
      this.pwOpen.set(false);
    } catch (e) {
      this.pwError.set(errorMessage(e));
    } finally {
      this.pwBusy.set(false);
    }
  }
}
