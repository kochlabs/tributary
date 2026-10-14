import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, Attribution, errorMessage, Notice } from './core/api';
import { Auth } from './core/auth';
import { readPref, writePref } from './core/time';
import { Theme } from './core/util';
import { TimeRangePicker } from './shared/time-range';

@Component({
  selector: 'nfa-shell',
  imports: [ClarityModule, RouterOutlet, RouterLink, RouterLinkActive, TimeRangePicker, FormsModule],
  template: `
    <div class="main-container">
      @if (visibleNotices().length) {
        <clr-alerts>
          @for (n of visibleNotices(); track n.id) {
            <clr-alert [clrAlertType]="n.level" [clrAlertAppLevel]="true" [clrAlertClosable]="n.dismissible" (clrAlertClosedChange)="$event && dismiss(n)">
              <clr-alert-item>
                <span class="alert-text">{{ n.message }}</span>
                @if (n.action) {
                  <div class="alert-actions">
                    <button class="btn alert-action" (click)="router.navigateByUrl(n.action.route)">{{ n.action.label }}</button>
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
            <button class="nav-text user-btn" clrDropdownTrigger aria-label="User menu">
              <cds-icon shape="user"></cds-icon>
              <span class="user-name">{{ auth.user()?.username }}</span>
              <cds-icon shape="angle" direction="down"></cds-icon>
            </button>
            <clr-dropdown-menu *clrIfOpen clrPosition="bottom-right">
              <h4 class="dropdown-header">{{ auth.user()?.fullName || auth.user()?.username }} · {{ auth.user()?.role }}</h4>
              <button clrDropdownItem (click)="theme.toggle()">
                <cds-icon [shape]="theme.mode() === 'dark' ? 'sun' : 'moon'"></cds-icon>
                {{ theme.mode() === 'dark' ? 'Light theme' : 'Dark theme' }}
              </button>
              <button clrDropdownItem (click)="openPassword()"><cds-icon shape="lock"></cds-icon> Change password</button>
              <button clrDropdownItem (click)="openAbout()"><cds-icon shape="info-circle"></cds-icon> About</button>
              <div class="dropdown-divider" role="separator"></div>
              <button clrDropdownItem (click)="logout()"><cds-icon shape="logout"></cds-icon> Log out</button>
            </clr-dropdown-menu>
          </clr-dropdown>
        </div>
      </header>
      <div class="content-container">
        <clr-vertical-nav [clrVerticalNavCollapsible]="true" [(clrVerticalNavCollapsed)]="navCollapsed">
          <a clrVerticalNavLink routerLink="/dashboard" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="dashboard"></cds-icon>Dashboard</a>
          <a clrVerticalNavLink routerLink="/explorer" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="line-chart"></cds-icon>Traffic Explorer</a>
          <a clrVerticalNavLink routerLink="/flows" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="table"></cds-icon>Flow Search</a>
          <a clrVerticalNavLink routerLink="/devices" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="devices"></cds-icon>Devices</a>
          <a clrVerticalNavLink routerLink="/exporters" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="router"></cds-icon>Exporters</a>
          <a clrVerticalNavLink routerLink="/system" routerLinkActive="active"><cds-icon clrVerticalNavIcon shape="host"></cds-icon>System Health</a>
          @if (auth.isAdmin()) {
            <clr-vertical-nav-group routerLinkActive="active" [clrVerticalNavGroupExpanded]="true">
              <cds-icon clrVerticalNavIcon shape="cog"></cds-icon>
              Administration
              <clr-vertical-nav-group-children>
                <a clrVerticalNavLink routerLink="/admin/settings" routerLinkActive="active">Settings</a>
                <a clrVerticalNavLink routerLink="/admin/users" routerLinkActive="active">Users</a>
                <a clrVerticalNavLink routerLink="/admin/identity-sources" routerLinkActive="active">Identity Sources</a>
                <a clrVerticalNavLink routerLink="/admin/data-sources" routerLinkActive="active">Data Sources</a>
                <a clrVerticalNavLink routerLink="/admin/certificates" routerLinkActive="active">Certificates</a>
                <a clrVerticalNavLink routerLink="/admin/services" routerLinkActive="active">Services</a>
                <a clrVerticalNavLink routerLink="/admin/time" routerLinkActive="active">Time</a>
                <a clrVerticalNavLink routerLink="/admin/updates" routerLinkActive="active">Updates</a>
                <a clrVerticalNavLink routerLink="/admin/audit" routerLinkActive="active">Audit Log</a>
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
      <h3 class="modal-title">Change password</h3>
      <div class="modal-body">
        <form clrForm clrLayout="vertical" id="pwform" (ngSubmit)="changePassword()">
          <clr-password-container>
            <label>Current password</label>
            <input clrPassword name="cur" [(ngModel)]="pwCurrent" autocomplete="current-password" required />
          </clr-password-container>
          <clr-password-container>
            <label>New password</label>
            <input clrPassword name="new" [(ngModel)]="pwNew" autocomplete="new-password" required minlength="8" />
            <clr-control-helper>At least 8 characters.</clr-control-helper>
          </clr-password-container>
          <clr-password-container>
            <label>Confirm new password</label>
            <input clrPassword name="confirm" [(ngModel)]="pwConfirm" autocomplete="new-password" required />
          </clr-password-container>
        </form>
        @if (pwError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ pwError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="pwOpen.set(false)">Cancel</button>
        <button type="submit" form="pwform" class="btn btn-primary" [clrLoading]="pwBusy()">Change password</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="aboutOpen()" (clrModalOpenChange)="aboutOpen.set($event)" clrModalSize="md">
      <h3 class="modal-title"><img class="about-logo" src="brand/mark.png" alt="" /> Tributary</h3>
      <div class="modal-body about">
        <p class="ver">Version {{ version() }}</p>
        <p>
          Tributary is free software, licensed under the
          <a href="LICENSE.txt" target="_blank" rel="noopener">GNU Affero General Public License v3.0</a> or later.
          @if (source()) {
            <a [href]="source()" target="_blank" rel="noopener">Source code</a> is available to everyone who uses it.
          }
        </p>
        @if (attributions().length) {
          <h4>Data</h4>
          <ul class="list-unstyled">
            @for (a of attributions(); track a.text) {
              <li><a [href]="a.url" target="_blank" rel="noopener">{{ a.text }}</a>{{ a.license ? ' (' + a.license + ')' : '' }}</li>
            }
          </ul>
        }
        <h4>Open-source components</h4>
        <p>
          <a href="THIRD_PARTY_NOTICES.txt" target="_blank" rel="noopener">Server components</a> ·
          <a href="3rdpartylicenses.txt" target="_blank" rel="noopener">Web interface components</a>
        </p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-primary" (click)="aboutOpen.set(false)">Close</button>
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
      this.pwError.set('New passwords do not match.');
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
