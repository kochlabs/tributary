import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, APIToken, errorMessage, User } from '../core/api';
import { Auth } from '../core/auth';
import { ago, dateOnly } from '../core/format';
import { loader, trackByKey } from '../core/util';

/** API tokens for MCP clients (Access → API Tokens). */
@Component({
  selector: 'nfa-api-tokens',
  imports: [ClarityModule, FormsModule, RouterLink],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.apiTokens">API Tokens</h2>
        <p class="subtitle" i18n="@@tokens.subtitle">Tokens for MCP clients, such as Claude. A token acts as its owner, read-only.</p>
      </div>
    </div>

    @if (list.value(); as st) {
      @if (!st.mcpEnabled) {
        <div class="alert alert-info" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">
          <ng-container i18n="@@tokens.mcpOff">MCP is turned off, so tokens can't be used yet. Turn it on under <a routerLink="/admin/settings">Configuration → Settings</a>.</ng-container>
        </span></div></div></div>
      }
    }
    @if (list.error() || pageError()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ pageError() || list.error() }}</span></div></div></div>
    }

    <div class="toolbar">
      <div>
        <button class="btn btn-primary" (click)="openCreate()"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@tokens.create">Create token</ng-container></button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="confirmRevoke.set(selected()!)"><cds-icon shape="trash"></cds-icon> <ng-container i18n="@@tokens.revoke">Revoke</ng-container></button>
      </div>
      <button class="btn btn-link btn-icon" (click)="list.reload()" aria-label="Refresh" i18n-aria-label="@@common.refresh"><cds-icon shape="refresh"></cds-icon></button>
    </div>

    <clr-datagrid class="datagrid-compact" clrDgSelectionType="single" [clrDgSelected]="selectedList()" (clrDgSelectedChange)="selected.set($event[0])" [clrDgLoading]="list.loading()">
      <clr-dg-column [clrDgField]="'name'" i18n="@@tokens.name">Name</clr-dg-column>
      <clr-dg-column [clrDgField]="'username'" i18n="@@tokens.owner">Owner</clr-dg-column>
      <clr-dg-column i18n="@@tokens.token">Token</clr-dg-column>
      <clr-dg-column [clrDgField]="'createdAt'" [clrDgSortOrder]="-1" i18n="@@tokens.created">Created</clr-dg-column>
      <clr-dg-column [clrDgField]="'lastUsed'" i18n="@@tokens.lastUsed">Last used</clr-dg-column>
      <clr-dg-column [clrDgField]="'expiresAt'" i18n="@@tokens.expires">Expires</clr-dg-column>
      <clr-dg-row *clrDgItems="let t of list.value()?.tokens ?? []; trackBy: byId" [clrDgItem]="t">
        <clr-dg-cell>{{ t.name }}</clr-dg-cell>
        <clr-dg-cell>{{ t.username }}@if (roleOf(t.username); as r) { <span class="label" [class.label-purple]="r === 'admin'" [class.label-blue]="r === 'viewer'">{{ r }}</span>}</clr-dg-cell>
        <clr-dg-cell><code>{{ t.prefix }}…</code></clr-dg-cell>
        <clr-dg-cell>{{ day(t.createdAt) }}</clr-dg-cell>
        <clr-dg-cell>@if (t.lastUsed) {{{ ago(t.lastUsed) }}} @else {<span class="muted" i18n="@@tokens.never">never</span>}</clr-dg-cell>
        <clr-dg-cell [class.expired]="t.expiresAt && t.expiresAt < now">@if (t.expiresAt) {{{ day(t.expiresAt) }}} @else {<span class="muted" i18n="@@tokens.noExpiry">no expiry</span>}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder i18n="@@tokens.placeholder">No API tokens.</clr-dg-placeholder>
      <clr-dg-footer><ng-container i18n="@@tokens.count">{count(), plural, =1 {1 token} other {{{ count() }} tokens}}</ng-container></clr-dg-footer>
    </clr-datagrid>

    <clr-modal [clrModalOpen]="createOpen()" (clrModalOpenChange)="closeCreate($event)" clrModalSize="lg" [clrModalStaticBackdrop]="true">
      <h3 class="modal-title" i18n="@@tokens.createTitle">Create API token</h3>
      <div class="modal-body">
        @if (created(); as c) {
          <p i18n="@@tokens.copyNow">Copy the token now: it won't be shown again.</p>
          <div class="secret"><code>{{ c }}</code> <button type="button" class="btn btn-link btn-sm" (click)="copy(c, 'token')">{{ copied() === 'token' ? copiedLabel : copyLabel }}</button></div>
          <p class="sub" i18n="@@tokens.claudeCode">For Claude Code:</p>
          <div class="secret"><code>{{ claudeCommand(c) }}</code> <button type="button" class="btn btn-link btn-sm" (click)="copy(claudeCommand(c), 'cmd')">{{ copied() === 'cmd' ? copiedLabel : copyLabel }}</button></div>
          <p class="sub" i18n="@@tokens.otherClients">Other clients: the endpoint is {{ list.value()?.endpoint }}, with the header <code>Authorization: Bearer</code> and the token.</p>
        } @else {
          <form clrForm clrLayout="horizontal" clrLabelSize="3" id="tokenform" (ngSubmit)="create()">
            <clr-input-container>
              <label i18n="@@tokens.name">Name</label>
              <input clrInput name="tokenName" [(ngModel)]="name" required maxlength="64" placeholder="Claude on my laptop" i18n-placeholder="@@tokens.namePlaceholder2" autocomplete="off" />
            </clr-input-container>
            <clr-select-container>
              <label i18n="@@tokens.owner">Owner</label>
              <select clrSelect name="tokenOwner" [(ngModel)]="owner">
                @for (u of users.value() ?? []; track u.username) {
                  <option [value]="u.username">{{ u.username }} ({{ u.role }})</option>
                }
              </select>
              <clr-control-helper i18n="@@tokens.ownerHelp">The token has this user's role. Choose a viewer account to keep an assistant to viewing.</clr-control-helper>
            </clr-select-container>
            <clr-select-container>
              <label i18n="@@tokens.expires">Expires</label>
              <select clrSelect name="tokenDays" [(ngModel)]="days">
                <option [ngValue]="30" i18n="@@tokens.days30">In 30 days</option>
                <option [ngValue]="90" i18n="@@tokens.days90">In 90 days</option>
                <option [ngValue]="365" i18n="@@tokens.days365">In a year</option>
                <option [ngValue]="0" i18n="@@tokens.noExpiryOption">Never</option>
              </select>
            </clr-select-container>
          </form>
          @if (formError()) {
            <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ formError() }}</span></div></div></div>
          }
        }
      </div>
      <div class="modal-footer">
        @if (created()) {
          <button type="button" class="btn btn-primary" (click)="closeCreate(false)" i18n="@@tokens.done">Done</button>
        } @else {
          <button type="button" class="btn btn-outline" (click)="closeCreate(false)" i18n="@@common.cancel">Cancel</button>
          <button type="submit" form="tokenform" class="btn btn-primary" [disabled]="!name.trim() || !owner" [clrLoading]="busy()" i18n="@@tokens.create">Create token</button>
        }
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="!!confirmRevoke()" (clrModalOpenChange)="!$event && confirmRevoke.set(null)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@tokens.revokeTitle">Revoke {{ confirmRevoke()?.name }}?</h3>
      <div class="modal-body"><p i18n="@@tokens.revokeText">Clients using it stop working at once.</p></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmRevoke.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="revoke()" i18n="@@tokens.revoke">Revoke</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .alert { margin: 0 0 16px; }
    .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .toolbar .btn { margin: 0 6px 0 0; }
    .label { margin-left: 6px; }
    .muted { color: var(--cds-alias-typography-color-300); }
    .expired { color: var(--cds-alias-status-danger); }
    .sub { font-size: 13px; color: var(--cds-alias-typography-color-300); margin-top: 14px; }
    .secret { display: flex; align-items: center; gap: 8px; }
    .secret code { font-size: 12px; word-break: break-all; }
    .secret .btn { margin: 0; flex: none; }
  `,
})
export class ApiTokens {
  readonly byId = trackByKey<{ id: number }>((t) => t.id);
  private api = inject(Api);
  private auth = inject(Auth);
  readonly list = loader(() => true, () => this.api.apiTokens());
  readonly users = loader(() => true, () => this.api.users());
  readonly selected = signal<APIToken | undefined>(undefined);
  readonly selectedList = computed(() => {
    const t = this.selected();
    return t ? [t] : [];
  });
  readonly createOpen = signal(false);
  readonly created = signal('');
  readonly busy = signal(false);
  readonly formError = signal('');
  readonly pageError = signal('');
  readonly confirmRevoke = signal<APIToken | null>(null);
  readonly copied = signal('');
  readonly copyLabel = $localize`:@@identitySources.copy:Copy`;
  readonly copiedLabel = $localize`:@@identitySources.copied:Copied`;
  readonly now = Date.now();
  name = '';
  owner = '';
  days = 90;
  ago = ago;
  day = dateOnly;

  readonly count = computed(() => this.list.value()?.tokens?.length ?? 0);

  roleOf(username: string) {
    return (this.users.value() ?? []).find((u: User) => u.username === username)?.role ?? '';
  }

  openCreate() {
    this.name = '';
    this.owner = this.auth.user()?.username ?? '';
    this.days = 90;
    this.created.set('');
    this.formError.set('');
    this.createOpen.set(true);
  }

  closeCreate(open: boolean) {
    if (!open) {
      this.created.set(''); // the secret is never kept
      this.createOpen.set(false);
    }
  }

  claudeCommand(token: string) {
    return `claude mcp add --transport http tributary ${this.list.value()?.endpoint} --header "Authorization: Bearer ${token}"`;
  }

  async create() {
    this.busy.set(true);
    this.formError.set('');
    try {
      const r = await this.api.createApiToken(this.owner, this.name.trim(), this.days);
      this.created.set(r.token);
      this.list.reload();
    } catch (e) {
      this.formError.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  async revoke() {
    const t = this.confirmRevoke();
    this.confirmRevoke.set(null);
    if (!t) return;
    try {
      await this.api.deleteApiToken(t.id);
      this.selected.set(undefined);
      this.pageError.set('');
    } catch (e) {
      this.pageError.set(errorMessage(e));
    }
    this.list.reload();
  }

  async copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      this.copied.set(key);
      setTimeout(() => this.copied.set(''), 2000);
    } catch {
      /* clipboard unavailable: the text is selectable */
    }
  }
}
