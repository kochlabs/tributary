import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, User } from '../core/api';
import { Auth } from '../core/auth';
import { dateTime } from '../core/format';
import { loader, trackByKey } from '../core/util';

@Component({
  selector: 'nfa-users',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.users">Users</h2>
        <p class="subtitle" i18n="@@users.subtitle">Administrators can change configuration; viewers have read-only access.</p>
      </div>
      <button class="btn btn-sm btn-primary" (click)="openCreate()"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@users.addUser">Add user</ng-container></button>
    </div>
    @if (actionError()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ actionError() }}</span></div></div></div>
    }

    <clr-datagrid class="datagrid-compact" [clrDgLoading]="users.loading()">
      <clr-dg-column [clrDgField]="'username'" [clrDgSortOrder]="1" i18n="@@users.col.username">Username</clr-dg-column>
      <clr-dg-column [clrDgField]="'fullName'" i18n="@@users.col.fullName">Full name</clr-dg-column>
      <clr-dg-column [clrDgField]="'role'" i18n="@@users.col.role">Role</clr-dg-column>
      <clr-dg-column [clrDgField]="'source'" i18n="@@users.col.source">Source</clr-dg-column>
      <clr-dg-column [clrDgField]="'lastLogin'" i18n="@@users.col.lastLogin">Last sign-in</clr-dg-column>
      <clr-dg-column [clrDgField]="'createdAt'" i18n="@@users.col.created">Created</clr-dg-column>
      <clr-dg-row *clrDgItems="let u of users.value() ?? []; trackBy: byUsername" [clrDgItem]="u">
        <clr-dg-action-overflow>
          <button class="action-item" (click)="openEdit(u)"><cds-icon shape="pencil"></cds-icon> <ng-container i18n="@@common.edit">Edit</ng-container></button>
          @if (u.username !== auth.user()?.username) {
            <button class="action-item" (click)="confirmDelete.set(u)"><cds-icon shape="trash"></cds-icon> <ng-container i18n="@@common.delete">Delete</ng-container></button>
          }
        </clr-dg-action-overflow>
        <clr-dg-cell><cds-icon shape="user"></cds-icon> {{ u.username }} @if (u.username === auth.user()?.username) {<span class="label" i18n="Marks the signed-in user's own row@@users.you">you</span>}</clr-dg-cell>
        <clr-dg-cell>{{ u.fullName }}</clr-dg-cell>
        <clr-dg-cell><span class="label" [class.label-purple]="u.role === 'admin'" [class.label-blue]="u.role === 'viewer'">{{ roleLabel(u.role) }}</span></clr-dg-cell>
        <clr-dg-cell>@if (!u.sourceId) {<ng-container i18n="@@users.local">Local</ng-container>} @else if (u.source) {<ng-container>{{ u.source }}</ng-container>} @else {<ng-container i18n="@@users.identitySource">Identity source</ng-container>}</clr-dg-cell>
        <clr-dg-cell>{{ dt(u.lastLogin) }}</clr-dg-cell>
        <clr-dg-cell>{{ dt(u.createdAt) }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-footer>
        <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@users.footer">{{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} users</ng-container>
          } @else {
            <ng-container i18n="@@users.empty">No users</ng-container>
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <clr-modal [(clrModalOpen)]="formOpen" clrModalSize="md">
      <h3 class="modal-title">@if (editing) {<ng-container i18n="@@users.editTitle">Edit {{ form.username }}</ng-container>} @else {<ng-container i18n="@@users.addUser">Add user</ng-container>}</h3>
      <div class="modal-body">
        <form clrForm clrLayout="vertical" id="userform" (ngSubmit)="save()">
          @if (!editing) {
            <clr-input-container>
              <label i18n="@@users.username">Username</label>
              <input clrInput name="username" [(ngModel)]="form.username" required maxlength="64" autocomplete="off" />
            </clr-input-container>
          }
          <clr-input-container>
            <label i18n="@@users.fullName">Full name</label>
            <input clrInput name="fullName" [(ngModel)]="form.fullName" maxlength="128" />
          </clr-input-container>
          @if (external) {
            <p class="managed" i18n="@@users.managedExternally">Signs in with <b>{{ externalSource }}</b>. The role is set by that source's group mappings at every sign-in, and there is no local password.</p>
          } @else {
          <clr-radio-container clrInline>
            <label i18n="@@users.role">Role</label>
            <clr-radio-wrapper>
              <input type="radio" clrRadio name="role" value="viewer" [(ngModel)]="form.role" />
              <label i18n="@@users.roleViewer">Viewer</label>
            </clr-radio-wrapper>
            <clr-radio-wrapper>
              <input type="radio" clrRadio name="role" value="admin" [(ngModel)]="form.role" />
              <label i18n="@@users.roleAdministrator">Administrator</label>
            </clr-radio-wrapper>
          </clr-radio-container>
          <clr-password-container>
            <label>@if (editing) {<ng-container i18n="@@users.newPassword">New password (leave blank to keep)</ng-container>} @else {<ng-container i18n="@@users.password">Password</ng-container>}</label>
            <input clrPassword name="password" [(ngModel)]="form.password" autocomplete="new-password" [required]="!editing" />
            <clr-control-helper i18n="@@users.passwordHelp">At least 8 characters.</clr-control-helper>
          </clr-password-container>
          }
        </form>
        @if (formError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ formError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="formOpen.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="submit" form="userform" class="btn btn-primary">@if (editing) {<ng-container i18n="@@common.save">Save</ng-container>} @else {<ng-container i18n="@@users.createUser">Create user</ng-container>}</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="!!confirmDelete()" (clrModalOpenChange)="!$event && confirmDelete.set(null)" clrModalSize="sm">
      <h3 class="modal-title" i18n="@@users.deleteTitle">Delete user?</h3>
      <div class="modal-body"><p i18n="@@users.deleteConfirm">Delete <b>{{ confirmDelete()?.username }}</b>? Their sessions end immediately.</p></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmDelete.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="remove()" i18n="@@common.delete">Delete</button>
      </div>
    </clr-modal>
  `,
  styles: `.label { margin-left: 6px; } .managed { font-size: 13px; margin-top: 18px; }`,
})
export class Users {
  readonly byUsername = trackByKey<{ username: string }>((u) => u.username);
  private api = inject(Api);
  readonly auth = inject(Auth);
  readonly users = loader(() => true, () => this.api.users());
  dt = dateTime;

  readonly formOpen = signal(false);
  editing = false;
  readonly confirmDelete = signal<User | null>(null);
  form = { username: '', fullName: '', role: 'viewer', password: '' };
  external = false;
  externalSource = '';
  readonly formError = signal('');
  readonly actionError = signal('');

  openCreate() {
    this.editing = false;
    this.form = { username: '', fullName: '', role: 'viewer', password: '' };
    this.external = false;
    this.formError.set('');
    this.formOpen.set(true);
  }

  openEdit(u: User) {
    this.editing = true;
    this.form = { username: u.username, fullName: u.fullName, role: u.role, password: '' };
    this.external = u.sourceId !== 0;
    this.externalSource = u.source || $localize`:@@users.anIdentitySource:an identity source`;
    this.formError.set('');
    this.formOpen.set(true);
  }

  async save() {
    try {
      if (this.editing) {
        await this.api.updateUser(this.form.username, {
          fullName: this.form.fullName,
          ...(this.external ? {} : { role: this.form.role }),
          ...(this.form.password && !this.external ? { password: this.form.password } : {}),
        });
      } else {
        await this.api.createUser(this.form);
      }
      this.formOpen.set(false);
      this.users.reload();
    } catch (e) {
      this.formError.set(errorMessage(e));
    }
  }

  roleLabel(role: string) {
    return role === 'admin' ? $localize`:@@users.roleAdmin:admin` : role === 'viewer' ? $localize`:@@users.roleViewerShort:viewer` : role;
  }

  async remove() {
    const u = this.confirmDelete();
    this.confirmDelete.set(null);
    if (!u) return;
    try {
      await this.api.deleteUser(u.username);
      this.actionError.set('');
    } catch (e) {
      this.actionError.set(errorMessage(e));
    }
    this.users.reload();
  }
}
