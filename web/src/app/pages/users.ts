import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, User } from '../core/api';
import { Auth } from '../core/auth';
import { dateTime } from '../core/format';
import { loader } from '../core/util';

@Component({
  selector: 'nfa-users',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2>Users</h2>
        <p class="subtitle">Administrators can change configuration; viewers have read-only access.</p>
      </div>
      <button class="btn btn-sm btn-primary" (click)="openCreate()"><cds-icon shape="plus"></cds-icon> Add user</button>
    </div>
    @if (actionError()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ actionError() }}</span></div></div></div>
    }

    <clr-datagrid class="datagrid-compact" [clrDgLoading]="users.loading()">
      <clr-dg-column [clrDgField]="'username'" [clrDgSortOrder]="1">Username</clr-dg-column>
      <clr-dg-column [clrDgField]="'fullName'">Full name</clr-dg-column>
      <clr-dg-column [clrDgField]="'role'">Role</clr-dg-column>
      <clr-dg-column [clrDgField]="'lastLogin'">Last sign-in</clr-dg-column>
      <clr-dg-column [clrDgField]="'createdAt'">Created</clr-dg-column>
      <clr-dg-row *clrDgItems="let u of users.value() ?? []" [clrDgItem]="u">
        <clr-dg-action-overflow>
          <button class="action-item" (click)="openEdit(u)"><cds-icon shape="pencil"></cds-icon> Edit</button>
          @if (u.username !== auth.user()?.username) {
            <button class="action-item" (click)="confirmDelete.set(u)"><cds-icon shape="trash"></cds-icon> Delete</button>
          }
        </clr-dg-action-overflow>
        <clr-dg-cell><cds-icon shape="user"></cds-icon> {{ u.username }} @if (u.username === auth.user()?.username) {<span class="label">you</span>}</clr-dg-cell>
        <clr-dg-cell>{{ u.fullName }}</clr-dg-cell>
        <clr-dg-cell><span class="label" [class.label-purple]="u.role === 'admin'" [class.label-blue]="u.role === 'viewer'">{{ u.role }}</span></clr-dg-cell>
        <clr-dg-cell>{{ dt(u.lastLogin) }}</clr-dg-cell>
        <clr-dg-cell>{{ dt(u.createdAt) }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-footer>{{ (users.value() ?? []).length }} users</clr-dg-footer>
    </clr-datagrid>

    <clr-modal [(clrModalOpen)]="formOpen" clrModalSize="md">
      <h3 class="modal-title">{{ editing ? 'Edit ' + form.username : 'Add user' }}</h3>
      <div class="modal-body">
        <form clrForm clrLayout="vertical" id="userform" (ngSubmit)="save()">
          @if (!editing) {
            <clr-input-container>
              <label>Username</label>
              <input clrInput name="username" [(ngModel)]="form.username" required maxlength="64" autocomplete="off" />
            </clr-input-container>
          }
          <clr-input-container>
            <label>Full name</label>
            <input clrInput name="fullName" [(ngModel)]="form.fullName" maxlength="128" />
          </clr-input-container>
          <clr-radio-container clrInline>
            <label>Role</label>
            <clr-radio-wrapper>
              <input type="radio" clrRadio name="role" value="viewer" [(ngModel)]="form.role" />
              <label>Viewer</label>
            </clr-radio-wrapper>
            <clr-radio-wrapper>
              <input type="radio" clrRadio name="role" value="admin" [(ngModel)]="form.role" />
              <label>Administrator</label>
            </clr-radio-wrapper>
          </clr-radio-container>
          <clr-password-container>
            <label>{{ editing ? 'New password (leave blank to keep)' : 'Password' }}</label>
            <input clrPassword name="password" [(ngModel)]="form.password" autocomplete="new-password" [required]="!editing" />
            <clr-control-helper>At least 8 characters.</clr-control-helper>
          </clr-password-container>
        </form>
        @if (formError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ formError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="formOpen.set(false)">Cancel</button>
        <button type="submit" form="userform" class="btn btn-primary">{{ editing ? 'Save' : 'Create user' }}</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="!!confirmDelete()" (clrModalOpenChange)="!$event && confirmDelete.set(null)" clrModalSize="sm">
      <h3 class="modal-title">Delete user?</h3>
      <div class="modal-body"><p>Delete <b>{{ confirmDelete()?.username }}</b>? Their sessions end immediately.</p></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmDelete.set(null)">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="remove()">Delete</button>
      </div>
    </clr-modal>
  `,
  styles: `.label { margin-left: 6px; }`,
})
export class Users {
  private api = inject(Api);
  readonly auth = inject(Auth);
  readonly users = loader(() => true, () => this.api.users());
  dt = dateTime;

  readonly formOpen = signal(false);
  editing = false;
  readonly confirmDelete = signal<User | null>(null);
  form = { username: '', fullName: '', role: 'viewer', password: '' };
  readonly formError = signal('');
  readonly actionError = signal('');

  openCreate() {
    this.editing = false;
    this.form = { username: '', fullName: '', role: 'viewer', password: '' };
    this.formError.set('');
    this.formOpen.set(true);
  }

  openEdit(u: User) {
    this.editing = true;
    this.form = { username: u.username, fullName: u.fullName, role: u.role, password: '' };
    this.formError.set('');
    this.formOpen.set(true);
  }

  async save() {
    try {
      if (this.editing) {
        await this.api.updateUser(this.form.username, {
          fullName: this.form.fullName,
          role: this.form.role,
          ...(this.form.password ? { password: this.form.password } : {}),
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
