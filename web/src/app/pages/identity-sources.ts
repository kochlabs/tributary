import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, IdentitySource, ProviderTest, RoleMapping } from '../core/api';
import { loader } from '../core/util';

const TYPE_LABELS: Record<string, string> = { oidc: 'OpenID Connect', ldap: 'LDAP / Active Directory', radius: 'RADIUS', saml: 'SAML 2.0' };

interface Form {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  issuer: string;
  clientId: string;
  clientSecret: string;
  hasSecret: boolean;
  scopes: string[];
  usernameClaim: string;
  groupsClaim: string;
  mappings: RoleMapping[];
  defaultRole: '' | 'viewer' | 'admin';
}

function blankForm(): Form {
  return {
    id: 0, name: '', enabled: true, priority: 10, issuer: '', clientId: '', clientSecret: '', hasSecret: false,
    scopes: ['openid', 'profile', 'email'], usernameClaim: 'preferred_username', groupsClaim: 'groups',
    mappings: [{ group: '', role: 'admin' }], defaultRole: '',
  };
}

@Component({
  selector: 'nfa-identity-sources',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-header">
      <div>
        <h2>Identity Sources</h2>
        <p class="subtitle">Single sign-on providers for console sign-in</p>
      </div>
    </div>

    <div class="toolbar">
      <div>
        <button class="btn btn-primary" (click)="chooserOpen.set(true)"><cds-icon shape="plus"></cds-icon> Add source</button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="openEdit(selected()!)"><cds-icon shape="pencil"></cds-icon> Edit</button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="confirmDelete.set(selected())"><cds-icon shape="trash"></cds-icon> Delete</button>
      </div>
      <button class="btn btn-link btn-icon" (click)="list.reload()" aria-label="Refresh"><cds-icon shape="refresh"></cds-icon></button>
    </div>

    @if (list.error() || pageError()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ pageError() || list.error() }}</span></div></div></div>
    }

    <clr-datagrid class="datagrid-compact" clrDgSelectionType="single" [clrDgSelected]="selectedList()" (clrDgSelectedChange)="selected.set($event[0])" [clrDgLoading]="list.loading()">
      <clr-dg-column [clrDgField]="'name'">Name</clr-dg-column>
      <clr-dg-column [clrDgField]="'type'">Type</clr-dg-column>
      <clr-dg-column>Status</clr-dg-column>
      <clr-dg-column>Used for</clr-dg-column>
      <clr-dg-column [clrDgField]="'priority'" [clrDgSortOrder]="1">Priority</clr-dg-column>
      <clr-dg-column>Role mappings</clr-dg-column>
      <clr-dg-column>Users</clr-dg-column>
      <clr-dg-row *clrDgItems="let s of list.value() ?? []" [clrDgItem]="s">
        <clr-dg-cell><a href="#" (click)="$event.preventDefault(); openEdit(s)">{{ s.name }}</a></clr-dg-cell>
        <clr-dg-cell>{{ typeLabel(s.type) }}</clr-dg-cell>
        <clr-dg-cell><span class="dot" [class.ok]="s.enabled" [class.off]="!s.enabled"></span> {{ s.enabled ? 'Enabled' : 'Disabled' }}</clr-dg-cell>
        <clr-dg-cell><span class="label label-blue">Console</span></clr-dg-cell>
        <clr-dg-cell>{{ s.priority }}</clr-dg-cell>
        <clr-dg-cell>{{ s.mappings.length }} mapping{{ s.mappings.length === 1 ? '' : 's' }}{{ s.defaultRole ? ' · others: ' + roleLabel(s.defaultRole) : '' }}</clr-dg-cell>
        <clr-dg-cell>{{ s.users }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder>No identity sources. Everyone signs in with local accounts.</clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            {{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} sources
          } @else {
            No sources
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <div class="card how">
      <div class="card-block">
        <h4 class="card-title">How sign-in works</h4>
        <ul>
          <li><b>Local accounts</b> always authenticate locally with their password and are never passed to a provider.</li>
          <li>Enabled <b>OpenID Connect</b> sources appear as buttons on the sign-in page, in priority order (lowest first).</li>
          <li>The role comes from the highest matching group mapping, otherwise the "everyone else" role. With neither, access is denied. Roles are re-evaluated at every sign-in.</li>
          <li>A provider can never sign in to a local account, or to an account created by another source, even with the same username.</li>
        </ul>
      </div>
    </div>

    <!-- Type chooser -->
    <clr-modal [clrModalOpen]="chooserOpen()" (clrModalOpenChange)="chooserOpen.set($event)" clrModalSize="lg">
      <h3 class="modal-title">Add identity source</h3>
      <div class="modal-body">
        <div class="types">
          <button class="type-card" (click)="openNew()">
            <h4>OpenID Connect</h4>
            <p>Single sign-on with Authentik, Entra ID, Okta, Keycloak, Google and other OIDC providers.</p>
          </button>
          @for (t of later; track t.title) {
            <div class="type-card disabled" aria-disabled="true">
              <h4>{{ t.title }} <span class="label">Coming soon</span></h4>
              <p>{{ t.text }}</p>
            </div>
          }
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="chooserOpen.set(false)">Cancel</button>
      </div>
    </clr-modal>

    <!-- OpenID Connect editor -->
    <clr-modal [clrModalOpen]="editOpen()" (clrModalOpenChange)="editOpen.set($event)" clrModalSize="xl" [clrModalStaticBackdrop]="true">
      <h3 class="modal-title">{{ form.id ? 'Edit' : 'Add' }} OpenID Connect source</h3>
      <div class="modal-body">
        <div class="editor">
          <form clrForm clrLayout="horizontal" clrLabelSize="4" class="editor-form" id="srcform" (ngSubmit)="save()">
            <h5 class="section">General</h5>
            <clr-input-container>
              <label>Name</label>
              <input clrInput name="name" [(ngModel)]="form.name" required maxlength="64" placeholder="Authentik" />
              <clr-control-helper>Shown on the sign-in button</clr-control-helper>
            </clr-input-container>
            <clr-toggle-container>
              <label>Enabled</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="enabled" [(ngModel)]="form.enabled" />
                <label>Accept sign-ins from this source</label>
              </clr-toggle-wrapper>
            </clr-toggle-container>
            <clr-input-container>
              <label>Priority</label>
              <input clrInput type="number" name="priority" [(ngModel)]="form.priority" min="0" max="1000" />
              <clr-control-helper>Order of sign-in buttons (lowest first)</clr-control-helper>
            </clr-input-container>

            <h5 class="section">Provider</h5>
            <clr-input-container>
              <label>Issuer URL</label>
              <input clrInput name="issuer" [(ngModel)]="form.issuer" required placeholder="https://auth.example.com/application/o/tributary/" class="wide" />
            </clr-input-container>
            <clr-input-container>
              <label>Client ID</label>
              <input clrInput name="clientId" [(ngModel)]="form.clientId" required class="wide" />
            </clr-input-container>
            <clr-password-container>
              <label>Client secret</label>
              <input clrPassword name="clientSecret" [(ngModel)]="form.clientSecret" autocomplete="new-password"
                [placeholder]="form.hasSecret ? 'Unchanged (stored securely)' : 'Required for confidential clients'" />
            </clr-password-container>
            <div class="clr-form-control clr-row list-row">
              <label class="clr-control-label clr-col-12 clr-col-md-4">Scopes</label>
              <div class="clr-col-12 clr-col-md-8">
                @for (sc of form.scopes; track $index; let i = $index) {
                  <div class="list-item">
                    <input class="clr-input" [name]="'scope' + i" [(ngModel)]="form.scopes[i]" [disabled]="sc === 'openid' && i === 0" />
                    @if (!(sc === 'openid' && i === 0)) {
                      <button type="button" class="btn btn-link btn-icon btn-sm" (click)="form.scopes.splice(i, 1)" aria-label="Remove scope"><cds-icon shape="times"></cds-icon></button>
                    }
                  </div>
                }
                <button type="button" class="btn btn-link btn-sm add" (click)="form.scopes.push('')"><cds-icon shape="plus"></cds-icon> Add scope</button>
              </div>
            </div>
            <clr-input-container>
              <label>Username claim</label>
              <input clrInput name="usernameClaim" [(ngModel)]="form.usernameClaim" />
            </clr-input-container>
            <clr-input-container>
              <label>Groups claim</label>
              <input clrInput name="groupsClaim" [(ngModel)]="form.groupsClaim" />
              <clr-control-helper>Read from the ID token, or from userinfo if absent</clr-control-helper>
            </clr-input-container>

            <div class="redirect">
              <h5>Redirect URI</h5>
              @if (redirectUri()) {
                <p>Register this redirect URI in the provider's application settings:</p>
                <div class="uri"><code>{{ redirectUri() }}</code> <button type="button" class="btn btn-link btn-sm" (click)="copy()">{{ copied() ? 'Copied' : 'Copy' }}</button></div>
              } @else {
                <p>Save the source first; its redirect URI appears here, ready to copy into the provider.</p>
              }
            </div>

            <h5 class="section">Role mapping</h5>
            <div class="mappings">
              <div class="map-head"><span>Group</span><span>Role</span><span></span></div>
              @for (m of form.mappings; track $index; let i = $index) {
                <div class="map-row">
                  <input class="clr-input" [name]="'group' + i" [(ngModel)]="m.group" placeholder="tributary-admins" />
                  <div class="clr-select-wrapper">
                    <select class="clr-select" [name]="'role' + i" [(ngModel)]="m.role">
                      <option value="admin">Administrator</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </div>
                  <button type="button" class="btn btn-link btn-icon btn-sm" (click)="form.mappings.splice(i, 1)" aria-label="Remove mapping"><cds-icon shape="times"></cds-icon></button>
                </div>
              }
              <button type="button" class="btn btn-link btn-sm add" (click)="form.mappings.push({ group: '', role: 'viewer' })"><cds-icon shape="plus"></cds-icon> Add mapping</button>
            </div>
            <clr-select-container>
              <label>Everyone else</label>
              <select clrSelect name="defaultRole" [(ngModel)]="form.defaultRole">
                <option value="">Deny console access</option>
                <option value="viewer">Viewer</option>
                <option value="admin">Administrator</option>
              </select>
              <clr-control-helper>Role for authenticated users matching no mapping</clr-control-helper>
            </clr-select-container>
          </form>

          <aside class="test">
            <h5>Test connection</h5>
            <p>Checks that the provider's metadata can be loaded. Complete a full sign-in with the button on the sign-in page.</p>
            <button type="button" class="btn btn-outline btn-sm" (click)="runTest()" [clrLoading]="testing()" [disabled]="!form.issuer"><cds-icon shape="play"></cds-icon> Run test</button>
            @if (test(); as t) {
              <div class="result" [class.bad]="!t.ok">
                <div><span class="dot" [class.ok]="t.ok" [class.bad]="!t.ok"></span> {{ t.message }}</div>
                @if (t.ok) {
                  <dl>
                    <dt>Authorization</dt><dd>{{ t.authorizationEndpoint }}</dd>
                    <dt>Token</dt><dd>{{ t.tokenEndpoint }}</dd>
                    @if (t.userinfoEndpoint) {<dt>Userinfo</dt><dd>{{ t.userinfoEndpoint }}</dd>}
                    <dt>PKCE</dt><dd>{{ t.pkce?.includes('S256') ? 'S256 supported' : 'not advertised (sign-in still sends S256)' }}</dd>
                    @if (t.claims?.length) {<dt>Claims</dt><dd>{{ claimHint(t) }}</dd>}
                  </dl>
                }
              </div>
            }
          </aside>
        </div>
        @if (formError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ formError() }}</span></div></div></div>
        }
        @if (savedNote()) {
          <div class="alert alert-success alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ savedNote() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="editOpen.set(false)">{{ savedNote() ? 'Close' : 'Cancel' }}</button>
        <button type="submit" form="srcform" class="btn btn-primary" [clrLoading]="saving()">Save</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="!!confirmDelete()" (clrModalOpenChange)="!$event && confirmDelete.set(null)" clrModalSize="md">
      <h3 class="modal-title">Delete {{ confirmDelete()?.name }}?</h3>
      <div class="modal-body">
        <p>The sign-in button disappears and the {{ confirmDelete()?.users }} account(s) created by this source are deleted and signed out. Local accounts are not affected.</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmDelete.set(null)">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="remove()">Delete</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .toolbar .btn { margin: 0 6px 0 0; }
    .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 4px; }
    .ok { background: var(--cds-alias-status-success); }
    .off { background: var(--cds-alias-status-neutral); }
    .bad { background: var(--cds-alias-status-danger); }
    .how { margin-top: 18px; }
    .how ul { margin: 6px 0 0 18px; }
    .how li { margin: 3px 0; }
    .types { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    .type-card { text-align: left; padding: 18px 20px; border: 1px solid var(--cds-alias-object-border-color); border-radius: 4px; background: var(--cds-alias-object-container-background); cursor: pointer; font: inherit; color: inherit; }
    .type-card:hover:not(.disabled) { border-color: var(--cds-alias-status-info); }
    .type-card h4 { margin: 0 0 6px; }
    .type-card p { margin: 0; font-size: 13px; color: var(--cds-alias-typography-color-300); }
    .type-card.disabled { opacity: 0.55; cursor: not-allowed; }
    .type-card .label { margin-left: 6px; vertical-align: 2px; }
    .editor { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 28px; }
    .editor-form { max-height: 62vh; overflow-y: auto; padding-right: 12px; }
    .section { text-transform: uppercase; letter-spacing: 0.06em; font-size: 12px; color: var(--cds-alias-typography-color-300); margin: 18px 0 4px; }
    .section:first-child { margin-top: 0; }
    .wide { width: 360px; }
    .list-row { margin-top: 18px; }
    .list-item { display: flex; align-items: center; gap: 4px; margin-bottom: 4px; }
    .list-item .clr-input { width: 260px; }
    .add { margin: 2px 0 0; padding-left: 0; }
    .redirect { margin: 20px 0 6px; padding: 14px 16px; border: 1px dashed var(--cds-alias-object-border-color); border-radius: 4px; }
    .redirect h5 { margin: 0 0 4px; }
    .redirect p { margin: 0 0 6px; font-size: 13px; }
    .uri { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .uri code { font-size: 12px; word-break: break-all; }
    .uri .btn { margin: 0; }
    .mappings { margin-top: 6px; }
    .map-head, .map-row { display: grid; grid-template-columns: minmax(0, 1fr) 170px 32px; gap: 12px; align-items: center; }
    .map-head { font-size: 11px; text-transform: uppercase; color: var(--cds-alias-typography-color-300); }
    .map-row { margin: 4px 0; }
    .map-row .clr-input, .map-row .clr-select, .map-row .clr-select-wrapper { width: 100%; }
    .test { border-left: 1px solid var(--cds-alias-object-border-color); padding-left: 24px; }
    .test h5 { margin-top: 0; }
    .test p { font-size: 13px; }
    .result { margin-top: 12px; font-size: 13px; }
    .result dl { margin: 8px 0 0; }
    .result dt { font-size: 11px; color: var(--cds-alias-typography-color-300); margin-top: 6px; }
    .result dd { margin: 0; word-break: break-all; }
    @media (max-width: 900px) { .editor { grid-template-columns: 1fr; } .test { border-left: 0; padding-left: 0; } .types { grid-template-columns: 1fr; } }
  `,
})
export class IdentitySources {
  private api = inject(Api);
  readonly list = loader(() => true, () => this.api.identitySources());
  readonly selected = signal<IdentitySource | undefined>(undefined);
  readonly selectedList = computed(() => {
    const s = this.selected();
    return s ? [s] : [];
  });
  readonly chooserOpen = signal(false);
  readonly editOpen = signal(false);
  readonly confirmDelete = signal<IdentitySource | null | undefined>(null);
  readonly redirectUri = signal('');
  readonly test = signal<ProviderTest | null>(null);
  readonly testing = signal(false);
  readonly saving = signal(false);
  readonly copied = signal(false);
  readonly formError = signal('');
  readonly savedNote = signal('');
  readonly pageError = signal('');
  form: Form = blankForm();

  readonly later = [
    { title: 'LDAP / Active Directory', text: 'Bind to a directory and map groups to roles.' },
    { title: 'RADIUS', text: 'PAP authentication against a RADIUS server (NPS, FreeRADIUS, MFA proxies).' },
    { title: 'SAML 2.0', text: 'Single sign-on with ADFS, Entra ID, Okta, Shibboleth and other SAML providers.' },
  ];

  typeLabel(t: string) {
    return TYPE_LABELS[t] ?? t;
  }

  roleLabel(r: string) {
    return r === 'admin' ? 'Administrator' : r === 'viewer' ? 'Viewer' : 'denied';
  }

  private reset() {
    this.test.set(null);
    this.formError.set('');
    this.savedNote.set('');
    this.copied.set(false);
  }

  openNew() {
    this.chooserOpen.set(false);
    this.form = blankForm();
    this.redirectUri.set('');
    this.reset();
    this.editOpen.set(true);
  }

  async openEdit(s: IdentitySource) {
    this.reset();
    try {
      const r = await this.api.identitySource(s.id);
      const src = r.source;
      const o = src.oidc!;
      this.form = {
        id: src.id, name: src.name, enabled: src.enabled, priority: src.priority, issuer: o.issuer, clientId: o.clientId,
        clientSecret: '', hasSecret: src.hasSecret, scopes: [...o.scopes], usernameClaim: o.usernameClaim, groupsClaim: o.groupsClaim,
        mappings: src.mappings.map((m) => ({ ...m })), defaultRole: src.defaultRole,
      };
      this.redirectUri.set(r.redirectUri);
      this.editOpen.set(true);
    } catch (e) {
      this.pageError.set(errorMessage(e));
    }
  }

  async save() {
    this.saving.set(true);
    this.formError.set('');
    this.savedNote.set('');
    const f = this.form;
    try {
      const r = await this.api.saveIdentitySource({
        id: f.id || undefined, type: 'oidc', name: f.name, enabled: f.enabled, priority: Number(f.priority) || 0,
        oidc: { issuer: f.issuer, clientId: f.clientId, clientSecret: f.clientSecret, scopes: f.scopes, usernameClaim: f.usernameClaim, groupsClaim: f.groupsClaim },
        mappings: f.mappings.filter((m) => m.group.trim()), defaultRole: f.defaultRole,
      });
      const created = !f.id;
      f.id = r.id;
      if (f.clientSecret) f.hasSecret = true;
      f.clientSecret = '';
      this.redirectUri.set(r.redirectUri);
      this.list.reload();
      if (created) {
        // Keep the dialog open so the redirect URI can be copied into the provider.
        this.savedNote.set('Saved. Register the redirect URI above in your provider, then sign in with the new button on the sign-in page.');
      } else {
        this.editOpen.set(false);
      }
    } catch (e) {
      this.formError.set(errorMessage(e));
    } finally {
      this.saving.set(false);
    }
  }

  async runTest() {
    this.testing.set(true);
    try {
      this.test.set(await this.api.testIdentitySource(this.form.issuer));
    } catch (e) {
      this.test.set({ ok: false, message: errorMessage(e) });
    } finally {
      this.testing.set(false);
    }
  }

  claimHint(t: ProviderTest) {
    const c = t.claims ?? [];
    const want = [this.form.usernameClaim, this.form.groupsClaim].filter(Boolean);
    const missing = want.filter((w) => !c.includes(w));
    return missing.length ? `${missing.join(', ')} not advertised (may still be sent)` : `${want.join(', ')} advertised`;
  }

  async copy() {
    try {
      await navigator.clipboard.writeText(this.redirectUri());
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 2000);
    } catch {
      /* clipboard unavailable: the URI is selectable */
    }
  }

  async remove() {
    const s = this.confirmDelete();
    this.confirmDelete.set(null);
    if (!s) return;
    try {
      await this.api.deleteIdentitySource(s.id);
      this.selected.set(undefined);
      this.pageError.set('');
    } catch (e) {
      this.pageError.set(errorMessage(e));
    }
    this.list.reload();
  }
}
