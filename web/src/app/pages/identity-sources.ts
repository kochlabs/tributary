import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, IdentitySource, LDAPConfig, ProviderTest, RADIUSConfig, RoleMapping, SAMLConfig, SAMLInfo } from '../core/api';
import { dateOnly } from '../core/format';
import { loader, trackByKey } from '../core/util';
import { ListEditor, listValues } from '../shared/list-editor';

const TYPE_LABELS: Record<string, string> = { oidc: 'OpenID Connect', ldap: 'LDAP / Active Directory', radius: 'RADIUS', saml: 'SAML 2.0' };

interface Form {
  id: number;
  type: 'oidc' | 'saml' | 'ldap' | 'radius';
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
  saml: SAMLConfig;
  /** Where the provider metadata comes from. */
  samlSource: 'url' | 'xml';
  ldap: LDAPConfig;
  radius: RADIUSConfig;
  testUser: string;
  testPass: string;
}

const AD_PRESET = { userFilter: '(&(objectClass=user)(sAMAccountName={username}))', usernameAttr: 'sAMAccountName', nameAttr: 'displayName', groupAttr: 'memberOf' };
const OPENLDAP_PRESET = { userFilter: '(&(objectClass=inetOrgPerson)(uid={username}))', usernameAttr: 'uid', nameAttr: 'cn', groupAttr: 'memberOf' };

/** Attribute names each SAML provider sends by default (username empty: the NameID). */
const SAML_PRESETS: Record<string, Pick<SAMLConfig, 'usernameAttr' | 'nameAttr' | 'groupsAttr'>> = {
  entra: {
    usernameAttr: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    nameAttr: 'http://schemas.microsoft.com/identity/claims/displayname',
    groupsAttr: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
  },
  adfs: {
    usernameAttr: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
    nameAttr: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    groupsAttr: 'http://schemas.xmlsoap.org/claims/Group',
  },
  okta: { usernameAttr: '', nameAttr: 'displayName', groupsAttr: 'groups' },
  authentik: {
    usernameAttr: 'http://schemas.goauthentik.io/2021/02/saml/username',
    nameAttr: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    groupsAttr: 'http://schemas.xmlsoap.org/claims/Group',
  },
};

function blankForm(type: Form['type'] = 'oidc'): Form {
  return {
    id: 0, type, name: '', enabled: true, priority: 10, issuer: '', clientId: '', clientSecret: '', hasSecret: false,
    scopes: ['openid', 'profile', 'email'], usernameClaim: 'preferred_username', groupsClaim: 'groups',
    mappings: [{ group: '', role: 'admin' }], defaultRole: '',
    saml: { metadataUrl: '', metadataXml: '', entityId: '', signRequests: true, ...SAML_PRESETS['entra'] },
    samlSource: 'url',
    ldap: { url: '', startTls: false, bindDn: '', baseDn: '', nestedGroups: false, ...AD_PRESET },
    radius: { servers: [''], nasIdentifier: 'tributary', timeoutSec: 5, roleAttribute: 'Class' },
    testUser: '', testPass: '',
  };
}

@Component({
  selector: 'nfa-identity-sources',
  imports: [ClarityModule, FormsModule, ListEditor],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.identitySources">Identity Sources</h2>
        <p class="subtitle" i18n="@@identitySources.subtitle">Single sign-on providers for console sign-in</p>
      </div>
    </div>

    <div class="toolbar">
      <div>
        <button class="btn btn-primary" (click)="chooserOpen.set(true)"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@identitySources.addSource">Add source</ng-container></button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="openEdit(selected()!)"><cds-icon shape="pencil"></cds-icon> <ng-container i18n="@@common.edit">Edit</ng-container></button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="confirmDelete.set(selected())"><cds-icon shape="trash"></cds-icon> <ng-container i18n="@@common.delete">Delete</ng-container></button>
      </div>
      <button class="btn btn-link btn-icon" (click)="list.reload()" aria-label="Refresh" i18n-aria-label="@@common.refresh"><cds-icon shape="refresh"></cds-icon></button>
    </div>

    @if (list.error() || pageError()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ pageError() || list.error() }}</span></div></div></div>
    }

    <clr-datagrid class="datagrid-compact" clrDgSelectionType="single" [clrDgSelected]="selectedList()" (clrDgSelectedChange)="selected.set($event[0])" [clrDgLoading]="list.loading()">
      <clr-dg-column [clrDgField]="'name'" i18n="@@common.name">Name</clr-dg-column>
      <clr-dg-column [clrDgField]="'type'" i18n="@@identitySources.col.type">Type</clr-dg-column>
      <clr-dg-column i18n="@@identitySources.col.status">Status</clr-dg-column>
      <clr-dg-column i18n="@@identitySources.col.usedFor">Used for</clr-dg-column>
      <clr-dg-column [clrDgField]="'priority'" [clrDgSortOrder]="1" i18n="@@identitySources.col.priority">Priority</clr-dg-column>
      <clr-dg-column i18n="@@identitySources.col.roleMappings">Role mappings</clr-dg-column>
      <clr-dg-column i18n="@@identitySources.col.users">Users</clr-dg-column>
      <clr-dg-row *clrDgItems="let s of list.value() ?? []; trackBy: byId" [clrDgItem]="s">
        <clr-dg-cell><a href="#" (click)="$event.preventDefault(); openEdit(s)">{{ s.name }}</a></clr-dg-cell>
        <clr-dg-cell>{{ typeLabel(s.type) }}</clr-dg-cell>
        <clr-dg-cell><span class="dot" [class.ok]="s.enabled" [class.off]="!s.enabled"></span> @if (s.enabled) {<ng-container i18n="@@identitySources.enabled">Enabled</ng-container>} @else {<ng-container i18n="@@identitySources.disabled">Disabled</ng-container>}</clr-dg-cell>
        <clr-dg-cell><span class="label label-blue" i18n="@@identitySources.console">Console</span></clr-dg-cell>
        <clr-dg-cell>{{ s.priority }}</clr-dg-cell>
        <clr-dg-cell><ng-container i18n="@@identitySources.mappingCount">{s.mappings.length, plural, =1 {1 mapping} other {{{ s.mappings.length }} mappings}}</ng-container>@if (s.defaultRole) {<ng-container i18n="@@identitySources.othersRole"> · others: {{ roleLabel(s.defaultRole) }}</ng-container>}</clr-dg-cell>
        <clr-dg-cell>{{ s.users }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder i18n="@@identitySources.placeholder">No identity sources. Everyone signs in with local accounts.</clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #pg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (pg.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@identitySources.footer">{{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems.toLocaleString() }} sources</ng-container>
          } @else {
            <ng-container i18n="@@identitySources.empty">No sources</ng-container>
          }
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <div class="card how">
      <div class="card-block">
        <h4 class="card-title" i18n="@@identitySources.howTitle">How sign-in works</h4>
        <ul>
          <li i18n="@@identitySources.howLocal"><b>Local accounts</b> always authenticate locally with their password and are never passed to a provider.</li>
          <li i18n="@@identitySources.howSso">Enabled <b>OpenID Connect</b> and <b>SAML</b> sources appear as buttons on the sign-in page, in priority order (lowest first).</li>
          <li i18n="@@identitySources.howDirectory"><b>LDAP</b> and <b>RADIUS</b> sources check the regular username and password form, after local accounts.</li>
          <li i18n="@@identitySources.howRole">The role comes from the highest matching group mapping, otherwise the "everyone else" role. With neither, access is denied. Roles are re-evaluated at every sign-in.</li>
          <li i18n="@@identitySources.howIsolation">A provider can never sign in to a local account, or to an account created by another source, even with the same username.</li>
        </ul>
      </div>
    </div>

    <!-- Type chooser -->
    <clr-modal [clrModalOpen]="chooserOpen()" (clrModalOpenChange)="chooserOpen.set($event)" clrModalSize="lg">
      <h3 class="modal-title" i18n="@@identitySources.addTitle">Add identity source</h3>
      <div class="modal-body">
        <div class="types">
          <button class="type-card" (click)="openNew('oidc')">
            <h4>OpenID Connect</h4>
            <p i18n="@@identitySources.oidcDescription">Single sign-on with Authentik, Entra ID, Okta, Keycloak, Google and other OIDC providers.</p>
          </button>
          <button class="type-card" (click)="openNew('saml')">
            <h4>SAML 2.0</h4>
            <p i18n="@@identitySources.samlDescription">Single sign-on with ADFS, Entra ID, Okta, Shibboleth and other SAML providers.</p>
          </button>
          <button class="type-card" (click)="openNew('ldap')">
            <h4>LDAP / Active Directory</h4>
            <p i18n="@@identitySources.ldapDescription">Bind to a directory and map groups to roles.</p>
          </button>
          <button class="type-card" (click)="openNew('radius')">
            <h4>RADIUS</h4>
            <p i18n="@@identitySources.radiusDescription">PAP authentication against a RADIUS server (NPS, FreeRADIUS, MFA proxies).</p>
          </button>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="chooserOpen.set(false)" i18n="@@common.cancel">Cancel</button>
      </div>
    </clr-modal>

    <!-- Source editor -->
    <clr-modal [clrModalOpen]="editOpen()" (clrModalOpenChange)="editOpen.set($event)" clrModalSize="xl" [clrModalStaticBackdrop]="true">
      <h3 class="modal-title">@if (form.id) {<ng-container i18n="@@identitySources.editTitle">Edit {{ typeLabel(form.type) }} source</ng-container>} @else {<ng-container i18n="@@identitySources.addTypeTitle">Add {{ typeLabel(form.type) }} source</ng-container>}</h3>
      <div class="modal-body">
        <div class="editor">
          <form clrForm clrLayout="horizontal" clrLabelSize="4" class="editor-form" id="srcform" (ngSubmit)="save()">
            <h5 class="section" i18n="@@identitySources.general">General</h5>
            <clr-input-container>
              <label i18n="@@common.name">Name</label>
              <input clrInput name="name" [(ngModel)]="form.name" required maxlength="64" [placeholder]="namePlaceholder[form.type]" />
              @if (form.type === 'oidc' || form.type === 'saml') {
                <clr-control-helper i18n="@@identitySources.nameHelp">Shown on the sign-in button</clr-control-helper>
              } @else {
                <clr-control-helper i18n="@@identitySources.namePasswordHelp">Users sign in with the regular username and password form</clr-control-helper>
              }
            </clr-input-container>
            <clr-toggle-container>
              <label i18n="@@identitySources.enabled">Enabled</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="enabled" [(ngModel)]="form.enabled" />
                <label i18n="@@identitySources.enabledToggle">Accept sign-ins from this source</label>
              </clr-toggle-wrapper>
            </clr-toggle-container>
            <clr-input-container>
              <label i18n="@@identitySources.priority">Priority</label>
              <input clrInput type="number" name="priority" [(ngModel)]="form.priority" min="0" max="1000" />
              <clr-control-helper i18n="@@identitySources.priorityHelp2">Lowest first: the order of sign-in buttons, and of directories tried for a password sign-in</clr-control-helper>
            </clr-input-container>

            @if (form.type === 'ldap') {
              <h5 class="section" i18n="@@identitySources.directory">Directory</h5>
              <clr-input-container>
                <label i18n="@@identitySources.ldapUrl">Server URL</label>
                <input clrInput name="ldapUrl" [(ngModel)]="form.ldap.url" required placeholder="ldaps://dc1.corp.example.com" class="wide" />
                <clr-control-helper i18n="@@identitySources.ldapUrlHelp">ldaps:// (port 636) or ldap:// with StartTLS. Certificates are checked against the trusted CAs on the Certificates page.</clr-control-helper>
              </clr-input-container>
              <clr-checkbox-container>
                <label></label>
                <clr-checkbox-wrapper>
                  <input type="checkbox" clrCheckbox name="startTls" [(ngModel)]="form.ldap.startTls" [disabled]="form.ldap.url.startsWith('ldaps:')" />
                  <label i18n="@@identitySources.startTls">Use StartTLS (for ldap:// URLs)</label>
                </clr-checkbox-wrapper>
              </clr-checkbox-container>
              @if (form.ldap.url.startsWith('ldap://') && !form.ldap.startTls) {
                <p class="warn-text" i18n="@@identitySources.ldapPlainWarning">Without TLS, passwords cross the network unencrypted.</p>
              }
              <clr-input-container>
                <label i18n="@@identitySources.bindDn">Bind DN</label>
                <input clrInput name="bindDn" [(ngModel)]="form.ldap.bindDn" required placeholder="CN=svc-tributary,OU=Service Accounts,DC=corp,DC=example,DC=com" class="wide" />
                <clr-control-helper i18n="@@identitySources.bindDnHelp">A read-only service account used to find users</clr-control-helper>
              </clr-input-container>
              <clr-password-container>
                <label i18n="@@identitySources.bindPassword">Bind password</label>
                <input clrPassword name="bindPassword" [(ngModel)]="form.clientSecret" autocomplete="new-password" [placeholder]="form.hasSecret ? secretUnchanged : ''" />
              </clr-password-container>
              <clr-input-container>
                <label i18n="@@identitySources.baseDn">Base DN</label>
                <input clrInput name="baseDn" [(ngModel)]="form.ldap.baseDn" required placeholder="DC=corp,DC=example,DC=com" class="wide" />
              </clr-input-container>
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-4" i18n="@@identitySources.schema">Directory type</label>
                <div class="clr-col-12 clr-col-md-8 presets">
                  <button type="button" class="btn btn-sm btn-outline" (click)="preset('ad')">Active Directory</button>
                  <button type="button" class="btn btn-sm btn-outline" (click)="preset('openldap')">OpenLDAP</button>
                </div>
              </div>
              <clr-input-container>
                <label i18n="@@identitySources.userFilter">User filter</label>
                <input clrInput name="userFilter" [(ngModel)]="form.ldap.userFilter" class="wide mono" />
                <clr-control-helper i18n="@@identitySources.userFilterHelp">{{ '{' }}username{{ '}' }} is replaced with the name typed on the sign-in page</clr-control-helper>
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@identitySources.usernameAttr">Username attribute</label>
                <input clrInput name="usernameAttr" [(ngModel)]="form.ldap.usernameAttr" />
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@identitySources.nameAttr">Display name attribute</label>
                <input clrInput name="nameAttr" [(ngModel)]="form.ldap.nameAttr" />
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@identitySources.groupAttr">Group attribute</label>
                <input clrInput name="groupAttr" [(ngModel)]="form.ldap.groupAttr" />
              </clr-input-container>
              <clr-checkbox-container>
                <label></label>
                <clr-checkbox-wrapper>
                  <input type="checkbox" clrCheckbox name="nested" [(ngModel)]="form.ldap.nestedGroups" />
                  <label i18n="@@identitySources.nestedGroups">Include nested groups (Active Directory)</label>
                </clr-checkbox-wrapper>
              </clr-checkbox-container>
            }
            @if (form.type === 'radius') {
              <h5 class="section" i18n="@@identitySources.radiusServers">RADIUS</h5>
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-4" i18n="@@identitySources.servers">Servers</label>
                <div class="clr-control-container clr-col-12 clr-col-md-8">
                  <nfa-list-editor [(items)]="form.radius.servers" [ordered]="true" placeholder="nps1.corp.example.com or 10.0.0.5:1812" label="RADIUS server" i18n-label="@@identitySources.radiusServer" [validate]="serverError" />
                  <span class="clr-subtext" i18n="@@identitySources.serversHelp">Tried in order when one doesn't answer; default port 1812. Add this appliance as a client on each server.</span>
                </div>
              </div>
              <clr-password-container>
                <label i18n="@@identitySources.sharedSecret">Shared secret</label>
                <input clrPassword name="radiusSecret" [(ngModel)]="form.clientSecret" autocomplete="new-password" [placeholder]="form.hasSecret ? secretUnchanged : ''" />
              </clr-password-container>
              <clr-input-container>
                <label i18n="@@identitySources.nasId">NAS-Identifier</label>
                <input clrInput name="nasId" [(ngModel)]="form.radius.nasIdentifier" />
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@identitySources.timeout">Timeout (seconds)</label>
                <input clrInput type="number" name="timeout" [(ngModel)]="form.radius.timeoutSec" min="1" max="30" />
              </clr-input-container>
              <clr-select-container>
                <label i18n="@@identitySources.roleAttribute">Role attribute</label>
                <select clrSelect name="roleAttr" [(ngModel)]="form.radius.roleAttribute">
                  <option value="Class">Class</option>
                  <option value="Filter-Id">Filter-Id</option>
                </select>
                <clr-control-helper i18n="@@identitySources.roleAttributeHelp">Values of this reply attribute are matched against the role mappings below</clr-control-helper>
              </clr-select-container>
            }
            @if (form.type === 'saml') {
              <h5 class="section" i18n="@@identitySources.provider">Provider</h5>
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-4" i18n="@@identitySources.samlMetadata">Provider metadata</label>
                <div class="clr-col-12 clr-col-md-8">
                  <div class="btn-group btn-sm" role="group">
                    <button type="button" class="btn" [class.btn-primary]="form.samlSource === 'url'" [class.btn-outline]="form.samlSource !== 'url'" (click)="form.samlSource = 'url'" i18n="@@identitySources.samlFromUrl">From URL</button>
                    <button type="button" class="btn" [class.btn-primary]="form.samlSource === 'xml'" [class.btn-outline]="form.samlSource !== 'xml'" (click)="form.samlSource = 'xml'" i18n="@@identitySources.samlPasteXml">Paste XML</button>
                  </div>
                </div>
              </div>
              @if (form.samlSource === 'url') {
                <clr-input-container>
                  <label i18n="@@identitySources.samlMetadataUrl">Metadata URL</label>
                  <input clrInput name="samlUrl" [(ngModel)]="form.saml.metadataUrl" required placeholder="https://login.microsoftonline.com/…/federationmetadata/2007-06/federationmetadata.xml" class="wide" />
                  <clr-control-helper i18n="@@identitySources.samlMetadataUrlHelp">Fetched when you save and refreshed daily, so certificate rollovers are picked up</clr-control-helper>
                </clr-input-container>
              } @else {
                <div class="clr-form-control clr-row">
                  <label class="clr-control-label clr-col-12 clr-col-md-4" i18n="@@identitySources.samlMetadataXml">Metadata XML</label>
                  <div class="clr-control-container clr-col-12 clr-col-md-8">
                    <textarea class="clr-textarea xml mono" name="samlXml" [(ngModel)]="form.saml.metadataXml" rows="7" spellcheck="false" placeholder="<EntityDescriptor …>"></textarea>
                    <span class="clr-subtext" i18n="@@identitySources.samlMetadataXmlHelp">For providers without a metadata URL. Paste the new metadata here when the provider's signing certificate changes.</span>
                  </div>
                </div>
              }
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-4" i18n="@@identitySources.samlProviderType">Provider type</label>
                <div class="clr-col-12 clr-col-md-8 presets">
                  <button type="button" class="btn btn-sm btn-outline" (click)="samlPreset('entra')">Entra ID</button>
                  <button type="button" class="btn btn-sm btn-outline" (click)="samlPreset('adfs')">AD FS</button>
                  <button type="button" class="btn btn-sm btn-outline" (click)="samlPreset('okta')">Okta</button>
                  <button type="button" class="btn btn-sm btn-outline" (click)="samlPreset('authentik')">Authentik</button>
                </div>
              </div>
              <clr-input-container>
                <label i18n="@@identitySources.samlUsernameAttr">Username attribute</label>
                <input clrInput name="samlUser" [(ngModel)]="form.saml.usernameAttr" class="wide mono" placeholder="NameID" i18n-placeholder="@@identitySources.samlNameId" />
                <clr-control-helper i18n="@@identitySources.samlUsernameAttrHelp">Empty: the assertion's NameID. Attributes match by Name or FriendlyName.</clr-control-helper>
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@identitySources.nameAttr">Display name attribute</label>
                <input clrInput name="samlName" [(ngModel)]="form.saml.nameAttr" class="wide mono" />
              </clr-input-container>
              <clr-input-container>
                <label i18n="@@identitySources.samlGroupsAttr">Groups attribute</label>
                <input clrInput name="samlGroups" [(ngModel)]="form.saml.groupsAttr" class="wide mono" />
                <clr-control-helper i18n="@@identitySources.samlGroupsAttrHelp">Its values are matched against the role mappings below (Entra ID sends group object IDs)</clr-control-helper>
              </clr-input-container>
              <clr-checkbox-container>
                <label></label>
                <clr-checkbox-wrapper>
                  <input type="checkbox" clrCheckbox name="signReq" [(ngModel)]="form.saml.signRequests" />
                  <label i18n="@@identitySources.samlSignRequests">Sign authentication requests</label>
                </clr-checkbox-wrapper>
              </clr-checkbox-container>
              <clr-input-container>
                <label i18n="@@identitySources.samlEntityId">Entity ID</label>
                <input clrInput name="samlEntity" [(ngModel)]="form.saml.entityId" class="wide" [placeholder]="samlInfo()?.metadataUrl ?? ''" />
                <clr-control-helper i18n="@@identitySources.samlEntityIdHelp">How this appliance identifies itself to the provider. Empty: its metadata URL.</clr-control-helper>
              </clr-input-container>

              <div class="redirect">
                <h5 i18n="@@identitySources.samlThisAppliance">This appliance (service provider)</h5>
                @if (samlInfo(); as si) {
                  <p i18n="@@identitySources.samlRegister">Import the metadata into the provider, or enter these values:</p>
                  <dl class="sp">
                    <dt i18n="@@identitySources.samlEntityId">Entity ID</dt>
                    <dd class="uri"><code>{{ si.entityId }}</code> <button type="button" class="btn btn-link btn-sm" (click)="copy(si.entityId, 'entity')">{{ copied() === 'entity' ? copiedLabel : copyLabel }}</button></dd>
                    <dt i18n="@@identitySources.samlAcs">Reply / ACS URL (HTTP-POST)</dt>
                    <dd class="uri"><code>{{ si.acsUrl }}</code> <button type="button" class="btn btn-link btn-sm" (click)="copy(si.acsUrl, 'acs')">{{ copied() === 'acs' ? copiedLabel : copyLabel }}</button></dd>
                    <dt i18n="@@identitySources.samlSpMetadata">Metadata</dt>
                    <dd class="uri"><code>{{ si.metadataUrl }}</code> <button type="button" class="btn btn-link btn-sm" (click)="copy(si.metadataUrl, 'meta')">{{ copied() === 'meta' ? copiedLabel : copyLabel }}</button>
                      <a class="btn btn-link btn-sm" [href]="si.metadataUrl + '?download'" i18n="@@identitySources.download">Download</a></dd>
                    @if (si.certExpires) {
                      <dt i18n="@@identitySources.samlSpCert">Signing certificate</dt>
                      <dd i18n="@@identitySources.samlSpCertExpires">Self-signed, expires {{ dateOnly(si.certExpires) }}</dd>
                    }
                  </dl>
                } @else {
                  <p i18n="@@identitySources.samlSaveFirst">Save the source first: its entity ID, reply URL and metadata appear here, ready for the provider.</p>
                }
              </div>
            }
            @if (form.type === 'oidc') {
            <h5 class="section" i18n="@@identitySources.provider">Provider</h5>
            <clr-input-container>
              <label i18n="@@identitySources.issuerUrl">Issuer URL</label>
              <input clrInput name="issuer" [(ngModel)]="form.issuer" required placeholder="https://auth.example.com/application/o/tributary/" class="wide" />
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@identitySources.clientId">Client ID</label>
              <input clrInput name="clientId" [(ngModel)]="form.clientId" required class="wide" />
            </clr-input-container>
            <clr-password-container>
              <label i18n="@@identitySources.clientSecret">Client secret</label>
              <input clrPassword name="clientSecret" [(ngModel)]="form.clientSecret" autocomplete="new-password"
                [placeholder]="form.hasSecret ? secretUnchanged : secretRequired" />
            </clr-password-container>
            <div class="clr-form-control clr-row list-row">
              <label class="clr-control-label clr-col-12 clr-col-md-4" i18n="@@identitySources.scopes">Scopes</label>
              <div class="clr-col-12 clr-col-md-8">
                @for (sc of form.scopes; track $index; let i = $index) {
                  <div class="list-item">
                    <input class="clr-input" [name]="'scope' + i" [(ngModel)]="form.scopes[i]" [disabled]="sc === 'openid' && i === 0" />
                    @if (!(sc === 'openid' && i === 0)) {
                      <button type="button" class="btn btn-link btn-icon btn-sm" (click)="form.scopes.splice(i, 1)" aria-label="Remove scope" i18n-aria-label="@@identitySources.removeScope"><cds-icon shape="times"></cds-icon></button>
                    }
                  </div>
                }
                <button type="button" class="btn btn-link btn-sm add" (click)="form.scopes.push('')"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@identitySources.addScope">Add scope</ng-container></button>
              </div>
            </div>
            <clr-input-container>
              <label i18n="@@identitySources.usernameClaim">Username claim</label>
              <input clrInput name="usernameClaim" [(ngModel)]="form.usernameClaim" />
            </clr-input-container>
            <clr-input-container>
              <label i18n="@@identitySources.groupsClaim">Groups claim</label>
              <input clrInput name="groupsClaim" [(ngModel)]="form.groupsClaim" />
              <clr-control-helper i18n="@@identitySources.groupsClaimHelp">Read from the ID token, or from userinfo if absent</clr-control-helper>
            </clr-input-container>

            <div class="redirect">
              <h5 i18n="@@identitySources.redirectUri">Redirect URI</h5>
              @if (redirectUri()) {
                <p i18n="@@identitySources.redirectUriRegister">Register this redirect URI in the provider's application settings:</p>
                <div class="uri"><code>{{ redirectUri() }}</code> <button type="button" class="btn btn-link btn-sm" (click)="copy(redirectUri(), 'redirect')">{{ copied() === 'redirect' ? copiedLabel : copyLabel }}</button></div>
              } @else {
                <p i18n="@@identitySources.redirectUriSaveFirst">Save the source first; its redirect URI appears here, ready to copy into the provider.</p>
              }
            </div>
            }

            <h5 class="section" i18n="@@identitySources.roleMapping">Role mapping</h5>
            <div class="mappings">
              <div class="map-head"><span i18n="@@identitySources.group">Group</span><span i18n="@@identitySources.role">Role</span><span></span></div>
              @for (m of form.mappings; track $index; let i = $index) {
                <div class="map-row">
                  <input class="clr-input" [name]="'group' + i" [(ngModel)]="m.group" [placeholder]="groupPlaceholder[form.type]" />
                  <div class="clr-select-wrapper">
                    <select class="clr-select" [name]="'role' + i" [(ngModel)]="m.role">
                      <option value="admin" i18n="@@identitySources.roleAdministrator">Administrator</option>
                      <option value="viewer" i18n="@@identitySources.roleViewer">Viewer</option>
                    </select>
                  </div>
                  <button type="button" class="btn btn-link btn-icon btn-sm" (click)="form.mappings.splice(i, 1)" aria-label="Remove mapping" i18n-aria-label="@@identitySources.removeMapping"><cds-icon shape="times"></cds-icon></button>
                </div>
              }
              <button type="button" class="btn btn-link btn-sm add" (click)="form.mappings.push({ group: '', role: 'viewer' })"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@identitySources.addMapping">Add mapping</ng-container></button>
            </div>
            <clr-select-container>
              <label i18n="@@identitySources.everyoneElse">Everyone else</label>
              <select clrSelect name="defaultRole" [(ngModel)]="form.defaultRole">
                <option value="" i18n="@@identitySources.denyAccess">Deny console access</option>
                <option value="viewer" i18n="@@identitySources.roleViewer">Viewer</option>
                <option value="admin" i18n="@@identitySources.roleAdministrator">Administrator</option>
              </select>
              <clr-control-helper i18n="@@identitySources.everyoneElseHelp">Role for authenticated users matching no mapping</clr-control-helper>
            </clr-select-container>
          </form>

          <aside class="test">
            <h5 i18n="@@identitySources.testConnection">Test connection</h5>
            @if (form.type === 'oidc') {
              <p i18n="@@identitySources.testHelp">Checks that the provider's metadata can be loaded. Complete a full sign-in with the button on the sign-in page.</p>
            } @else if (form.type === 'saml') {
              <p i18n="@@identitySources.testSamlHelp">Loads the provider's metadata and shows its sign-in URL and certificates. Complete a full sign-in with the button on the sign-in page.</p>
            } @else if (form.type === 'ldap') {
              <p i18n="@@identitySources.testLdapHelp">Connects and signs in with the service account. Enter a username to also see their entry, groups and the role they would get.</p>
              <input class="clr-input test-input" name="testUser" [(ngModel)]="form.testUser" placeholder="Username (optional)" i18n-placeholder="@@identitySources.testUserOptional" autocomplete="off" />
            } @else {
              <p i18n="@@identitySources.testRadiusHelp">RADIUS can only be tested with a sign-in attempt. Even a rejection shows the server is reachable and the shared secret is right.</p>
              <input class="clr-input test-input" name="testUser" [(ngModel)]="form.testUser" placeholder="Username" i18n-placeholder="@@identitySources.testUser" autocomplete="off" />
              <input class="clr-input test-input" type="password" name="testPass" [(ngModel)]="form.testPass" placeholder="Password" i18n-placeholder="@@identitySources.testPass" autocomplete="new-password" />
            }
            <button type="button" class="btn btn-outline btn-sm" (click)="runTest()" [clrLoading]="testing()"><cds-icon shape="play"></cds-icon> <ng-container i18n="@@identitySources.runTest">Run test</ng-container></button>
            @if (test(); as t) {
              <div class="result" [class.bad]="!t.ok">
                <div><span class="dot" [class.ok]="t.ok" [class.bad]="!t.ok"></span> {{ t.message }}</div>
                @if (t.ok && (form.type === 'ldap' || form.type === 'radius') && (t.dn || t.groups)) {
                  <dl>
                    @if (t.dn) {<dt>DN</dt><dd>{{ t.dn }}</dd>}
                    <dt i18n="@@identitySources.groupsFound">Groups</dt><dd>{{ t.groups?.length ? t.groups!.join('; ') : '–' }}</dd>
                    <dt i18n="@@identitySources.role">Role</dt><dd>{{ roleLabel(t.role ?? '') }}</dd>
                  </dl>
                }
                @if (t.ok && form.type === 'saml') {
                  <dl>
                    <dt i18n="@@identitySources.samlIdpEntity">Provider entity ID</dt><dd>{{ t.idpEntityId }}</dd>
                    <dt i18n="@@identitySources.samlSsoUrl">Sign-in URL</dt><dd>{{ t.ssoUrl }}</dd>
                    @for (c of t.signingCerts ?? []; track $index) {
                      <dt i18n="@@identitySources.samlIdpCert">Signing certificate</dt>
                      <dd>{{ c.subject }} <span [class.bad-text]="c.notAfter < now" i18n="@@identitySources.samlIdpCertExpires">(expires {{ dateOnly(c.notAfter) }})</span></dd>
                    }
                    <dt i18n="@@identitySources.samlSignedRequests">Signed requests</dt>
                    <dd>@if (t.wantsSignedRequests) {<ng-container i18n="@@identitySources.samlRequired">required</ng-container>} @else {<ng-container i18n="@@identitySources.samlOptional">optional</ng-container>}</dd>
                  </dl>
                }
                @if (t.ok && form.type === 'oidc') {
                  <dl>
                    <dt i18n="OIDC authorization endpoint@@identitySources.authorization">Authorization</dt><dd>{{ t.authorizationEndpoint }}</dd>
                    <dt i18n="OIDC token endpoint@@identitySources.token">Token</dt><dd>{{ t.tokenEndpoint }}</dd>
                    @if (t.userinfoEndpoint) {<dt>Userinfo</dt><dd>{{ t.userinfoEndpoint }}</dd>}
                    <dt>PKCE</dt><dd>@if (t.pkce?.includes('S256')) {<ng-container i18n="@@identitySources.pkceSupported">S256 supported</ng-container>} @else {<ng-container i18n="@@identitySources.pkceNotAdvertised">not advertised (sign-in still sends S256)</ng-container>}</dd>
                    @if (t.claims?.length) {<dt i18n="@@identitySources.claims">Claims</dt><dd>{{ claimHint(t) }}</dd>}
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
        <button type="button" class="btn btn-outline" (click)="editOpen.set(false)">@if (savedNote()) {<ng-container i18n="@@common.close">Close</ng-container>} @else {<ng-container i18n="@@common.cancel">Cancel</ng-container>}</button>
        <button type="submit" form="srcform" class="btn btn-primary" [clrLoading]="saving()" i18n="@@common.save">Save</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="!!confirmDelete()" (clrModalOpenChange)="!$event && confirmDelete.set(null)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@identitySources.deleteTitle">Delete {{ confirmDelete()?.name }}?</h3>
      <div class="modal-body">
        <p i18n="@@identitySources.deleteConfirm">The sign-in button disappears and the {{ confirmDelete()?.users }} account(s) created by this source are deleted and signed out. Local accounts are not affected.</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmDelete.set(null)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="remove()" i18n="@@common.delete">Delete</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .presets { display: flex; gap: 6px; padding-top: 4px; }
    .presets .btn { margin: 0; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .warn-text { font-size: 12px; color: var(--cds-alias-status-danger); margin: 2px 0 0; }
    .test-input { display: block; width: 100%; margin: 0 0 8px; }
    .clr-subtext { display: block; margin-top: 6px; }
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
    .sp { margin: 0; font-size: 13px; }
    .sp dt { font-size: 11px; color: var(--cds-alias-typography-color-300); margin-top: 8px; }
    .sp dd { margin: 0; }
    .xml { width: 100%; max-width: 520px; font-size: 11px; }
    .btn-group { margin: 0; }
    .bad-text { color: var(--cds-alias-status-danger); }
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
  readonly byId = trackByKey<{ id: number }>((s) => s.id);
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
  readonly copied = signal('');
  readonly samlInfo = signal<SAMLInfo | null>(null);
  readonly now = Date.now();
  readonly dateOnly = dateOnly;
  readonly copyLabel = $localize`:@@identitySources.copy:Copy`;
  readonly copiedLabel = $localize`:@@identitySources.copied:Copied`;
  readonly namePlaceholder: Record<Form['type'], string> = { oidc: 'Authentik', saml: 'Entra ID', ldap: 'Corporate AD', radius: 'NPS' };
  readonly groupPlaceholder: Record<Form['type'], string> = {
    oidc: 'tributary-admins',
    saml: $localize`:@@identitySources.samlGroupPlaceholder:Group name or object ID`,
    ldap: 'Net Admins (CN or full DN)',
    radius: 'Class or Filter-Id value',
  };
  readonly formError = signal('');
  readonly savedNote = signal('');
  readonly pageError = signal('');
  form: Form = blankForm();
  readonly secretUnchanged = $localize`:@@identitySources.secretUnchanged:Unchanged (stored securely)`;
  readonly secretRequired = $localize`:@@identitySources.secretRequired:Required for confidential clients`;

  typeLabel(t: string) {
    return TYPE_LABELS[t] ?? t;
  }

  roleLabel(r: string) {
    return r === 'admin' ? $localize`:@@identitySources.roleAdministrator:Administrator` : r === 'viewer' ? $localize`:@@identitySources.roleViewer:Viewer` : $localize`:@@identitySources.roleDenied:denied`;
  }

  private reset() {
    this.test.set(null);
    this.formError.set('');
    this.savedNote.set('');
    this.copied.set('');
  }

  readonly serverError = (v: string) => (/^[^\s/\\]+$/.test(v) ? null : $localize`:@@identitySources.badServer:Not a host name or address`);

  preset(kind: 'ad' | 'openldap') {
    Object.assign(this.form.ldap, kind === 'ad' ? AD_PRESET : OPENLDAP_PRESET);
  }

  samlPreset(kind: string) {
    Object.assign(this.form.saml, SAML_PRESETS[kind]);
  }

  openNew(type: Form['type'] = 'oidc') {
    this.chooserOpen.set(false);
    this.form = blankForm(type);
    this.redirectUri.set('');
    this.samlInfo.set(null);
    this.reset();
    this.editOpen.set(true);
  }

  async openEdit(s: IdentitySource) {
    this.reset();
    try {
      const r = await this.api.identitySource(s.id);
      const src = r.source;
      const f = blankForm(src.type as Form['type']);
      Object.assign(f, { id: src.id, name: src.name, enabled: src.enabled, priority: src.priority, hasSecret: src.hasSecret,
        mappings: src.mappings.map((m) => ({ ...m })), defaultRole: src.defaultRole });
      if (src.oidc) {
        const o = src.oidc;
        Object.assign(f, { issuer: o.issuer, clientId: o.clientId, scopes: [...o.scopes], usernameClaim: o.usernameClaim, groupsClaim: o.groupsClaim });
      }
      if (src.saml) {
        f.saml = { ...src.saml };
        f.samlSource = src.saml.metadataUrl ? 'url' : 'xml';
      }
      if (src.ldap) f.ldap = { ...src.ldap, bindPassword: undefined };
      if (src.radius) f.radius = { ...src.radius, secret: undefined, servers: [...src.radius.servers] };
      this.form = f;
      this.redirectUri.set(r.redirectUri);
      this.samlInfo.set(r.saml ?? null);
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
        id: f.id || undefined, type: f.type, name: f.name, enabled: f.enabled, priority: Number(f.priority) || 0,
        ...this.typeConfig(),
        mappings: f.mappings.filter((m) => m.group.trim()), defaultRole: f.defaultRole,
      });
      const created = !f.id;
      f.id = r.id;
      if (f.clientSecret) f.hasSecret = true;
      f.clientSecret = '';
      this.redirectUri.set(r.redirectUri);
      this.samlInfo.set(r.saml ?? null);
      this.list.reload();
      if (created && f.type === 'oidc') {
        // Keep the dialog open so the redirect URI can be copied into the provider.
        this.savedNote.set($localize`:@@identitySources.savedNote:Saved. Register the redirect URI above in your provider, then sign in with the new button on the sign-in page.`);
      } else if (created && f.type === 'saml') {
        this.savedNote.set($localize`:@@identitySources.samlSavedNote:Saved. Add this appliance to your provider with the metadata or values above, then sign in with the new button on the sign-in page.`);
      } else {
        this.editOpen.set(false);
      }
    } catch (e) {
      this.formError.set(errorMessage(e));
    } finally {
      this.saving.set(false);
    }
  }

  /** The type-specific settings, with the secret typed in the form. */
  private typeConfig(): { oidc?: IdentitySource['oidc']; saml?: SAMLConfig; ldap?: LDAPConfig; radius?: RADIUSConfig } {
    const f = this.form;
    switch (f.type) {
      case 'saml': {
        const url = f.samlSource === 'url';
        return { saml: { ...f.saml, metadataUrl: url ? f.saml.metadataUrl : '', metadataXml: url ? '' : f.saml.metadataXml } };
      }
      case 'ldap':
        return { ldap: { ...f.ldap, bindPassword: f.clientSecret } };
      case 'radius':
        return { radius: { ...f.radius, servers: listValues(f.radius.servers), timeoutSec: Number(f.radius.timeoutSec) || 5, secret: f.clientSecret } };
    }
    return { oidc: { issuer: f.issuer, clientId: f.clientId, clientSecret: f.clientSecret, scopes: f.scopes, usernameClaim: f.usernameClaim, groupsClaim: f.groupsClaim } };
  }

  async runTest() {
    this.testing.set(true);
    const f = this.form;
    try {
      this.test.set(await this.api.testIdentitySource({ type: f.type, id: f.id || undefined, issuer: f.issuer, ...this.typeConfig(), username: f.testUser, password: f.testPass,
        mappings: f.mappings.filter((m) => m.group.trim()), defaultRole: f.defaultRole }));
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
    return missing.length
      ? $localize`:@@identitySources.claimsMissing:${missing.join(', ')}:claims: not advertised (may still be sent)`
      : $localize`:@@identitySources.claimsAdvertised:${want.join(', ')}:claims: advertised`;
  }

  async copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      this.copied.set(key);
      setTimeout(() => this.copied.set(''), 2000);
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
