import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, CertDetails, CertIdentity, CSRInfo, errorMessage, TrustedCA } from '../core/api';
import { dateTime } from '../core/format';
import { loader, trackByKey } from '../core/util';
import { validAddrOrPrefix } from '../core/cidr';
import { ListEditor, listValues } from '../shared/list-editor';

const KEY_TYPES = [
  { id: 'ecdsa-p256', label: $localize`:@@certificates.keyRecommended:ECDSA P-256 (recommended)` },
  { id: 'ecdsa-p384', label: 'ECDSA P-384' },
  { id: 'rsa-2048', label: 'RSA 2048' },
  { id: 'rsa-3072', label: 'RSA 3072' },
  { id: 'rsa-4096', label: 'RSA 4096' },
];

interface IdForm {
  commonName: string;
  organization: string;
  keyType: string;
  days: number;
}

function download(name: string, text: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

@Component({
  selector: 'nfa-certificates',
  imports: [ClarityModule, FormsModule, ListEditor],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.certificates">Certificates</h2>
        <p class="subtitle" i18n="@@certificates.subtitle">Management UI certificate and trusted certificate authorities</p>
      </div>
    </div>

    @if (notice()) {
      <div class="alert alert-success" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ notice() }}</span></div></div></div>
    }
    @if (pageError()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ pageError() }}</span></div></div></div>
    }

    <clr-tabs>
      <clr-tab>
        <button clrTabLink i18n="@@certificates.tab.appliance">Appliance certificate</button>
        <clr-tab-content *clrIfActive="true">
          @if (cert.value(); as cv) {
            @let c = cv.status.certificate;
            @if (cv.status.pendingCsr; as p) {
              <div class="alert alert-info pending" role="alert">
                <div class="alert-items"><div class="alert-item static">
                  <div class="alert-icon-wrapper"><cds-icon class="alert-icon" shape="info-circle"></cds-icon></div>
                  <span class="alert-text" i18n="@@certificates.pendingCsr">A CSR for <b>{{ p.commonName }}</b> ({{ p.key }}, {{ dt(p.created) }}) is waiting for its signed certificate. Upload the certificate from your CA; its key is already on the appliance.</span>
                  <div class="alert-actions">
                    <button class="btn btn-sm btn-link" (click)="showCSR(p)" i18n="@@certificates.showCsr">Show CSR</button>
                    <button class="btn btn-sm btn-link" (click)="discardCSR()" i18n="@@certificates.discard">Discard</button>
                  </div>
                </div></div>
              </div>
            }
            <div class="cert-layout">
              <div class="card cert">
                <div class="card-header">
                  <span class="cert-title"><cds-icon shape="certificate" size="md"></cds-icon> {{ c.commonName || c.subject }}</span>
                  <span class="days"><span class="dot" [class]="expiryClass(c.daysLeft)"></span> {{ daysText(c.daysLeft) }}</span>
                </div>
                <div class="card-block">
                  <table class="table table-noborder kv">
                    <tbody>
                      <tr><td i18n="@@certificates.subject">Subject</td><td>{{ c.subject }}</td></tr>
                      <tr><td i18n="@@certificates.issuer">Issuer</td><td>{{ c.selfSigned ? txt.selfSigned : c.issuer }}</td></tr>
                      <tr><td i18n="@@certificates.sans">Subject alternative names</td><td>{{ sans(c) || txt.none }}</td></tr>
                      <tr><td i18n="@@certificates.validFrom">Valid from</td><td>{{ dt(c.notBefore) }}</td></tr>
                      <tr><td i18n="@@certificates.validUntil">Valid until</td><td>{{ dt(c.notAfter) }}</td></tr>
                      <tr><td i18n="@@certificates.key">Key</td><td>{{ c.key }}</td></tr>
                      <tr><td i18n="@@certificates.chain">Chain</td><td i18n="@@certificates.chainCount">{c.chain, plural, =1 {1 certificate} other {{{c.chain}} certificates}}</td></tr>
                      <tr><td i18n="@@certificates.serial">Serial</td><td class="mono">{{ c.serial }}</td></tr>
                      <tr><td i18n="@@certificates.sha256Fingerprint">SHA-256 fingerprint</td><td class="mono small">{{ c.sha256 }}</td></tr>
                    </tbody>
                  </table>
                </div>
                <div class="card-footer">
                  <a class="btn btn-link" href="/api/certificates/appliance/download" download><cds-icon shape="download"></cds-icon> <ng-container i18n="@@certificates.download">Download</ng-container></a>
                </div>
              </div>

              <div class="card replace">
                <div class="card-header" i18n="@@certificates.replaceTitle">Replace certificate</div>
                <div class="card-block">
                  <section>
                    <h5 i18n="@@certificates.uploadTitle">Upload a certificate</h5>
                    <p i18n="@@certificates.uploadHelp">Install a certificate and private key issued by your CA, or the signed answer to a CSR.</p>
                    <button class="btn btn-primary btn-sm" (click)="openUpload()"><cds-icon shape="upload"></cds-icon> <ng-container i18n="@@certificates.upload">Upload</ng-container></button>
                  </section>
                  <section>
                    <h5 i18n="@@certificates.requestTitle">Request from your CA</h5>
                    <p i18n="@@certificates.requestHelp">Generate a key on the appliance and a CSR to submit to your certificate authority.</p>
                    <button class="btn btn-outline btn-sm" (click)="openId('csr')"><cds-icon shape="file"></cds-icon> <ng-container i18n="@@certificates.generateCsr">Generate CSR</ng-container></button>
                  </section>
                  <section>
                    <h5 i18n="@@certificates.selfSignedTitle">Self-signed</h5>
                    <p i18n="@@certificates.selfSignedHelp">Create a new self-signed certificate, e.g. after changing the hostname or address.</p>
                    <button class="btn btn-outline btn-sm" (click)="openId('self')"><cds-icon shape="refresh"></cds-icon> <ng-container i18n="@@certificates.regenerate">Regenerate</ng-container></button>
                  </section>
                  @if (cv.status.hasPrevious) {
                    <section>
                      <h5 i18n="@@certificates.previousTitle">Previous certificate</h5>
                      <p i18n="@@certificates.previousHelp">Switch back to the certificate that was active before the last change.</p>
                      <button class="btn btn-link btn-sm restore" (click)="restoreOpen.set(true)"><cds-icon shape="history"></cds-icon> <ng-container i18n="@@certificates.restorePrevious">Restore previous</ng-container></button>
                    </section>
                  }
                </div>
              </div>
            </div>
          } @else if (cert.error()) {
            <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ cert.error() }}</span></div></div></div>
          } @else {
            <div class="center"><span class="spinner" i18n="@@certificates.loading">Loading…</span></div>
          }
        </clr-tab-content>
      </clr-tab>

      <clr-tab>
        <button clrTabLink i18n="@@certificates.tab.trustedCas">Trusted CAs ({{ (cas.value() ?? []).length }})</button>
        <clr-tab-content *clrIfActive>
          <p class="hint" i18n="@@certificates.trustedHint">Certificate authorities the appliance trusts for outbound TLS, in addition to the operating system's public CAs: identity providers (OpenID Connect) now, and LDAPS directories such as Active Directory later. Add your internal root and issuing CAs here.</p>
          <div class="toolbar">
            <button class="btn btn-primary btn-sm" (click)="openAddCA()"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@certificates.addCa">Add CA</ng-container></button>
            <button class="btn btn-outline btn-sm" [disabled]="!selectedCA()" (click)="confirmCA.set(selectedCA())"><cds-icon shape="trash"></cds-icon> <ng-container i18n="@@common.delete">Delete</ng-container></button>
          </div>
          <clr-datagrid class="datagrid-compact" clrDgSelectionType="single" [clrDgSelected]="selectedCAList()" (clrDgSelectedChange)="selectedCA.set($event[0])" [clrDgLoading]="cas.loading()">
            <clr-dg-column [clrDgField]="'name'" i18n="@@common.name">Name</clr-dg-column>
            <clr-dg-column i18n="@@certificates.col.type">Type</clr-dg-column>
            <clr-dg-column [clrDgField]="'notAfter'" i18n="@@certificates.col.expires">Expires</clr-dg-column>
            <clr-dg-column i18n="@@certificates.col.key">Key</clr-dg-column>
            <clr-dg-column>SHA-256</clr-dg-column>
            <clr-dg-row *clrDgItems="let ca of cas.value() ?? []; trackBy: byId" [clrDgItem]="ca">
              <clr-dg-cell>{{ ca.name }}<div class="sub">{{ ca.subject }}</div></clr-dg-cell>
              <clr-dg-cell>{{ ca.selfSigned ? txt.root : txt.intermediate }}@if (!ca.selfSigned) {<div class="sub" i18n="@@certificates.issuedBy">issued by {{ ca.issuer }}</div>}</clr-dg-cell>
              <clr-dg-cell><span class="dot" [class]="expiryClass(ca.daysLeft)"></span> {{ dt(ca.notAfter) }}<div class="sub">{{ daysText(ca.daysLeft) }}</div></clr-dg-cell>
              <clr-dg-cell>{{ ca.key }}</clr-dg-cell>
              <clr-dg-cell class="mono small" [title]="ca.sha256">{{ ca.sha256.slice(0, 23) }}…</clr-dg-cell>
            </clr-dg-row>
            <clr-dg-placeholder i18n="@@certificates.noTrustedCas">No trusted CAs added. Only the operating system's public CAs are trusted.</clr-dg-placeholder>
            <clr-dg-footer>
            <clr-dg-pagination #caPg [clrDgPageSize]="25">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50, 100]" i18n="@@common.rowsPerPage">Rows per page</clr-dg-page-size>
          @if (caPg.totalItems) {
            <ng-container i18n="Datagrid footer: first–last of total@@certificates.footer">{{ caPg.firstItem + 1 }}–{{ caPg.lastItem + 1 }} of {{ caPg.totalItems.toLocaleString() }} CAs</ng-container>
          } @else {
            <ng-container i18n="@@certificates.noCas">No CAs</ng-container>
          }
        </clr-dg-pagination>
            </clr-dg-footer>
          </clr-datagrid>
        </clr-tab-content>
      </clr-tab>
    </clr-tabs>

    <!-- Upload -->
    <clr-modal [clrModalOpen]="uploadOpen()" (clrModalOpenChange)="uploadOpen.set($event)" clrModalSize="lg">
      <h3 class="modal-title" i18n="@@certificates.uploadTitle">Upload a certificate</h3>
      <div class="modal-body">
        <label class="field-label" i18n="@@certificates.certPem">Certificate (PEM), including intermediate CAs</label>
        <textarea class="clr-textarea pem" [(ngModel)]="upCert" name="upCert" rows="7" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
        <input type="file" accept=".pem,.crt,.cer,.txt" (change)="readFile($event, 'cert')" />
        <label class="field-label" i18n="@@certificates.keyPem">Private key (PEM)</label>
        <textarea class="clr-textarea pem" [(ngModel)]="upKey" name="upKey" rows="5"
          [placeholder]="cert.value()?.status?.pendingCsr ? txt.keyPlaceholderPending : '-----BEGIN PRIVATE KEY-----'"></textarea>
        <input type="file" accept=".pem,.key,.txt" (change)="readFile($event, 'key')" />
        <p class="hint" i18n="@@certificates.uploadHint">The certificate takes effect immediately for new connections; reload the page afterwards. The previous certificate is kept and can be restored.</p>
        @if (modalError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ modalError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="uploadOpen.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-primary" [disabled]="!upCert.trim()" [clrLoading]="busy()" (click)="upload()" i18n="@@certificates.install">Install</button>
      </div>
    </clr-modal>

    <!-- CSR / self-signed identity form -->
    <clr-modal [clrModalOpen]="idOpen()" (clrModalOpenChange)="idOpen.set($event)" clrModalSize="lg">
      <h3 class="modal-title">{{ idMode() === 'csr' ? txt.csrTitle : txt.selfTitle }}</h3>
      <div class="modal-body">
        <form clrForm clrLayout="horizontal" clrLabelSize="4" id="idform" (ngSubmit)="submitId()">
          <clr-input-container>
            <label i18n="@@certificates.commonName">Common name</label>
            <input clrInput name="cn" [(ngModel)]="idf.commonName" required maxlength="64" />
          </clr-input-container>
          <clr-input-container>
            <label i18n="@@certificates.organization">Organization</label>
            <input clrInput name="org" [(ngModel)]="idf.organization" maxlength="64" />
          </clr-input-container>
          <div class="clr-form-control clr-row">
            <label class="clr-control-label clr-col-12 clr-col-md-4" i18n="@@certificates.dnsNames">DNS names</label>
            <div class="clr-control-container clr-col-12 clr-col-md-8">
              <nfa-list-editor [(items)]="dnsList" placeholder="appliance.example.com" label="DNS name" i18n-label="@@certificates.dnsNameLabel" [validate]="dnsNameError" />
              <span class="clr-subtext" i18n="@@certificates.dnsHelp3">Pre-filled with the current certificate's names and those detected on this appliance (host name, FQDN, Tailscale MagicDNS name). Add any other name clients use, such as a DNS alias. Browsers check these, not the common name.</span>
            </div>
          </div>
          <div class="clr-form-control clr-row">
            <label class="clr-control-label clr-col-12 clr-col-md-4" i18n="@@certificates.ipAddresses">IP addresses</label>
            <div class="clr-control-container clr-col-12 clr-col-md-8">
              <nfa-list-editor [(items)]="ipList" placeholder="192.168.1.10" label="IP address" i18n-label="@@certificates.ipLabel" [validate]="ipError" />
              <span class="clr-subtext" i18n="@@certificates.ipHelp3">Pre-filled with this appliance's addresses, including Tailscale. Add any other address clients browse to, such as a NAT or VPN address.</span>
            </div>
          </div>
          <clr-select-container>
            <label i18n="@@certificates.key">Key</label>
            <select clrSelect name="kt" [(ngModel)]="idf.keyType">
              @for (k of keyTypes; track k.id) {
                <option [value]="k.id">{{ k.label }}</option>
              }
            </select>
          </clr-select-container>
          @if (idMode() === 'self') {
            <clr-input-container>
              <label i18n="@@certificates.validDays">Valid for (days)</label>
              <input clrInput type="number" name="days" [(ngModel)]="idf.days" min="1" max="825" />
              <clr-control-helper i18n="@@certificates.validDaysHelp">At most 825 days, the limit browsers accept.</clr-control-helper>
            </clr-input-container>
          }
        </form>
        @if (idMode() === 'self') {
          <p class="hint" i18n="@@certificates.selfHint">Browsers will warn about the new certificate until you accept it again, as with the current one.</p>
        } @else {
          <p class="hint" i18n="@@certificates.csrHint">The private key stays on the appliance. Submit the CSR to your CA, then upload the certificate it returns (no key needed).</p>
        }
        @if (modalError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ modalError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="idOpen.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="submit" form="idform" class="btn btn-primary" [clrLoading]="busy()">{{ idMode() === 'csr' ? txt.generateCsr : txt.regenerate }}</button>
      </div>
    </clr-modal>

    <!-- CSR result -->
    <clr-modal [clrModalOpen]="!!csr()" (clrModalOpenChange)="!$event && csr.set(null)" clrModalSize="lg">
      <h3 class="modal-title" i18n="@@certificates.csrResultTitle">Certificate signing request</h3>
      <div class="modal-body">
        @if (csr(); as r) {
          <p i18n="@@certificates.csrFor">For <b>{{ r.commonName }}</b> ({{ r.key }}){{ r.dnsNames.length || r.ipAddresses.length ? ' · ' + r.dnsNames.concat(r.ipAddresses).join(', ') : '' }}</p>
          <textarea class="clr-textarea pem" readonly rows="12">{{ r.pem }}</textarea>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="copyCSR()">{{ copied() ? txt.copied : txt.copy }}</button>
        <button type="button" class="btn btn-outline" (click)="downloadCSR()"><cds-icon shape="download"></cds-icon> <ng-container i18n="@@certificates.download">Download</ng-container></button>
        <button type="button" class="btn btn-primary" (click)="csr.set(null)" i18n="@@certificates.done">Done</button>
      </div>
    </clr-modal>

    <!-- Restore -->
    <clr-modal [clrModalOpen]="restoreOpen()" (clrModalOpenChange)="restoreOpen.set($event)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@certificates.restoreTitle">Restore the previous certificate?</h3>
      <div class="modal-body"><p i18n="@@certificates.restoreBody">The certificate active before the last change is reinstated; the current one becomes the "previous" one, so this can be undone.</p></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="restoreOpen.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-primary" [clrLoading]="busy()" (click)="restore()" i18n="@@certificates.restore">Restore</button>
      </div>
    </clr-modal>

    <!-- Trusted CAs -->
    <clr-modal [clrModalOpen]="addCAOpen()" (clrModalOpenChange)="addCAOpen.set($event)" clrModalSize="lg">
      <h3 class="modal-title" i18n="@@certificates.addCaTitle">Add trusted CA</h3>
      <div class="modal-body">
        <label class="field-label" i18n="@@certificates.nameOptional">Name (optional)</label>
        <input class="clr-input name-input" [(ngModel)]="caName" name="caName" placeholder="Defaults to the certificate's common name" i18n-placeholder="@@certificates.caNamePlaceholder" />
        <label class="field-label" i18n="@@certificates.caPem">CA certificate(s), PEM</label>
        <textarea class="clr-textarea pem" [(ngModel)]="caPem" name="caPem" rows="10" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
        <input type="file" accept=".pem,.crt,.cer,.txt" (change)="readFile($event, 'ca')" />
        <p class="hint" i18n="@@certificates.caHint">A bundle with several certificates (root and intermediates) adds each one. Only CA certificates are accepted.</p>
        @if (modalError()) {
          <div class="alert alert-danger alert-sm" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ modalError() }}</span></div></div></div>
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="addCAOpen.set(false)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-primary" [disabled]="!caPem.trim()" [clrLoading]="busy()" (click)="addCA()" i18n="@@common.add">Add</button>
      </div>
    </clr-modal>

    <clr-modal [clrModalOpen]="!!confirmCA()" (clrModalOpenChange)="!$event && confirmCA.set(undefined)" clrModalSize="md">
      <h3 class="modal-title" i18n="@@certificates.removeTitle">Remove {{ confirmCA()?.name }}?</h3>
      <div class="modal-body"><p i18n="@@certificates.removeBody">Connections to servers whose certificates chain only to this CA (for example an internal identity provider) will fail verification.</p></div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="confirmCA.set(undefined)" i18n="@@common.cancel">Cancel</button>
        <button type="button" class="btn btn-danger" (click)="deleteCA()" i18n="@@common.remove">Remove</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .clr-subtext { display: block; margin-top: 6px; }
    .cert-layout { display: grid; grid-template-columns: minmax(0, 2fr) minmax(300px, 1fr); gap: 16px; align-items: start; margin-top: 12px; }
    .cert-layout .card { margin: 0; }
    .card-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    .cert-title { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 500; }
    .days { font-size: 16px; white-space: nowrap; }
    .kv { margin: 0; }
    .kv td { text-align: left; padding: 6px 0; border: 0; vertical-align: top; }
    .kv td:first-child { width: 220px; color: var(--cds-alias-typography-color-300); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .small { font-size: 12px; word-break: break-all; }
    .replace section { padding: 12px 0; border-bottom: 1px solid var(--cds-alias-object-border-color); }
    .replace section:first-child { padding-top: 0; }
    .replace section:last-child { border-bottom: 0; padding-bottom: 0; }
    .replace h5 { margin: 0 0 4px; }
    .replace p { margin: 0 0 10px; font-size: 13px; }
    .replace .btn { margin: 0; }
    .restore { padding-left: 0; }
    .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 4px; }
    .ok { background: var(--cds-alias-status-success); }
    .warn { background: var(--cds-alias-status-warning); }
    .bad { background: var(--cds-alias-status-danger); }
    .pending { margin-top: 12px; }
    .hint { font-size: 13px; color: var(--cds-alias-typography-color-300); }
    .toolbar { margin: 8px 0; }
    .toolbar .btn { margin: 0 6px 0 0; }
    .sub { font-size: 11px; color: var(--cds-alias-typography-color-300); }
    .field-label { display: block; font-size: 13px; font-weight: 600; margin: 12px 0 4px; }
    .field-label:first-child { margin-top: 0; }
    .pem { width: 100%; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .name-input { width: 100%; }
    .center { display: flex; justify-content: center; padding: 60px; }
    @media (max-width: 1000px) { .cert-layout { grid-template-columns: 1fr; } }
  `,
})
export class Certificates {
  readonly byId = trackByKey<{ id: number }>((c) => c.id);
  private api = inject(Api);
  private tick = signal(0);
  readonly cert = loader(() => this.tick(), () => this.api.certificate());
  readonly cas = loader(() => this.tick(), () => this.api.trustedCAs());
  readonly keyTypes = KEY_TYPES;
  readonly notice = signal('');
  readonly pageError = signal('');
  readonly modalError = signal('');
  readonly busy = signal(false);
  readonly copied = signal(false);

  readonly uploadOpen = signal(false);
  readonly idOpen = signal(false);
  readonly idMode = signal<'csr' | 'self'>('csr');
  readonly csr = signal<CSRInfo | null>(null);
  readonly restoreOpen = signal(false);
  readonly addCAOpen = signal(false);
  readonly selectedCA = signal<TrustedCA | undefined>(undefined);
  readonly selectedCAList = computed(() => (this.selectedCA() ? [this.selectedCA()!] : []));
  readonly confirmCA = signal<TrustedCA | undefined>(undefined);

  upCert = '';
  upKey = '';
  caName = '';
  caPem = '';
  idf: IdForm = { commonName: '', organization: '', keyType: 'ecdsa-p256', days: 825 };
  dt = dateTime;
  readonly txt = {
    selfSigned: $localize`:@@certificates.selfSignedLabel:Self-signed`,
    none: $localize`:@@certificates.none:none`,
    root: $localize`:@@certificates.root:Root`,
    intermediate: $localize`:@@certificates.intermediate:Intermediate`,
    keyPlaceholderPending: $localize`:@@certificates.keyPlaceholderPending:Leave empty: this answers the pending CSR, whose key is on the appliance`,
    csrTitle: $localize`:@@certificates.csrTitle:Generate a certificate signing request`,
    selfTitle: $localize`:@@certificates.selfTitle:Regenerate self-signed certificate`,
    generateCsr: $localize`:@@certificates.generateCsr:Generate CSR`,
    regenerate: $localize`:@@certificates.regenerate:Regenerate`,
    copied: $localize`:@@certificates.copied:Copied`,
    copy: $localize`:@@certificates.copy:Copy`,
  };

  private refresh() {
    this.tick.update((t) => t + 1);
  }

  expiryClass(days: number) {
    return days < 7 ? 'bad' : days < 30 ? 'warn' : 'ok';
  }

  daysText(days: number) {
    if (days < 0) return $localize`:@@certificates.expiredDaysAgo:expired ${-days}:days: days ago`;
    return days === 1 ? $localize`:@@certificates.oneDayLeft:${days}:days: day left` : $localize`:@@certificates.daysLeft:${days}:days: days left`;
  }

  sans(c: CertDetails) {
    return [...c.dnsNames, ...c.ipAddresses].join(', ');
  }

  readFile(ev: Event, target: 'cert' | 'key' | 'ca') {
    const f = (ev.target as HTMLInputElement).files?.[0];
    if (!f) return;
    f.text().then((t) => {
      if (target === 'cert') this.upCert = t;
      else if (target === 'key') this.upKey = t;
      else this.caPem = t;
    });
  }

  openUpload() {
    this.upCert = this.upKey = '';
    this.modalError.set('');
    this.uploadOpen.set(true);
  }

  async upload() {
    this.busy.set(true);
    this.modalError.set('');
    try {
      const d = await this.api.uploadCertificate(this.upCert, this.upKey);
      this.uploadOpen.set(false);
      this.done($localize`:@@certificates.installed:Installed the certificate for ${d.commonName}:name:, valid until ${this.dt(d.notAfter)}:validUntil:. Reload the page to use it.`);
    } catch (e) {
      this.modalError.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  readonly dnsList = signal<string[]>([]);
  readonly ipList = signal<string[]>([]);
  readonly dnsNameError = (v: string) =>
    /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(v) && v.length <= 253
      ? null
      : $localize`:@@certificates.notDnsName:Not a DNS name (letters, digits, hyphens and dots; *. allowed at the start)`;
  readonly ipError = (v: string) => (validAddrOrPrefix(v) && !v.includes('/') ? null : $localize`:@@certificates.notIp:Not an IP address`);

  openId(mode: 'csr' | 'self') {
    const d = this.cert.value()?.defaults;
    const cur = this.cert.value()?.status.certificate;
    // Keep the current certificate's names and add what the appliance is
    // reachable as now (e.g. a Tailscale name or address added since).
    this.idf = {
      commonName: cur?.commonName || d?.commonName || '',
      organization: d?.organization || '',
      keyType: 'ecdsa-p256',
      days: 825,
    };
    this.dnsList.set(mergeNames(cur?.dnsNames, d?.dnsNames));
    this.ipList.set(mergeNames(cur?.ipAddresses, d?.ipAddresses).filter((ip) => !/^fe[89ab][0-9a-f]:/i.test(ip))); // link-local: unusable in URLs
    this.idMode.set(mode);
    this.modalError.set('');
    this.idOpen.set(true);
  }

  private identity(): CertIdentity {
    return { commonName: this.idf.commonName, organization: this.idf.organization, dnsNames: listValues(this.dnsList()), ipAddresses: listValues(this.ipList()) };
  }

  async submitId() {
    const bad = [...listValues(this.dnsList()).filter((v) => this.dnsNameError(v)), ...listValues(this.ipList()).filter((v) => this.ipError(v))];
    if (bad.length) {
      this.modalError.set($localize`:@@certificates.fixEntries:Fix the highlighted entries first: ${bad.join(', ')}:entries:`);
      return;
    }
    this.busy.set(true);
    this.modalError.set('');
    try {
      if (this.idMode() === 'csr') {
        const r = await this.api.generateCSR(this.identity(), this.idf.keyType);
        this.idOpen.set(false);
        this.csr.set(r);
        this.refresh();
      } else {
        const d = await this.api.selfSigned(this.identity(), this.idf.keyType, Number(this.idf.days) || 825);
        this.idOpen.set(false);
        this.done($localize`:@@certificates.installedSelfSigned:Installed a new self-signed certificate for ${d.commonName}:name:. Reload the page and accept it in your browser.`);
      }
    } catch (e) {
      this.modalError.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  showCSR(p: CSRInfo) {
    this.csr.set(p);
  }

  async discardCSR() {
    await this.api.discardCSR();
    this.done($localize`:@@certificates.csrDiscarded:Discarded the pending CSR and its key.`);
  }

  async copyCSR() {
    try {
      await navigator.clipboard.writeText(this.csr()?.pem ?? '');
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 2000);
    } catch {
      /* clipboard unavailable: the text is selectable */
    }
  }

  downloadCSR() {
    const r = this.csr();
    if (r) download(`${r.commonName || 'tributary'}.csr`, r.pem);
  }

  async restore() {
    this.busy.set(true);
    try {
      const d = await this.api.restoreCertificate();
      this.restoreOpen.set(false);
      this.done($localize`:@@certificates.restored:Restored the certificate for ${d.commonName}:name:. Reload the page to use it.`);
    } catch (e) {
      this.restoreOpen.set(false);
      this.pageError.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  openAddCA() {
    this.caName = this.caPem = '';
    this.modalError.set('');
    this.addCAOpen.set(true);
  }

  async addCA() {
    this.busy.set(true);
    this.modalError.set('');
    try {
      const r = await this.api.addTrustedCA(this.caName, this.caPem);
      this.addCAOpen.set(false);
      this.done(r.added.length ? $localize`:@@certificates.nowTrusting:Now trusting ${r.added.join(', ')}:names:.` : $localize`:@@certificates.alreadyTrusted:Those CAs were already trusted.`);
    } catch (e) {
      this.modalError.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }

  async deleteCA() {
    const ca = this.confirmCA();
    this.confirmCA.set(undefined);
    if (!ca) return;
    try {
      await this.api.deleteTrustedCA(ca.id);
      this.selectedCA.set(undefined);
      this.done($localize`:@@certificates.removed:Removed ${ca.name}:name:.`);
    } catch (e) {
      this.pageError.set(errorMessage(e));
    }
  }

  private done(msg: string) {
    this.pageError.set('');
    this.notice.set(msg);
    this.refresh();
  }
}

/** Union of name lists, first list's order first, ignoring case and blanks. */
function mergeNames(...lists: (string[] | undefined)[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const l of lists) {
    for (const n of l ?? []) {
      const k = n.trim().toLowerCase();
      if (k && !seen.has(k)) {
        seen.add(k);
        out.push(n.trim());
      }
    }
  }
  return out;
}
