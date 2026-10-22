import { HttpClient, HttpErrorResponse, HttpEvent, HttpInterceptorFn, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, firstValueFrom, Observable, throwError } from 'rxjs';

export type Filters = Record<string, string>;
export type Metric = 'bps' | 'pps' | 'fps';

/** Authenticator app setup: the secret, its otpauth URI and a QR code image. */
export interface MfaSetup {
  secret: string;
  uri: string;
  qr: string;
}

export interface User {
  username: string;
  role: 'admin' | 'viewer';
  fullName: string;
  createdAt: number;
  lastLogin: number;
  sourceId: number; // 0 = local account
  source?: string;
  mfa?: boolean;
}

export interface RoleMapping {
  group: string;
  role: 'admin' | 'viewer';
}

export interface OIDCConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string; // write-only
  scopes: string[];
  usernameClaim: string;
  groupsClaim: string;
}

export interface LDAPConfig {
  url: string;
  startTls: boolean;
  bindDn: string;
  bindPassword?: string; // write-only
  baseDn: string;
  userFilter: string;
  usernameAttr: string;
  nameAttr: string;
  groupAttr: string;
  nestedGroups: boolean;
}

export interface RADIUSConfig {
  servers: string[];
  secret?: string; // write-only
  nasIdentifier: string;
  timeoutSec: number;
  roleAttribute: 'Class' | 'Filter-Id';
}

export interface SAMLConfig {
  metadataUrl: string;
  metadataXml: string;
  metadataFetched?: number;
  entityId: string;
  usernameAttr: string;
  nameAttr: string;
  groupsAttr: string;
  signRequests: boolean;
}

/** The appliance's side of a SAML source, for the provider administrator. */
export interface SAMLInfo {
  entityId: string;
  acsUrl: string;
  metadataUrl: string;
  certExpires?: number;
}

export interface IdentitySource {
  id: number;
  type: 'oidc' | 'ldap' | 'radius' | 'saml';
  name: string;
  enabled: boolean;
  priority: number;
  oidc?: OIDCConfig;
  saml?: SAMLConfig;
  ldap?: LDAPConfig;
  radius?: RADIUSConfig;
  mappings: RoleMapping[];
  defaultRole: '' | 'viewer' | 'admin';
  hasSecret: boolean;
  users: number;
  createdAt: number;
}

export interface ProviderTest {
  ok: boolean;
  message: string;
  dn?: string;
  groups?: string[];
  role?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  scopes?: string[];
  claims?: string[];
  pkce?: string[];
  idpEntityId?: string;
  ssoUrl?: string;
  signingCerts?: { subject: string; notAfter: number }[];
  wantsSignedRequests?: boolean;
}

export interface LocalSuggestions {
  transitPct: number;
  suggestions: { prefix: string; hosts: number; peers: number; bytes: number }[];
}

export interface Summary {
  downloadBytes: number;
  uploadBytes: number;
  downloadBps: number;
  uploadBps: number;
  peakDownloadBps: number;
  peakUploadBps: number;
  localHosts: number;
  remoteHosts: number;
  bytes: number;
  packets: number;
  flows: number;
  exporters: number;
  srcHosts: number;
  dstHosts: number;
  avgBps: number;
  peakBps: number;
  avgPps: number;
}

export interface Series {
  key: string;
  label: string;
  values: number[];
  total: number;
}

export interface TimeSeries {
  step: number;
  metric: Metric;
  times: number[];
  series: Series[];
  source: string;
}

export interface TopRow {
  key: string;
  label: string;
  detail?: string;
  ends?: { addr: string; name: string; detail: string; local: boolean }[];
  bytes: number;
  packets: number;
  flows: number;
  rate: number;
  pct: number;
}

/** Traffic across 2–3 dimensions, for a Sankey diagram. */
export interface PathNode {
  column: number;
  key: string; // '__other__' collects values outside the column's top N
  label: string;
  detail?: string;
  bytes: number;
  packets: number;
  flows: number;
  rate: number;
}

export interface PathLink {
  source: number; // node indexes
  target: number;
  bytes: number;
  packets: number;
  flows: number;
  rate: number;
}

export interface PathResult {
  dimensions: string[];
  metric: Metric;
  nodes: PathNode[];
  links: PathLink[];
  source: string;
}

export interface TopResult {
  dimension: string;
  metric: Metric;
  rows: TopRow[];
  total: TopRow;
  source: string;
}

export interface FlowRow {
  timeReceived: number;
  timeStart: number;
  timeEnd: number;
  flowType: number;
  exporter: string;
  sampling: number;
  inIf: number;
  outIf: number;
  srcAddr: string;
  dstAddr: string;
  nextHop: string;
  srcPort: number;
  dstPort: number;
  proto: number;
  tcpFlags: number;
  tos: number;
  srcAs: number;
  dstAs: number;
  vlan: number;
  bytes: number;
  packets: number;
  exporterName?: string;
  srcMac?: string;
  dstMac?: string;
  deviceMac?: string;
  srcCountry: string;
  dstCountry: string;
  srcHost?: string;
  dstHost?: string;
  srcAsName?: string;
  dstAsName?: string;
}

export interface FlowPage {
  total: number;
  rows: FlowRow[];
}

export interface ExporterLive {
  addr: string;
  types: string[];
  packets: number;
  flows: number;
  errors: number;
  missingTemplates: number;
  lost: number;
  templates: number;
  sampling: number;
  samplingSource: 'announced' | 'remembered' | 'packet' | 'unsampled';
  firstSeen: number;
  lastSeen: number;
  flowsPerSec: number;
  bitsPerSec: number;
  lastError?: string;
}

export interface Exporter {
  addr: string;
  name: string;
  description: string;
  location: string;
  sampling: number;
  firstSeen: number;
  live: ExporterLive | null;
  bytes: number;
  flows: number;
  status: 'active' | 'idle' | 'stale';
  snmp?: { version: string; sysName: string; sysDescr: string; lastPoll: number; lastError?: string };
}

export interface Interface {
  exporter: string;
  index: number;
  name: string;
  description: string;
  speed: number;
  inBytes: number;
  outBytes: number;
  /** Name/description came from NetFlow options rather than an administrator. */
  learned: boolean;
  snmpName: string;
  snmpAlias: string;
  snmpSpeed: number;
}

/** An exporter's SNMP polling settings; secrets are write-only. */
export interface SnmpSettings {
  version: '' | '2c' | '3';
  host: string;
  port: number;
  community?: string;
  user: string;
  authProto: '' | 'MD5' | 'SHA' | 'SHA256' | 'SHA512';
  authPass?: string;
  privProto: '' | 'DES' | 'AES' | 'AES256';
  privPass?: string;
  hasCommunity?: boolean;
  hasAuthPass?: boolean;
  hasPrivPass?: boolean;
  status?: { sysName: string; sysDescr: string; lastPoll: number; lastError: string; interfaces: number };
}

export interface Settings {
  rawRetentionDays: number;
  rollupRetentionDays: number;
  netflowPort: number;
  ipfixPort: number;
  sflowPort: number;
  applianceName: string;
  sessionHours: number;
  reverseDns: boolean;
  onlineAsnLookup: boolean;
  localNetworks: string[];
  dnsServers: string[];
  exporterAllowlist: string[];
  requireMfaAdmins: boolean;
  mcpEnabled: boolean;
}

/** An API token for MCP clients (the secret is shown only when created). */
export interface APIToken {
  id: number;
  username: string;
  name: string;
  prefix: string;
  createdAt: number;
  expiresAt: number;
  lastUsed: number;
}

/** An appliance-wide condition shown as a banner above the header. */
export interface Notice {
  id: string;
  level: 'info' | 'warning' | 'danger';
  /** Lets the UI phrase the notice in its language; message is the English fallback. */
  kind: string;
  params?: Record<string, string>;
  message: string;
  action?: { label: string; route: string };
  dismissible: boolean;
}

export interface Attribution {
  text: string;
  url: string;
  license?: string;
}

export interface GeoStatus {
  geo: {
    source: string;
    country: string;
    countryType: string;
    countryBuilt: number;
    countryKept: boolean;
    asn: string;
    asnType: string;
    asnBuilt: number;
    asnKept: boolean;
    lastUpdate: string;
    attributions: Attribution[];
  };
  vendors: { source: string; location: string; entries: number; updated: number; lastUpdate: string };
  rdnsEnabled: boolean;
  rdnsCache: number;
  systemDnsServers: string[];
}

/** GeoIP and MAC vendor database sources. Secrets are write-only. */
export interface Enrichment {
  autoUpdate: boolean;
  geoSource: 'dbip-lite' | 'maxmind' | 'urls' | 'files';
  maxmindAccountId: string;
  maxmindLicenseKey?: string;
  maxmindCountryEdition: string;
  maxmindAsnEdition: string;
  geoCountryUrl?: string;
  geoAsnUrl?: string;
  geoCountryFile: string;
  geoAsnFile: string;
  ouiSource: 'ieee' | 'url' | 'file';
  ouiUrl: string;
  ouiFile: string;
  hasLicenseKey?: boolean;
  geoCountryHost?: string;
  geoAsnHost?: string;
}

/** Audit log forwarding to syslog. */
export interface SyslogTarget {
  address: string;
  transport: 'udp' | 'tcp' | 'tls';
}

export interface SyslogConfig {
  enabled: boolean;
  targets: SyslogTarget[];
  format: 'rfc5424' | 'rfc3164';
  facility: number;
}

export interface SyslogStatus {
  sent: number;
  dropped: number;
  lastError?: string;
  lastErrorAt?: number;
}

/** Backup and restore. */
export interface BackupTable {
  table: string;
  rows: number;
}

export interface BackupInfo {
  name: string;
  size: number;
  created: number;
  hostname: string;
  version: string;
  flows?: BackupTable[];
  scheduled?: boolean;
}

export interface BackupDestination {
  type: '' | 'smb' | 's3' | 'sftp';
  host: string;
  port: number;
  share: string;
  domain: string;
  username: string;
  path: string;
  password?: string; // write-only
  hasPassword?: boolean;
  endpoint: string;
  region: string;
  bucket: string;
  accessKey: string;
  secretKey?: string; // write-only
  hasSecretKey?: boolean;
  pathStyle: boolean;
  sftpAuth: 'key' | 'password';
  hostKey: string;
}

export interface BackupSchedule {
  enabled: boolean;
  frequency: 'daily' | 'weekly';
  weekday: number;
  time: string;
  includeFlows: boolean;
  encryption: 'passphrase' | 'publickey';
  passphrase?: string; // write-only
  hasPassphrase?: boolean;
  publicKeys: string;
  keepLocal: number;
  keepRemote: number;
  destination: BackupDestination;
  updated?: number;
}

export interface BackupRun {
  started: number;
  finished: number;
  ok: boolean;
  error?: string;
  name?: string;
  size?: number;
  copied: boolean;
  lastSuccess: number;
}

export interface BackupScheduleStatus {
  schedule: BackupSchedule;
  run: BackupRun;
  running?: boolean;
  phase?: string;
  next?: number;
  sshKey?: SSHKeyInfo;
  minPassphrase: number;
}

/** The appliance's SSH key for SFTP destinations (never the private key). */
export interface SSHKeyInfo {
  publicKey: string;
  fingerprint: string;
  type: string;
  created: number;
  source: 'generated' | 'uploaded';
}

export interface DestinationTest {
  ok: boolean;
  message: string;
  backups: number;
  hostKey?: string;
  fingerprint?: string;
  keyFile?: string;
}

export interface BackupJob {
  kind: 'backup' | 'restore';
  state: 'running' | 'done' | 'failed';
  phase: string;
  bytes: number;
  error?: string;
  started: number;
  finished?: number;
  name?: string;
}

export interface BackupManifest {
  format: number;
  version: string;
  created: number;
  hostname: string;
  files: string[];
  flows?: BackupTable[];
}

export interface BackupStatus {
  backups: BackupInfo[];
  job: BackupJob | null;
  freeBytes: number;
  flowsBytes: number;
  minPassphrase: number;
}

export interface UpdateStatus {
  installed: boolean;
  state: 'idle' | 'running' | 'done' | 'failed';
  action: string;
  startedAt: number | null;
  finishedAt: number | null;
  exitCode: number | null;
  lastCheck: number | null;
  lastInstall: number | null;
  lastInstallExit: number | null;
  upgradable: { name: string; suite: string; version: string; from: string; security: boolean }[];
  rebootRequired: boolean;
  os: string;
  kernel: string;
  pending?: string;
}

export interface TimeStatus {
  timezone: string;
  ntpEnabled: boolean;
  synchronized: boolean;
  now: number;
  servers: string[];
  defaultServers: string[];
  serverName: string;
  serverAddress: string;
  stratum: number;
  offset: string;
  delay: string;
  jitter: string;
  pollInterval: string;
  lastSync: number;
}

export interface ServiceUnit {
  unit: string;
  description: string;
  active: string;
  sub: string;
  onBoot: string;
  since: number;
  mainPid: number;
  memory: number;
  ops: string[];
}

export interface AdminResult {
  id: string;
  action: string;
  ok: boolean;
  message: string;
  at: number;
  pending: boolean;
}

export interface StorageRate {
  table: string;
  bytesPerRow: number;
  rowsPerDay: number;
  bytesNow: number;
  sampleHours: number;
}

export interface StorageEstimate {
  tables: StorageRate[];
  diskFree: number;
  diskTotal: number;
}

export interface CertDetails {
  commonName: string;
  subject: string;
  issuer: string;
  selfSigned: boolean;
  dnsNames: string[];
  ipAddresses: string[];
  notBefore: number;
  notAfter: number;
  daysLeft: number;
  key: string;
  chain: number;
  serial: string;
  sha256: string;
  isCa: boolean;
}

export interface CSRInfo {
  commonName: string;
  dnsNames: string[];
  ipAddresses: string[];
  key: string;
  created: number;
  pem: string;
}

export interface CertIdentity {
  commonName: string;
  organization: string;
  dnsNames: string[];
  ipAddresses: string[];
}

export interface CertStatus {
  status: { certificate: CertDetails; pendingCsr?: CSRInfo; hasPrevious: boolean };
  defaults: CertIdentity;
}

export interface TrustedCA extends CertDetails {
  id: number;
  name: string;
  createdAt: number;
}

export interface DeviceInfo {
  mac: string;
  name: string;
  customName: string;
  nameSource: 'name' | 'dns' | 'vendor' | 'mac';
  vendor: string;
  randomized: boolean;
  firstSeen: number;
  lastSeen: number;
  ipv4: string[];
  ipv6: string[];
  bytes: number;
  flows: number;
  ips: { ip: string; seen: number }[];
}

export interface AuditEntry {
  id: number;
  ts: number;
  username: string;
  action: string;
  detail: string;
}

export interface TimeQuery {
  from: number;
  to: number;
}

/** Adds the CSRF header and sends the user to the login page on 401. */
export const apiInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const r = req.clone({ setHeaders: { 'X-Requested-With': 'nfa' } });
  return next(r).pipe(
    catchError((err: HttpErrorResponse) => {
      if (err.status === 401 && !req.url.endsWith('/api/auth/login') && !req.url.endsWith('/api/auth/me')) {
        router.navigate(['/login'], { queryParams: { next: router.url } });
      }
      return throwError(() => err);
    }),
  );
};

export function errorMessage(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    if (err.error && typeof err.error === 'object' && 'error' in err.error) return String(err.error.error);
    if (err.status === 0) return $localize`:@@api.unreachable:Cannot reach the appliance.`;
    return `${err.status} ${err.statusText}`;
  }
  return String(err);
}

@Injectable({ providedIn: 'root' })
export class Api {
  private http = inject(HttpClient);

  private params(t: TimeQuery, filters: Filters = {}, extra: Record<string, string | number | boolean | undefined> = {}) {
    let p = new HttpParams().set('from', Math.round(t.from)).set('to', Math.round(t.to));
    for (const [k, v] of Object.entries(filters)) if (v) p = p.set(k, v);
    for (const [k, v] of Object.entries(extra)) if (v !== undefined && v !== '') p = p.set(k, String(v));
    return p;
  }

  private get<T>(url: string, params?: HttpParams) {
    return firstValueFrom(this.http.get<T>(url, { params }));
  }

  publicInfo() {
    return this.get<{ name: string; version: string; source: string; sso: { id: number; name: string }[]; languages?: string[]; language?: string }>('/api/public/info');
  }
  me() {
    return this.get<User>('/api/auth/me');
  }
  /** First sign-in step: the account, or a request for a second factor. */
  login(username: string, password: string) {
    return firstValueFrom(this.http.post<User & { mfaRequired?: boolean; mfaSetupRequired?: boolean; token?: string }>('/api/auth/login', { username, password }));
  }
  mfaVerify(token: string, code: string) {
    return firstValueFrom(this.http.post<{ user: User; recoveryUsed: boolean; recoveryLeft: number }>('/api/auth/mfa', { token, code }));
  }
  /** Setup required at sign-in: without a code returns the QR, with one finishes. */
  mfaEnroll(token: string, code = '') {
    return firstValueFrom(this.http.post<MfaSetup & { user?: User; recoveryCodes?: string[] }>('/api/auth/mfa/enroll', { token, code }));
  }
  mfaStatus() {
    return this.get<{ available: boolean; enabled: boolean; recoveryLeft: number; required: boolean }>('/api/auth/mfa/status');
  }
  mfaSetup() {
    return firstValueFrom(this.http.post<MfaSetup>('/api/auth/mfa/setup', {}));
  }
  mfaSetupConfirm(code: string) {
    return firstValueFrom(this.http.post<{ recoveryCodes: string[] }>('/api/auth/mfa/setup/confirm', { code }));
  }
  mfaDisable(code: string) {
    return firstValueFrom(this.http.post('/api/auth/mfa/disable', { code }));
  }
  resetUserMfa(username: string) {
    return firstValueFrom(this.http.post(`/api/users/${encodeURIComponent(username)}/mfa/reset`, {}));
  }
  logout() {
    return firstValueFrom(this.http.post('/api/auth/logout', {}));
  }
  changePassword(current: string, next: string) {
    return firstValueFrom(this.http.post('/api/auth/password', { current, new: next }));
  }

  summary(t: TimeQuery, f: Filters) {
    return this.get<Summary>('/api/summary', this.params(t, f));
  }
  timeseries(t: TimeQuery, f: Filters, metric: Metric, groupBy = '', limit = 8) {
    return this.get<TimeSeries>('/api/timeseries', this.params(t, f, { metric, groupBy, limit }));
  }
  top(t: TimeQuery, f: Filters, dimension: string, metric: Metric, limit = 10) {
    return this.get<TopResult>('/api/top', this.params(t, f, { dimension, metric, limit }));
  }
  paths(t: TimeQuery, f: Filters, dims: string[], metric: Metric, limit = 8) {
    return this.get<PathResult>('/api/paths', this.params(t, f, { dims: dims.join(','), metric, limit }));
  }
  flows(t: TimeQuery, f: Filters, opts: { sort?: string; desc?: boolean; limit?: number; offset?: number }) {
    return this.get<FlowPage>('/api/flows', this.params(t, f, opts));
  }
  flowsCsvUrl(t: TimeQuery, f: Filters, sort?: string, desc?: boolean) {
    return '/api/flows.csv?' + this.params(t, f, { sort, desc }).toString();
  }

  exporters(t: TimeQuery) {
    return this.get<Exporter[]>('/api/exporters', this.params(t));
  }
  updateExporter(e: Pick<Exporter, 'addr' | 'name' | 'description' | 'location' | 'sampling'>) {
    const { addr, name, description, location, sampling } = e;
    return firstValueFrom(this.http.put(`/api/exporters/${encodeURIComponent(addr)}`, { name, description, location, sampling }));
  }
  deleteExporter(addr: string) {
    return firstValueFrom(this.http.delete(`/api/exporters/${encodeURIComponent(addr)}`));
  }
  snmp(addr: string) {
    return this.get<SnmpSettings>(`/api/exporters/${encodeURIComponent(addr)}/snmp`);
  }
  saveSnmp(addr: string, s: SnmpSettings) {
    return firstValueFrom(this.http.put<SnmpSettings>(`/api/exporters/${encodeURIComponent(addr)}/snmp`, s));
  }
  pollSnmp(addr: string) {
    return firstValueFrom(this.http.post<SnmpSettings>(`/api/exporters/${encodeURIComponent(addr)}/snmp/poll`, {}));
  }
  interfaces(addr: string, t: TimeQuery) {
    return this.get<Interface[]>(`/api/exporters/${encodeURIComponent(addr)}/interfaces`, this.params(t));
  }
  updateInterface(i: Pick<Interface, 'exporter' | 'index' | 'name' | 'description' | 'speed'>) {
    return firstValueFrom(
      this.http.put(`/api/exporters/${encodeURIComponent(i.exporter)}/interfaces/${i.index}`, {
        name: i.name,
        description: i.description,
        speed: i.speed,
      }),
    );
  }

  system() {
    return this.get<any>('/api/system');
  }
  settings() {
    return this.get<Settings>('/api/settings');
  }
  saveSettings(s: Settings) {
    return firstValueFrom(this.http.put<Settings>('/api/settings', s));
  }
  /** Changes some settings, on top of the current ones, so pages that edit
   * different settings don't overwrite each other's changes. */
  async updateSettings(patch: Partial<Settings>) {
    return this.saveSettings({ ...(await this.settings()), ...patch });
  }

  users() {
    return this.get<User[]>('/api/users');
  }
  createUser(u: { username: string; password: string; role: string; fullName: string }) {
    return firstValueFrom(this.http.post('/api/users', u));
  }
  updateUser(name: string, u: { role?: string; fullName?: string; password?: string }) {
    return firstValueFrom(this.http.put(`/api/users/${encodeURIComponent(name)}`, u));
  }
  deleteUser(name: string) {
    return firstValueFrom(this.http.delete(`/api/users/${encodeURIComponent(name)}`));
  }
  localSuggestions() {
    return this.get<LocalSuggestions>('/api/local-suggestions');
  }
  geo() {
    return this.get<GeoStatus>('/api/geo');
  }
  updateGeo() {
    return firstValueFrom(this.http.post('/api/geo/update', {}));
  }
  syslog() {
    return this.get<{ config: SyslogConfig; status: SyslogStatus }>('/api/syslog');
  }
  saveSyslog(c: SyslogConfig) {
    return firstValueFrom(this.http.put<{ config: SyslogConfig; status: SyslogStatus }>('/api/syslog', c));
  }
  testSyslog(c: SyslogConfig) {
    return firstValueFrom(this.http.post<{ address: string; ok: boolean; error?: string }[]>('/api/syslog/test', c));
  }
  backups() {
    return this.get<BackupStatus>('/api/backups');
  }
  createBackup(passphrase: string, includeFlows: boolean) {
    return firstValueFrom(this.http.post<BackupJob>('/api/backups', { passphrase, includeFlows }));
  }
  backupSchedule() {
    return this.get<BackupScheduleStatus>('/api/backup-schedule');
  }
  saveBackupSchedule(s: BackupSchedule) {
    return firstValueFrom(this.http.put<BackupScheduleStatus>('/api/backup-schedule', s));
  }
  testBackupDestination(s: BackupSchedule) {
    return firstValueFrom(this.http.post<DestinationTest>('/api/backup-schedule/test', s));
  }
  apiTokens() {
    return this.get<{ tokens: APIToken[]; mcpEnabled: boolean; endpoint: string }>('/api/tokens');
  }
  createApiToken(username: string, name: string, days: number) {
    return firstValueFrom(this.http.post<{ token: string; info: APIToken }>('/api/tokens', { username, name, days }));
  }
  deleteApiToken(id: number) {
    return firstValueFrom(this.http.delete(`/api/tokens/${id}`));
  }
  regenerateBackupSSHKey() {
    return firstValueFrom(this.http.post<SSHKeyInfo>('/api/backup-schedule/ssh-key/regenerate', {}));
  }
  uploadBackupSSHKey(privateKey: string, passphrase: string) {
    return firstValueFrom(this.http.put<SSHKeyInfo>('/api/backup-schedule/ssh-key', { privateKey, passphrase }));
  }
  runBackupSchedule() {
    return firstValueFrom(this.http.post('/api/backup-schedule/run', {}));
  }
  deleteBackup(name: string) {
    return firstValueFrom(this.http.delete(`/api/backups/${encodeURIComponent(name)}`));
  }
  backupUrl(name: string) {
    return `/api/backups/${encodeURIComponent(name)}`;
  }
  /** Uploads a backup file for restore, reporting progress events. */
  uploadRestore(file: Blob): Observable<HttpEvent<{ size: number }>> {
    return this.http.post<{ size: number }>('/api/restore/upload', file, {
      headers: { 'Content-Type': 'application/octet-stream' },
      reportProgress: true,
      observe: 'events',
    });
  }
  inspectRestore(passphrase: string) {
    return firstValueFrom(this.http.post<BackupManifest>('/api/restore/inspect', { passphrase }));
  }
  applyRestore(passphrase: string, restoreFlows: boolean) {
    return firstValueFrom(this.http.post<BackupJob>('/api/restore', { passphrase, restoreFlows }));
  }
  notices() {
    return this.get<Notice[]>('/api/notices');
  }
  updateVendors() {
    return firstValueFrom(this.http.post('/api/oui/update', {}));
  }
  enrichment() {
    return this.get<Enrichment>('/api/enrichment');
  }
  saveEnrichment(e: Enrichment & { clearGeoAsnUrl?: boolean }) {
    return firstValueFrom(this.http.put<Enrichment>('/api/enrichment', e));
  }
  updates() {
    return this.get<UpdateStatus>('/api/updates');
  }
  updatesLog(offset: number) {
    return this.get<{ text: string; offset: number }>('/api/updates/log', new HttpParams().set('offset', offset));
  }
  requestUpdate(action: 'check' | 'upgrade' | 'reboot') {
    return firstValueFrom(this.http.post('/api/updates', { action }));
  }
  time() {
    return this.get<{ status: TimeStatus; installed: boolean }>('/api/time');
  }
  timeZones() {
    return this.get<string[]>('/api/time/zones');
  }
  setTime(t: { timezone: string; ntp: boolean; servers: string[] }) {
    return firstValueFrom(this.http.put<AdminResult>('/api/time', t));
  }
  services() {
    return this.get<{ services: ServiceUnit[]; installed: boolean }>('/api/services');
  }
  serviceAction(unit: string, op: string) {
    return firstValueFrom(this.http.post<AdminResult>(`/api/services/${encodeURIComponent(unit)}/${op}`, {}));
  }
  storageEstimate() {
    return this.get<StorageEstimate>('/api/storage-estimate');
  }
  identitySources() {
    return this.get<IdentitySource[]>('/api/identity-sources');
  }
  identitySource(id: number) {
    return this.get<{ source: IdentitySource; redirectUri: string; saml?: SAMLInfo }>(`/api/identity-sources/${id}`);
  }
  saveIdentitySource(s: Partial<IdentitySource>) {
    type Saved = { id: number; redirectUri: string; saml?: SAMLInfo };
    const req = s.id ? this.http.put<Saved>(`/api/identity-sources/${s.id}`, s) : this.http.post<Saved>('/api/identity-sources', s);
    return firstValueFrom(req);
  }
  deleteIdentitySource(id: number) {
    return firstValueFrom(this.http.delete(`/api/identity-sources/${id}`));
  }
  testIdentitySource(body: { type: string; id?: number; issuer?: string; saml?: SAMLConfig; ldap?: LDAPConfig; radius?: RADIUSConfig; username?: string; password?: string; mappings?: RoleMapping[]; defaultRole?: string }) {
    return firstValueFrom(this.http.post<ProviderTest>('/api/identity-sources/test', body));
  }
  certificate() {
    return this.get<CertStatus>('/api/certificates/appliance');
  }
  uploadCertificate(certificate: string, privateKey: string) {
    return firstValueFrom(this.http.post<CertDetails>('/api/certificates/appliance/upload', { certificate, privateKey }));
  }
  generateCSR(identity: CertIdentity, keyType: string) {
    return firstValueFrom(this.http.post<CSRInfo>('/api/certificates/appliance/csr', { identity, keyType }));
  }
  discardCSR() {
    return firstValueFrom(this.http.delete('/api/certificates/appliance/csr'));
  }
  selfSigned(identity: CertIdentity, keyType: string, days: number) {
    return firstValueFrom(this.http.post<CertDetails>('/api/certificates/appliance/self-signed', { identity, keyType, days }));
  }
  restoreCertificate() {
    return firstValueFrom(this.http.post<CertDetails>('/api/certificates/appliance/restore', {}));
  }
  trustedCAs() {
    return this.get<TrustedCA[]>('/api/certificates/trusted');
  }
  addTrustedCA(name: string, pem: string) {
    return firstValueFrom(this.http.post<{ added: string[] }>('/api/certificates/trusted', { name, pem }));
  }
  deleteTrustedCA(id: number) {
    return firstValueFrom(this.http.delete(`/api/certificates/trusted/${id}`));
  }
  devices(t: TimeQuery) {
    return this.get<DeviceInfo[]>('/api/devices', this.params(t));
  }
  renameDevice(mac: string, name: string) {
    return firstValueFrom(this.http.put(`/api/devices/${encodeURIComponent(mac)}`, { name }));
  }
  audit() {
    return this.get<AuditEntry[]>('/api/audit');
  }
}
