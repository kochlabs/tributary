import { NgFor } from '@angular/common';
import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Api, errorMessage, TimeStatus } from '../core/api';
import { dateTime } from '../core/format';

const HOST_RE = /^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)$/;

@Component({
  selector: 'nfa-time',
  imports: [ClarityModule, FormsModule, NgFor],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.time">Time</h2>
        <p class="subtitle" i18n="@@timeSettings.subtitle">Clock, time zone and NTP servers</p>
      </div>
      <button class="btn btn-link" (click)="load()"><cds-icon shape="refresh"></cds-icon> <ng-container i18n="@@common.refresh">Refresh</ng-container></button>
    </div>

    @if (error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ error() }}</span></div></div></div>
    }
    @if (saved()) {
      <div class="alert alert-success" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text" i18n="@@timeSettings.applied">Time settings applied.</span></div></div></div>
    }
    @if (!installed()) {
      <div class="alert alert-warning" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text" i18n="@@timeSettings.readOnly">The admin helper isn't installed; settings are read-only. Re-run <code>deploy/install.sh</code>.</span></div></div></div>
    }

    @if (st(); as s) {
      <div class="card">
        <div class="card-block">
          <table class="table table-noborder kv">
            <tbody>
              <tr><td i18n="@@timeSettings.localTime">Local time</td><td>{{ local() }}</td></tr>
              <tr><td>UTC</td><td>{{ utc() }}</td></tr>
              <tr>
                <td i18n="@@timeSettings.sync">Synchronisation</td>
                <td>
                  @if (!s.ntpEnabled) {
                    <span class="dot off"></span> <ng-container i18n="@@timeSettings.disabled">Disabled</ng-container>
                  } @else if (s.synchronized) {
                    <span class="dot ok"></span> <ng-container i18n="@@timeSettings.synchronised">Synchronised</ng-container>
                  } @else {
                    <span class="dot warn"></span> <ng-container i18n="@@timeSettings.notSynchronised">Not synchronised yet</ng-container>
                  }
                </td>
              </tr>
              @if (s.ntpEnabled && s.serverName) {
                <tr><td i18n="@@timeSettings.server">Server</td><td>{{ s.serverName }}{{ s.serverAddress ? ' (' + s.serverAddress + ')' : '' }}@if (s.stratum) {<ng-container i18n="@@timeSettings.stratum"> · stratum {{ s.stratum }}</ng-container>}</td></tr>
              }
              @if (s.offset) {
                <tr><td i18n="@@timeSettings.offset">Offset</td><td>{{ s.offset }}@if (s.delay) {<ng-container i18n="@@timeSettings.delay"> · delay {{ s.delay }}</ng-container>}@if (s.jitter) {<ng-container i18n="@@timeSettings.jitter"> · jitter {{ s.jitter }}</ng-container>}</td></tr>
              }
              @if (s.lastSync) {
                <tr><td i18n="@@timeSettings.lastSync">Last sync</td><td>{{ dt(s.lastSync) }}@if (s.pollInterval) {<ng-container i18n="@@timeSettings.every"> · every {{ s.pollInterval }}</ng-container>}</td></tr>
              }
            </tbody>
          </table>
        </div>
      </div>

      <form clrForm clrLayout="horizontal" clrLabelSize="3" class="time-form">
        <clr-select-container>
          <label i18n="@@timeSettings.timeZone">Time zone</label>
          <select clrSelect name="tz" [ngModel]="tz()" (ngModelChange)="tz.set($event)" [disabled]="!installed()">
            @for (z of zones(); track z) {
              <option [value]="z">{{ z }}</option>
            }
          </select>
        </clr-select-container>
        <clr-toggle-container>
          <label>NTP</label>
          <clr-toggle-wrapper>
            <input type="checkbox" clrToggle name="ntp" [ngModel]="ntp()" (ngModelChange)="ntp.set($event)" [disabled]="!installed()" />
            <label i18n="@@timeSettings.syncWithNtp">Synchronise with NTP servers</label>
          </clr-toggle-wrapper>
        </clr-toggle-container>
      </form>

      <h3 class="section-title" i18n="@@timeSettings.ntpServers">NTP servers</h3>
      <form class="add-row" (ngSubmit)="add()">
        <input class="clr-input" name="newServer" [(ngModel)]="newServer" placeholder="pool.ntp.org or 192.0.2.123" i18n-placeholder="@@timeSettings.serverPlaceholder" aria-label="NTP server" i18n-aria-label="@@timeSettings.ntpServer" [disabled]="!installed()" />
        <button type="submit" class="btn btn-sm btn-outline" [disabled]="!canAdd()"><cds-icon shape="plus"></cds-icon> <ng-container i18n="@@common.add">Add</ng-container></button>
        @if (addError()) {
          <span class="error-text">{{ addError() }}</span>
        }
      </form>

      @if (servers().length) {
        <clr-datagrid class="datagrid-compact">
          <clr-dg-column class="order-col">#</clr-dg-column>
          <clr-dg-column i18n="@@timeSettings.col.server">Server</clr-dg-column>
          <clr-dg-row *ngFor="let srv of servers(); let i = index">
            <clr-dg-action-overflow>
              <button class="action-item" (click)="remove(i)"><cds-icon shape="trash"></cds-icon> <ng-container i18n="@@common.remove">Remove</ng-container></button>
            </clr-dg-action-overflow>
            <clr-dg-cell class="order-col">
              <span class="pos">{{ i + 1 }}</span>
              <button class="btn btn-icon btn-link btn-sm mv" (click)="move(i, -1)" [disabled]="i === 0" aria-label="Move up" i18n-aria-label="@@timeSettings.moveUp"><cds-icon shape="angle" direction="up"></cds-icon></button>
              <button class="btn btn-icon btn-link btn-sm mv" (click)="move(i, 1)" [disabled]="i === servers().length - 1" aria-label="Move down" i18n-aria-label="@@timeSettings.moveDown"><cds-icon shape="angle" direction="down"></cds-icon></button>
            </clr-dg-cell>
            <clr-dg-cell>
              {{ srv }}
              @if (s.ntpEnabled && srv === s.serverName) {
                <span class="label label-success" i18n="@@timeSettings.inUse">In use</span>
              }
            </clr-dg-cell>
          </clr-dg-row>
        </clr-datagrid>
      } @else {
        <p class="hint" i18n="@@timeSettings.noServers">No servers configured: using the distribution defaults ({{ s.defaultServers.join(', ') || noneLabel }}).</p>
      }

      <div class="actions">
        <button class="btn btn-primary" (click)="save()" [disabled]="!dirty() || !installed()" [clrLoading]="busy()" i18n="@@common.save">Save</button>
        <button class="btn btn-outline" (click)="reset()" [disabled]="!dirty()" i18n="@@timeSettings.reset">Reset</button>
      </div>
    } @else if (!error()) {
      <div class="center"><span class="spinner" i18n="@@timeSettings.loading">Loading…</span></div>
    }
  `,
  styles: `
    .card { margin-top: 0; }
    .kv { margin: 0; max-width: 900px; }
    .kv td { text-align: left; padding: 6px 0; border: 0; }
    .kv td:first-child { width: 260px; color: var(--cds-alias-typography-color-300); }
    .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin: 0 4px 0 2px; }
    .ok { background: var(--cds-alias-status-success); }
    .warn { background: var(--cds-alias-status-warning); }
    .off { background: var(--cds-alias-status-neutral); }
    .time-form { margin-top: 24px; max-width: 720px; }
    .section-title { margin-top: 24px; }
    .add-row { display: flex; align-items: center; gap: 10px; margin: 8px 0 12px; }
    .add-row .clr-input { width: 280px; }
    .add-row .btn { margin: 0; }
    .order-col { width: 150px; max-width: 150px; }
    .pos { display: inline-block; width: 20px; }
    .mv { margin: 0; padding: 0 4px; min-width: 0; height: auto; line-height: 1; }
    .label { margin-left: 8px; }
    .hint { font-size: 13px; color: var(--cds-alias-typography-color-300); }
    .error-text { color: var(--cds-alias-status-danger); font-size: 12px; }
    .actions { margin-top: 16px; }
    .center { display: flex; justify-content: center; padding: 60px; }
  `,
})
export class Time {
  private api = inject(Api);
  readonly st = signal<TimeStatus | null>(null);
  readonly installed = signal(true);
  readonly zones = signal<string[]>([]);
  readonly error = signal('');
  readonly saved = signal(false);
  readonly busy = signal(false);
  readonly addError = signal('');
  readonly tz = signal('');
  readonly ntp = signal(true);
  readonly servers = signal<string[]>([]);
  readonly now = signal(Date.now());
  newServer = '';
  private loadedAt = 0;
  private serverOffset = 0;
  dt = dateTime;
  readonly noneLabel = $localize`:@@timeSettings.none:none`;

  readonly dirty = computed(() => {
    const s = this.st();
    return !!s && (this.tz() !== s.timezone || this.ntp() !== s.ntpEnabled || JSON.stringify(this.servers()) !== JSON.stringify(s.servers));
  });
  readonly local = computed(() => this.fmt(this.st()?.timezone || 'UTC'));
  readonly utc = computed(() => this.fmt('UTC'));

  constructor() {
    this.load();
    this.api.timeZones().then((z) => this.zones.set(z)).catch(() => {});
    const id = setInterval(() => this.now.set(Date.now()), 1000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
  }

  fmt(tz: string) {
    const t = this.now() + this.serverOffset;
    try {
      return new Intl.DateTimeFormat(undefined, { timeZone: tz, weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZoneName: 'short' }).format(t);
    } catch {
      return new Date(t).toISOString();
    }
  }

  async load() {
    this.error.set('');
    try {
      const r = await this.api.time();
      this.installed.set(r.installed);
      this.st.set(r.status);
      // Show the appliance's clock, not the browser's.
      this.serverOffset = r.status.now - Date.now();
      this.loadedAt = Date.now();
      this.reset();
    } catch (e) {
      this.error.set(errorMessage(e));
    }
  }

  reset() {
    const s = this.st();
    if (!s) return;
    this.tz.set(s.timezone);
    this.ntp.set(s.ntpEnabled);
    this.servers.set([...s.servers]);
    this.addError.set('');
  }

  canAdd() {
    const v = this.newServer.trim();
    return this.installed() && !!v && this.servers().length < 10;
  }

  add() {
    const v = this.newServer.trim();
    if (!HOST_RE.test(v) && !IP_RE.test(v)) {
      this.addError.set($localize`:@@timeSettings.invalidServer:Enter a host name or IP address.`);
      return;
    }
    if (this.servers().includes(v)) {
      this.addError.set($localize`:@@timeSettings.duplicateServer:Already in the list.`);
      return;
    }
    this.servers.update((l) => [...l, v]);
    this.newServer = '';
    this.addError.set('');
  }

  remove(i: number) {
    this.servers.update((l) => l.filter((_, j) => j !== i));
  }

  move(i: number, d: number) {
    this.servers.update((l) => {
      const n = [...l];
      [n[i], n[i + d]] = [n[i + d], n[i]];
      return n;
    });
  }

  async save() {
    this.busy.set(true);
    this.error.set('');
    this.saved.set(false);
    try {
      await this.api.setTime({ timezone: this.tz(), ntp: this.ntp(), servers: this.servers() });
      this.saved.set(true);
      // Give timesyncd a moment to pick a server before re-reading.
      await new Promise((r) => setTimeout(r, 1500));
      await this.load();
    } catch (e) {
      this.error.set(errorMessage(e));
    } finally {
      this.busy.set(false);
    }
  }
}
