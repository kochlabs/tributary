import { Component, computed, inject } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, TopRow } from '../core/api';
import { Auth } from '../core/auth';
import { ago, bytes, count, drillFilter } from '../core/format';
import { TimeRange } from '../core/time';
import { loader } from '../core/util';
import { ConversationTable } from '../shared/conversation-table';
import { RangeBar } from '../shared/range-bar';
import { TopTable } from '../shared/top-table';

const MATCHED = { threat: '*' };

const PANELS = [
  { dim: 'threat_host', title: $localize`:@@detections.panel.hosts:Listed Hosts`, col: $localize`:@@detections.panel.hostsCol:Remote host`, hint: $localize`:@@detections.panel.hostsHint:Addresses on a threat feed` },
  { dim: 'device', title: $localize`:@@detections.panel.devices:Local Devices`, col: $localize`:@@dashboard.panel.devicesCol:Device`, hint: $localize`:@@detections.panel.devicesHint:Talking to listed hosts` },
  { dim: 'threat', title: $localize`:@@detections.panel.feeds:By Feed`, col: $localize`:@@detections.panel.feedsCol:Feed`, hint: $localize`:@@detections.panel.feedsHint:First feed listing the host` },
  { dim: 'app', title: $localize`:@@dashboard.panel.apps:Applications`, col: $localize`:@@dashboard.panel.appsCol:Protocol / port`, hint: $localize`:@@dashboard.panel.appsHint:Well-known port of the flow` },
  { dim: 'conversation', title: $localize`:@@dashboard.panel.conversations:Top Conversations`, col: '', hint: $localize`:@@dashboard.panel.conversationsHint:Who talks to whom, your device first`, wide: true },
];

/** Traffic to and from addresses on threat feeds (Security → Detections). */
@Component({
  selector: 'nfa-detections',
  imports: [ClarityModule, RouterLink, RangeBar, TopTable, ConversationTable],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.detections">Detections</h2>
        <p class="subtitle" i18n="@@detections.subtitle">Traffic with addresses on threat feeds · {{ time.label() }}</p>
      </div>
      <div class="header-controls"><nfa-range-bar /></div>
    </div>

    @if (status.value(); as st) {
      @if (!st.feeds.length || !st.ranges) {
        <div class="alert alert-info" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">
          @if (!st.feeds.length) {
            <ng-container i18n="@@detections.noFeeds">No threat feeds are enabled, so nothing is matched.</ng-container>
          } @else {
            <ng-container i18n="@@detections.notLoaded">The threat feeds haven't been downloaded yet.</ng-container>
          }
          @if (auth.isAdmin()) {
            <a routerLink="/security/threat-feeds" i18n="@@detections.manageFeeds">Manage threat feeds</a>
          }
        </span></div></div></div>
      }
    }
    @if (summary.error() || status.error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ summary.error() || status.error() }}</span></div></div></div>
    }

    <div class="kpis">
      @for (k of kpis(); track k.label) {
        <div class="kpi card">
          <div class="kpi-label"><cds-icon [shape]="k.icon"></cds-icon> {{ k.label }}</div>
          <div class="kpi-value">{{ k.value }}</div>
          <div class="kpi-sub">{{ k.sub }}</div>
        </div>
      }
    </div>

    <div class="panels">
      @for (p of panels; track p.dim; let i = $index) {
        <div class="card panel" [class.wide]="p.wide">
          <div class="card-header">
            <span>{{ p.title }} <span class="card-hint">{{ p.hint }}</span></span>
            <a class="card-link" [routerLink]="['/explorer']" [queryParams]="{ threat: '*', groupBy: p.dim }"><ng-container i18n="@@dashboard.explore">Explore</ng-container> <cds-icon shape="angle" direction="right"></cds-icon></a>
          </div>
          <div class="card-block">
            @let res = tops[i].value();
            @if (tops[i].error()) {
              <div class="error-text">{{ tops[i].error() }}</div>
            } @else if (!res) {
              <div class="center"><span class="spinner spinner-md" i18n="@@dashboard.loading">Loading…</span></div>
            } @else if (p.dim === 'conversation') {
              <nfa-conversation-table [rows]="res.rows" [metric]="'bps'" (drill)="drill(p.dim, $event)" />
            } @else {
              <nfa-top-table [rows]="res.rows" [metric]="'bps'" [title]="p.col" (drill)="drill(p.dim, $event)" />
            }
          </div>
        </div>
      }
    </div>

    @if (status.value(); as st) {
      @if (st.feeds.length) {
        <div class="card">
          <div class="card-header">
            <span><ng-container i18n="@@detections.feeds">Enabled feeds</ng-container> <span class="card-hint" i18n="@@detections.feedsHint">{{ count(st.ranges) }} address ranges matched</span></span>
            @if (auth.isAdmin()) {
              <a class="card-link" routerLink="/security/threat-feeds"><ng-container i18n="@@detections.manage">Manage</ng-container> <cds-icon shape="angle" direction="right"></cds-icon></a>
            }
          </div>
          <div class="card-block">
            <table class="table table-compact table-noborder feeds">
              <thead>
                <tr>
                  <th class="left" i18n="@@detections.col.feed">Feed</th>
                  <th class="num" i18n="@@detections.col.entries">Entries</th>
                  <th class="left" i18n="@@detections.col.updated">Updated</th>
                  <th class="num" i18n="@@detections.col.hosts24">Hosts seen (24 h)</th>
                  <th class="num" i18n="@@detections.col.flows24">Flows (24 h)</th>
                </tr>
              </thead>
              <tbody>
                @for (f of st.feeds; track f.name) {
                  @let h = hit(f.name);
                  <tr>
                    <td class="left">{{ f.name }}@if (!f.notify) { <span class="label" i18n="@@detections.noNotices">no notices</span>}</td>
                    <td class="num">{{ f.entries ? count(f.entries) : '–' }}</td>
                    <td class="left">
                      @if (f.lastSuccess) {{{ ago(f.lastSuccess) }}} @else {<span class="muted" i18n="@@detections.pending">pending</span>}
                      @if (f.lastError) { <cds-icon shape="exclamation-triangle" status="warning" [title]="f.lastError"></cds-icon>}
                    </td>
                    <td class="num">@if (h) {<a href="#" (click)="$event.preventDefault(); toFlows({ threat: f.name })">{{ count(h.hosts) }}</a>} @else {0}</td>
                    <td class="num">{{ h ? count(h.flows) : 0 }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </div>
      }
    }
  `,
  styles: `
    .header-controls { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .alert { margin: 0 0 12px; }
    .alert a { margin-left: 6px; }
    .card-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
    .card-hint { font-size: 11px; font-weight: 400; color: var(--cds-alias-typography-color-300); margin-left: 6px; }
    .card-link { font-size: 12px; font-weight: 400; }
    .panels { display: grid; grid-template-columns: repeat(auto-fill, minmax(460px, 1fr)); gap: 12px; margin: 12px 0; }
    .panels .card { margin: 0; }
    .panel.wide { grid-column: 1 / -1; }
    .panel .card-block { padding-top: 6px; }
    .center { display: flex; justify-content: center; padding: 40px; }
    .error-text { color: var(--cds-alias-status-danger); padding: 4px 0; }
    .feeds { margin: 0; width: 100%; }
    .left { text-align: left; }
    .num { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
    .label { margin-left: 6px; }
    .muted { color: var(--cds-alias-typography-color-300); }
    @media (max-width: 560px) { .panels { grid-template-columns: 1fr; } }
  `,
})
export class Detections {
  readonly time = inject(TimeRange);
  readonly auth = inject(Auth);
  private api = inject(Api);
  private router = inject(Router);
  readonly panels = PANELS;
  count = count;
  ago = ago;

  readonly status = loader(() => this.time.tick(), () => this.api.threatStatus());
  readonly summary = loader(() => this.time.window(), (w) => this.api.summary(w, MATCHED));
  readonly tops = PANELS.map((p) => loader(() => this.time.window(), (w) => this.api.top(w, MATCHED, p.dim, 'bps', p.wide ? 12 : 8)));

  readonly kpis = computed(() => {
    const s = this.summary.value();
    const dash = '–';
    return [
      { icon: 'shield', label: $localize`:@@detections.kpi.listed:Listed hosts`, value: s ? count(s.remoteHosts) : dash, sub: $localize`:@@detections.kpi.listedSub:seen in range` },
      { icon: 'host', label: $localize`:@@detections.kpi.local:Local addresses`, value: s ? count(s.localHosts) : dash, sub: $localize`:@@detections.kpi.localSub:talking to them` },
      { icon: 'list', label: $localize`:@@dashboard.kpi.flows:Flows`, value: s ? count(s.flows) : dash, sub: '' },
      { icon: 'storage', label: $localize`:@@dashboard.kpi.volume:Total volume`, value: s ? bytes(s.bytes) : dash, sub: '' },
    ];
  });

  hit(feed: string) {
    return this.status.value()?.hits.find((h) => h.feed === feed);
  }

  drill(dim: string, row: TopRow) {
    const f = drillFilter(dim, row.key, row.label);
    if (f) this.toFlows(f);
  }

  toFlows(f: Record<string, string>) {
    this.router.navigate(['/flows'], { queryParams: { threat: '*', ...f } });
  }
}
