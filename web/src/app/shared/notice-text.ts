import { Component, computed, input } from '@angular/core';
import { Notice } from '../core/api';

/**
 * Renders an appliance notice in the UI language. The server sends a kind
 * and parameters along with an English message; unknown kinds (e.g. from a
 * newer server) fall back to that message.
 */
@Component({
  selector: 'nfa-notice-text',
  template: `
    @let p = params();
    @switch (notice().kind) {
      @case ('db-down') {
        <ng-container i18n="@@notice.dbDown">The flow database is unavailable: flows are not being stored and reports may fail.</ng-container>
      }
      @case ('disk-low') {
        <ng-container i18n="@@notice.diskLow">Disk space is low: {{ p['free'] }} free of {{ p['total'] }} ({{ p['percent'] }}%) on {{ p['path'] }}. Flow storage stops when the disk is full; shorten retention or add space.</ng-container>
      }
      @case ('listen-failed') {
        <ng-container i18n="@@notice.listenFailed">Not receiving {{ p['protocol'] }}: {{ p['error'] }}</ng-container>
      }
      @case ('drops') {
        <ng-container i18n="@@notice.drops">{num('count'), plural, =1 {1 flow record was dropped in the last minute because the database could not keep up.} other {{{ p['count'] }} flow records were dropped in the last minute because the database could not keep up.}}</ng-container>
      }
      @case ('exporters-silent') {
        <ng-container i18n="@@notice.exportersSilent">{num('count'), plural, =1 {{{ p['names'] }} has stopped sending flows.} other {{{ p['count'] }} exporters have stopped sending flows: {{ p['names'] }}.}}</ng-container>
      }
      @case ('exporters-rejected') {
        <ng-container i18n="@@notice.exportersRejected">Flows from sources not in the exporter allowlist are being dropped: {{ p['addrs'] }}.</ng-container>
      }
      @case ('updates') {
        @if (num('security') > 0) {
          <ng-container i18n="@@notice.updatesSecurity">{num('count'), plural, =1 {1 operating system update available, including {{ p['security'] }} security update.} other {{{ p['count'] }} operating system updates available, including {{ p['security'] }} security updates.}}</ng-container>
        } @else {
          <ng-container i18n="@@notice.updates">{num('count'), plural, =1 {1 operating system update available.} other {{{ p['count'] }} operating system updates available.}}</ng-container>
        }
      }
      @case ('reboot-required') {
        <ng-container i18n="@@notice.rebootRequired">A restart is required to finish installing updates.</ng-container>
      }
      @case ('cert-expired') {
        <ng-container i18n="@@notice.certExpired">The appliance's TLS certificate has expired; browsers will refuse to connect.</ng-container>
      }
      @case ('cert-expiring') {
        <ng-container i18n="@@notice.certExpiring">{num('days'), plural, =1 {The appliance's TLS certificate expires in 1 day.} other {The appliance's TLS certificate expires in {{ p['days'] }} days.}}</ng-container>
      }
      @case ('initial-password') {
        <ng-container i18n="@@notice.initialPassword">The admin account still uses its generated initial password. Change it, or create your own administrator and remove this one.</ng-container>
      }
      @case ('time-unsynced') {
        <ng-container i18n="@@notice.timeUnsynced">The clock is not synchronized with a time server; flow timestamps may drift.</ng-container>
      }
      @case ('datasource-failed') {
        @if (p['database'] === 'geoip') {
          <ng-container i18n="@@notice.geoipFailed">The GeoIP database could not be updated: {{ p['error'] }}</ng-container>
        } @else {
          <ng-container i18n="@@notice.vendorsFailed">The MAC vendor database could not be updated: {{ p['error'] }}</ng-container>
        }
      }
      @case ('backup-failed') {
        <ng-container i18n="@@notice.backupFailed">The last scheduled backup failed: {{ p['error'] }}</ng-container>
      }
      @case ('backup-overdue') {
        <ng-container i18n="@@notice.backupOverdue">No scheduled backup has succeeded recently. Check the backup schedule and its destination.</ng-container>
      }
      @default {
        {{ notice().message }}
      }
    }
  `,
})
export class NoticeText {
  readonly notice = input.required<Notice>();
  readonly params = computed(() => this.notice().params ?? {});

  num(key: string) {
    return Number(this.params()[key]) || 0;
  }
}

/** The label of a notice's action button, in the UI language. */
export function noticeActionLabel(n: Notice): string {
  switch (n.kind) {
    case 'db-down':
    case 'drops':
      return $localize`:@@notice.action.systemHealth:System health`;
    case 'disk-low':
      return $localize`:@@notice.action.retention:Retention settings`;
    case 'listen-failed':
      return $localize`:@@notice.action.ports:Collector ports`;
    case 'exporters-silent':
      return $localize`:@@nav.exporters:Exporters`;
    case 'exporters-rejected':
      return $localize`:@@notice.action.systemHealth:System health`;
    case 'updates':
      return $localize`:@@notice.action.viewUpdates:View updates`;
    case 'reboot-required':
      return $localize`:@@notice.action.restart:Restart`;
    case 'cert-expired':
    case 'cert-expiring':
      return $localize`:@@nav.certificates:Certificates`;
    case 'initial-password':
      return $localize`:@@nav.users:Users`;
    case 'time-unsynced':
      return $localize`:@@notice.action.time:Time settings`;
    case 'datasource-failed':
      return $localize`:@@nav.enrichment:Enrichment`;
    case 'backup-failed':
    case 'backup-overdue':
      return $localize`:@@nav.backup:Backup & Restore`;
  }
  return n.action?.label ?? '';
}
