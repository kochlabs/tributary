import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { Meter } from '../shared/meter';
import { Api } from '../core/api';
import { ago, bits, bytes, count, dateTime, duration } from '../core/format';
import { loader } from '../core/util';

@Component({
  selector: 'nfa-system',
  imports: [ClarityModule, Meter],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.system">System Health</h2>
        <p class="subtitle" i18n="@@system.subtitle">Collector, storage and host status · refreshes every 5 seconds</p>
      </div>
    </div>
    @if (sys.error()) {
      <div class="alert alert-danger" role="alert"><div class="alert-items"><div class="alert-item static"><span class="alert-text">{{ sys.error() }}</span></div></div></div>
    }
    @if (s(); as s) {
      @if (alerts().length) {
        <div class="alert alert-warning" role="alert">
          <div class="alert-items">
            @for (a of alerts(); track a) {
              <div class="alert-item static"><span class="alert-text">{{ a }}</span></div>
            }
          </div>
        </div>
      }
      <div class="kpis">
        <div class="kpi card"><div class="kpi-label"><cds-icon shape="network-globe"></cds-icon> <ng-container i18n="@@system.kpi.flowsReceived">Flows received</ng-container></div><div class="kpi-value">{{ s.collector.flowsPerSec.toFixed(0) }}/s</div><div class="kpi-sub" i18n="@@system.kpi.sinceStart">{{ fmtCount(s.collector.flows) }} since start</div></div>
        <div class="kpi card"><div class="kpi-label"><cds-icon shape="download"></cds-icon> <ng-container i18n="@@system.kpi.datagrams">Datagrams</ng-container></div><div class="kpi-value">{{ s.collector.packetsPerSec.toFixed(0) }}/s</div><div class="kpi-sub" i18n="@@system.kpi.exportTraffic">{{ fmtBits(s.collector.bitsPerSec) }} export traffic</div></div>
        <div class="kpi card"><div class="kpi-label"><cds-icon shape="data-cluster"></cds-icon> <ng-container i18n="@@system.kpi.rowsStored">Rows stored</ng-container></div><div class="kpi-value">{{ fmtCount(s.writer.rowsWritten) }}</div><div class="kpi-sub" i18n="@@system.kpi.batches">{{ fmtCount(s.writer.batches) }} batches · last {{ ago(s.writer.lastFlush) }}</div></div>
        <div class="kpi card" [class.bad]="s.writer.dropped > 0"><div class="kpi-label"><cds-icon shape="exclamation-triangle"></cds-icon> <ng-container i18n="@@system.kpi.dropped">Dropped</ng-container></div><div class="kpi-value">{{ fmtCount(s.writer.dropped) }}</div><div class="kpi-sub" i18n="@@system.kpi.decodeErrors">{{ s.collector.errors }} decode errors</div></div>
        <div class="kpi card"><div class="kpi-label"><cds-icon shape="clock"></cds-icon> <ng-container i18n="@@system.kpi.serviceUptime">Service uptime</ng-container></div><div class="kpi-value">{{ dur((now() - s.started) / 1000) }}</div><div class="kpi-sub" i18n="@@system.kpi.version">version {{ s.version }}</div></div>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-header"><cds-icon shape="network-switch"></cds-icon> <ng-container i18n="@@system.collector">Collector</ng-container></div>
          <div class="card-block">
            <table class="table table-compact table-noborder kv">
              <tbody>
                <tr><td i18n="@@system.netflowListener">NetFlow v5/v9 listener</td><td>{{ port(s.collector.ports.NetFlow, 'netflow') }}</td></tr>
                <tr><td i18n="@@system.ipfixListener">IPFIX listener</td><td>{{ port(s.collector.ports.IPFIX, 'ipfix') }}</td></tr>
                <tr><td i18n="@@system.sflowListener">sFlow listener</td><td>{{ port(s.collector.ports.SFlow, 'sflow') }}</td></tr>
                <tr><td i18n="@@system.receiveWorkers">Receive workers</td><td>{{ s.collector.workers }} (SO_REUSEPORT)</td></tr>
                <tr><td i18n="@@system.datagramsReceived">Datagrams received</td><td>{{ fmtCount(s.collector.packets) }} ({{ fmtBytes(s.collector.bytes) }})</td></tr>
                <tr><td i18n="@@system.decodeErrors">Decode errors</td><td>{{ s.collector.errors }}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><cds-icon shape="storage"></cds-icon> <ng-container i18n="@@system.writerQueue">Writer queue</ng-container></div>
          <div class="card-block">
            <nfa-meter label="Queue" i18n-label="@@system.queue" [value]="queueValue(s.writer.queue, s.writer.queueCap)" [percent]="(s.writer.queue / s.writer.queueCap) * 100" [warnAt]="50" [badAt]="80" />
            <table class="table table-compact table-noborder kv">
              <tbody>
                <tr><td i18n="@@system.insertErrors">Insert errors</td><td>{{ s.writer.errors }}</td></tr>
                <tr><td i18n="@@system.lastError">Last error</td><td class="wrap">@if (s.writer.lastError) { {{ s.writer.lastError }} } @else {<ng-container i18n="No error@@system.none">none</ng-container>}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><cds-icon shape="host"></cds-icon> <ng-container i18n="@@system.host">Host · {{ s.host.hostname }}</ng-container></div>
          <div class="card-block">
            <nfa-meter label="Memory" i18n-label="@@system.memory" [value]="ofValue(fmtBytes(s.host.memTotal - s.host.memAvailable), fmtBytes(s.host.memTotal))" [percent]="memPct()" />
            <table class="table table-compact table-noborder kv">
              <tbody>
                <tr><td i18n="@@system.cpus">CPUs</td><td>{{ s.host.cpus }}</td></tr>
                <tr><td i18n="@@system.loadAverage">Load average</td><td>{{ s.host.load?.join(' / ') }}</td></tr>
                <tr><td i18n="@@system.hostUptime">Host uptime</td><td>{{ dur(s.host.uptime) }}</td></tr>
                <tr><td i18n="@@system.serviceHeap">Service heap</td><td i18n="@@system.heapGoroutines">{{ fmtBytes(s.process.heapAlloc) }} · {{ s.process.goroutines }} goroutines</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        @if (s.database; as db) {
          <div class="card">
            <div class="card-header"><cds-icon shape="hard-disk"></cds-icon> <ng-container i18n="@@system.storage">Storage · ClickHouse {{ db.version }}</ng-container></div>
            <div class="card-block">
              @for (d of db.disks; track d.name) {
                <nfa-meter [label]="diskLabel(d.path)" [value]="ofValue(fmtBytes(d.total - d.free), fmtBytes(d.total))" [percent]="((d.total - d.free) / d.total) * 100" [warnAt]="80" />
              }
              <table class="table table-compact table-noborder kv">
                <tbody>
                  <tr><td i18n="@@system.databaseUptime">Database uptime</td><td>{{ dur(db.uptime) }}</td></tr>
                <tr><td i18n="@@system.geoipCountry">GeoIP country</td><td>@if (s.geo?.country) { {{ s.geo?.country }} } @else {<ng-container i18n="@@system.notInstalled">not installed</ng-container>}</td></tr>
                <tr><td i18n="@@system.geoipAsn">GeoIP ASN</td><td>@if (s.geo?.asn) { {{ s.geo?.asn }} } @else {<ng-container i18n="@@system.notInstalled">not installed</ng-container>}</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        }
      </div>

      @if (s.database?.tables; as tables) {
        <h3 class="section-title" i18n="@@system.dataTables">Data tables</h3>
        <table class="table table-compact">
          <thead><tr><th class="left" i18n="@@system.col.table">Table</th><th i18n="@@system.col.rows">Rows</th><th i18n="@@system.col.onDisk">On disk</th><th i18n="@@system.col.uncompressed">Uncompressed</th><th i18n="@@system.col.ratio">Ratio</th><th i18n="@@system.col.parts">Parts</th><th i18n="@@system.col.oldest">Oldest</th><th i18n="@@system.col.newest">Newest</th></tr></thead>
          <tbody>
            @for (t of tables; track t.table) {
              <tr>
                <td class="left">{{ tableName(t.table) }}</td>
                <td>{{ fmtCount(t.rows) }}</td>
                <td>{{ fmtBytes(t.bytesOnDisk) }}</td>
                <td>{{ fmtBytes(t.uncompressed) }}</td>
                <td>{{ (t.uncompressed / (t.bytesOnDisk || 1)).toFixed(1) }}×</td>
                <td>{{ t.parts }}</td>
                <td>{{ dt(t.oldest) }}</td>
                <td>{{ dt(t.newest) }}</td>
              </tr>
            }
          </tbody>
        </table>
      }
    } @else if (!sys.error()) {
      <div class="center"><span class="spinner" i18n="@@system.loading">Loading…</span></div>
    }
  `,
  styles: `
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 12px; margin-top: 12px; }
    .grid .card { margin: 0; }
    .card-header cds-icon { margin-right: 6px; }
    .kv td { padding: 3px 0; text-align: left; }
    .kv td:first-child { color: var(--cds-alias-typography-color-300); width: 45%; }
    .wrap { white-space: normal; word-break: break-word; }
    .section-title { margin-top: 24px; }
    .left { text-align: left; }
    .kpi.bad .kpi-value { color: var(--cds-alias-status-danger); }
    .center { display: flex; justify-content: center; padding: 60px; }
  `,
})
export class System {
  private api = inject(Api);
  private tick = signal(0);
  readonly now = signal(Date.now());
  readonly sys = loader(() => this.tick(), () => this.api.system());
  readonly s = computed(() => this.sys.value());
  readonly memPct = computed(() => {
    const h = this.s()?.host;
    return h ? ((h.memTotal - h.memAvailable) / h.memTotal) * 100 : 0;
  });
  readonly alerts = computed(() => {
    const s = this.s();
    if (!s) return [];
    const out: string[] = [];
    for (const [k, v] of Object.entries(s.collector.listenErrors ?? {})) out.push($localize`:@@system.alertListener:The ${k}:listener: listener could not start: ${v}:error:`);
    if (s.databaseError) out.push($localize`:@@system.alertDatabase:Database unavailable: ${s.databaseError}:error:`);
    if (s.writer.dropped > 0) out.push($localize`:@@system.alertDropped:${count(s.writer.dropped)}:count: flows were dropped because the database could not keep up or was unavailable.`);
    for (const d of s.database?.disks ?? []) if ((d.total - d.free) / d.total > 0.9) out.push($localize`:@@system.alertDisk:Disk ${d.path}:path: is over 90% full — reduce retention in Settings.`);
    return out;
  });

  ago = ago;
  dt = dateTime;
  dur = duration;
  fmtBits = bits;
  fmtBytes = bytes;
  fmtCount = count;

  constructor() {
    const id = setInterval(() => {
      this.tick.update((t) => t + 1);
      this.now.set(Date.now());
    }, 5000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
  }

  port(p: number, name: string) {
    const err = this.s()?.collector.listenErrors?.[name];
    if (!p) return $localize`:Listener state@@system.portDisabled:disabled`;
    return err ? $localize`:@@system.portError:UDP ${p}:port: — error` : $localize`:@@system.portListening:UDP ${p}:port: — listening`;
  }

  ofValue(used: string, total: string) {
    return $localize`:Meter value, e.g. 3 GB of 8 GB@@system.ofValue:${used}:used: of ${total}:total:`;
  }

  queueValue(queue: number, cap: number) {
    return $localize`:@@system.queueValue:${queue}:queue: of ${cap}:cap: batches`;
  }

  diskLabel(path: string) {
    return $localize`:@@system.diskLabel:Disk ${path}:path:`;
  }

  tableName(t: string) {
    if (t === 'flows') return $localize`:@@system.tableRawFlows:Raw flows`;
    if (t === 'traffic_1m') return $localize`:@@system.tableRollup:1-minute rollup`;
    return t;
  }
}
