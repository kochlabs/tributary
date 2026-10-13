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
        <h2>System Health</h2>
        <p class="subtitle">Collector, storage and host status · refreshes every 5 seconds</p>
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
        <div class="kpi card"><div class="kpi-label"><cds-icon shape="network-globe"></cds-icon> Flows received</div><div class="kpi-value">{{ s.collector.flowsPerSec.toFixed(0) }}/s</div><div class="kpi-sub">{{ fmtCount(s.collector.flows) }} since start</div></div>
        <div class="kpi card"><div class="kpi-label"><cds-icon shape="download"></cds-icon> Datagrams</div><div class="kpi-value">{{ s.collector.packetsPerSec.toFixed(0) }}/s</div><div class="kpi-sub">{{ fmtBits(s.collector.bitsPerSec) }} export traffic</div></div>
        <div class="kpi card"><div class="kpi-label"><cds-icon shape="data-cluster"></cds-icon> Rows stored</div><div class="kpi-value">{{ fmtCount(s.writer.rowsWritten) }}</div><div class="kpi-sub">{{ fmtCount(s.writer.batches) }} batches · last {{ ago(s.writer.lastFlush) }}</div></div>
        <div class="kpi card" [class.bad]="s.writer.dropped > 0"><div class="kpi-label"><cds-icon shape="exclamation-triangle"></cds-icon> Dropped</div><div class="kpi-value">{{ fmtCount(s.writer.dropped) }}</div><div class="kpi-sub">{{ s.collector.errors }} decode errors</div></div>
        <div class="kpi card"><div class="kpi-label"><cds-icon shape="clock"></cds-icon> Service uptime</div><div class="kpi-value">{{ dur((now() - s.started) / 1000) }}</div><div class="kpi-sub">version {{ s.version }}</div></div>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-header"><cds-icon shape="network-switch"></cds-icon> Collector</div>
          <div class="card-block">
            <table class="table table-compact table-noborder kv">
              <tbody>
                <tr><td>NetFlow v5/v9 listener</td><td>{{ port(s.collector.ports.NetFlow, 'netflow') }}</td></tr>
                <tr><td>IPFIX listener</td><td>{{ port(s.collector.ports.IPFIX, 'ipfix') }}</td></tr>
                <tr><td>sFlow listener</td><td>{{ port(s.collector.ports.SFlow, 'sflow') }}</td></tr>
                <tr><td>Receive workers</td><td>{{ s.collector.workers }} (SO_REUSEPORT)</td></tr>
                <tr><td>Datagrams received</td><td>{{ fmtCount(s.collector.packets) }} ({{ fmtBytes(s.collector.bytes) }})</td></tr>
                <tr><td>Decode errors</td><td>{{ s.collector.errors }}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><cds-icon shape="storage"></cds-icon> Writer queue</div>
          <div class="card-block">
            <nfa-meter label="Queue" [value]="s.writer.queue + ' of ' + s.writer.queueCap + ' batches'" [percent]="(s.writer.queue / s.writer.queueCap) * 100" [warnAt]="50" [badAt]="80" />
            <table class="table table-compact table-noborder kv">
              <tbody>
                <tr><td>Insert errors</td><td>{{ s.writer.errors }}</td></tr>
                <tr><td>Last error</td><td class="wrap">{{ s.writer.lastError || 'none' }}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><cds-icon shape="host"></cds-icon> Host · {{ s.host.hostname }}</div>
          <div class="card-block">
            <nfa-meter label="Memory" [value]="fmtBytes(s.host.memTotal - s.host.memAvailable) + ' of ' + fmtBytes(s.host.memTotal)" [percent]="memPct()" />
            <table class="table table-compact table-noborder kv">
              <tbody>
                <tr><td>CPUs</td><td>{{ s.host.cpus }}</td></tr>
                <tr><td>Load average</td><td>{{ s.host.load?.join(' / ') }}</td></tr>
                <tr><td>Host uptime</td><td>{{ dur(s.host.uptime) }}</td></tr>
                <tr><td>Service heap</td><td>{{ fmtBytes(s.process.heapAlloc) }} · {{ s.process.goroutines }} goroutines</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        @if (s.database; as db) {
          <div class="card">
            <div class="card-header"><cds-icon shape="hard-disk"></cds-icon> Storage · ClickHouse {{ db.version }}</div>
            <div class="card-block">
              @for (d of db.disks; track d.name) {
                <nfa-meter [label]="'Disk ' + d.path" [value]="fmtBytes(d.total - d.free) + ' of ' + fmtBytes(d.total)" [percent]="((d.total - d.free) / d.total) * 100" [warnAt]="80" />
              }
              <table class="table table-compact table-noborder kv">
                <tbody>
                  <tr><td>Database uptime</td><td>{{ dur(db.uptime) }}</td></tr>
                <tr><td>GeoIP country</td><td>{{ s.geo?.country || 'not installed' }}</td></tr>
                <tr><td>GeoIP ASN</td><td>{{ s.geo?.asn || 'not installed' }}</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        }
      </div>

      @if (s.database?.tables; as tables) {
        <h3 class="section-title">Data tables</h3>
        <table class="table table-compact">
          <thead><tr><th class="left">Table</th><th>Rows</th><th>On disk</th><th>Uncompressed</th><th>Ratio</th><th>Parts</th><th>Oldest</th><th>Newest</th></tr></thead>
          <tbody>
            @for (t of tables; track t.table) {
              <tr>
                <td class="left">{{ t.table === 'flows' ? 'Raw flows' : t.table === 'traffic_1m' ? '1-minute rollup' : t.table }}</td>
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
      <div class="center"><span class="spinner">Loading…</span></div>
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
    for (const [k, v] of Object.entries(s.collector.listenErrors ?? {})) out.push(`The ${k} listener could not start: ${v}`);
    if (s.databaseError) out.push(`Database unavailable: ${s.databaseError}`);
    if (s.writer.dropped > 0) out.push(`${count(s.writer.dropped)} flows were dropped because the database could not keep up or was unavailable.`);
    for (const d of s.database?.disks ?? []) if ((d.total - d.free) / d.total > 0.9) out.push(`Disk ${d.path} is over 90% full — reduce retention in Settings.`);
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
    if (!p) return 'disabled';
    return err ? `UDP ${p} — error` : `UDP ${p} — listening`;
  }
}
