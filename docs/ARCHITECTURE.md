# Architecture

```mermaid
flowchart LR
    exp["routers, switches,<br/>firewalls"] -->|"UDP 2055 NetFlow<br/>4739 IPFIX<br/>6343 sFlow"| recv
    recv["receivers<br/>SO_REUSEPORT,<br/>one socket per CPU"] --> dec["decoders<br/>v5 · v9 · IPFIX · sFlow<br/>templates, sampling"]
    dec --> enr["enrichment<br/>GeoIP/ASN · device MAC<br/>threat feed match"]
    enr --> wr["batching writer<br/>non-blocking,<br/>drops counted"]
    wr --> ch[("ClickHouse<br/>raw flows +<br/>1-min rollup")]

    users(["browsers,<br/>MCP clients"]) --> api["HTTPS: REST API, MCP,<br/>Angular/Clarity UI<br/>sessions · RBAC · audit"]
    api --> ch
    api <--> db[("SQLite<br/>configuration")]
    bg["background jobs<br/>notices · reports · SNMP<br/>threat feeds · inventory<br/>notifications · backups"] --> ch
    bg <--> db
    bg --> out(["NetBox, feeds, SMTP,<br/>webhooks, Telegram,<br/>syslog, SFTP"])

    classDef nfad fill:#e8f1fb,stroke:#2f6db5,color:#1b1b1b
    class recv,dec,enr,wr,api,bg nfad
```

Blue boxes run inside `nfad`, a single Go binary.

Flows are written to `netflow.flows` (raw, partitioned by day) and rolled up
per minute into `netflow.traffic_1m` by a materialized view. Queries over more
than three hours that only need rollup columns (exporter, interfaces, protocol)
read the rollup. Configuration lives in SQLite under `/var/lib/nfa`; both
schemas are in [DATABASE.md](DATABASE.md).
See [INSTALL.md](INSTALL.md#how-clickhouse-is-set-up-for-tributary) for the
ClickHouse setup.

## Source layout

| Path | Contents |
|---|---|
| `cmd/nfad` | the daemon |
| `cmd/flowgen` | traffic simulator (live UDP export or ClickHouse backfill) |
| `internal/decode` | protocol decoders, with round-trip tests and fuzzing |
| `internal/collector` | UDP listeners, per-exporter stats |
| `internal/store` | ClickHouse schema, writer, query builder |
| `internal/enrich` | GeoIP/ASN and reverse DNS |
| `internal/api` | REST API, authentication, UI serving |
| `internal/config` | SQLite configuration store |
| `internal/backup`, `internal/offsite` | backup, restore and scheduled copies |
| `web/` | Angular + Clarity front end, embedded in the binary |
| `deploy/` | packaging, systemd units, install script, ClickHouse and sysctl settings |

## Performance

On a 2 vCPU / 4 GB VM: decoding runs at about 4.4M flows/s per core with no
allocations (`make bench`); ingest sustained 14k flows/s end to end without
drops, with the traffic generator on the same CPUs. Flows take about 17 bytes
each on disk (≈6× compression), so 20 GB holds roughly a billion.
