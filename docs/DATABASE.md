# Databases

Tributary keeps flows in ClickHouse and everything else in SQLite.

```mermaid
flowchart LR
    collector["collector<br/>decode + enrich"] -->|batches| flows[("ClickHouse<br/>netflow.flows")]
    flows -->|materialized view| rollup[("ClickHouse<br/>netflow.traffic_1m")]
    api["API, UI, MCP,<br/>reports"] --> flows
    api --> rollup
    api <--> config[("SQLite<br/>config.db")]
    collector <-->|exporters, devices,<br/>threat feeds| config
```

Both schemas are created and migrated by `nfad` at start
(`internal/store/store.go`, `internal/config/*.go`); there are no separate
migration files. Migrations only add: columns and tables are never dropped
in place.

## ClickHouse

Database `netflow`, user `netflow` (see
[INSTALL.md](INSTALL.md#how-clickhouse-is-set-up-for-tributary)). Times are
`DateTime('UTC')`; the UI converts to local time.

```mermaid
flowchart LR
    w[writer] -->|INSERT| flows
    subgraph netflow
      flows["flows<br/>MergeTree · day partitions<br/>TTL raw retention (7 days)"]
      mv{{"traffic_1m_mv2<br/>materialized view"}}
      rollup["traffic_1m<br/>SummingMergeTree · month partitions<br/>TTL rollup retention (365 days)"]
    end
    flows --> mv -->|"per minute, spread<br/>over each flow's duration"| rollup
```

Retention is set in **Configuration → Settings** and applied with `ALTER
TABLE … MODIFY TTL`.

### `flows`

One row per flow record. Ordered by `(time_received, exporter)`, with bloom
filter indexes on both addresses.

| Column | Type | |
|---|---|---|
| `time_received` | DateTime | when the collector received the record; the partition and sort key |
| `time_start`, `time_end` | DateTime | the flow's own timestamps, from the exporter |
| `flow_type` | UInt8 | 1 NetFlow v5, 2 v9, 3 IPFIX, 4 sFlow v5 |
| `exporter` | IPv6 | the exporter's address (IPv4 as `::ffff:a.b.c.d`) |
| `sampling_rate` | UInt32 | 1 when unsampled |
| `in_if`, `out_if` | UInt32 | SNMP interface indexes |
| `direction` | UInt8 | 0 ingress, 1 egress (v9/IPFIX field 61) |
| `src_addr`, `dst_addr`, `next_hop` | IPv6 | |
| `src_port`, `dst_port` | UInt16 | |
| `proto`, `tcp_flags`, `tos` | UInt8 | |
| `src_as`, `dst_as` | UInt32 | from the exporter, or the ASN database |
| `src_country`, `dst_country` | LowCardinality(String) | ISO 3166 alpha-2, from GeoIP |
| `src_mac`, `dst_mac` | UInt64 | as exported, 48-bit; 0 unknown |
| `device_mac` | UInt64 | the local device the flow belongs to (device tracker) |
| `src_threat`, `dst_threat` | LowCardinality(String) | ID of the threat feed listing the address; empty if none |
| `src_mask`, `dst_mask` | UInt8 | prefix lengths |
| `vlan`, `etype` | UInt16 | |
| `bytes`, `packets` | UInt64 | already multiplied by `sampling_rate` |

Names (exporters, interfaces, devices, threat feeds, inventory) are not
stored in flows: they are looked up when shown, so renaming applies to all
history.

### `traffic_1m`

Per-minute totals by `(ts, exporter, in_if, out_if, proto, etype)`:
`bytes`, `packets`, `flows`. Queries longer than three hours that only use
those dimensions read it instead of `flows`.

## SQLite

`/var/lib/nfa/config.db` in WAL mode, with foreign keys on. Times are Unix
milliseconds. Secrets (bot tokens, passwords for LDAP, SMTP, SNMP and backup
destinations, TOTP seeds, API keys) are encrypted with AES-GCM using
`/var/lib/nfa/secret.key`; passwords, session and API tokens are stored as
hashes. Both files are in backups.

Solid lines are foreign keys; dotted lines are references by value (IDs in
JSON lists, addresses).

### Access

```mermaid
erDiagram
    users ||--o{ sessions : has
    users ||--o{ api_tokens : has
    users ||--o{ saved_queries : owns
    identity_sources |o..o{ users : "signs in (source_id)"
    users ||..o{ audit : "username"

    users {
        text username PK
        text password "hash"
        text role "admin | viewer"
        text full_name
        int source_id "0 = local"
        text totp_secret "encrypted"
        int totp_enabled
        int totp_last
        text recovery "hashed codes, JSON"
        int created_at
        int last_login
    }
    sessions {
        text token_hash PK
        text username FK
        int expires_at
    }
    saved_queries {
        int id PK
        text name "unique per owner"
        text query "canonical form"
        text owner FK
        int shared
        int created_at
        int updated_at
    }
    api_tokens {
        int id PK
        text username FK
        text name
        text token_hash UK
        text prefix
        int created_at
        int expires_at "0 = never"
        int last_used
    }
    identity_sources {
        int id PK
        text type "oidc | saml | ldap | radius"
        text name
        int enabled
        int priority
        text config "JSON, secrets encrypted"
        text mappings "group to role, JSON"
        text default_role
        int created_at
    }
    audit {
        int id PK
        int ts
        text username
        text action
        text detail
    }
```

### Exporters and devices

```mermaid
erDiagram
    exporters ||..o{ interfaces : "addr"
    exporters ||..o| exporter_snmp : "addr"
    exporter_snmp ||..o{ interface_snmp : "addr"
    devices ||..o{ device_ips : "mac"

    exporters {
        text addr PK
        text name
        text description
        text location
        int sampling "override, 0 = as exported"
        int first_seen
    }
    interfaces {
        text exporter PK
        int idx PK
        text name
        text description
        int speed
        int learned "1 = from NetFlow options, SNMP may replace"
    }
    exporter_snmp {
        text addr PK
        text config "JSON, community or v3 secrets encrypted"
        text sys_name
        text sys_descr
        int last_poll
        text last_error
        int if_count
    }
    interface_snmp {
        text exporter PK
        int idx PK
        text name
        text alias
        int speed
    }
    devices {
        int mac PK "48-bit"
        text name
        int first_seen
        int last_seen
    }
    device_ips {
        text ip PK
        int mac
        int seen
    }
```

### Threat feeds, inventory, reports and notifications

```mermaid
erDiagram
    threat_feeds ||..o{ threat_alerts : "feed_id"
    inventory_sources ||--o| inventory_snapshots : caches
    reports ||--o{ report_runs : has
    notify_channels ||--o{ notify_deliveries : queues
    reports }o..o{ notify_channels : "channels (JSON)"
    threat_feeds }o..o{ notify_channels : "channels (JSON)"

    threat_feeds {
        int id PK "stored in flows"
        text name UK
        text url "or a file path"
        text format "text | csv | json"
        text field
        int column_no
        text delimiter
        int enabled
        int notify "raise notices"
        int interval_hours
        text channels "JSON IDs"
        int position "match order"
        int last_attempt
        int last_success
        text last_error
        int entries
        int created_at
    }
    threat_alerts {
        int feed_id PK
        text host PK
        int last_sent
    }
    inventory_sources {
        int id PK
        text name UK
        text type "netbox"
        int enabled
        int priority
        text url
        text token "encrypted"
        text scope_site
        text scope_tenant
        text scope_tag
        int interval_min
        text local_tag
        int last_attempt
        int last_success
        text last_error
        text counts "JSON"
        int created_at
    }
    inventory_snapshots {
        int source_id PK, FK
        text data "JSON snapshot"
        int synced_at
    }
    reports {
        int id PK
        text name UK
        text template "summary | security"
        text sections "JSON"
        text period
        text query "docs/QUERIES.md"
        text filters "older form, converted to query"
        text schedule "off | daily | weekly | monthly"
        int hour
        int weekday
        int monthday
        text recipients
        text channels "JSON IDs"
        int keep
        text created_by
        int created_at
        int updated_at
        int next_run
    }
    report_runs {
        int id PK
        int report_id FK
        int started_at
        int range_from
        int range_to
        text trigger "schedule | manual"
        text status
        text error
        text file "under /var/lib/nfa/reports"
        int size
        text emailed
    }
    notify_channels {
        int id PK
        text name UK
        text type "webhook | telegram"
        int enabled
        text url
        text secret "encrypted"
        text chat_id
        int last_success
        text last_error
        int failing_since
        int created_at
    }
    notify_deliveries {
        int id PK
        int channel_id FK
        text event_id
        text event_type
        text payload "JSON event"
        text attachment "file path"
        text status "pending | delivered | failed"
        int attempts
        int next_attempt
        text last_error
        int created_at
        int done_at
    }
```

### Other tables

| Table | |
|---|---|
| `trusted_cas` | CA certificates trusted for LDAP, SAML, NetBox, webhooks (`id`, `name`, `pem`, `sha256`, `created_at`) |
| `settings` | key → JSON value, below |

| `settings` key | |
|---|---|
| `settings` | general settings: retention, ports, appliance name and address, local networks, DNS, exporter allowlist |
| `email` | SMTP server (password encrypted) |
| `syslog` | syslog forwarding |
| `enrichment` | GeoIP / ASN sources (license key encrypted) |
| `backup_schedule`, `backup_run` | scheduled backups and the last run |
| `backup_ssh_key` | the appliance's SSH key for SFTP destinations (encrypted) |
| `ai` | the AI assistant: provider, URL, model, names switch (API key encrypted) |
| `notice_routing` | notice level and channels |
| `notices_sent` | notices sent to channels, until they clear |
| `threat_feeds_seeded` | the default feeds were added once |
| `sampling:<exporter>` | the sampling rate an exporter announced (`/system` when it applies to all its flows) |
