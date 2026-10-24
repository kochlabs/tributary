# Features

## Collection

- NetFlow v5 and v9 (including options templates), IPFIX (variable-length
  fields, NSEL byte counters; unknown enterprise elements are skipped), sFlow v5
  (raw header parsing with 802.1Q, extended switch, router and gateway records).
- Sampling rates learned from v5 headers, v9/IPFIX options data (fields 34, 50,
  305, 306) and sFlow; per-exporter override. Volumes are sampling-corrected.
- Sequence tracking per exporter and observation domain to detect loss.
- Exporter allowlist by address or prefix; rejected senders are counted.

## Enrichment

- Local networks (Configuration → Local Networks): your public prefixes, in
  addition to private ranges. They decide download and upload, devices, and
  local and remote hosts; suggestions come from recent traffic.
- Country and ASN (with organization names) at ingest. Sources, chosen under
  Configuration → Enrichment: DB-IP Lite (default), MaxMind GeoLite2 or
  GeoIP2, custom URLs, or files kept up to date by `geoipupdate`.
- MAC vendors from the IEEE registry (default, refreshed weekly), a URL or a file.
- Reverse DNS at query time, cached.
- Inventory sources (NetBox 4.2+), read-only: device and VM names, roles,
  sites and documented services, matched by MAC or IP and applied to past
  traffic too; prefixes with a chosen tag can extend Local Networks
  ([design](design/INVENTORY.md)).
- SNMP v2c/v3 polling of IF-MIB every 15 minutes for interface names,
  descriptions and speeds. Values set by hand take precedence.

## Analysis

- Dashboard: traffic over time, top conversations, devices, services,
  applications, remote hosts and countries.
- Traffic Explorer: any dimension by any filter, stacked series with "Other",
  drag to zoom, shareable URLs.
- Paths: Sankey diagram across two or three dimensions.
- Flow Search: individual records, server-side paging and sorting, CSV export.
- Exporter and interface pages with utilization.
- Devices: local hosts identified by MAC address and vendor.
- Queries: `AND`/`OR`/`NOT`, grouping, ranges, comparisons and names over
  addresses and prefixes (v4 and v6), ports, protocols, AS, country,
  interfaces, VLAN, DSCP, threat feeds, devices and per-flow sizes, e.g.
  `host:nas AND NOT country:(US OR CA)`, with suggestions as you type
  ([QUERIES.md](QUERIES.md)).

## Reports

- PDF reports (network summary, security digest) with selectable sections,
  periods and filters; on demand or scheduled daily, weekly or monthly,
  emailed as attachments and kept on the appliance ([REPORTS.md](REPORTS.md)).

## Security

- Threat feeds: flows to or from addresses on lists of known-bad addresses are
  tagged at ingest. Spamhaus DROP, abuse.ch Feodo Tracker, FireHOL Level 1 and
  others are seeded; add your own as text, CSV or JSON from a URL or file
  ([THREAT-FEEDS.md](THREAT-FEEDS.md)).
- Detections page and notices for matches.

## Access

- Local accounts, OpenID Connect, SAML 2.0, LDAP/Active Directory (StartTLS or
  LDAPS, nested groups) and RADIUS (Message-Authenticator, failover).
- Roles mapped from directory or IdP groups; admin and viewer roles.
- TOTP two-factor authentication with recovery codes, optionally required for
  administrators.
- Audit log, forwarded to syslog over UDP, TCP or TLS (RFC 5424 or 3164).
- Read-only MCP endpoint for AI assistants, with per-user API tokens
  ([MCP.md](MCP.md)).

## Appliance

- HTTPS by default with a self-signed certificate on first start; CSRs and
  uploaded certificates; port 80 redirects.
- Encrypted backup and restore of the configuration, optionally with flow
  history. Scheduled backups to SMB/CIFS, S3-compatible storage or SFTP, with
  retention at both ends; encryption to an age public key lets the appliance
  write backups it cannot read.
- Notification channels: signed webhooks (Standard Webhooks) and Telegram,
  queued and retried, for notices, threat feed matches and reports
  ([NOTIFICATIONS.md](NOTIFICATIONS.md)).
- Email through your SMTP server (STARTTLS, TLS or a plain relay; trusted CAs
  apply), with a test send; used by scheduled reports.
- Notices for low disk space, OS updates, expiring certificates, silent
  exporters, failed backups and database problems.
- OS updates, time and NTP, and service restarts from the UI.
- Retention settings for raw flows and rollups.
- Interface ready for translation (see [TRANSLATING.md](TRANSLATING.md)).
