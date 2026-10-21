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

- Country and ASN (with organization names) at ingest. Sources, chosen under
  Administration → Data Sources: DB-IP Lite (default), MaxMind GeoLite2 or
  GeoIP2, custom URLs, or files kept up to date by `geoipupdate`.
- MAC vendors from the IEEE registry (default, refreshed weekly), a URL or a file.
- Reverse DNS at query time, cached.
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
- Filters: IP/CIDR (v4 and v6), ports and ranges, protocols, AS, country,
  interface, VLAN, DSCP, `proto/port`; `,` for OR, `!` for NOT.

## Access

- Local accounts, OpenID Connect, SAML 2.0, LDAP/Active Directory (StartTLS or
  LDAPS, nested groups) and RADIUS (Message-Authenticator, failover).
- Roles mapped from directory or IdP groups; admin and viewer roles.
- TOTP two-factor authentication with recovery codes, optionally required for
  administrators.
- Audit log, forwarded to syslog over UDP, TCP or TLS (RFC 5424 or 3164).

## Appliance

- HTTPS by default with a self-signed certificate on first start; CSRs and
  uploaded certificates; port 80 redirects.
- Encrypted backup and restore of the configuration, optionally with flow
  history. Scheduled backups to SMB/CIFS, S3-compatible storage or SFTP, with
  retention at both ends; encryption to an age public key lets the appliance
  write backups it cannot read.
- Notices for low disk space, OS updates, expiring certificates, silent
  exporters, failed backups and database problems.
- OS updates, time and NTP, and service restarts from the UI.
- Retention settings for raw flows and rollups.
- Interface ready for translation (see [TRANSLATING.md](TRANSLATING.md)).
