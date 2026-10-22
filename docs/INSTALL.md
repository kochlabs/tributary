# Installing Tributary

Tributary is a single `.deb` package for Debian or Ubuntu on amd64. It stores
flows in [ClickHouse](https://clickhouse.com), which Debian doesn't ship, so
ClickHouse comes from ClickHouse's own apt repository. Tributary doesn't bundle
or rebuild ClickHouse: ClickHouse Inc. publishes it, including its security
updates.

It is developed and tested on Debian 13 (trixie). Give the machine at least
4 GB of RAM: ClickHouse is capped at half of it.

- [Quick install](#quick-install)
- [Manual install](#manual-install)
- [How ClickHouse is set up for Tributary](#how-clickhouse-is-set-up-for-tributary)
- [Inspecting the database](#inspecting-the-database)
- [Upgrading](#upgrading)
- [Removing Tributary](#removing-tributary)

## Quick install

Download `tributary_<version>_amd64.deb` and `install.sh` from the
[releases page](https://github.com/kochlabs/tributary/releases) (or build the
package with `make deb`), then:

```bash
sudo ./install.sh tributary_<version>_amd64.deb
```

To check the download first: `SHA256SUMS` lists the files' checksums, and
each file has a build attestation showing it was built from this repository
by its release workflow:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify tributary_<version>_amd64.deb --repo kochlabs/tributary
```

The script does exactly the steps in [Manual install](#manual-install). It
shows what it will add to apt and asks first; `-y` skips the question for
unattended installs. Running it again later is safe: it checks that the
ClickHouse key and the repository restriction are still in place and installs
the given package.

## Manual install

### 1. Add ClickHouse's repository

Fetch ClickHouse's signing key and check its fingerprint before trusting it:

```bash
curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key \
  | gpg --dearmor > clickhouse-keyring.gpg
gpg --show-keys --with-fingerprint clickhouse-keyring.gpg
```

The output must show exactly one key, `ClickHouse Inc. Repositories Key
<packages@clickhouse.com>`, with this fingerprint:

```text
3A9E A119 3A97 B548 BE14  57D4 8919 F6BD 2B48 D754
```

ClickHouse's own installation guide gives the same key (its ID is the last 16
characters, `8919F6BD2B48D754`). If the fingerprint differs, stop: either
ClickHouse has changed its key (check their documentation) or something is
intercepting the download.

Then install the key and the repository. `signed-by` makes apt trust this key
for this repository only:

```bash
sudo install -m 644 clickhouse-keyring.gpg /usr/share/keyrings/clickhouse-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb lts main" \
  | sudo tee /etc/apt/sources.list.d/clickhouse.list
```

### 2. Restrict the repository to ClickHouse's packages

`signed-by` limits which key may sign the repository, not what the repository
may contain: without a restriction, it could offer a "newer" version of any
package on the system, such as `openssl`. This apt preferences file allows only
`clickhouse-*` packages from it and blocks everything else:

```bash
sudo tee /etc/apt/preferences.d/clickhouse <<'EOF'
# Only ClickHouse's own packages may come from its repository.
Package: clickhouse-*
Pin: origin packages.clickhouse.com
Pin-Priority: 500

Package: *
Pin: origin packages.clickhouse.com
Pin-Priority: -1
EOF
sudo apt update
```

`origin` is the repository's host name, so the repository can't get around the
rule through its own metadata. To check it, `apt-cache policy clickhouse-server`
should list the repository's versions with priority 500.

### 3. Install Tributary

```bash
sudo DEBIAN_FRONTEND=noninteractive CLICKHOUSE_PASSWORD='' apt install ./tributary_<version>_amd64.deb
```

apt installs `clickhouse-server` and `clickhouse-client` as dependencies. The
ClickHouse package would otherwise prompt for a password for its built-in
`default` user; Tributary doesn't use that user (see [ClickHouse
users](#users-and-credentials)).

The installer prints the address and the initial `admin` password, which is
also in `/var/lib/nfa/initial-admin-password`. Sign in, change the password,
then delete that file.

Point flow exporters at UDP 2055 (NetFlow), 4739 (IPFIX) or 6343 (sFlow); the
ports can be changed under Settings. Set the exporters' active timeout to about
60 seconds so long-lived flows are reported promptly: traffic is counted when a
record arrives.

## How ClickHouse is set up for Tributary

Everything below is created by the package. Nothing is changed in ClickHouse's
own `config.xml` or `users.xml`; Tributary only adds files to the
`config.d/` and `users.d/` override directories.

### Server settings

`/etc/clickhouse-server/config.d/tributary.xml` (a conffile: your edits survive
upgrades, and apt asks before replacing it):

| Setting | Value | Why |
|---|---|---|
| `listen_host` | `127.0.0.1` | only programs on this machine can connect |
| `mysql_port`, `postgresql_port`, `interserver_http_port` | removed | protocols Tributary doesn't use |
| `max_server_memory_usage_to_ram_ratio` | `0.5` | ClickHouse uses at most half the RAM, leaving room for the OS and Tributary |
| `memory_worker_dynamic_hard_limit` | `0` | keeps that cap fixed instead of adjusting it to the page cache |
| `mark_cache_size` | 256 MB | smaller than the default 5 GB, sized for a small appliance |
| `uncompressed_cache_size` | `0` | not useful for this workload |
| `concurrent_threads_soft_limit_num` | `2` | limits CPU use by queries |
| `background_schedule_pool_size` | `8` | fewer background threads |
| `logger` | `warning`, 3 × 100 MB | quieter, bounded server logs in `/var/log/clickhouse-server/` |
| `query_log` | kept 3 days | recent queries for troubleshooting, without growing forever |
| `trace_log`, `text_log`, `metric_log`, `asynchronous_metric_log`, `part_log`, `processors_profile_log`, `latency_log` | removed | ClickHouse's internal telemetry tables, which otherwise take disk space and I/O |

ClickHouse is restarted only when this file or the user files below change, so
upgrading Tributary doesn't usually interrupt the database.

### Users and credentials

- **`netflow`**: the user Tributary connects as, defined in
  `/etc/clickhouse-server/users.d/netflow.xml`. It may connect only from
  `127.0.0.1` and `::1`, has a per-query memory limit of 1 GB and at most 2
  threads per query, and its rights are limited to what Tributary needs:

  ```sql
  GRANT SHOW, SELECT, INSERT, ALTER, CREATE, DROP, TRUNCATE, OPTIMIZE
    ON netflow.*                      -- its own database and its tables
  GRANT SELECT ON system.parts        -- storage figures
  GRANT SELECT ON system.columns      -- schema checks when upgrading
  GRANT SELECT ON system.disks        -- free disk space
  ```

  It can't read other databases or other system tables, read files or URLs
  through ClickHouse, manage users or run server commands.
- **Its password** is 32 random hex characters generated at the first install,
  stored in `/etc/netflow/clickhouse.pw` (owner `root`, group `nfa`, mode 640,
  so only root and Tributary's service account can read it). ClickHouse stores
  only its SHA-256 hash.
- **`default`**: ClickHouse's built-in administrator, which ClickHouse
  installs without a password. Tributary sets a random password for it (in
  `/etc/clickhouse-server/users.d/tributary-default.xml`), kept for root in
  `/etc/tributary/clickhouse-default.pw`, so other local accounts can't use
  the database as an administrator. Tributary itself never
  uses this user. To use it:

  ```bash
  sudo sh -c 'clickhouse-client --password "$(cat /etc/tributary/clickhouse-default.pw)"'
  ```

  To choose your own password, write it to that file and run
  `sudo dpkg-reconfigure tributary`. If you set a password when ClickHouse
  was installed (ClickHouse keeps it in `users.d/default-password.xml`),
  Tributary leaves the `default` user alone.

The users and grants are generated by `/usr/lib/tributary/clickhouse-users.sh`
(`deploy/clickhouse/users.sh` in the source), which the package runs at each
install and upgrade.

### Ports

ClickHouse listens on `127.0.0.1` only, on 9000 (native protocol) and 8123
(HTTP, used to back up and restore flow history). `tributary.xml` turns off
the other protocols ClickHouse enables by default: MySQL (9004), PostgreSQL
(9005) and replication (9009). Nothing of ClickHouse is reachable from the
network; only Tributary's own ports are (443, 80 and the flow ports).

### Database and tables

Tributary creates and migrates its schema itself each time it starts; the
package runs no SQL. Everything is in the `netflow` database:

| Table | Contents | Kept for |
|---|---|---|
| `flows` | every flow record (addresses, ports, protocol, interfaces, AS, country, MACs, bytes, packets), partitioned by day | 7 days by default |
| `traffic_1m` | per-minute totals by exporter, interface, protocol and EtherType, for long-range charts | 365 days by default |
| `traffic_1m_mv2` | materialized view that fills `traffic_1m` as flows are written | |

Retention is set under Settings, which changes the tables' TTLs; old data is
dropped a whole partition at a time. Times are stored in UTC.

### Other system changes

- `/usr/lib/sysctl.d/99-tributary.conf` raises the kernel's UDP receive buffers
  so bursts of flow packets aren't dropped.
- A system account `nfa` runs Tributary (`nfad.service`), with its data in
  `/var/lib/nfa`.
- `tributary-admin` is a small root helper, started through a systemd path unit,
  that performs the operating system tasks the web interface offers (updates,
  time, restarting services) from a fixed list of commands.

### Files

| Path | Contents |
|---|---|
| `/usr/bin/nfad`, `/usr/bin/tributary-flowgen` | daemon and traffic simulator |
| `/usr/lib/systemd/system/` | `nfad.service`, `tributary-admin.path`/`.service`, `tributary-update-check.timer` |
| `/usr/lib/tributary/` | root helper for the Updates, Time and Services pages; ClickHouse user generator |
| `/etc/tributary/services.conf` | services the UI may restart (conffile) |
| `/etc/clickhouse-server/config.d/tributary.xml` | ClickHouse settings (conffile) |
| `/var/lib/nfa` | configuration database, TLS certificate, GeoIP and MAC vendor data |

## Inspecting the database

Connect as Tributary's user:

```bash
clickhouse-client --user netflow --password "$(sudo cat /etc/netflow/clickhouse.pw)"
```

Some useful queries:

```sql
-- Size on disk per table
SELECT table, formatReadableSize(sum(bytes_on_disk)) AS size, sum(rows) AS rows
FROM system.parts WHERE database = 'netflow' AND active GROUP BY table;

-- Flows received in the last 5 minutes, per exporter
SELECT IPv6NumToString(exporter) AS exporter, count() FROM netflow.flows
WHERE time_received > now() - INTERVAL 5 MINUTE GROUP BY exporter;
```

Logs: `journalctl -u nfad` for Tributary, `/var/log/clickhouse-server/` for
ClickHouse.

## Upgrading

- **Tributary**: install the new `.deb` the same way (`sudo deploy/install.sh
  new.deb`, or `sudo apt install ./new.deb`). The configuration and flow data
  are kept, and the schema is migrated when Tributary starts.
- **ClickHouse**: updated with the operating system (`apt upgrade`, or
  Appliance → Updates in the web interface), following ClickHouse's LTS
  releases.

## Removing Tributary

- `sudo apt remove tributary` stops and removes the program, keeping its
  configuration.
- `sudo apt purge tributary` also deletes the configuration (`/var/lib/nfa`),
  the `netflow` ClickHouse user and its password file, Tributary's password
  for the `default` user (which goes back to ClickHouse's own setting, no
  password) and the `nfa` account.

Neither removes the flow data, ClickHouse itself or the ClickHouse repository.
To remove those too:

```bash
clickhouse-client -q 'DROP DATABASE netflow'
sudo apt purge clickhouse-server clickhouse-client clickhouse-common-static
sudo rm /etc/apt/sources.list.d/clickhouse.list /etc/apt/preferences.d/clickhouse \
  /usr/share/keyrings/clickhouse-keyring.gpg
sudo apt update
```
