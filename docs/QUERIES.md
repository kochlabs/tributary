# Queries

The query bar on the Traffic Explorer, Flow Search and Detections, and in
reports, narrows traffic down. The API takes the same query as `q`, and the
MCP tools as `query`.

## The query bar

- Fields and values are suggested as you type (exporters, devices, names,
  threat feeds, countries, services). Tab or Enter picks one; Ctrl+Space
  shows them.
- Mistakes are underlined as you type; hover for the reason. Enter runs
  the query, which goes into the page's address for bookmarking.
- ↑ in an empty bar lists saved queries, then recent ones (kept in this
  browser).
- The bookmark button saves the query in the bar under a name, and lists
  saved queries: yours, and ones others share. A saved query is private
  unless you share it; only you or an administrator can change or delete
  it. Saving under a name you already use updates that query.
- Clicking an address, row or chart series adds `AND field:value`;
  Alt-click on Flow Search excludes it instead.

```
src:10.0.0.0/8 AND dst_port:[1 TO 1023] AND NOT country:(US OR CA)
host:nas AND host:203.0.113.9
bytes:>100MB AND direction:upload
threat:* OR (remote_country:RU AND dst_port:3389)
flags:syn AND NOT flags:ack
device:"Living room TV" AND NOT app:tcp/443
```

## Syntax

| | |
|---|---|
| `field:value` | `dst_port:443`, `src:10.0.0.0/8`, `host:2001:db8::1` |
| any of several | `dst_port:(80 OR 443)` |
| range | `dst_port:[1 TO 1023]`, `dst_port:1-1023`, `bytes:[1MB TO *]`, `src:10.0.0.10-10.0.0.20` |
| comparison | `bytes:>100MB`, `packets:<=3`, `duration:>=5m` |
| any value | `threat:*`, `vlan:*` |
| not | `NOT country:US`, `!country:US`, `country:!US` |
| and, or | `AND` / `&&`, `OR` / `\|\|`; terms side by side are combined with **OR**, as in Graylog |
| grouping | `(a OR b) AND c`; `AND` binds tighter than `OR` |
| quotes | for values with spaces: `device:"Living room TV"` |
| bare value | an address, prefix or name alone means `host:` it; a number alone is an error |

Values are addresses, prefixes and ranges, MACs, numbers, sizes (`100MB`,
`2GiB`), durations (`500ms`, `30s`, `5m`, `2h`), two-letter country codes,
protocols (`tcp`, `17`), `proto/port` and names.

A name is looked up where an address or device goes (`host:nas`,
`device:"Living room TV"`): inventory, names set in Tributary, then reverse
DNS, ignoring case. `nas` also matches `nas.home.lan`, and `nas*` matches by
prefix. A name nothing has matches nothing, with a warning.

## Fields

| Field | |
|---|---|
| `host`, `src`, `dst` | either side, source, destination |
| `local`, `remote` | the side in, or outside, the local networks |
| `nexthop`, `exporter` | |
| `port`, `src_port`, `dst_port` | |
| `proto`, `app` | `tcp`; `tcp/443` (the application side) |
| `iface`, `in_if`, `out_if` | interface index |
| `as`, `src_as`, `dst_as`, `remote_as` | `13335` or `AS13335` |
| `country`, `src_country`, `dst_country`, `remote_country` | |
| `direction` | `download`, `upload`, `internal`, `transit` |
| `device` | name, MAC or address of the local device |
| `mac`, `src_mac`, `dst_mac` | as exported |
| `threat` | a feed's name, or `*` |
| `vlan`, `dscp`, `etype`, `flow_type` | |
| `bytes`, `packets`, `duration`, `sampling` | per flow record |
| `flags` | TCP flag set: `syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr` |

Aliases: `ip`, `addr`, `ip.addr`, `peer` (host); `ip.src`, `ip.dst`;
`sport`, `dport`; `tcp.port`, `udp.port` (port, with the protocol);
`eth.addr`, `eth.src`, `eth.dst` (MACs).

The design is in [design/QUERY-LANGUAGE.md](design/QUERY-LANGUAGE.md).
