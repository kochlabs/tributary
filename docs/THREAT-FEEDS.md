# Threat feeds

Flows to or from addresses on threat feeds (lists of known-bad addresses) are
tagged at ingest with the name of the first feed listing the address.
**Security → Detections** shows the matches; a notice appears when traffic
matches a feed in the last hour.

## Feeds

Managed under **Security → Threat Feeds**. The table is seeded on first start
with:

| Feed | Enabled |
|---|---|
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) (IPv4, IPv6) | yes |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | yes |
| [FireHOL Level 1](https://iplists.firehol.org/?ipset=firehol_level1) | yes |
| [Emerging Threats compromised](https://rules.emergingthreats.net/blockrules/) | yes |
| [CINS Army](https://cinsscore.com/) | no |
| [Tor exit nodes](https://check.torproject.org/torbulkexitlist) | no, and no notices |

These are suggestions, not built in: edit, disable or delete them, or add
your own. **Add default feeds** brings back any that were deleted. Check each
publisher's terms of use for your setting.

A source is an http(s) URL or the absolute path of a file on the appliance
(gzip is detected). Formats:

- **Text:** the first word of each line; comments start with `#`, `;` or `//`.
- **CSV:** one column; a delimiter of one character or `\t`.
- **JSON:** a field of each object, in an array or one object per line, or an
  array of strings.

**Test** downloads and parses a feed without saving it. Feeds update on their
own interval; the last good list stays in use when a download fails.

## Matching

- Only addresses outside the local networks are matched. Private, CGNAT,
  reserved and documentation ranges never match (FireHOL Level 1 lists them
  as bogons).
- A flow records the first feed listing the address; reorder feeds with
  **Move up** and **Move down** to put the most specific first.
- Tags are set when a flow arrives: changing feeds doesn't re-tag stored flows.

## Querying

- Dimensions: `threat` (the feed) and `threat_host` (the listed address).
- Filter: `threat=*` for any feed, or `threat=<feed name>`.
- MCP `lookup_address` lists every enabled feed listing an address.
