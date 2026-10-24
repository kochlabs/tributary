# Design: inventory sources

Status: draft. Tributary reads devices, addresses and services from an
inventory (a CMDB or source of truth), starting with NetBox, so names and
context are maintained in one place.

## Goals

- Name a device once, in the inventory, and see that name everywhere in
  Tributary: dashboard, Explorer, Flow Search, Devices, reports, MCP.
- Show inventory context next to what Tributary observes: role, site, tags,
  documented services, a link to the inventory object.
- Optionally take local networks from the inventory's prefixes.
- Pluggable: NetBox first; Nautobot, phpIPAM or a static file later.

## Non-goals

- Writing to the inventory, or suggesting additions. Tributary only consumes;
  finding gaps between observed and documented is the security assistant's job.
- Flagging "undocumented" devices or services in Tributary.
- Changing detection: inventory data labels, it never suppresses threat
  matches or notices.
- Discovery. Tributary already learns devices from flows; the inventory is the
  documented view, not a second discovery engine.

## Model

An **inventory source** is configured like an identity source
(Configuration → Inventory Sources):

| Field | |
|---|---|
| type | `netbox` (later others) |
| name, enabled, priority | as identity sources; the highest-priority match wins |
| url | e.g. `https://netbox.kochlabs.io` |
| token | read-only API token, stored encrypted, never returned |
| scope | optional filters: site, tenant, tag (NetBox query parameters) |
| sync interval | default 15 minutes |
| use prefixes as local networks | off; when on, prefixes with a chosen tag (default `tributary-local`) are added to Local Networks |

TLS uses the trust store (Appliance → Certificates), like LDAP and SAML.

## Backend interface

```go
// Source is an inventory backend. Sync returns a complete snapshot; the
// caller replaces its cache atomically.
type Source interface {
	Sync(ctx context.Context) (*Snapshot, error)
	Test(ctx context.Context) (Summary, error) // counts and a sample, for the form
}

type Snapshot struct {
	Objects  []Object   // devices and VMs
	Addrs    []Address  // IP → object (+ interface), DNS name
	MACs     []MAC      // MAC → object (+ interface)
	Services []Service  // object, protocol, ports, name
	Prefixes []Prefix   // prefix, tags, description
}

type Object struct {
	ID, Kind, Name, Role, Site, Tenant, Status, URL string // Kind: device | vm
	Tags []string
}
```

Backends map their data model to these few types; Tributary never sees
backend specifics.

## Sync and cache

- Full snapshot every interval, stored in SQLite tables (`inv_objects`,
  `inv_addrs`, `inv_macs`, `inv_services`, `inv_prefixes`) per source,
  replaced in one transaction. Lookups are in-memory maps rebuilt after sync.
- Ingest and queries never call the inventory. If it's unreachable, the last
  snapshot stays in use; the source shows the error and a notice appears after
  repeated failures (like threat feeds).
- Size: a lab is hundreds of objects, a large site tens of thousands; a full
  sync is cheap at that scale. Incremental sync (`last_updated__gte` plus the
  change log for deletions) and NetBox webhooks are later options.

## NetBox mapping (4.2+)

| Snapshot | NetBox API | Notes |
|---|---|---|
| Objects | `dcim/devices/`, `virtualization/virtual-machines/` | role, site, tenant, status, tags; URL from `display_url` |
| MACs | `dcim/mac-addresses/` | assigned interface → parent object |
| Addrs | `ipam/ip-addresses/` | `assigned_object` → interface → object; `dns_name` |
| Services | `ipam/services/` | `parent_object_type` / `parent_object_id` (device, VM, FHRP group), protocol, ports, name |
| Prefixes | `ipam/prefixes/` | tags, description |

Paginate with `limit=1000` and `next`. Requests send `Authorization: Bearer
nbt_<key>.<token>` (v2 tokens; v1 `Token <key>` also accepted). Scope filters
are passed through as query parameters. NetBox older than 4.2 keeps MACs on
interfaces (`mac_address`); support it only if needed.

## Matching

An address in a flow, or a learned device, is matched in order:

1. MAC (device MAC from flows or learned bindings) → object.
2. IP address (exact) → object.
3. DNS name (reverse DNS result) → object with that name or IP `dns_name`.

Randomized (locally administered) MACs match only by IP. Ambiguous matches
(the same IP on two objects) pick the primary IP's object, else none.

## Using it

Flows store identifiers (addresses, MACs, ifIndex, exporter address, AS
number), never names; names are looked up when shown. Inventory names
therefore apply to history as soon as they sync, and renaming in the
inventory relabels past traffic.

- **Names:** inventory name → name set in Tributary → DHCP / reverse DNS →
  vendor + MAC. The Devices page shows where the name came from (already does
  for DNS and vendor) and links to the inventory object.
- **Context:** Devices and address detail show role, site, tenant, tags.
  Top-N detail lines can include the role ("Fozzie · media server").
- **Services:** where Tributary shows observed services (the Exposed services
  report section, address lookups), it adds the documented service name for a
  matching port, e.g. "tcp/32400 · Plex (NetBox)". No match shows nothing.
- **Local networks:** optional, from tagged prefixes, merged with the
  configured list (union), so turning it off never loses local networks.
- **Filters:** later, `role=` and `tag=` filters resolve to the matching
  objects' addresses at query time.
- **MCP:** `lookup_address` and `devices` include the inventory record; the
  assistant can also query the inventory directly.

## Security

- Read-only token; the form warns if the token can write (`users/tokens/`
  shows a token its own `write_enabled`, read-only tokens included).
- Token encrypted at rest like other secrets; audit on create, change, test.
- Inventory text (names, descriptions, tags) is untrusted display data:
  escaped in the UI and reports, never interpreted.

## Open questions

1. Name precedence: inventory over a name typed in Tributary (proposed), or
   the reverse?
2. Should a name typed in Tributary be disabled when an inventory name exists,
   to avoid two places to edit?
3. Prefixes as local networks: union with the configured list (proposed), or
   replace it?
4. Multiple sources at once (e.g. NetBox for infrastructure, a file for
   home devices), or one active source?
