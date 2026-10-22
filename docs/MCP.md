# MCP

Tributary has a read-only [Model Context Protocol](https://modelcontextprotocol.io)
endpoint, so AI assistants such as Claude can query flow data: "what used the
uplink at 2 pm?", "who is 10.10.0.14 talking to?".

## Setup

1. Turn it on: **Configuration → Settings → MCP**.
2. Create a token: **Access → API Tokens**. It is shown once. The token acts
   as its owner, with the owner's role; a token for a viewer account can only
   view.
3. Point the client at `https://<appliance>/mcp` with the header
   `Authorization: Bearer <token>`.

Claude Code:

```bash
claude mcp add --transport http tributary https://<appliance>/mcp --header "Authorization: Bearer <token>"
```

Claude Desktop, through the [mcp-remote](https://www.npmjs.com/package/mcp-remote)
bridge (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tributary": {
      "command": "npx",
      "args": ["mcp-remote", "https://<appliance>/mcp", "--header", "Authorization: Bearer ${TRIBUTARY_TOKEN}"],
      "env": { "TRIBUTARY_TOKEN": "<token>" }
    }
  }
}
```

With the appliance's self-signed certificate, Node-based clients need to trust
it: download it from **Appliance → Certificates** and set
`NODE_EXTRA_CA_CERTS=/path/to/tributary.crt`, or install a certificate from
your own CA.

## Tools

| Tool | Returns |
|---|---|
| `summary` | totals and rates for a time range |
| `top` | top values of a dimension (hosts, apps, organizations, interfaces…) |
| `traffic_over_time` | a time series, optionally split by a dimension |
| `traffic_paths` | traffic across 2–3 dimensions (Sankey data) |
| `search_flows` | individual flow records |
| `exporters` | exporters with rates, sampling and health |
| `interfaces` | an exporter's interfaces and utilization |
| `devices` | local devices by MAC address |
| `lookup_address` | geo, AS, hostname and top traffic of one address |
| `appliance_health` | collector, database, disk and notices |

Most take a `range` (`15m`, `24h`, `7d`) or `from`/`to`, and `filters` with the
same syntax as the UI.

## Security

- Off by default. Results are sent to the assistant's provider.
- Read-only. Tokens act as their owner, with the owner's role.
- Only administrators create and revoke tokens. Tokens are stored as hashes,
  can expire, stop working while the owner's identity source is disabled, and
  are deleted with the owner.
- Every tool call is in the audit log (and syslog, if forwarded).
- 120 requests a minute per token; results are capped in size.
