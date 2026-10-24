# Notifications

**Configuration → Notifications** sets up channels: webhooks and Telegram.
A channel is only a destination; what gets sent there is chosen where it
comes from (a report's **Send to channels**; later, rules). Deliveries
are queued and retried (1 min, 5 min, 30 min, 2 h, then every 6 h) for up to
a day; a channel failing for a day is turned off and a notice says so. Set
**Configuration → Settings → Appliance address** to get links back to
Tributary in messages.

## Events

| Type | When |
|---|---|
| `report.completed` | a scheduled report run finishes, or one run with **Also send** (Telegram gets the PDF) |
| `report.failed` | it fails |
| `test` | **Send test** |

## Webhooks

A `POST` with a JSON body:

```json
{
  "id": "evt_5f1c…",
  "type": "report.completed",
  "timestamp": "2026-10-24T07:00:41-04:00",
  "appliance": "Tributary",
  "level": "info",
  "title": "Weekly security digest",
  "message": "Oct 13 – Oct 19, 2026",
  "url": "https://tributary.example.com/reports",
  "data": { "reportId": 3, "trigger": "schedule", "from": …, "to": …, "size": 48211, "attachment": "Weekly-security-digest-2026-10-13.pdf" }
}
```

Requests are signed per [Standard Webhooks](https://www.standardwebhooks.com/):

| Header | |
|---|---|
| `webhook-id` | the event ID (the same on retries: use it to drop duplicates) |
| `webhook-timestamp` | Unix seconds |
| `webhook-signature` | `v1,` + base64 HMAC-SHA256 of `id.timestamp.body`, keyed with the base64-decoded secret after `whsec_` |

Any Standard Webhooks library verifies them. By hand, in Python:

```python
key = base64.b64decode(secret.removeprefix("whsec_"))
expected = "v1," + base64.b64encode(hmac.new(key, f"{id}.{timestamp}.{raw_body}".encode(), hashlib.sha256).digest()).decode()
```

Reject timestamps more than a few minutes old. The secret is shown once,
when the channel is created; **Regenerate secret** replaces it. A 2xx reply
counts as delivered.

## Telegram

Create a bot with @BotFather, send it a message, and read your chat ID from
`https://api.telegram.org/bot<token>/getUpdates` (`message.chat.id`; groups
are negative). Report runs arrive as PDF documents.
