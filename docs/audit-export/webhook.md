# Webhook destination

The webhook destination POSTs each audit event as a separate HTTP request
to the configured URL. The body format is configurable (`json`, `cef`, or
`rfc5424`).

## Configuration

`POST /audit/destinations` (admin-only):

```json
{
  "name": "datadog-bridge",
  "organization_id": null,
  "kind": {
    "type": "webhook",
    "url": "https://hooks.example.com/yauth-audit",
    "format": "json",
    "hmac_secret": "<32-byte cryptographic random>",
    "headers": {
      "X-Tenant-Id": "tenant-prod-1"
    }
  }
}
```

- `format`: one of `json` (default), `cef`, `rfc5424`. JSON is the most
  universally consumable.
- `hmac_secret`: optional. When set, requests carry `X-Yauth-Signature`
  (see `README.md` § HMAC signing).
- `headers`: arbitrary static headers. Treated as **secrets** — never
  logged in responses.

## Request shape

`POST <url>` with:

- `Content-Type: application/json` (for JSON format) or `text/plain;
  charset=utf-8` (CEF / RFC 5424).
- `User-Agent: yauth-audit-export/1`
- `X-Yauth-Signature: t=<unix_secs>,v1=<hex_signature>` (when HMAC is on)
- Any extra headers from the destination config

Body: the rendered audit event. See `README.md` § Formats for the JSON
schema.

## Response handling

- `200..=299`: success. The outbox row is marked `sent`.
- `400..=499`: client error. The outbox row is marked `failed` with the
  HTTP status. After 5 attempts the row is dead-lettered. 4xx responses
  are retried — this matches Stripe's webhook semantics (a 4xx from a
  flaky reverse-proxy shouldn't drop the event silently).
- `500..=599`: server error. Retried per the backoff schedule.
- Network timeout / connection refused: treated like a server error.

## SSRF defense

The webhook destination shares the SSRF allowlist used by the existing
`webhooks` plugin (loopback, private ranges, `metadata.google.internal`,
etc.). Attempting to create a destination pointing to a blocked URL
returns `400 Bad Request`.

## Backoff schedule

Attempt → retry delay:

| Attempt | Delay before next attempt |
|---|---|
| 1 | 1s |
| 2 | 5s |
| 3 | 30s |
| 4 | 5m |
| 5 | 1h |
| 6 | dead-letter |

After the 5th failed attempt the outbox entry transitions to
`dead_letter` and the `yauth_audit_export_dead_letter_total` counter
increments.

## End-to-end pentest

`crates/yauth/tests/audit_export_pentest.rs::webhook_sends_signed_body_verifiable_by_receiver`
spins up an in-process axum receiver, has the dispatcher sign + ship,
and asserts the receiver's verification helper accepts the signature.

## Local development

You can post a synthetic test event by:

1. Create a destination with a fake receiver URL (see
   `crates/yauth/tests/audit_export_pentest.rs::FakeReceiver` for a
   template).
2. `POST /audit/replay { audit_log_ids: [...], destination_ids: [...] }`
   to re-route an existing audit row.

A dedicated "Send Test Event" button on the admin UI is deferred to a
follow-up (see `docs/audit-export/README.md` § Out-of-scope).
