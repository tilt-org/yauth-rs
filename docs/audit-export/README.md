# Audit log SIEM/syslog export (issue #96)

yauth ships an opt-in plugin (`audit-export`) that streams every row in the
existing `AuditLog` table out to one or more external destinations: webhooks,
syslog (RFC 5424), S3-flavored object storage, Splunk HEC (stub), and
Datadog HTTP intake (stub). This document is the architectural overview.
Per-destination integration guides live alongside it (`webhook.md`,
`syslog.md`, `splunk.md`).

## Why

The compliance value of the in-database audit log is bounded — admins can
query the last N events from inside yauth, but SOC 2 Type II reviewers
expect logs to flow into a **separate** SIEM with its own tamper-evident
retention and query tooling.

This plugin closes that gap. The audit table stays as the source of truth;
exports flow asynchronously, durably, and with **at-least-once** delivery.

## High-level flow

```
  Auth event
      │
      ▼
 ┌──────────────┐    1. transactional insert (audit + outbox)
 │ write_audit_ │
 │ log_scoped() │───►  AuditLog row
 │              │───►  AuditOutboxEntry rows (one per active destination
 │              │      whose org_id matches the audit's org_id, OR is None)
 └──────────────┘
                              │
                              ▼
                ┌────────────────────────────┐
                │ per-destination drain      │
                │ worker (one tokio task     │
                │ per destination)           │
                │                            │
                │  ┌──────────────────────┐  │
                │  │ claim_pending(N)     │  │
                │  └─────────┬────────────┘  │
                │            ▼               │
                │  ┌──────────────────────┐  │
                │  │ Dispatcher.send_one  │  │  Webhook / Syslog / S3
                │  └─────────┬────────────┘  │
                │            ▼               │
                │  ┌──────────────────────┐  │
                │  │ mark_sent /          │  │
                │  │ mark_failed /        │  │
                │  │ mark_dead_letter     │  │
                │  └──────────────────────┘  │
                └────────────────────────────┘
```

## Durability model

The memory backend is the **canonical-semantics** implementation. SQL
backends ship `RepoError::NotImplemented` stubs (HTTP 501) and will be
replaced with real implementations in follow-up issues
(`feat/96-audit-export-pg`, `feat/96-audit-export-mysql`, …).

**Trade-off**: in the memory backend, outbox entries are lost on process
restart. This is acceptable for development and CI; in production with a
SQL backend, the outbox row is inserted in the same transaction as the
audit row, giving genuine at-least-once delivery.

Operators running production today have two options:

1. Wait for the SQL backend implementation (recommended for SOC 2 Type II).
2. Ship the memory backend with the understanding that an unclean shutdown
   may drop in-flight exports.

The contract is **always** "if the audit row is committed, the export was
attempted at least once" — never "at most once" / drop-on-failure.

## Replay

`POST /audit/replay { audit_log_ids, destination_ids }` (admin-only) re-enqueues
outbox entries for the named audit rows + destinations. Two rules:

- The audit row must still exist in `AuditLog`. If it's been purged, the
  endpoint returns `206 Partial Content` with the missing ids in `gone[]`.
- The destination must currently exist. Deleted destinations are 404 at
  validation time.

## HMAC signing

Webhook destinations may carry a per-destination `hmac_secret`. When set,
each request body is signed:

- Header: `X-Yauth-Signature: t=<unix_secs>,v1=<hex_signature>`
- Signature input: `<unix_secs>.<body_bytes>` (Stripe-style — same body
  produces different signatures at different times, so replay needs the
  matching `t=`)
- Algorithm: HMAC-SHA256

### Receiver-side verification (Node.js)

```js
import crypto from 'crypto';

function verifyYauthSignature(secret, header, body, signatureWindowSecs = 300) {
  const parts = Object.fromEntries(
    header.split(',').map(p => p.split('=').map(s => s.trim())),
  );
  const t = Number(parts.t);
  const v1 = parts.v1;
  if (!Number.isFinite(t) || !v1) return false;
  const drift = Math.abs(Math.floor(Date.now() / 1000) - t);
  if (drift > signatureWindowSecs) return false;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${t}.`)
    .update(body)
    .digest('hex');
  // constant-time compare
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(v1, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

### Receiver-side verification (Python)

```python
import hmac
import hashlib
import time

def verify_yauth_signature(secret: str, header: str, body: bytes,
                            window_secs: int = 300) -> bool:
    parts = dict(p.strip().split("=", 1) for p in header.split(",") if "=" in p)
    try:
        t = int(parts["t"])
        v1 = parts["v1"]
    except (KeyError, ValueError):
        return False
    if abs(int(time.time()) - t) > window_secs:
        return False
    expected = hmac.new(
        secret.encode(),
        f"{t}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, v1)
```

Always use `crypto.timingSafeEqual` / `hmac.compare_digest` — a naive `==`
comparison leaks the signature byte-by-byte through timing side channels.

## Rotation runbook

To rotate a webhook destination's HMAC secret:

1. `PATCH /audit/destinations/{id}` with the new `hmac_secret` in the
   request body. This atomically swaps the secret.
2. Deploy the receiver-side change to accept BOTH old and new secret for
   a 24-hour overlap window. (The receiver, not yauth, is responsible for
   tolerating overlap — yauth only ever signs with the current secret.)
3. After the overlap window, retire the old secret on the receiver.

## Dead-letter triage

Dead-lettered entries (`status = dead_letter`) are visible via
`GET /audit/destinations/{id}/outbox`. To re-attempt delivery after the
underlying issue is fixed:

1. Identify the affected `audit_log_id` values from the outbox list.
2. Issue a `POST /audit/replay` for those ids + the destination.
3. Monitor `yauth_audit_export_events_total{outcome="success"}` to confirm.

The `yauth_audit_export_dead_letter_total{destination}` counter is
intentionally never reset — a non-decreasing counter is the right shape
for SLO-style alerting on persistent destination failures.

## OTel metrics

| Metric | Labels | Meaning |
|---|---|---|
| `yauth_audit_export_events_total` | `destination`, `format`, `outcome` | Events shipped per destination/format/outcome (`success`, `retry`, `dead_letter`, `not_implemented`) |
| `yauth_audit_export_lag_seconds` | `destination` | Seconds since the oldest pending outbox entry — a gauge that climbs when the destination is unhealthy |
| `yauth_audit_export_dead_letter_total` | `destination` | Monotonic counter for dead-letter transitions |

Alert on:
- `lag_seconds > 300` for 5 minutes → destination receiver is unhealthy
- `dead_letter_total` rate > 0 → at least one event gave up

## Security gotchas

- **Never log destination secrets.** The dispatcher takes the HMAC secret /
  HEC token / Datadog API key by value and uses it only inside the
  request-signing path. The route layer strips secrets from list/get
  responses (only `hmac_configured: true/false` surfaces).
- **TLS for syslog**: TCP+TLS (port 6514) is the conventional secure
  transport. The current implementation supports `transport=tcp` and
  `transport=udp`; `transport=tls` is reserved and returns
  `NotImplemented` until the rustls wiring lands in the follow-up.
- **UDP syslog is unauthenticated**: any host with network reach to the
  receiver can forge messages. Use TCP+TLS for compliance environments.
- **Cross-org leakage**: per-org destinations match ONLY on identical
  `organization_id`. Pentest 03 asserts this property — see
  `crates/yauth/tests/audit_export_pentest.rs`.
- **PII**: audit events carry IPs, emails, and free-form metadata. SIEM
  ingestion contracts must comply with your data-classification policy.

## Configuration

```rust
use yauth::prelude::*;
use yauth::config::AuditExportConfig;
use std::time::Duration;

let yauth = YAuthBuilder::new(backend, config)
    .with_bearer(bearer_config)
    .with_audit_export(AuditExportConfig {
        batch_size: 100,
        batch_interval: Duration::from_secs(5),
        max_inflight: 4,
        retry_max_attempts: 5,
        include_event_types: None,
        http_timeout: Duration::from_secs(10),
        signature_window: Duration::from_secs(300),
    })
    .build()
    .await?;

// Spawn drain workers (one per active destination) AFTER build:
let workers = yauth::plugins::audit_export::AuditExportWorkers::spawn(
    yauth.state(),
    &yauth.state().config_audit_export_or_default(),
).await?;

// On shutdown:
let report = workers.shutdown(Duration::from_secs(10)).await;
log::info!("audit-export shutdown: clean={} forced={}", report.clean, report.forced);
```

## Out-of-scope / follow-up

The following items are intentionally NOT in the MVP and are tracked as
follow-up work:

- ~~**Splunk HEC dispatch**~~ — SHIPPED in #96 Phase B. See
  `docs/audit-export/splunk.md`. Real `POST /services/collector` with
  documented HEC envelope, two wiremock-backed pentests.
- ~~**Datadog logs dispatch**~~ — SHIPPED in #96 Phase B. See
  `docs/audit-export/datadog.md`. Real `POST /api/v2/logs` with
  documented log envelope, two wiremock-backed pentests.
- ~~**TCP+TLS syslog (port 6514)**~~ — SHIPPED in #96 Phase B. See
  `docs/audit-export/syslog.md`. RFC 6587 octet-counted framing on a
  rustls TLS stream, two in-process pentests with `rcgen`-generated
  self-signed certs (no real network).
- ~~**Real S3 dispatch via `object_store`**~~ — SHIPPED in #96 Phase B.
  Production uses `AmazonS3` (built per-(bucket, region) from
  `AmazonS3Builder::from_env`); tests + self-hosted MinIO/R2/Wasabi
  deployments install a custom `Arc<dyn ObjectStore>` via
  `set_s3_object_store_override`. Newline-delimited JSON, three
  partition strategies (`by_date` / `by_org` / `by_date_and_org`),
  three `InMemory`-backed pentests.
- **CEF**: implemented + tested; pending real-world validation against
  enterprise CEF parsers (ArcSight, Splunk Universal Forwarder).
- **SolidJS UI**: Vue UI ships in this PR; SolidJS port follows.
- **SQL backend impls** for `AuditExportDestinationRepository` and
  `AuditOutboxRepository` — Memory backend is canonical; SQL backends
  stub at HTTP 501.
