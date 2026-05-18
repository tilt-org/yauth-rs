# Splunk HEC destination

> **Status**: SHIPPED in #96 Phase B. The dispatcher posts events to Splunk's
> HTTP Event Collector at `/services/collector` with `Authorization: Splunk
> <token>` and a documented HEC envelope.

## Configuration

`POST /audit/destinations` (admin-only):

```json
{
  "name": "prod-splunk",
  "kind": {
    "type": "splunk",
    "hec_url": "https://splunk.example.com:8088",
    "hec_token": "<HEC token>"
  }
}
```

- `hec_url`: the base of the Splunk HEC instance. The dispatcher posts to
  `<hec_url>/services/collector` — the suffix is appended automatically and is
  idempotent against a trailing slash. Operators who already include the full
  collector path will have it deduplicated.
- `hec_token`: HEC token from your Splunk admin. **Never logged**, even
  masked. The token is attached to the outbound `Authorization` header only;
  it is never written into `DispatchError`, span attributes, or the
  per-destination outbox row.

## Request shape

```
POST <hec_url>/services/collector
Authorization: Splunk <hec_token>
Content-Type: application/json
User-Agent: yauth-audit-export/1

{
  "time": 1779000000,
  "host": "<YAUTH_AUDIT_HOSTNAME or 'yauth'>",
  "source": "yauth",
  "sourcetype": "yauth:audit",
  "event": {
    "id": "...",
    "timestamp": "...",
    "event_type": "user.login",
    "user_id": "...",
    "ip_address": "...",
    "metadata": { ... }
  }
}
```

Splunk parses `sourcetype = yauth:audit` as structured JSON; you don't need a
sourcetype definition on the Splunk side for fields to be searchable.

## Failure semantics

| Outcome | Dispatcher action | Worker action |
|---|---|---|
| Connection refused / TLS handshake fails / timeout | `DispatchError::Transport(...)` | retry per backoff schedule, dead-letter after 5 attempts |
| HEC returns 2xx | `Ok(())` | mark sent |
| HEC returns 4xx / 5xx | `DispatchError::Transport("splunk status N body=...")` | retry; dead-letter after 5 attempts |

The dispatcher never echoes the HEC token into the `Transport` error, even if
the upstream proxy logs it. The error body is truncated to 512 bytes.

## Hostname override

The `host` field defaults to the string `yauth`. To set it to your pod /
machine hostname, export `YAUTH_AUDIT_HOSTNAME=<value>` in the deployment
environment. We intentionally avoid `gethostname(3)` to keep the dispatcher
free of OS-specific PII (FQDNs in shared clusters).

## Test coverage

Two pentests in `crates/yauth/tests/audit_export_pentest.rs`:

- `pentest_splunk_real_round_trip` — spins up `wiremock` as a fake HEC,
  asserts the request hits `/services/collector` with the documented
  Authorization header and HEC envelope shape.
- `pentest_splunk_transport_error_dead_letters` — fake HEC returns 500,
  asserts the dispatcher returns `Transport(...)` and that the HEC token is
  NOT in the error string.

Neither test makes a real network call; both run in <1s.
