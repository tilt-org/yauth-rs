# Datadog logs destination

> **Status**: SHIPPED in #96 Phase B. The dispatcher posts events to Datadog's
> HTTP log intake at `/api/v2/logs` with the `DD-API-KEY` header and a
> documented log envelope.

## Configuration

`POST /audit/destinations` (admin-only):

```json
{
  "name": "prod-datadog",
  "kind": {
    "type": "datadog",
    "site": "datadoghq.com",
    "api_key": "<DD API key>"
  }
}
```

- `site`: Datadog region code. All current DD regions are supported:

  | Region | `site` value         |
  |--------|----------------------|
  | US1    | `datadoghq.com`      |
  | US3    | `us3.datadoghq.com`  |
  | US5    | `us5.datadoghq.com`  |
  | EU     | `datadoghq.eu`       |
  | AP1    | `ap1.datadoghq.com`  |
  | US1-FED| `ddog-gov.com`       |

  If you accidentally paste the full URL (`https://datadoghq.com`), the
  dispatcher strips the scheme — but operators should provide just the
  hostname suffix.

- `api_key`: Datadog API key with `logs_write` scope. **Never logged**, even
  masked. The key attaches to the `DD-API-KEY` request header only and is
  redacted from any `DispatchError::Transport` message.

## Request shape

```
POST https://http-intake.logs.<site>/api/v2/logs
DD-API-KEY: <api_key>
Content-Type: application/json
User-Agent: yauth-audit-export/1

[
  {
    "ddsource": "yauth",
    "service": "yauth",
    "hostname": "<YAUTH_AUDIT_HOSTNAME or 'yauth'>",
    "timestamp": 1779000000000,
    "message": "{\"id\":\"...\",\"event_type\":\"user.login\",...}",
    "audit": {
      "id": "...",
      "timestamp": "...",
      "event_type": "user.login",
      "user_id": "...",
      "ip_address": "...",
      "metadata": { ... }
    }
  }
]
```

- `message` is the audit row stringified — DD uses this field for free-text
  search.
- `audit` is the structured object — DD parses this and exposes the fields
  as `@audit.event_type`, `@audit.user_id`, etc. in dashboards.
- `timestamp` is **milliseconds** since epoch (DD spec; Splunk uses seconds).

## Failure semantics

| Outcome | Dispatcher action | Worker action |
|---|---|---|
| Connection refused / TLS handshake / timeout | `DispatchError::Transport(...)` | retry per backoff, dead-letter after 5 attempts |
| Intake returns 2xx (typically 202) | `Ok(())` | mark sent |
| Intake returns 4xx / 5xx | `DispatchError::Transport("datadog status N body=...")` | retry; dead-letter after 5 attempts |

The dispatcher redacts the API key from any error string we surface, and
truncates the response body to 512 bytes.

## Intake URL override (tests + corporate proxies)

The crate exposes `yauth::plugins::audit_export::destination::set_datadog_intake_base_override`
for tests and air-gapped corporate-proxy deployments. When set, the
dispatcher replaces `https://http-intake.logs.<site>/api/v2/logs` with
`<override>/api/v2/logs`.

This is the same hook used by the wiremock-backed pentests in this PR; we
expose it publicly so operators behind an outbound proxy can point at the
proxy's `/api/v2/logs` shim.

## Test coverage

Two pentests in `crates/yauth/tests/audit_export_pentest.rs`:

- `pentest_datadog_real_round_trip` — wiremock fake intake asserts the
  request hits `/api/v2/logs` with `DD-API-KEY` and the documented envelope.
- `pentest_datadog_transport_error_dead_letters` — fake intake returns 500,
  asserts the dispatcher returns `Transport(...)` AND that the API key is
  not leaked into the error string.

Both tests run in <1s and never make a real network call.
