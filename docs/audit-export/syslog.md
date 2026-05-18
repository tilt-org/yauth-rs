# Syslog destination (RFC 5424)

The syslog destination ships each audit event as a single RFC 5424
formatted message over TCP, UDP, or TCP+TLS.

## Configuration

`POST /audit/destinations` (admin-only):

```json
{
  "name": "siem-collector",
  "kind": {
    "type": "syslog",
    "host": "siem.example.internal",
    "port": 6514,
    "transport": "tcp",
    "facility": 13
  }
}
```

- `transport`:
  - `tcp` (default) — RFC 6587 octet-counting framing, plaintext.
  - `udp` — unauthenticated; **not recommended** for compliance contexts.
  - `tls` — RFC 5425 secure syslog. RFC 6587 octet-counted framing on a
    TCP+TLS stream. Default port is 6514. Trust anchors are the standard
    webpki-roots set; operators with private CAs can install a custom
    `tokio_rustls::TlsConnector` via
    `set_syslog_tls_connector_override()`.
- `facility`: RFC 5424 facility code 0..=23. Default is 13 (security/auth).

## Wire format

```
<PRI>1 <TIMESTAMP> <HOSTNAME> <APP-NAME> <PROCID> <MSGID> <SD> <MSG>
```

- `PRI` = `facility * 8 + severity`. Severity is hardcoded to 6 (info).
  Facility 13 + severity 6 = `<110>`.
- `TIMESTAMP`: RFC 3339 with microsecond precision, UTC (`Z`).
- `HOSTNAME` + `APP-NAME`: both `yauth`. Operators tag the collector side
  with their own hostname.
- `PROCID`: `-` (nilvalue).
- `MSGID`: the audit event_type, sanitized to `[A-Za-z0-9._-]{1,32}`.
- `SD` (structured data): `[yauth@32473 id="..." event_type="..." user_id="..." ip="..."]`.
  PEN 32473 is the IANA-reserved documentation enterprise number.
  Operators who need a canonical PEN should override this in a follow-up.
- `MSG`: JSON-encoded audit metadata.

Example:

```
<110>1 2026-05-17T16:22:45.235404Z yauth yauth - user.login [yauth@32473 id="019e36bf-..." event_type="user.login" user_id="019e36bf-..." ip="203.0.113.5"] {"event_type":"user.login","ip_address":"203.0.113.5","metadata":null,"user_id":"019e36bf-..."}
```

## TLS (RFC 5425)

TCP+TLS over port 6514 is the conventional secure transport. The
dispatcher:

1. Opens a TCP connection to `<host>:<port>` (default port 6514 in the
   admin UI form).
2. Wraps the stream with rustls using `host` as the SNI. The standard
   X.509 verifier path applies — the chain must terminate at a trusted
   root and the leaf SAN must match `host`.
3. Writes the RFC 6587 §3.4.1 octet-counted frame on the encrypted
   stream.

We don't pin a specific server certificate — pinning prevents rotation.
For private-CA deployments, install a custom `TlsConnector` at startup:

```rust
use yauth::plugins::audit_export::destination::set_syslog_tls_connector_override;

let private_ca: &[u8] = include_bytes!("/etc/yauth/private-ca.der");
let mut roots = tokio_rustls::rustls::RootCertStore::empty();
roots.add(tokio_rustls::rustls::pki_types::CertificateDer::from(private_ca.to_vec()))?;
let config = tokio_rustls::rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
set_syslog_tls_connector_override(Some(tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))));
```

Failures (connect refused, handshake failure, write error) surface as
`DispatchError::Transport(...)` and follow the same retry + dead-letter
path as every other dispatcher.

## End-to-end pentests

`crates/yauth/tests/audit_export_pentest.rs`:

- `pentest_09_rfc5424_framing` — asserts the wire format invariants
  (PRI, version, app, PROCID, SD with `[yauth@32473 ...]`).
- `pentest_syslog_tls_round_trip` — runs an in-process rustls server
  with an `rcgen`-generated self-signed cert. Dispatcher → real TLS
  handshake → real frame on the wire → server reads the bytes. Asserts
  the octet count matches the body length and the body begins with
  `<110>1 yauth yauth - user.login`.
- `pentest_syslog_tls_handshake_failure_dead_letters` — points the
  dispatcher at a closed port; asserts `DispatchError::Transport(_)`.
