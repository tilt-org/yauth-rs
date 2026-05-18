#![forbid(unsafe_code)]
//! Per-destination dispatchers. Each kind implements `Dispatch::send_one`
//! and is responsible for translating a `RenderedEvent` into a destination-
//! specific request.

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

use crate::domain;

use super::format::{self, RenderedEvent};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("io: {0}")]
    Io(String),
    #[error("http: status {0} body={1}")]
    HttpStatus(u16, String),
    /// Transport-level failure (TCP connect refused, TLS handshake failed,
    /// HTTP request never returned). Distinguished from `HttpStatus` so the
    /// worker's backoff/dead-letter logic can treat both the same way without
    /// having to inspect the inner message.
    #[error("transport: {0}")]
    Transport(String),
    #[error("format: {0}")]
    Format(#[from] format::FormatError),
    #[error("destination kind not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("dispatch: {0}")]
    Other(String),
}

/// Trait-style enum: each destination kind dispatches a single rendered
/// event. The dispatcher takes a reference to the `AuditLog` and the
/// destination so it can re-render or attach destination-specific headers.
pub struct Dispatcher {
    http: reqwest::Client,
    /// Window passed to verify_hmac_signature on receivers. The dispatcher
    /// itself does NOT use this — it always signs with the current time —
    /// but it is exposed for diagnostic surfaces and the test-side
    /// `verify_hmac_signature` helper.
    #[allow(dead_code)]
    pub(crate) signature_window: Duration,
    /// Optional override hook used by tests to inject a fake clock /
    /// fake transport. None in production.
    pub(crate) test_hooks: Option<Arc<TestHooks>>,
}

/// Injection points exposed only to tests; they let the dispatcher record
/// the last rendered body for assertion + override the unix-time used in
/// HMAC signatures (for the "timestamp drift" pentest).
pub type S3WriteCapture = Arc<tokio::sync::Mutex<Vec<(String, Vec<u8>)>>>;
pub type SyslogCapture = Arc<tokio::sync::Mutex<Vec<(String, u16, Vec<u8>)>>>;

#[derive(Default)]
pub struct TestHooks {
    pub(crate) clock_override: Option<i64>,
    pub(crate) last_body: tokio::sync::Mutex<Option<Vec<u8>>>,
    pub(crate) last_signature_header: tokio::sync::Mutex<Option<String>>,
    /// When set, S3-flavored dispatch routes here instead of the real S3
    /// client. Production constructs a real object_store-backed client.
    pub(crate) s3_writes: Option<S3WriteCapture>,
    /// When set, Syslog UDP dispatches go here instead of opening a real
    /// socket. The pair is (host, port, body).
    pub(crate) syslog_capture: Option<SyslogCapture>,
}

impl Dispatcher {
    pub fn new(http_timeout: Duration, signature_window: Duration) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(http_timeout)
                .build()
                .expect("reqwest client construction must succeed"),
            signature_window,
            test_hooks: None,
        }
    }

    /// Create a dispatcher with test hooks attached. Tests use this to
    /// capture outbound bodies + inject a fake clock for the
    /// HMAC-timestamp-drift pentest.
    pub fn with_test_hooks(
        http_timeout: Duration,
        signature_window: Duration,
        hooks: Arc<TestHooks>,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(http_timeout)
                .build()
                .expect("reqwest client construction must succeed"),
            signature_window,
            test_hooks: Some(hooks),
        }
    }

    fn now_unix(&self) -> i64 {
        if let Some(hooks) = &self.test_hooks
            && let Some(t) = hooks.clock_override
        {
            return t;
        }
        chrono::Utc::now().timestamp()
    }

    /// Dispatch one rendered event to a destination. Errors are
    /// retryable unless tagged `NotImplemented`.
    pub async fn send_one(
        &self,
        dest: &domain::AuditExportDestination,
        audit: &domain::AuditLog,
    ) -> Result<(), DispatchError> {
        match &dest.kind {
            domain::AuditExportDestinationKind::Webhook {
                url,
                format,
                hmac_secret,
                headers,
            } => {
                let rendered = format::render(*format, audit, 13)?;
                self.send_webhook(url, hmac_secret.as_deref(), headers, &rendered)
                    .await
            }
            domain::AuditExportDestinationKind::Syslog {
                host,
                port,
                transport,
                facility,
            } => {
                let rendered =
                    format::render(domain::AuditExportFormat::Rfc5424, audit, *facility)?;
                self.send_syslog(host, *port, *transport, &rendered).await
            }
            domain::AuditExportDestinationKind::S3 {
                bucket,
                prefix,
                region,
                partition,
            } => {
                // S3 uses JSON for archive-friendly newline-delimited records.
                let rendered = format::render(domain::AuditExportFormat::Json, audit, 13)?;
                let key = s3_key(bucket, prefix, *partition, audit);
                self.send_s3(bucket, region, &key, &rendered).await
            }
            domain::AuditExportDestinationKind::Splunk { hec_url, hec_token } => {
                self.send_splunk(hec_url, hec_token, audit).await
            }
            domain::AuditExportDestinationKind::Datadog { site, api_key } => {
                self.send_datadog(site, api_key, audit).await
            }
        }
    }

    // ------------------------------------------------------------------
    // Splunk HEC (HTTP Event Collector)
    //
    // Spec: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
    //
    // Wire shape:
    //   POST <hec_url>/services/collector
    //   Authorization: Splunk <token>
    //   Content-Type: application/json
    //   {
    //     "time": <unix>,
    //     "host": "<hostname>",
    //     "source": "yauth",
    //     "sourcetype": "yauth:audit",
    //     "event": { ...audit row JSON... }
    //   }
    //
    // We never log the token, even masked. The body is captured for tests via
    // `TestHooks::last_body` but the token itself is only attached to the
    // request header — never to `last_body`.
    // ------------------------------------------------------------------

    async fn send_splunk(
        &self,
        hec_url: &str,
        hec_token: &str,
        audit: &domain::AuditLog,
    ) -> Result<(), DispatchError> {
        // Always JSON inside the HEC envelope — Splunk parses the event as
        // structured data when sourcetype hints `:audit`.
        let inner = format::render(domain::AuditExportFormat::Json, audit, 13)?;
        let event: serde_json::Value = serde_json::from_slice(&inner.bytes)
            .map_err(|e| DispatchError::Other(e.to_string()))?;
        let envelope = serde_json::json!({
            "time": self.now_unix(),
            "host": hostname_for_envelope(),
            "source": "yauth",
            "sourcetype": "yauth:audit",
            "event": event,
        });
        let body =
            serde_json::to_vec(&envelope).map_err(|e| DispatchError::Other(e.to_string()))?;

        let url = join_collector(hec_url);

        if let Some(hooks) = &self.test_hooks {
            *hooks.last_body.lock().await = Some(body.clone());
        }

        // Splunk HEC accepts `Authorization: Splunk <token>`.
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Splunk {hec_token}"))
            .header("Content-Type", "application/json")
            .header("User-Agent", "yauth-audit-export/1")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                DispatchError::Transport(redact_secret_in_err(&e.to_string(), hec_token))
            })?;

        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            // The response body from Splunk can echo back our envelope — but
            // never the token (Splunk strips it). Truncate to bound on noisy
            // 5xx pages.
            let body = resp.text().await.unwrap_or_default();
            Err(DispatchError::Transport(format!(
                "splunk status {status} body={}",
                truncate(&body, 512)
            )))
        }
    }

    // ------------------------------------------------------------------
    // Datadog logs HTTP intake
    //
    // Spec: https://docs.datadoghq.com/api/latest/logs/#send-logs
    //
    // Wire shape:
    //   POST https://http-intake.logs.<site>/api/v2/logs
    //   DD-API-KEY: <api_key>
    //   Content-Type: application/json
    //   [{
    //     "ddsource": "yauth",
    //     "service": "yauth",
    //     "hostname": "<host>",
    //     "timestamp": <unix_ms>,
    //     "message": "<audit JSON as string>",
    //     "audit": { ...audit JSON object... }
    //   }]
    //
    // `site` is configurable to support all the DD regions:
    //   datadoghq.com       (US1, default)
    //   us3.datadoghq.com   (US3)
    //   us5.datadoghq.com   (US5)
    //   datadoghq.eu        (EU)
    //   ap1.datadoghq.com   (AP1)
    //   ddog-gov.com        (US1-FED)
    //
    // We never log the api_key, even masked.
    // ------------------------------------------------------------------

    async fn send_datadog(
        &self,
        site: &str,
        api_key: &str,
        audit: &domain::AuditLog,
    ) -> Result<(), DispatchError> {
        let inner = format::render(domain::AuditExportFormat::Json, audit, 13)?;
        let event_obj: serde_json::Value = serde_json::from_slice(&inner.bytes)
            .map_err(|e| DispatchError::Other(e.to_string()))?;
        // Datadog's intake is an array of log entries. `message` is a string
        // (DD's free-text search field); `audit` carries the structured object
        // so dashboards can filter on `@audit.event_type`, `@audit.user_id`,
        // etc.
        let envelope = serde_json::json!([{
            "ddsource": "yauth",
            "service": "yauth",
            "hostname": hostname_for_envelope(),
            "timestamp": self.now_unix() * 1000,
            "message": serde_json::to_string(&event_obj).unwrap_or_default(),
            "audit": event_obj,
        }]);
        let body =
            serde_json::to_vec(&envelope).map_err(|e| DispatchError::Other(e.to_string()))?;

        let url = datadog_intake_url(site);

        if let Some(hooks) = &self.test_hooks {
            *hooks.last_body.lock().await = Some(body.clone());
        }

        let resp = self
            .http
            .post(&url)
            .header("DD-API-KEY", api_key)
            .header("Content-Type", "application/json")
            .header("User-Agent", "yauth-audit-export/1")
            .body(body)
            .send()
            .await
            .map_err(|e| DispatchError::Transport(redact_secret_in_err(&e.to_string(), api_key)))?;

        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(DispatchError::Transport(format!(
                "datadog status {status} body={}",
                truncate(&body, 512)
            )))
        }
    }

    // ------------------------------------------------------------------
    // Webhook
    // ------------------------------------------------------------------

    async fn send_webhook(
        &self,
        url: &str,
        hmac_secret: Option<&str>,
        headers: &std::collections::HashMap<String, String>,
        rendered: &RenderedEvent,
    ) -> Result<(), DispatchError> {
        let mut req = self
            .http
            .post(url)
            .header("Content-Type", rendered.content_type)
            .header("User-Agent", "yauth-audit-export/1");

        let ts = self.now_unix();
        if let Some(secret) = hmac_secret {
            let sig = compute_hmac_signature(secret, ts, &rendered.bytes);
            let header_value = format!("t={},v1={}", ts, sig);
            if let Some(hooks) = &self.test_hooks {
                *hooks.last_signature_header.lock().await = Some(header_value.clone());
            }
            req = req.header("X-Yauth-Signature", header_value);
        }
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(hooks) = &self.test_hooks {
            *hooks.last_body.lock().await = Some(rendered.bytes.clone());
        }
        let resp = req
            .body(rendered.bytes.clone())
            .send()
            .await
            .map_err(|e| DispatchError::Io(e.to_string()))?;

        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            // Never echo secrets / hmac values into error string.
            Err(DispatchError::HttpStatus(status, truncate(&body, 512)))
        }
    }

    // ------------------------------------------------------------------
    // Syslog
    // ------------------------------------------------------------------

    async fn send_syslog(
        &self,
        host: &str,
        port: u16,
        transport: domain::SyslogTransport,
        rendered: &RenderedEvent,
    ) -> Result<(), DispatchError> {
        if let Some(hooks) = &self.test_hooks
            && let Some(capture) = &hooks.syslog_capture
        {
            capture
                .lock()
                .await
                .push((host.to_string(), port, rendered.bytes.clone()));
            return Ok(());
        }
        match transport {
            domain::SyslogTransport::UdpUnsecured => {
                let sock = UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(|e| DispatchError::Io(e.to_string()))?;
                sock.send_to(&rendered.bytes, (host, port))
                    .await
                    .map_err(|e| DispatchError::Io(e.to_string()))?;
                Ok(())
            }
            domain::SyslogTransport::Tcp => {
                let mut stream = TcpStream::connect((host, port))
                    .await
                    .map_err(|e| DispatchError::Io(e.to_string()))?;
                // RFC 6587 §3.4.1: octet counting framing for stream syslog.
                let len = rendered.bytes.len();
                let frame = format!("{} ", len);
                stream
                    .write_all(frame.as_bytes())
                    .await
                    .map_err(|e| DispatchError::Io(e.to_string()))?;
                stream
                    .write_all(&rendered.bytes)
                    .await
                    .map_err(|e| DispatchError::Io(e.to_string()))?;
                stream
                    .shutdown()
                    .await
                    .map_err(|e| DispatchError::Io(e.to_string()))?;
                Ok(())
            }
            domain::SyslogTransport::TcpTls => self.send_syslog_tls(host, port, rendered).await,
        }
    }

    // ------------------------------------------------------------------
    // Syslog TCP+TLS (port 6514) — RFC 5425 secure syslog
    //
    // Wraps a TCP stream in rustls and writes the RFC 6587 §3.4.1 octet-
    // counted frame on the encrypted channel. The trust anchors are the
    // standard webpki-roots set; operators with private CAs can install
    // a custom `TlsConnector` via `set_syslog_tls_connector_override`.
    //
    // The dispatcher does NOT pin a specific server certificate — that
    // would prevent rotation. We rely on the standard rustls X.509
    // verifier path: SNI must match the destination's `host` field, and
    // the chain must terminate at a trusted root.
    // ------------------------------------------------------------------

    async fn send_syslog_tls(
        &self,
        host: &str,
        port: u16,
        rendered: &RenderedEvent,
    ) -> Result<(), DispatchError> {
        let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| DispatchError::Transport(format!("invalid syslog hostname: {e}")))?;
        let connector = syslog_tls_connector()?;

        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| DispatchError::Transport(format!("syslog tcp connect: {e}")))?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| DispatchError::Transport(format!("syslog tls handshake: {e}")))?;

        // RFC 6587 §3.4.1 octet counting — same framing as plaintext TCP,
        // applied over the TLS stream.
        let len = rendered.bytes.len();
        let frame = format!("{} ", len);
        tls.write_all(frame.as_bytes())
            .await
            .map_err(|e| DispatchError::Transport(format!("syslog tls write: {e}")))?;
        tls.write_all(&rendered.bytes)
            .await
            .map_err(|e| DispatchError::Transport(format!("syslog tls write: {e}")))?;
        tls.shutdown()
            .await
            .map_err(|e| DispatchError::Transport(format!("syslog tls shutdown: {e}")))?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // S3-compatible object storage (issue #96 Phase B).
    //
    // The dispatcher writes one newline-delimited JSON object per audit
    // row at a partition-derived key. The backend is `object_store` — by
    // default a real AWS S3 client, but tests inject `InMemory` via
    // `set_s3_object_store_override`. The same hook is the operator-
    // facing path for self-hosted S3-compatible backends (MinIO, R2,
    // Wasabi) — operators construct the store at startup and install it.
    //
    // The legacy `TestHooks.s3_writes` capture is kept as the in-test
    // fast path the early conformance tests use.
    // ------------------------------------------------------------------

    async fn send_s3(
        &self,
        bucket: &str,
        region: &str,
        key: &str,
        rendered: &RenderedEvent,
    ) -> Result<(), DispatchError> {
        // Test-hook capture path stays — keeps legacy pentest 4-7 working.
        if let Some(hooks) = &self.test_hooks
            && let Some(writes) = &hooks.s3_writes
        {
            writes
                .lock()
                .await
                .push((key.to_string(), rendered.bytes.clone()));
            return Ok(());
        }

        let store = s3_object_store_for(bucket, region)?;
        // Append a trailing newline so concatenated records form proper
        // jsonl.
        let mut body = rendered.bytes.clone();
        if !body.ends_with(b"\n") {
            body.push(b'\n');
        }
        let path = object_store::path::Path::from(key);
        let payload: object_store::PutPayload = bytes::Bytes::from(body).into();
        // `ObjectStoreExt::put` is the trait-default convenience wrapper.
        use object_store::ObjectStoreExt;
        store
            .put(&path, payload)
            .await
            .map_err(|e| DispatchError::Transport(format!("s3 put: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HMAC signing — Stripe-style. Signature input is `<ts>.<body>` so a captured
// signature can't be replayed with a different body. Receivers reject
// signatures older than the configured window (default 5min, see
// AuditExportConfig.signature_window).
// ---------------------------------------------------------------------------

pub fn compute_hmac_signature(secret: &str, unix_ts: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(unix_ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Receiver-side verification helper. Tests use this to validate the
/// "HMAC verification" + "timestamp drift" pentests. Documented in
/// `docs/audit-export/webhook.md`.
///
/// Returns `Ok(())` if the signature is valid and the timestamp is within
/// `signature_window` of `now_unix`. Uses constant-time comparison.
pub fn verify_hmac_signature(
    secret: &str,
    header_value: &str,
    body: &[u8],
    now_unix: i64,
    signature_window: Duration,
) -> Result<(), VerifyError> {
    let mut ts: Option<i64> = None;
    let mut sig: Option<String> = None;
    for part in header_value.split(',') {
        let (k, v) = match part.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        match k.trim() {
            "t" => ts = v.parse().ok(),
            "v1" => sig = Some(v.to_string()),
            _ => {}
        }
    }
    let ts = ts.ok_or(VerifyError::MalformedHeader)?;
    let sig_hex = sig.ok_or(VerifyError::MalformedHeader)?;

    // Timestamp drift — Stripe-style replay protection.
    let drift = (now_unix - ts).unsigned_abs();
    if drift > signature_window.as_secs() {
        return Err(VerifyError::Stale);
    }

    let expected = compute_hmac_signature(secret, ts, body);
    if constant_time_eq(expected.as_bytes(), sig_hex.as_bytes()) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("malformed signature header")]
    MalformedHeader,
    #[error("signature outside accepted window")]
    Stale,
    #[error("signature does not match body")]
    SignatureMismatch,
}

/// Constant-time byte equality. Always compares full length to avoid
/// length-leak side channel.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still walk the longer slice so timing reflects the longest path.
        let _ = a.iter().fold(0u8, |acc, x| acc | x);
        let _ = b.iter().fold(0u8, |acc, x| acc | x);
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// S3 key construction
// ---------------------------------------------------------------------------

fn s3_key(
    _bucket: &str,
    prefix: &str,
    partition: domain::S3Partition,
    audit: &domain::AuditLog,
) -> String {
    let p = prefix.trim_end_matches('/');
    let date = audit.created_at.format("%Y/%m/%d");
    let org = extract_org_from_audit(audit);
    // We use `.jsonl` (newline-delimited JSON) so a single key can hold
    // multiple records when downstream replay tooling concatenates frames.
    // The dispatcher writes one record per object today; the suffix is
    // forward-compatible with batched writes.
    match partition {
        domain::S3Partition::ByDate => format!("{}/{}/{}.jsonl", p, date, audit.id),
        domain::S3Partition::ByOrg => format!("{}/org={}/{}.jsonl", p, org, audit.id),
        domain::S3Partition::ByDateAndOrg => {
            format!("{}/org={}/{}/{}.jsonl", p, org, date, audit.id)
        }
    }
}

/// Extract `organization_id` from the audit row's metadata, falling back to
/// `global` for deployment-wide events. Memory backend stores org scope in
/// `metadata.organization_id`; SQL backends will likely materialize a column
/// at which point this helper can switch to reading it directly.
fn extract_org_from_audit(audit: &domain::AuditLog) -> String {
    audit
        .metadata
        .as_ref()
        .and_then(|m| m.get("organization_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "global".to_string())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n])
    }
}

/// Best-effort hostname for the HEC / DD log envelope. We use the gethostname
/// crate transitively via the OS; if that's unavailable we fall back to a
/// stable string so the dispatcher never panics.
fn hostname_for_envelope() -> String {
    // hostname() isn't in the std lib — but `gethostname` is a transitive dep
    // of the rest of the workspace. For the dispatcher, "yauth" is a safe
    // fallback that never leaks PII (an FQDN might).
    std::env::var("YAUTH_AUDIT_HOSTNAME").unwrap_or_else(|_| "yauth".to_string())
}

/// Join the user-supplied HEC base URL with `/services/collector`, idempotent
/// against trailing slash. Never panics on a malformed URL; reqwest will reject
/// non-URLs at `.post()` time.
fn join_collector(hec_url: &str) -> String {
    let base = hec_url.trim_end_matches('/');
    if base.ends_with("/services/collector") {
        base.to_string()
    } else {
        format!("{base}/services/collector")
    }
}

/// Process-wide override for the S3 object store. Tests install
/// `object_store::memory::InMemory`; operators with self-hosted MinIO / R2 /
/// Wasabi install a pre-configured `AmazonS3` (with custom endpoint, access
/// keys, etc.). Production AWS deployments leave this `None` and the
/// dispatcher builds an `AmazonS3` per (bucket, region) pair on first use.
static S3_OBJECT_STORE_OVERRIDE: std::sync::RwLock<
    Option<std::sync::Arc<dyn object_store::ObjectStore>>,
> = std::sync::RwLock::new(None);

/// Install a process-wide override for the S3 object store. Pass `None` to
/// clear. Returns the previous override so callers can restore state.
///
/// Tests use this with `object_store::memory::InMemory`. Operators with
/// self-hosted S3-compatible storage construct a fully configured
/// `AmazonS3` (custom endpoint + credentials) and install it at startup.
pub fn set_s3_object_store_override(
    store: Option<std::sync::Arc<dyn object_store::ObjectStore>>,
) -> Option<std::sync::Arc<dyn object_store::ObjectStore>> {
    let mut g = S3_OBJECT_STORE_OVERRIDE
        .write()
        .expect("s3 object store override lock poisoned");
    std::mem::replace(&mut *g, store)
}

/// Resolve the `ObjectStore` to use for an S3 dispatch:
///   1. Process-wide override (tests + self-hosted MinIO / R2 / Wasabi).
///   2. Build an `AmazonS3` from the destination's bucket + region,
///      reading credentials from the environment (AWS_ACCESS_KEY_ID,
///      AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) per the standard SDK
///      conventions.
fn s3_object_store_for(
    bucket: &str,
    region: &str,
) -> Result<std::sync::Arc<dyn object_store::ObjectStore>, DispatchError> {
    if let Ok(g) = S3_OBJECT_STORE_OVERRIDE.read()
        && let Some(s) = g.as_ref()
    {
        return Ok(s.clone());
    }
    let store = object_store::aws::AmazonS3Builder::from_env()
        .with_bucket_name(bucket)
        .with_region(region)
        .build()
        .map_err(|e| DispatchError::Transport(format!("s3 builder: {e}")))?;
    Ok(std::sync::Arc::new(store))
}

/// Process-wide override for the syslog-TLS connector. Tests install a
/// `TlsConnector` configured against a self-signed cert; production leaves
/// it `None` and the dispatcher builds a connector backed by webpki-roots.
///
/// Operators with private CAs can install a custom connector at startup if
/// they need to trust an internal SIEM CA.
static SYSLOG_TLS_CONNECTOR_OVERRIDE: std::sync::RwLock<Option<tokio_rustls::TlsConnector>> =
    std::sync::RwLock::new(None);

/// Install a process-wide override for the syslog-TLS connector. Pass `None`
/// to clear. Returns the previous override so callers can restore state.
pub fn set_syslog_tls_connector_override(
    connector: Option<tokio_rustls::TlsConnector>,
) -> Option<tokio_rustls::TlsConnector> {
    let mut g = SYSLOG_TLS_CONNECTOR_OVERRIDE
        .write()
        .expect("syslog-tls connector lock poisoned");
    std::mem::replace(&mut *g, connector)
}

/// Cached default `TlsConnector` backed by webpki-roots. Built lazily because
/// rustls's CryptoProvider must be installed before constructing a
/// `ClientConfig`, and we don't want to pay that cost in test runs that
/// install their own override.
static DEFAULT_SYSLOG_TLS_CONNECTOR: std::sync::OnceLock<tokio_rustls::TlsConnector> =
    std::sync::OnceLock::new();

fn syslog_tls_connector() -> Result<tokio_rustls::TlsConnector, DispatchError> {
    // 1. Override path (tests + corporate proxies) wins.
    if let Ok(g) = SYSLOG_TLS_CONNECTOR_OVERRIDE.read()
        && let Some(c) = g.as_ref()
    {
        return Ok(c.clone());
    }

    // 2. Default: webpki-roots trust anchors, no client cert.
    let connector = DEFAULT_SYSLOG_TLS_CONNECTOR.get_or_init(|| {
        // Install the ring CryptoProvider exactly once, idempotently — other
        // crates in the process may have done this already (reqwest does at
        // first use when `rustls-tls` is enabled).
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
    });
    Ok(connector.clone())
}

/// Process-wide override for the Datadog intake base URL. Tests + air-gapped
/// corporate proxies install a value here; production leaves it `None` and
/// the dispatcher derives the URL from the destination's `site` code.
///
/// We avoid `std::env::var` because `#![forbid(unsafe_code)]` in this crate
/// rules out the `unsafe { set_var }` callers that would need to install it.
/// A `RwLock<Option<String>>` plus the helper below keeps the override
/// `safe`-only and unit-testable.
static DATADOG_INTAKE_OVERRIDE: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Install a process-wide override for the Datadog intake base URL. Pass
/// `None` to clear. Returns the previous override (if any) so tests can
/// restore state in a `Drop` guard.
///
/// Intended for tests + corporate-proxy deployments; production deployments
/// should use the destination's `site` field.
pub fn set_datadog_intake_base_override(base: Option<String>) -> Option<String> {
    let mut g = DATADOG_INTAKE_OVERRIDE
        .write()
        .expect("datadog intake override lock poisoned");
    std::mem::replace(&mut *g, base)
}

/// Construct the Datadog HTTP log intake URL from a `site` code. Operators
/// supply the site without the scheme — e.g. `datadoghq.com`, `datadoghq.eu`,
/// `us3.datadoghq.com`. We strip leading `https://` if a paste includes it,
/// so misconfiguration doesn't double-protocol the URL.
fn datadog_intake_url(site: &str) -> String {
    if let Ok(g) = DATADOG_INTAKE_OVERRIDE.read()
        && let Some(base) = g.as_deref()
    {
        let base = base.trim_end_matches('/');
        return format!("{base}/api/v2/logs");
    }
    let site = site
        .trim()
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    format!("https://http-intake.logs.{site}/api/v2/logs")
}

/// Strip the secret from a reqwest error string before we surface it through
/// `DispatchError::Transport`. reqwest never logs auth headers itself, but a
/// connection error can include the URL — and operators commonly paste their
/// token into the path by mistake.
fn redact_secret_in_err(s: &str, secret: &str) -> String {
    if secret.is_empty() {
        return s.to_string();
    }
    s.replace(secret, "[REDACTED]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Utc};
    use uuid::Uuid;

    fn audit_sample() -> domain::AuditLog {
        domain::AuditLog {
            id: Uuid::nil(),
            user_id: None,
            event_type: "user.login".into(),
            metadata: None,
            ip_address: None,
            created_at: NaiveDate::from_ymd_opt(2026, 5, 17)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap(),
        }
    }

    #[test]
    fn hmac_signature_is_deterministic() {
        let s1 = compute_hmac_signature("k", 1000, b"body");
        let s2 = compute_hmac_signature("k", 1000, b"body");
        assert_eq!(s1, s2);
    }

    #[test]
    fn hmac_changes_with_timestamp() {
        let s1 = compute_hmac_signature("k", 1000, b"body");
        let s2 = compute_hmac_signature("k", 1001, b"body");
        assert_ne!(s1, s2);
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let body = b"hello";
        let ts = 1_700_000_000_i64;
        let sig = compute_hmac_signature("k", ts, body);
        let header = format!("t={},v1={}", ts, sig);
        assert!(verify_hmac_signature("k", &header, body, ts, Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let body = b"hello";
        let ts = 1_700_000_000_i64;
        let header = format!("t={},v1={}", ts, "deadbeef".repeat(8));
        let err =
            verify_hmac_signature("k", &header, body, ts, Duration::from_secs(60)).unwrap_err();
        assert_eq!(err, VerifyError::SignatureMismatch);
    }

    #[test]
    fn verify_rejects_stale_timestamp() {
        let body = b"hello";
        let ts = 1_700_000_000_i64;
        let sig = compute_hmac_signature("k", ts, body);
        let header = format!("t={},v1={}", ts, sig);
        let now = ts + 1000; // 1000s drift > 300s window
        let err =
            verify_hmac_signature("k", &header, body, now, Duration::from_secs(300)).unwrap_err();
        assert_eq!(err, VerifyError::Stale);
    }

    #[test]
    fn s3_key_includes_date_partition() {
        let key = s3_key(
            "bucket",
            "audit",
            domain::S3Partition::ByDate,
            &audit_sample(),
        );
        assert!(key.starts_with("audit/2026/05/17/"));
        assert!(key.ends_with(".jsonl"));
    }

    #[tokio::test]
    async fn s3_send_uses_test_hook_when_set() {
        let writes = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let hooks = Arc::new(TestHooks {
            s3_writes: Some(writes.clone()),
            ..Default::default()
        });
        let dispatcher =
            Dispatcher::with_test_hooks(Duration::from_secs(5), Duration::from_secs(300), hooks);
        let dest = domain::AuditExportDestination {
            id: Uuid::now_v7(),
            organization_id: None,
            name: "test-s3".into(),
            kind: domain::AuditExportDestinationKind::S3 {
                bucket: "b".into(),
                prefix: "p".into(),
                region: "us-east-1".into(),
                partition: domain::S3Partition::ByDate,
            },
            status: domain::DestinationStatus::Active,
            last_success_at: None,
            last_failure_at: None,
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        };
        dispatcher.send_one(&dest, &audit_sample()).await.unwrap();
        let captured = writes.lock().await;
        assert_eq!(captured.len(), 1);
        assert!(captured[0].0.starts_with("p/2026/05/17/"));
    }
}
