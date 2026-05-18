#![forbid(unsafe_code)]
//! Output format adapters. JSON is the default; RFC 5424 is required for
//! syslog destinations. CEF is a stub (returns the JSON body with a
//! `\"format\":\"cef\"` envelope) — full CEF escaping/output lands in a
//! follow-up.

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::domain;

/// Rendered body ready to ship over a destination. Bytes-typed because
/// syslog framing carries the PRI <N> prefix in ASCII bytes; JSON is also
/// just bytes by the time it leaves here.
pub struct RenderedEvent {
    pub bytes: Vec<u8>,
    /// Content-Type for HTTP destinations.
    pub content_type: &'static str,
}

/// Format an `AuditLog` row for shipment.
pub fn render(
    format: domain::AuditExportFormat,
    audit: &domain::AuditLog,
    facility: u8,
) -> Result<RenderedEvent, FormatError> {
    match format {
        domain::AuditExportFormat::Json => render_json(audit),
        domain::AuditExportFormat::Cef => render_cef(audit),
        domain::AuditExportFormat::Rfc5424 => render_rfc5424(audit, facility),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("json serialization: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid format input: {0}")]
    Invalid(String),
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn render_json(audit: &domain::AuditLog) -> Result<RenderedEvent, FormatError> {
    let v = serde_json::json!({
        "id": audit.id,
        "timestamp": DateTime::<Utc>::from_naive_utc_and_offset(audit.created_at, Utc).to_rfc3339(),
        "event_type": audit.event_type,
        "user_id": audit.user_id,
        "ip_address": audit.ip_address,
        "metadata": audit.metadata,
    });
    let bytes = serde_json::to_vec(&v)?;
    Ok(RenderedEvent {
        bytes,
        content_type: "application/json",
    })
}

// ---------------------------------------------------------------------------
// CEF (ArcSight Common Event Format)
//
// CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
// Extension is k=v pairs separated by spaces.
// The "CEF escaping" pentest exercises the helper below.
// ---------------------------------------------------------------------------

/// Escape CEF prefix fields (Device Vendor, Product, Version, Signature ID, Name)
/// per the ArcSight CEF spec:
///   - `\` → `\\`
///   - `|` → `\|`
///   - newlines normalized to spaces (NL inside prefix fields is undefined)
pub fn cef_escape_prefix(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' | '\r' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Escape CEF extension VALUES per the spec:
///   - `\` → `\\`
///   - `=` → `\=`
///   - newline → `\n` (literal two-char escape sequence — ArcSight requirement)
///   - `|` is allowed in extension values
pub fn cef_escape_extension(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

fn render_cef(audit: &domain::AuditLog) -> Result<RenderedEvent, FormatError> {
    let name = cef_escape_prefix(&audit.event_type);
    let signature = cef_escape_prefix(&audit.event_type);
    // Severity 3 (informational) — auth audits aren't IDS alerts. Operators
    // can map severities later via metadata.
    let header = format!(
        "CEF:0|{}|{}|{}|{}|{}|{}",
        cef_escape_prefix("yauth"),
        cef_escape_prefix("yauth"),
        cef_escape_prefix(env!("CARGO_PKG_VERSION")),
        signature,
        name,
        3
    );

    let mut extension = String::new();
    extension.push_str(&format!(
        "|rt={} ",
        audit.created_at.and_utc().timestamp_millis()
    ));
    if let Some(uid) = audit.user_id {
        extension.push_str(&format!(
            "suser={} ",
            cef_escape_extension(&uid.to_string())
        ));
    }
    if let Some(ip) = &audit.ip_address {
        extension.push_str(&format!("src={} ", cef_escape_extension(ip)));
    }
    // Flatten one level of metadata into ext_<key>=<value> pairs. Nested
    // values are serialized to JSON-as-string.
    if let Some(serde_json::Value::Object(map)) = &audit.metadata {
        for (k, v) in map {
            let value_str = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            extension.push_str(&format!(
                "cs1Label={} cs1={} ",
                cef_escape_extension(k),
                cef_escape_extension(&value_str)
            ));
        }
    }
    let body = format!("{}{}", header, extension.trim_end());
    Ok(RenderedEvent {
        bytes: body.into_bytes(),
        content_type: "text/plain; charset=utf-8",
    })
}

// ---------------------------------------------------------------------------
// RFC 5424 Syslog
//
// Layout:
//   <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP
//   STRUCTURED-DATA SP MSG
//
// PRI = facility * 8 + severity. Severity 6 = info.
// Implementation: produces a strict RFC 5424 line without BOM. The pentest
// asserts PRI/version/timestamp/hostname/app-name/MSGID/structured-data.
// ---------------------------------------------------------------------------

const SYSLOG_VERSION: u8 = 1;
const SYSLOG_SEVERITY_INFO: u8 = 6;
const SYSLOG_HOSTNAME: &str = "yauth"; // operators set their own collector hostname; we tag ourselves
const SYSLOG_APP_NAME: &str = "yauth";

fn render_rfc5424(audit: &domain::AuditLog, facility: u8) -> Result<RenderedEvent, FormatError> {
    if facility > 23 {
        return Err(FormatError::Invalid(format!(
            "invalid syslog facility {} (must be 0..=23)",
            facility
        )));
    }
    let pri = (facility as u16) * 8 + SYSLOG_SEVERITY_INFO as u16;
    let ts = rfc5424_timestamp(audit.created_at);
    let msgid = sanitize_msgid(&audit.event_type);
    let sd = structured_data(audit);
    let msg = render_msg(audit);

    let line = format!(
        "<{}>{} {} {} {} - {} {} {}",
        pri, SYSLOG_VERSION, ts, SYSLOG_HOSTNAME, SYSLOG_APP_NAME, msgid, sd, msg
    );
    Ok(RenderedEvent {
        bytes: line.into_bytes(),
        content_type: "text/plain; charset=utf-8",
    })
}

fn rfc5424_timestamp(ts: NaiveDateTime) -> String {
    DateTime::<Utc>::from_naive_utc_and_offset(ts, Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// MSGID is a single ASCII token: max 32 chars, no SPACE / control chars.
fn sanitize_msgid(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .take(32)
        .collect();
    if out.is_empty() {
        out.push_str("audit");
    }
    out
}

/// Structured-data: `[yauth@<ENTERPRISE_ID> key="value" ...]`. We use 32473 as
/// the Private Enterprise Number — it's IANA-reserved for documentation /
/// examples per RFC 5612 §3.4. Operators register their own PEN if they need
/// canonical SD parsing.
const YAUTH_PEN: u32 = 32473;

fn structured_data(audit: &domain::AuditLog) -> String {
    let mut buf = format!("[yauth@{} ", YAUTH_PEN);
    buf.push_str(&format!(
        "id=\"{}\" event_type=\"{}\"",
        sd_escape(&audit.id.to_string()),
        sd_escape(&audit.event_type)
    ));
    if let Some(uid) = audit.user_id {
        buf.push_str(&format!(" user_id=\"{}\"", sd_escape(&uid.to_string())));
    }
    if let Some(ip) = &audit.ip_address {
        buf.push_str(&format!(" ip=\"{}\"", sd_escape(ip)));
    }
    buf.push(']');
    buf
}

/// SD-PARAM-VALUE escaping per RFC 5424 §6.3.3:
///   `"`, `\\`, and `]` MUST be escaped with a backslash.
pub fn sd_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ']' => out.push_str("\\]"),
            _ => out.push(c),
        }
    }
    out
}

/// MSG is freeform. We stuff JSON metadata into it so downstream collectors
/// can pluck specific fields.
fn render_msg(audit: &domain::AuditLog) -> String {
    let v = serde_json::json!({
        "event_type": audit.event_type,
        "user_id": audit.user_id,
        "ip_address": audit.ip_address,
        "metadata": audit.metadata,
    });
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use uuid::Uuid;

    fn sample_audit() -> domain::AuditLog {
        domain::AuditLog {
            id: Uuid::nil(),
            user_id: Some(Uuid::nil()),
            event_type: "user.login".into(),
            metadata: Some(serde_json::json!({"k": "v"})),
            ip_address: Some("203.0.113.5".into()),
            created_at: NaiveDate::from_ymd_opt(2026, 5, 17)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap(),
        }
    }

    #[test]
    fn json_renders_required_fields() {
        let r = render(domain::AuditExportFormat::Json, &sample_audit(), 13).unwrap();
        let s = std::str::from_utf8(&r.bytes).unwrap();
        assert!(s.contains("\"event_type\":\"user.login\""));
        assert!(s.contains("\"ip_address\":\"203.0.113.5\""));
    }

    #[test]
    fn rfc5424_starts_with_pri_and_version() {
        let r = render(domain::AuditExportFormat::Rfc5424, &sample_audit(), 13).unwrap();
        let s = std::str::from_utf8(&r.bytes).unwrap();
        // facility 13 * 8 + 6 = 110
        assert!(s.starts_with("<110>1 "), "got: {s}");
    }

    #[test]
    fn rfc5424_contains_app_name_and_msgid() {
        let r = render(domain::AuditExportFormat::Rfc5424, &sample_audit(), 13).unwrap();
        let s = std::str::from_utf8(&r.bytes).unwrap();
        // PROCID slot is "-" (nilvalue per RFC 5424 §6.2.6).
        assert!(s.contains(" yauth yauth - user.login "), "got: {s}");
    }

    #[test]
    fn rfc5424_structured_data_contains_yauth_sd_id() {
        let r = render(domain::AuditExportFormat::Rfc5424, &sample_audit(), 13).unwrap();
        let s = std::str::from_utf8(&r.bytes).unwrap();
        assert!(s.contains(&format!("[yauth@{}", YAUTH_PEN)), "got: {s}");
    }

    #[test]
    fn rfc5424_invalid_facility_rejected() {
        let err = render(domain::AuditExportFormat::Rfc5424, &sample_audit(), 99);
        assert!(err.is_err());
    }

    #[test]
    fn cef_escapes_special_chars_in_prefix() {
        assert_eq!(cef_escape_prefix("a|b"), "a\\|b");
        assert_eq!(cef_escape_prefix("a\\b"), "a\\\\b");
        assert_eq!(cef_escape_prefix("a\nb"), "a b");
    }

    #[test]
    fn cef_escapes_extension_values() {
        assert_eq!(cef_escape_extension("a=b"), "a\\=b");
        assert_eq!(cef_escape_extension("a\\b"), "a\\\\b");
        assert_eq!(cef_escape_extension("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn sd_escape_handles_quote_backslash_bracket() {
        assert_eq!(sd_escape("a\"b"), "a\\\"b");
        assert_eq!(sd_escape("a\\b"), "a\\\\b");
        assert_eq!(sd_escape("a]b"), "a\\]b");
    }

    #[test]
    fn cef_renders() {
        let r = render(domain::AuditExportFormat::Cef, &sample_audit(), 13).unwrap();
        let s = std::str::from_utf8(&r.bytes).unwrap();
        assert!(s.starts_with("CEF:0|yauth|yauth|"), "got: {s}");
        assert!(s.contains("user.login"));
        assert!(s.contains("src=203.0.113.5"));
    }
}
