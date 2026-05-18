#![forbid(unsafe_code)]
//! Domain types for the audit-export plugin (issue #96).
//!
//! These types cross the repository trait boundary. They are ORM-agnostic
//! and have no backend-specific dependencies. Memory backend defines
//! correctness; SQL backends stub these repos with `RepoError::NotImplemented`
//! (HTTP 501) per the same precedent as Phase A/B / SAML / SCIM.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Format adapters
// ---------------------------------------------------------------------------

/// Output format for an audit-export destination.
///
/// JSON is the default and most universally consumable. RFC 5424 is the
/// canonical syslog framing. CEF (ArcSight/Splunk) is reserved for a
/// follow-up — current implementation maps `Cef` -> JSON with a TODO
/// span event so callers see they got a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuditExportFormat {
    #[default]
    Json,
    Cef,
    Rfc5424,
}

impl AuditExportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Cef => "cef",
            Self::Rfc5424 => "rfc5424",
        }
    }
}

// ---------------------------------------------------------------------------
// Destination configuration
// ---------------------------------------------------------------------------

/// Transport for syslog destinations. UDP is unauthenticated and not
/// recommended; TCP is plaintext; TCP+TLS is the conventional secure
/// path on port 6514.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SyslogTransport {
    UdpUnsecured,
    #[default]
    Tcp,
    TcpTls,
}

/// Object-store partitioning strategy for S3-flavored destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum S3Partition {
    #[default]
    ByDate,
    ByOrg,
    ByDateAndOrg,
}

/// Configuration for a single audit-export destination.
///
/// `Splunk` and `Datadog` variants are accepted at the API surface but
/// the dispatcher returns `RepoError::NotImplemented` (HTTP 501) until the
/// follow-up issues land. This keeps the wire shape stable for clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditExportDestinationKind {
    Webhook {
        url: String,
        format: AuditExportFormat,
        /// HMAC-SHA256 secret. **Never logged**, even masked. `None` disables
        /// signing (still allowed for fully-private receivers, but warned in
        /// admin UI).
        hmac_secret: Option<String>,
        /// Extra static headers (e.g. `Authorization: Bearer xxx`). Values are
        /// treated as secrets and **never logged**.
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    Syslog {
        host: String,
        port: u16,
        transport: SyslogTransport,
        /// RFC 5424 facility code 0..=23. Defaults to 13 (security/auth).
        #[serde(default = "default_facility")]
        facility: u8,
    },
    S3 {
        bucket: String,
        #[serde(default)]
        prefix: String,
        region: String,
        partition: S3Partition,
    },
    /// Splunk HEC (stub — returns 501 until follow-up issue).
    Splunk {
        hec_url: String,
        /// HEC token. **Never logged.**
        hec_token: String,
    },
    /// Datadog HTTP log intake (stub — returns 501 until follow-up issue).
    Datadog {
        site: String,
        /// `DD-API-KEY` header value. **Never logged.**
        api_key: String,
    },
}

fn default_facility() -> u8 {
    13
}

impl AuditExportDestinationKind {
    /// Stable string tag for OTel attribute values. Never includes secrets.
    pub fn kind_tag(&self) -> &'static str {
        match self {
            Self::Webhook { .. } => "webhook",
            Self::Syslog { .. } => "syslog",
            Self::S3 { .. } => "s3",
            Self::Splunk { .. } => "splunk",
            Self::Datadog { .. } => "datadog",
        }
    }

    /// Returns `true` if this destination kind has a real dispatcher impl.
    /// Splunk/Datadog return false and the worker emits a 501-style event.
    pub fn is_implemented(&self) -> bool {
        matches!(
            self,
            Self::Webhook { .. } | Self::Syslog { .. } | Self::S3 { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Destination row (deployment-wide or per-org)
// ---------------------------------------------------------------------------

/// Lifecycle status of a destination row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DestinationStatus {
    #[default]
    Active,
    Disabled,
}

/// Deployment-wide (no org_id) or org-scoped (`organization_id = Some(...)`)
/// audit-export destination. Per-org rows route events ONLY for that org —
/// the cross-org leakage pentest asserts this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportDestination {
    pub id: Uuid,
    /// `None` means deployment-wide (every audit event routes here).
    /// `Some(org_id)` means only that org's events route here, in addition
    /// to any deployment-wide rows.
    pub organization_id: Option<Uuid>,
    pub name: String,
    pub kind: AuditExportDestinationKind,
    pub status: DestinationStatus,
    pub last_success_at: Option<NaiveDateTime>,
    pub last_failure_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuditExportDestination {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub name: String,
    pub kind: AuditExportDestinationKind,
    pub status: DestinationStatus,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateAuditExportDestination {
    pub name: Option<String>,
    pub kind: Option<AuditExportDestinationKind>,
    pub status: Option<DestinationStatus>,
    pub last_success_at: Option<Option<NaiveDateTime>>,
    pub last_failure_at: Option<Option<NaiveDateTime>>,
    pub updated_at: Option<NaiveDateTime>,
}

// ---------------------------------------------------------------------------
// Outbox entry — at-least-once delivery queue
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    Pending,
    Sent,
    Failed,
    DeadLetter,
}

/// One row per (audit event, destination). Inserted in the same critical
/// section as the audit row (memory backend = mutex; SQL backends are
/// stubs — see RepoError::NotImplemented).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditOutboxEntry {
    pub id: Uuid,
    pub audit_log_id: Uuid,
    pub destination_id: Uuid,
    pub status: OutboxStatus,
    pub attempts: i32,
    pub last_attempt_at: Option<NaiveDateTime>,
    pub last_error: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuditOutboxEntry {
    pub id: Uuid,
    pub audit_log_id: Uuid,
    pub destination_id: Uuid,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateAuditOutboxEntry {
    pub status: Option<OutboxStatus>,
    pub attempts: Option<i32>,
    pub last_attempt_at: Option<Option<NaiveDateTime>>,
    pub last_error: Option<Option<String>>,
}
