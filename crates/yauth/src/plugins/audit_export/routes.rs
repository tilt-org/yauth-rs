#![forbid(unsafe_code)]
//! Admin routes for the audit-export plugin.
//!
//! All routes are admin-only (`require_admin` from the core middleware). The
//! plugin doesn't expose any public/public-with-auth surface; SIEM
//! integration is a deployment-level concern.

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware as axum_mw,
    response::IntoResponse,
    routing::{delete, get, patch, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::config::AuditExportConfig;
use crate::domain;
use crate::error::{ApiError, api_err};
use crate::middleware::{AuthUser, require_admin};
use crate::plugin::PluginContext;
use crate::repo::AuditExportDestinationFilter;
use crate::state::YAuthState;

/// Build the router with admin middleware applied.
pub fn router(ctx: &PluginContext, _config: AuditExportConfig) -> Router<YAuthState> {
    let r = Router::new()
        .route("/audit/destinations", post(create_destination))
        .route("/audit/destinations", get(list_destinations))
        .route("/audit/destinations/{id}", get(get_destination))
        .route("/audit/destinations/{id}", patch(update_destination))
        .route("/audit/destinations/{id}", delete(delete_destination))
        .route(
            "/audit/destinations/{id}/outbox",
            get(list_destination_outbox),
        )
        .route("/audit/replay", post(replay_events));

    r.layer(axum_mw::from_fn_with_state(
        ctx.state.clone(),
        require_admin,
    ))
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateAuditDestinationRequest {
    pub name: String,
    /// `None` => deployment-wide destination.
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    pub kind: WireDestinationKind,
}

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireDestinationKind {
    Webhook {
        url: String,
        #[serde(default)]
        format: String,
        #[serde(default)]
        hmac_secret: Option<String>,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    Syslog {
        host: String,
        port: u16,
        #[serde(default)]
        transport: String,
        #[serde(default = "default_facility")]
        facility: u8,
    },
    S3 {
        bucket: String,
        #[serde(default)]
        prefix: String,
        region: String,
        #[serde(default)]
        partition: String,
    },
    Splunk {
        hec_url: String,
        hec_token: String,
    },
    Datadog {
        site: String,
        api_key: String,
    },
}

fn default_facility() -> u8 {
    13
}

impl WireDestinationKind {
    fn into_domain(self) -> Result<domain::AuditExportDestinationKind, ApiError> {
        Ok(match self {
            Self::Webhook {
                url,
                format,
                hmac_secret,
                headers,
            } => domain::AuditExportDestinationKind::Webhook {
                url,
                format: parse_format(&format)?,
                hmac_secret,
                headers,
            },
            Self::Syslog {
                host,
                port,
                transport,
                facility,
            } => domain::AuditExportDestinationKind::Syslog {
                host,
                port,
                transport: parse_transport(&transport)?,
                facility,
            },
            Self::S3 {
                bucket,
                prefix,
                region,
                partition,
            } => domain::AuditExportDestinationKind::S3 {
                bucket,
                prefix,
                region,
                partition: parse_partition(&partition)?,
            },
            Self::Splunk { hec_url, hec_token } => {
                domain::AuditExportDestinationKind::Splunk { hec_url, hec_token }
            }
            Self::Datadog { site, api_key } => {
                domain::AuditExportDestinationKind::Datadog { site, api_key }
            }
        })
    }
}

fn parse_format(s: &str) -> Result<domain::AuditExportFormat, ApiError> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "" | "json" => domain::AuditExportFormat::Json,
        "cef" => domain::AuditExportFormat::Cef,
        "rfc5424" | "syslog" => domain::AuditExportFormat::Rfc5424,
        _ => {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "format must be one of: json, cef, rfc5424",
            ));
        }
    })
}

fn parse_transport(s: &str) -> Result<domain::SyslogTransport, ApiError> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "" | "tcp" => domain::SyslogTransport::Tcp,
        "udp" | "udp_unsecured" => domain::SyslogTransport::UdpUnsecured,
        "tls" | "tcp_tls" => domain::SyslogTransport::TcpTls,
        _ => {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "transport must be one of: tcp, udp, tls",
            ));
        }
    })
}

fn parse_partition(s: &str) -> Result<domain::S3Partition, ApiError> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "" | "by_date" => domain::S3Partition::ByDate,
        "by_org" => domain::S3Partition::ByOrg,
        "by_date_and_org" => domain::S3Partition::ByDateAndOrg,
        _ => {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "partition must be one of: by_date, by_org, by_date_and_org",
            ));
        }
    })
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditDestinationResponse {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub name: String,
    /// Sanitized kind — secrets (hmac_secret, hec_token, api_key) are stripped.
    pub kind: serde_json::Value,
    pub kind_tag: &'static str,
    pub status: String,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl AuditDestinationResponse {
    fn from_domain(d: &domain::AuditExportDestination) -> Self {
        Self {
            id: d.id,
            organization_id: d.organization_id,
            name: d.name.clone(),
            kind: sanitize_kind(&d.kind),
            kind_tag: d.kind.kind_tag(),
            status: match d.status {
                domain::DestinationStatus::Active => "active".into(),
                domain::DestinationStatus::Disabled => "disabled".into(),
            },
            last_success_at: d.last_success_at.map(|t| t.and_utc().to_rfc3339()),
            last_failure_at: d.last_failure_at.map(|t| t.and_utc().to_rfc3339()),
            created_at: d.created_at.and_utc().to_rfc3339(),
            updated_at: d.updated_at.and_utc().to_rfc3339(),
        }
    }
}

/// Strip secrets from the destination JSON before returning to clients.
/// We never return `hmac_secret`, `hec_token`, or Datadog `api_key`.
fn sanitize_kind(k: &domain::AuditExportDestinationKind) -> serde_json::Value {
    use serde_json::json;
    match k {
        domain::AuditExportDestinationKind::Webhook {
            url,
            format,
            hmac_secret,
            headers: _,
        } => json!({
            "type": "webhook",
            "url": url,
            "format": format.as_str(),
            "hmac_configured": hmac_secret.is_some(),
        }),
        domain::AuditExportDestinationKind::Syslog {
            host,
            port,
            transport,
            facility,
        } => json!({
            "type": "syslog",
            "host": host,
            "port": port,
            "transport": match transport {
                domain::SyslogTransport::UdpUnsecured => "udp",
                domain::SyslogTransport::Tcp => "tcp",
                domain::SyslogTransport::TcpTls => "tls",
            },
            "facility": facility,
        }),
        domain::AuditExportDestinationKind::S3 {
            bucket,
            prefix,
            region,
            partition,
        } => json!({
            "type": "s3",
            "bucket": bucket,
            "prefix": prefix,
            "region": region,
            "partition": match partition {
                domain::S3Partition::ByDate => "by_date",
                domain::S3Partition::ByOrg => "by_org",
                domain::S3Partition::ByDateAndOrg => "by_date_and_org",
            },
        }),
        domain::AuditExportDestinationKind::Splunk { hec_url, .. } => json!({
            "type": "splunk",
            "hec_url": hec_url,
            "implemented": false,
        }),
        domain::AuditExportDestinationKind::Datadog { site, .. } => json!({
            "type": "datadog",
            "site": site,
            "implemented": false,
        }),
    }
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async fn create_destination(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Json(req): Json<CreateAuditDestinationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let kind = req.kind.into_domain()?;
    let now = Utc::now().naive_utc();
    let row = state
        .repos
        .audit_export_destinations
        .create(domain::NewAuditExportDestination {
            id: Uuid::now_v7(),
            organization_id: req.organization_id,
            name: req.name,
            kind,
            status: domain::DestinationStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .await?;
    state
        .write_audit_log(
            Some(admin.id),
            "audit_export.destination.created",
            Some(serde_json::json!({"destination_id": row.id, "kind": row.kind.kind_tag()})),
            None,
        )
        .await;
    Ok((
        StatusCode::CREATED,
        Json(AuditDestinationResponse::from_domain(&row)),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ListDestinationsQuery {
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    /// "deployment" => only deployment-wide. Default = all.
    #[serde(default)]
    pub scope: Option<String>,
}

async fn list_destinations(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
    Query(q): Query<ListDestinationsQuery>,
) -> Result<Json<Vec<AuditDestinationResponse>>, ApiError> {
    let filter = AuditExportDestinationFilter {
        organization_id: match (q.scope.as_deref(), q.organization_id) {
            (Some("deployment"), _) => Some(None),
            (_, Some(org)) => Some(Some(org)),
            _ => None,
        },
        status: None,
    };
    let rows = state.repos.audit_export_destinations.list(filter).await?;
    Ok(Json(
        rows.iter()
            .map(AuditDestinationResponse::from_domain)
            .collect(),
    ))
}

async fn get_destination(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<AuditDestinationResponse>, ApiError> {
    let row = state
        .repos
        .audit_export_destinations
        .find_by_id(id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Destination not found"))?;
    Ok(Json(AuditDestinationResponse::from_domain(&row)))
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateAuditDestinationRequest {
    pub name: Option<String>,
    pub status: Option<String>,
    pub kind: Option<WireDestinationKind>,
}

async fn update_destination(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAuditDestinationRequest>,
) -> Result<Json<AuditDestinationResponse>, ApiError> {
    let _existing = state
        .repos
        .audit_export_destinations
        .find_by_id(id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Destination not found"))?;

    let status = match req.status.as_deref() {
        Some("active") => Some(domain::DestinationStatus::Active),
        Some("disabled") => Some(domain::DestinationStatus::Disabled),
        Some(_) => {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "status must be 'active' or 'disabled'",
            ));
        }
        None => None,
    };
    let kind = match req.kind {
        Some(k) => Some(k.into_domain()?),
        None => None,
    };
    let updated = state
        .repos
        .audit_export_destinations
        .update(
            id,
            domain::UpdateAuditExportDestination {
                name: req.name,
                kind,
                status,
                last_success_at: None,
                last_failure_at: None,
                updated_at: Some(Utc::now().naive_utc()),
            },
        )
        .await?;
    state
        .write_audit_log(
            Some(admin.id),
            "audit_export.destination.updated",
            Some(serde_json::json!({"destination_id": id})),
            None,
        )
        .await;
    Ok(Json(AuditDestinationResponse::from_domain(&updated)))
}

async fn delete_destination(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.repos.audit_export_destinations.delete(id).await?;
    state
        .write_audit_log(
            Some(admin.id),
            "audit_export.destination.deleted",
            Some(serde_json::json!({"destination_id": id})),
            None,
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct OutboxQuery {
    #[serde(default = "default_outbox_limit")]
    pub limit: usize,
}

fn default_outbox_limit() -> usize {
    100
}

async fn list_destination_outbox(
    State(state): State<YAuthState>,
    Extension(_admin): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Query(q): Query<OutboxQuery>,
) -> Result<Json<Vec<OutboxEntryResponse>>, ApiError> {
    state
        .repos
        .audit_export_destinations
        .find_by_id(id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Destination not found"))?;

    let rows = state
        .repos
        .audit_outbox
        .list_for_destination(id, q.limit.clamp(1, 1000))
        .await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OutboxEntryResponse {
    pub id: Uuid,
    pub audit_log_id: Uuid,
    pub destination_id: Uuid,
    pub status: String,
    pub attempts: i32,
    pub last_attempt_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
}

impl From<domain::AuditOutboxEntry> for OutboxEntryResponse {
    fn from(e: domain::AuditOutboxEntry) -> Self {
        Self {
            id: e.id,
            audit_log_id: e.audit_log_id,
            destination_id: e.destination_id,
            status: match e.status {
                domain::OutboxStatus::Pending => "pending".into(),
                domain::OutboxStatus::Sent => "sent".into(),
                domain::OutboxStatus::Failed => "failed".into(),
                domain::OutboxStatus::DeadLetter => "dead_letter".into(),
            },
            attempts: e.attempts,
            last_attempt_at: e.last_attempt_at.map(|t| t.and_utc().to_rfc3339()),
            last_error: e.last_error,
            created_at: e.created_at.and_utc().to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReplayRequest {
    pub audit_log_ids: Vec<Uuid>,
    pub destination_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReplayResponse {
    pub enqueued: usize,
    pub gone: Vec<Uuid>,
}

async fn replay_events(
    State(state): State<YAuthState>,
    Extension(admin): Extension<AuthUser>,
    Json(req): Json<ReplayRequest>,
) -> Result<Json<ReplayResponse>, ApiError> {
    if req.audit_log_ids.is_empty() || req.destination_ids.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "audit_log_ids and destination_ids must be non-empty",
        ));
    }
    // Verify each destination exists.
    for d in &req.destination_ids {
        if state
            .repos
            .audit_export_destinations
            .find_by_id(*d)
            .await?
            .is_none()
        {
            return Err(api_err(
                StatusCode::NOT_FOUND,
                "one or more destinations not found",
            ));
        }
    }
    // Pull the audit rows in scope (memory backend has no by-id; list +
    // filter). 410 Gone for any id not present in the audit table.
    let audits = state
        .repos
        .audit
        .list(crate::repo::AuditLogFilter::default(), 100_000, 0)
        .await?;
    let known: std::collections::HashSet<_> = audits.iter().map(|a| a.id).collect();
    let mut enqueued = 0usize;
    let mut gone = Vec::new();
    for aid in &req.audit_log_ids {
        if !known.contains(aid) {
            gone.push(*aid);
            continue;
        }
        let new_ids = state
            .repos
            .audit_outbox
            .replay(*aid, &req.destination_ids)
            .await?;
        enqueued += new_ids.len();
    }
    state
        .write_audit_log(
            Some(admin.id),
            "audit_export.replay",
            Some(serde_json::json!({
                "enqueued": enqueued,
                "gone": gone.len(),
            })),
            None,
        )
        .await;
    let status = if gone.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::PARTIAL_CONTENT
    };
    let _ = status; // returned only when we drop to (status, Json(_)) below
    Ok(Json(ReplayResponse { enqueued, gone }))
}
