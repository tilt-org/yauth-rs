//! Admin routes for OAuth2 client management: ban/unban + rotate-public-key.
//!
//! Mounted by the admin plugin when both `admin` and `oauth2-server` are
//! enabled. Each route writes an audit_log entry with the calling
//! principal (human admin or opted-in machine caller) so ops can answer
//! "who banned this client".

#![cfg(all(feature = "admin", feature = "oauth2-server"))]

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::crypto;
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::state::YAuthState;

#[derive(Deserialize)]
pub struct BanRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct BannedClient {
    pub client_id: String,
    pub reason: Option<String>,
    pub banned_at: chrono::DateTime<Utc>,
}

/// Public-facing serialization of an OAuth2 client. Matches yauth-go's
/// `Oauth2ClientJSON`.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2ClientView {
    pub id: String,
    pub client_id: String,
    /// yauth-go calls this field `name` on the wire — keep the Rust field
    /// `client_name` (closer to the domain model) but rename for serde.
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    pub is_public: bool,
    pub has_public_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    pub banned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banned_reason: Option<String>,
    pub created_at: String,
    /// OIDC RP-Initiated Logout 1.0: registered post-logout redirect URIs.
    /// Always emitted (empty list when none) to match yauth-go's wire shape.
    pub post_logout_redirect_uris: Vec<String>,
    /// OIDC Back-Channel Logout 1.0: the client's back-channel logout endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
}

impl From<crate::domain::Oauth2Client> for Oauth2ClientView {
    fn from(c: crate::domain::Oauth2Client) -> Self {
        let redirect_uris: Vec<String> =
            serde_json::from_value(c.redirect_uris).unwrap_or_default();
        let grant_types: Vec<String> = serde_json::from_value(c.grant_types).unwrap_or_default();
        let scopes: Option<Vec<String>> = c.scopes.and_then(|v| serde_json::from_value(v).ok());
        let post_logout_redirect_uris: Vec<String> = c
            .post_logout_redirect_uris
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        Self {
            id: c.id.to_string(),
            client_id: c.client_id,
            client_name: c.client_name,
            redirect_uris,
            grant_types,
            scopes,
            is_public: c.is_public,
            has_public_key: c.public_key_pem.is_some(),
            jwks_uri: c.jwks_uri,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            banned: c.banned_at.is_some(),
            banned_reason: c.banned_reason,
            created_at: c.created_at.and_utc().to_rfc3339(),
            post_logout_redirect_uris,
            backchannel_logout_uri: c.backchannel_logout_uri,
            backchannel_logout_session_required: c.backchannel_logout_session_required,
        }
    }
}

/// Response for `GET /oauth2/clients` (list banned). Mirrors yauth-go's
/// `Oauth2BannedClientsResponse`.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2BannedClientsResponse {
    pub banned: Vec<Oauth2ClientView>,
}

/// Body for `POST /oauth2/clients`. Admin-scoped client creation; mirrors
/// yauth-go's `Oauth2CreateClientRequest`.
#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2CreateClientRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub is_public: bool,
    /// Explicit `token_endpoint_auth_method` override. When omitted the
    /// server picks one based on `is_public` / whether `public_key_pem` or
    /// `jwks_uri` is set.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub public_key_pem: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// Response for `POST /oauth2/clients`. Mirrors yauth-go's
/// `Oauth2CreateClientResponse`.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2CreateClientResponse {
    pub client: Oauth2ClientView,
    /// Plaintext secret returned exactly once on creation. Empty for public
    /// clients (where `is_public=true` or `private_key_jwt` is in use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// Body for `PATCH /oauth2/clients/{id}`. Mirrors yauth-go's
/// `Oauth2PatchClientRequest`. Each field is optional; omitting a field
/// leaves it unchanged.
#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2PatchClientRequest {
    #[serde(default)]
    pub banned: Option<bool>,
    #[serde(default)]
    pub banned_reason: Option<String>,
    #[serde(default)]
    pub public_key_pem: Option<String>,
    /// OIDC logout config. Any present field triggers a logout-config update,
    /// merged with the client's current values for the fields left absent.
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_session_required: Option<bool>,
}

/// Strip CR/LF and trim surrounding whitespace from a URL. Terminals line-wrap
/// long URIs on copy/paste; a valid URI never contains raw newlines, so this
/// repairs that damage without altering real URIs. Mirrors yauth-go's
/// `sanitizeURL`.
fn sanitize_url(s: &str) -> String {
    s.replace(['\r', '\n'], "").trim().to_string()
}

/// Reject a URI that is not absolute http(s). This is the open-redirect /
/// SSRF guard for logout URIs — the back-channel logout URI is POSTed to
/// server-side, so a non-http(s) scheme (e.g. `file:`, `gopher:`) must never
/// be accepted.
fn is_http_url(s: &str) -> bool {
    matches!(url::Url::parse(s), Ok(u) if u.scheme() == "http" || u.scheme() == "https")
}

fn actor_from_extensions(
    user: Option<&AuthUser>,
    machine: Option<&crate::middleware::MachineCaller>,
) -> serde_json::Value {
    if let Some(u) = user {
        return serde_json::json!({
            "actor_type": "user",
            "actor_id": u.id.to_string(),
        });
    }
    if let Some(m) = machine {
        return serde_json::json!({
            "actor_type": "machine",
            "actor_client_id": m.client_id,
        });
    }
    serde_json::json!({ "actor_type": "system" })
}

async fn write_admin_audit(
    state: &YAuthState,
    user: Option<&AuthUser>,
    machine: Option<&crate::middleware::MachineCaller>,
    event_type: &str,
    metadata: serde_json::Value,
) {
    let actor = actor_from_extensions(user, machine);
    let mut merged = metadata;
    if let (Some(obj), Some(actor_obj)) = (merged.as_object_mut(), actor.as_object()) {
        for (k, v) in actor_obj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let user_id = user.map(|u| u.id);
    state
        .write_audit_log(user_id, event_type, Some(merged), None)
        .await;
}

pub async fn ban_oauth2_client(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
    Json(req): Json<BanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let updated = state
        .repos
        .oauth2_clients
        .set_banned(
            &client_id,
            Some((req.reason.clone(), Utc::now().naive_utc())),
        )
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_ban_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Ban failed")
        })?;
    if !updated {
        return Err(api_err(StatusCode::NOT_FOUND, "Client not found"));
    }

    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_banned",
        serde_json::json!({ "target_client_id": client_id, "reason": req.reason }),
    )
    .await;

    Ok((StatusCode::OK, Json(serde_json::json!({ "banned": true }))))
}

pub async fn unban_oauth2_client(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
) -> Result<impl IntoResponse, ApiError> {
    let updated = state
        .repos
        .oauth2_clients
        .set_banned(&client_id, None)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_unban_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Unban failed")
        })?;

    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_unbanned",
        serde_json::json!({ "target_client_id": client_id, "was_banned": updated }),
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "unbanned": updated })),
    ))
}

pub async fn list_banned_clients(
    State(state): State<YAuthState>,
) -> Result<Json<Vec<BannedClient>>, ApiError> {
    let rows = state
        .repos
        .oauth2_clients
        .list_banned()
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_list_banned_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "List failed")
        })?;
    Ok(Json(
        rows.into_iter()
            .filter_map(|c| {
                c.banned_at.map(|at| BannedClient {
                    client_id: c.client_id,
                    reason: c.banned_reason,
                    banned_at: at.and_utc(),
                })
            })
            .collect(),
    ))
}

#[cfg(feature = "asymmetric-jwt")]
#[derive(Deserialize)]
pub struct RotateKeyRequest {
    pub public_key_pem: String,
}

#[cfg(feature = "asymmetric-jwt")]
pub async fn rotate_public_key(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    crate::auth::client_keys::ClientKey::from_pem(&req.public_key_pem)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e))?;
    let key_source = if req.public_key_pem.contains("BEGIN PUBLIC KEY") {
        "spki_pem"
    } else {
        "pem"
    };

    let updated = state
        .repos
        .oauth2_clients
        .rotate_public_key(&client_id, Some(req.public_key_pem.clone()))
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_rotate_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Rotate failed")
        })?;
    if !updated {
        return Err(api_err(StatusCode::NOT_FOUND, "Client not found"));
    }

    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_public_key_rotated",
        serde_json::json!({ "target_client_id": client_id, "key_source": key_source }),
    )
    .await;

    Ok((StatusCode::OK, Json(serde_json::json!({ "rotated": true }))))
}

// ---------------------------------------------------------------------------
// /oauth2/clients — admin client CRUD (yauth-go convergence)
//
// These endpoints sit alongside the existing /admin/oauth2/clients/{id}/{ban,
// unban,rotate-public-key} ones to mirror yauth-go's surface 1:1. The PATCH
// route in particular consolidates the three admin actions into a single
// partial-update body the way yauth-go ships.
// ---------------------------------------------------------------------------

/// GET /oauth2/clients (admin) — list banned clients.
pub async fn list_oauth2_clients(
    State(state): State<YAuthState>,
) -> Result<Json<Oauth2BannedClientsResponse>, ApiError> {
    let rows = state
        .repos
        .oauth2_clients
        .list_banned()
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_list_banned_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "List failed")
        })?;
    Ok(Json(Oauth2BannedClientsResponse {
        banned: rows.into_iter().map(Into::into).collect(),
    }))
}

/// POST /oauth2/clients (admin) — register a new client. Admin-scoped; the
/// dynamic registration path (`POST /oauth/register`) is the public RFC 7591
/// surface.
pub async fn create_oauth2_client(
    State(state): State<YAuthState>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
    Json(req): Json<Oauth2CreateClientRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.redirect_uris.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "redirect_uris is required",
        ));
    }
    for uri in &req.redirect_uris {
        if url::Url::parse(uri).is_err() {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                &format!("Invalid redirect_uri: {}", uri),
            ));
        }
    }

    let grant_types = if req.grant_types.is_empty() {
        vec!["authorization_code".to_string()]
    } else {
        req.grant_types.clone()
    };

    // Public clients (or `private_key_jwt` ones with a key) get no secret.
    let using_pkjwt = req.public_key_pem.is_some() || req.jwks_uri.is_some();
    let (raw_secret, secret_hash) = if req.is_public || using_pkjwt {
        (None, None)
    } else {
        let s = crypto::generate_token();
        let h = crypto::hash_token(&s);
        (Some(s), Some(h))
    };

    let client_id = Uuid::now_v7().to_string();
    let now = Utc::now();
    let auth_method = req.token_endpoint_auth_method.clone().or_else(|| {
        Some(
            if req.is_public {
                "none"
            } else if using_pkjwt {
                "private_key_jwt"
            } else {
                "client_secret_basic"
            }
            .to_string(),
        )
    });

    let new_client = crate::domain::NewOauth2Client {
        id: Uuid::now_v7(),
        client_id: client_id.clone(),
        client_secret_hash: secret_hash,
        redirect_uris: serde_json::json!(req.redirect_uris),
        client_name: req.name.clone(),
        grant_types: serde_json::json!(grant_types),
        scopes: if req.scopes.is_empty() {
            None
        } else {
            Some(serde_json::json!(req.scopes))
        },
        is_public: req.is_public,
        created_at: now.naive_utc(),
        token_endpoint_auth_method: auth_method,
        public_key_pem: req.public_key_pem.clone(),
        jwks_uri: req.jwks_uri.clone(),
    };

    state
        .repos
        .oauth2_clients
        .create(new_client)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_admin_create_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Create failed")
        })?;

    let row = state
        .repos
        .oauth2_clients
        .find_by_client_id(&client_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_fetch_after_create_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Client vanished"))?;

    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_created",
        serde_json::json!({ "target_client_id": client_id, "name": req.name }),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(Oauth2CreateClientResponse {
            client: row.into(),
            client_secret: raw_secret,
        }),
    ))
}

/// GET /oauth2/clients/{id} (admin) — fetch a single client.
pub async fn get_oauth2_client(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
) -> Result<Json<Oauth2ClientView>, ApiError> {
    let row = state
        .repos
        .oauth2_clients
        .find_by_client_id(&client_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_fetch_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Fetch failed")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Client not found"))?;
    Ok(Json(row.into()))
}

/// PATCH /oauth2/clients/{id} (admin) — partial update. yauth-go consolidates
/// ban/unban/rotate-public-key behind this single endpoint.
pub async fn patch_oauth2_client(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
    Json(req): Json<Oauth2PatchClientRequest>,
) -> Result<Json<Oauth2ClientView>, ApiError> {
    // Verify the client exists up front so a no-op patch returns 404 cleanly.
    let current = state
        .repos
        .oauth2_clients
        .find_by_client_id(&client_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_fetch_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Fetch failed")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Client not found"))?;

    if let Some(banned) = req.banned {
        let new_state = if banned {
            Some((req.banned_reason.clone(), Utc::now().naive_utc()))
        } else {
            None
        };
        state
            .repos
            .oauth2_clients
            .set_banned(&client_id, new_state)
            .await
            .map_err(|e| {
                crate::otel::record_error("oauth2_client_set_banned_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Patch failed")
            })?;
        write_admin_audit(
            &state,
            user.as_ref().map(|Extension(u)| u),
            machine.as_ref().map(|Extension(m)| m),
            if banned {
                "oauth2_client_banned"
            } else {
                "oauth2_client_unbanned"
            },
            serde_json::json!({
                "target_client_id": client_id,
                "reason": req.banned_reason,
                "via": "patch",
            }),
        )
        .await;
    }

    #[cfg(feature = "asymmetric-jwt")]
    if let Some(ref pem) = req.public_key_pem {
        crate::auth::client_keys::ClientKey::from_pem(pem)
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e))?;
        state
            .repos
            .oauth2_clients
            .rotate_public_key(&client_id, Some(pem.clone()))
            .await
            .map_err(|e| {
                crate::otel::record_error("oauth2_client_rotate_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Patch failed")
            })?;
        write_admin_audit(
            &state,
            user.as_ref().map(|Extension(u)| u),
            machine.as_ref().map(|Extension(m)| m),
            "oauth2_client_public_key_rotated",
            serde_json::json!({ "target_client_id": client_id, "via": "patch" }),
        )
        .await;
    }
    #[cfg(not(feature = "asymmetric-jwt"))]
    if req.public_key_pem.is_some() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "public_key_pem requires the asymmetric-jwt feature",
        ));
    }

    // OIDC logout config. Any present field triggers an update, merged against
    // the client's current values for the fields left absent.
    if req.post_logout_redirect_uris.is_some()
        || req.backchannel_logout_uri.is_some()
        || req.backchannel_logout_session_required.is_some()
    {
        // post_logout_redirect_uris: replace the whole list when provided;
        // sanitize CR/LF and reject any non-http(s) entry (open-redirect guard).
        let plru = match req.post_logout_redirect_uris {
            Some(uris) => {
                let mut cleaned = Vec::with_capacity(uris.len());
                for u in uris {
                    let s = sanitize_url(&u);
                    if !is_http_url(&s) {
                        return Err(api_err(
                            StatusCode::BAD_REQUEST,
                            "post_logout_redirect_uris must be absolute http(s) URLs",
                        ));
                    }
                    cleaned.push(s);
                }
                Some(serde_json::json!(cleaned))
            }
            None => current.post_logout_redirect_uris.clone(),
        };

        // backchannel_logout_uri: a present empty string clears it; a present
        // non-empty value must be an http(s) URL (SSRF guard — we POST here).
        let bcl_uri = match req.backchannel_logout_uri {
            Some(raw) => {
                let s = sanitize_url(&raw);
                if s.is_empty() {
                    None
                } else if !is_http_url(&s) {
                    return Err(api_err(
                        StatusCode::BAD_REQUEST,
                        "backchannel_logout_uri must be an absolute http(s) URL",
                    ));
                } else {
                    Some(s)
                }
            }
            None => current.backchannel_logout_uri.clone(),
        };

        let sess_req = req
            .backchannel_logout_session_required
            .unwrap_or(current.backchannel_logout_session_required);

        state
            .repos
            .oauth2_clients
            .set_logout_config(&client_id, plru, bcl_uri, sess_req)
            .await
            .map_err(|e| {
                crate::otel::record_error("oauth2_client_set_logout_config_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Patch failed")
            })?;
        write_admin_audit(
            &state,
            user.as_ref().map(|Extension(u)| u),
            machine.as_ref().map(|Extension(m)| m),
            "oauth2_client_logout_config_updated",
            serde_json::json!({ "target_client_id": client_id, "via": "patch" }),
        )
        .await;
    }

    let row = state
        .repos
        .oauth2_clients
        .find_by_client_id(&client_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_fetch_after_patch_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Client not found"))?;
    Ok(Json(row.into()))
}

/// DELETE /oauth2/clients/{id} (admin) — soft-delete by banning. yauth-go
/// preserves history rather than dropping the row, and we mirror that.
pub async fn delete_oauth2_client(
    State(state): State<YAuthState>,
    Path(client_id): Path<String>,
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<crate::middleware::MachineCaller>>,
) -> Result<StatusCode, ApiError> {
    let updated = state
        .repos
        .oauth2_clients
        .set_banned(
            &client_id,
            Some((Some("deleted".to_string()), Utc::now().naive_utc())),
        )
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_delete_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Delete failed")
        })?;
    if !updated {
        return Err(api_err(StatusCode::NOT_FOUND, "Client not found"));
    }
    write_admin_audit(
        &state,
        user.as_ref().map(|Extension(u)| u),
        machine.as_ref().map(|Extension(m)| m),
        "oauth2_client_deleted",
        serde_json::json!({ "target_client_id": client_id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}
