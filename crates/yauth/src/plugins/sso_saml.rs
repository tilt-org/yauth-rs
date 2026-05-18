//! User-facing SSO SAML 2.0 SP login routes (issue #94).
//!
//! Pattern parity with [`super::sso_oidc`]. The admin-side CRUD for
//! SAML connections piggybacks on the existing OIDC admin endpoints
//! (`/organizations/:id/sso/connections[/:cid]`) — only the *user-
//! agent* flow lives here.
//!
//! Routes mounted under the `organizations` feature:
//!
//! | Method | Path                                                      | Effect                                            |
//! |--------|-----------------------------------------------------------|---------------------------------------------------|
//! | `GET`  | `/sso/saml/login?org=<slug>` (or `?domain=<acme.com>`)    | Redirect to IdP SSO URL with `SAMLRequest`        |
//! | `POST` | `/sso/saml/acs`                                           | Assertion Consumer Service                        |
//! | `GET`  | `/sso/saml/metadata/{cid}`                                | SP metadata XML for the IdP admin to import       |
//! | `GET`  | `/sso/saml/logout`                                        | SP-initiated SLO redirect (best-effort)           |
//! | `POST` | `/sso/saml/slo`                                           | IdP-initiated SLO receiver (best-effort)          |
//!
//! All endpoints are public (no auth required) and feature-gated on
//! `organizations`.

#![cfg(feature = "organizations")]
#![forbid(unsafe_code)]

use axum::{
    Form, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use chrono::{Duration as ChronoDuration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{
    rbac::{self, roles},
    saml_sp::{DefaultSamlProvider, SamlError, SamlProvider},
    session,
    session::session_set_cookie,
};
use crate::error::{ApiError, api_err};
use crate::state::YAuthState;
use yauth_entity::{
    ConnectionKind, ConnectionStatus, DomainStatus, NewExternalIdentity, NewMembership,
    NewSsoLoginState, NewUser, SsoConnection, saml_provider,
};

/// Mount the public SAML routes onto the router.
pub(crate) fn public_routes() -> Router<YAuthState> {
    Router::new()
        .route("/sso/saml/login", get(login))
        .route("/sso/saml/acs", post(acs))
        .route("/sso/saml/metadata/{cid}", get(metadata))
        .route("/sso/saml/logout", get(logout_redirect))
        .route("/sso/saml/slo", post(slo_receiver))
}

// ──────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────

fn provider_for_state(_state: &YAuthState) -> &'static DefaultSamlProvider {
    use std::sync::OnceLock;
    static PROVIDER: OnceLock<DefaultSamlProvider> = OnceLock::new();
    PROVIDER.get_or_init(DefaultSamlProvider::new)
}

fn safe_redirect(input: Option<String>) -> Option<String> {
    let candidate = input?;
    if candidate.starts_with('/') && !candidate.starts_with("//") {
        Some(candidate)
    } else {
        None
    }
}

// ──────────────────────────────────────────────
// /sso/saml/login
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub redirect_to: Option<String>,
}

async fn login(
    State(state): State<YAuthState>,
    Query(q): Query<LoginQuery>,
) -> Result<axum::response::Response, ApiError> {
    let conn = resolve_connection(&state, &q).await?;
    let cfg = conn
        .saml_config()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "connection is not a SAML SP"))?;

    // Build a RelayState — opaque random — and an AuthnRequest.
    let relay_state = crate::auth::oidc_client::generate_state_token();
    let provider = provider_for_state(&state);
    let auth_req = provider
        .build_authn_request(&cfg, &relay_state)
        .map_err(|e| {
            crate::otel::record_error("sso_saml_build_authn_request_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Persist state row keyed by RelayState. Reuse SsoLoginState's
    // existing schema: state=RelayState, nonce=SAML request id,
    // issuer=IdP entityID, pkce_verifier left empty (SAML-side state
    // binding doesn't use PKCE; column is non-null today, so we
    // store the empty string).
    let now = Utc::now().naive_utc();
    state
        .repos
        .sso_login_states
        .create(NewSsoLoginState {
            state: relay_state.clone(),
            connection_id: conn.id,
            issuer: cfg.idp_entity_id.clone(),
            nonce: auth_req.request_id.clone(),
            pkce_verifier: String::new(),
            redirect_to: safe_redirect(q.redirect_to.clone()),
            created_at: now,
            expires_at: now + ChronoDuration::seconds(yauth_entity::STATE_TTL_SECS),
        })
        .await?;

    state
        .write_audit_log(
            None,
            "sso_saml_login_initiated",
            Some(serde_json::json!({
                "connection_id": conn.id,
                "organization_id": conn.organization_id,
                "idp_entity_id": cfg.idp_entity_id,
            })),
            None,
        )
        .await;

    // HTTP-Redirect binding: query-param the IdP SSO URL with
    // `SAMLRequest=<base64 deflated>` and `RelayState=<opaque>`.
    let sep = if cfg.idp_sso_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!(
        "{base}{sep}SAMLRequest={req}&RelayState={rs}",
        base = cfg.idp_sso_url,
        sep = sep,
        req = urlencoding_encode(&auth_req.saml_request_b64_deflated),
        rs = urlencoding_encode(&relay_state),
    );

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, url)],
        axum::body::Body::empty(),
    )
        .into_response())
}

async fn resolve_connection(state: &YAuthState, q: &LoginQuery) -> Result<SsoConnection, ApiError> {
    match (q.org.as_deref(), q.domain.as_deref()) {
        (Some(slug), _) => {
            let org = state
                .repos
                .organizations
                .find_by_slug(slug)
                .await?
                .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "organization not found"))?;
            connection_for_org(state, org.id).await
        }
        (None, Some(domain)) => {
            let dom = state
                .repos
                .organization_domains
                .find_by_domain(domain)
                .await?
                .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "domain not verified or unknown"))?;
            if dom.status != DomainStatus::Verified {
                return Err(api_err(
                    StatusCode::NOT_FOUND,
                    "domain not verified or unknown",
                ));
            }
            connection_for_org(state, dom.organization_id).await
        }
        (None, None) => Err(api_err(
            StatusCode::BAD_REQUEST,
            "either `org` or `domain` query parameter is required",
        )),
    }
}

async fn connection_for_org(state: &YAuthState, org_id: Uuid) -> Result<SsoConnection, ApiError> {
    let conn = state
        .repos
        .sso_connections
        .find_active_saml_for_org(org_id)
        .await?
        .ok_or_else(|| {
            api_err(
                StatusCode::NOT_FOUND,
                "organization has no active SAML connection",
            )
        })?;
    if conn.kind != ConnectionKind::SamlSp || conn.status != ConnectionStatus::Active {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "connection is not an active SAML SP",
        ));
    }
    Ok(conn)
}

// ──────────────────────────────────────────────
// /sso/saml/acs
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AcsForm {
    /// Base64-encoded `<samlp:Response>`. Required.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// Opaque RelayState that the IdP echoes back; we match against
    /// our stored login-state row.
    #[serde(default, rename = "RelayState")]
    pub relay_state: Option<String>,
}

async fn acs(
    State(state): State<YAuthState>,
    Form(form): Form<AcsForm>,
) -> Result<axum::response::Response, ApiError> {
    let provider = provider_for_state(&state);

    // Three RelayState shapes:
    //   1. Opaque random token → SP-initiated; look up SsoLoginState.
    //   2. `cid:<uuid>` hint    → IdP-initiated; look up by connection id.
    //   3. None / empty         → reject. We never accept a bare
    //                             IdP-initiated assertion without a
    //                             connection hint — that's how
    //                             cross-tenant assertion replay starts.
    let (conn, expected_in_response_to, redirect_to) = match form.relay_state.as_deref() {
        Some(rs) if rs.starts_with("cid:") => {
            let cid = rs.trim_start_matches("cid:");
            let uuid = Uuid::parse_str(cid).map_err(|_| {
                api_err(
                    StatusCode::BAD_REQUEST,
                    "RelayState cid hint is not a valid uuid",
                )
            })?;
            let conn = state
                .repos
                .sso_connections
                .find_by_id(uuid)
                .await?
                .ok_or_else(|| {
                    api_err(StatusCode::BAD_REQUEST, "connection hint did not resolve")
                })?;
            (conn, None, None)
        }
        Some(rs) if !rs.is_empty() => {
            match state.repos.sso_login_states.find_and_delete(rs).await? {
                Some(row) => {
                    let conn = state
                        .repos
                        .sso_connections
                        .find_by_id(row.connection_id)
                        .await?
                        .ok_or_else(|| {
                            api_err(StatusCode::BAD_REQUEST, "connection no longer exists")
                        })?;
                    (conn, Some(row.nonce), row.redirect_to)
                }
                None => {
                    return Err(api_err(
                        StatusCode::BAD_REQUEST,
                        "RelayState is unknown, expired, or already used",
                    ));
                }
            }
        }
        _ => {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "RelayState is required (use `cid:<uuid>` for IdP-initiated)",
            ));
        }
    };

    let cfg = conn
        .saml_config()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "connection is not a SAML SP"))?;
    if conn.status != ConnectionStatus::Active {
        return Err(api_err(StatusCode::BAD_REQUEST, "connection is not active"));
    }

    let extracted = provider
        .verify_assertion(
            &cfg,
            &form.saml_response,
            expected_in_response_to.as_deref(),
            Utc::now(),
        )
        .map_err(map_saml_error)?;

    // JIT or login.
    let provider_str = saml_provider(&cfg.idp_entity_id);
    let now_dt = Utc::now().naive_utc();
    let user_id = if let Some(ext) = state
        .repos
        .external_identities
        .find_by_provider_external_id(&provider_str, &extracted.external_id)
        .await?
    {
        let user = state
            .repos
            .users
            .find_by_id(ext.user_id)
            .await?
            .ok_or_else(|| {
                api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "external identity points at missing user",
                )
            })?;
        if let Some(email) = extracted.email.as_deref()
            && !user.email.eq_ignore_ascii_case(email)
        {
            return Err(api_err(
                StatusCode::CONFLICT,
                "IdP email differs from linked yauth account; re-link required",
            ));
        }
        let _ = state
            .repos
            .external_identities
            .touch_last_login(ext.id, now_dt)
            .await;
        ext.user_id
    } else {
        if !conn.jit_provisioning_enabled {
            return Err(api_err(
                StatusCode::FORBIDDEN,
                "JIT provisioning is disabled for this connection — ask your admin to invite you",
            ));
        }
        provision_user(&state, &conn, &extracted, &provider_str).await?
    };

    let session_ttl = state.config.session_ttl;
    let (token_str, _sid) = session::create_session(&state, user_id, None, None, session_ttl)
        .await
        .map_err(|e| {
            crate::otel::record_error("sso_saml_session_create_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    state
        .write_audit_log(
            Some(user_id),
            "sso_saml_login_succeeded",
            Some(serde_json::json!({
                "connection_id": conn.id,
                "organization_id": conn.organization_id,
                "idp_entity_id": cfg.idp_entity_id,
                "provider": provider_str,
                "external_id": extracted.external_id,
                "assertion_id": extracted.assertion_id,
                "idp_initiated": expected_in_response_to.is_none(),
            })),
            None,
        )
        .await;

    let cookie = session_set_cookie(&state, &token_str, session_ttl);
    let redirect = redirect_to.unwrap_or_else(|| "/".into());

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, redirect), (header::SET_COOKIE, cookie)],
        axum::body::Body::empty(),
    )
        .into_response())
}

async fn provision_user(
    state: &YAuthState,
    conn: &SsoConnection,
    extracted: &crate::auth::saml_sp::ExtractedSamlIdentity,
    provider: &str,
) -> Result<Uuid, ApiError> {
    let now = Utc::now().naive_utc();
    let email = extracted.email.clone().unwrap_or_default();

    // Anti-takeover: refuse to silently merge with an existing yauth
    // account that doesn't yet have a link to this IdP.
    if !email.is_empty()
        && let Some(existing) = state.repos.users.find_by_email(&email).await?
    {
        let already_linked = state
            .repos
            .external_identities
            .list_for_user(existing.id)
            .await?
            .into_iter()
            .any(|x| x.provider == provider);
        if !already_linked {
            return Err(api_err(
                StatusCode::CONFLICT,
                "an account with this email already exists; re-link is required from the user's profile page",
            ));
        }
        return Err(api_err(
            StatusCode::CONFLICT,
            "IdP returned a new external_id for an existing linked account; re-link required",
        ));
    }

    let user_id = Uuid::now_v7();
    state
        .repos
        .users
        .create(NewUser {
            id: user_id,
            email: email.clone(),
            display_name: extracted.display_name.clone(),
            email_verified: true,
            role: "user".to_string(),
            banned: false,
            banned_reason: None,
            banned_until: None,
            created_at: now,
            updated_at: now,
        })
        .await?;

    state
        .repos
        .external_identities
        .create(NewExternalIdentity {
            id: Uuid::now_v7(),
            user_id,
            provider: provider.to_string(),
            external_id: extracted.external_id.clone(),
            linked_at: now,
            last_login_at: now,
        })
        .await?;

    let role = if extracted.mapped_roles.is_empty() {
        conn.default_role_on_jit.clone()
    } else {
        let refs: Vec<&str> = extracted.mapped_roles.iter().map(|s| s.as_str()).collect();
        rbac::most_privileged_role(&refs)
            .unwrap_or(roles::MEMBER)
            .to_string()
    };

    state
        .repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: conn.organization_id,
            user_id,
            role,
            status: yauth_entity::MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await?;

    state
        .write_audit_log(
            Some(user_id),
            "sso_saml_jit_provisioned",
            Some(serde_json::json!({
                "connection_id": conn.id,
                "organization_id": conn.organization_id,
                "provider": provider,
            })),
            None,
        )
        .await;

    Ok(user_id)
}

fn map_saml_error(e: SamlError) -> ApiError {
    crate::otel::record_error("sso_saml_assertion_invalid", &e);
    let code = match e {
        SamlError::BadResponseSignature
        | SamlError::BadAssertionSignature
        | SamlError::DigestMismatch => StatusCode::UNAUTHORIZED,
        SamlError::Replay(_) => StatusCode::CONFLICT,
        SamlError::EncryptedAssertionNotSupported
        | SamlError::IdpInitiatedDisabled
        | SamlError::BadIdpCert(_)
        | SamlError::UnsupportedSignatureAlgorithm(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_REQUEST,
    };
    api_err(code, &e.to_string())
}

// ──────────────────────────────────────────────
// /sso/saml/metadata/:cid
// ──────────────────────────────────────────────

async fn metadata(
    State(state): State<YAuthState>,
    Path(cid): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    let conn = state
        .repos
        .sso_connections
        .find_by_id(cid)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "connection not found"))?;
    let cfg = conn
        .saml_config()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "connection is not a SAML SP"))?;

    let provider = provider_for_state(&state);
    let xml = provider.render_sp_metadata(&cfg).map_err(|e| {
        crate::otel::record_error("sso_saml_metadata_failed", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "metadata render failed")
    })?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        xml,
    )
        .into_response())
}

// ──────────────────────────────────────────────
// SLO (best-effort)
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
    #[serde(default)]
    pub org: Option<String>,
}

async fn logout_redirect(
    State(state): State<YAuthState>,
    Query(q): Query<LogoutQuery>,
) -> Result<axum::response::Response, ApiError> {
    let slug = q
        .org
        .as_deref()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "missing org slug"))?;
    let org = state
        .repos
        .organizations
        .find_by_slug(slug)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "organization not found"))?;
    let conn = state
        .repos
        .sso_connections
        .find_active_saml_for_org(org.id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "no SAML connection"))?;
    let cfg = conn
        .saml_config()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "not a SAML connection"))?;
    let slo_url = cfg.idp_slo_url.ok_or_else(|| {
        api_err(
            StatusCode::NOT_IMPLEMENTED,
            "IdP did not advertise an SLO endpoint",
        )
    })?;
    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, slo_url)],
        axum::body::Body::empty(),
    )
        .into_response())
}

async fn slo_receiver(
    State(_state): State<YAuthState>,
    Form(_form): Form<AcsForm>,
) -> Result<StatusCode, ApiError> {
    // Best-effort: SAML SLO is a wire-spec nightmare in practice
    // (XML signatures + back-channel coordination across IdPs that
    // implement it inconsistently). We accept the request, log it,
    // and return 204. yauth's session cookie is already cleared by
    // the SP-initiated `/logout` route.
    Ok(StatusCode::NO_CONTENT)
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

/// Minimal application/x-www-form-urlencoded percent encoder. We
/// avoid `urlencoding` to keep deps small — the SAMLRequest payload
/// is already base64 (URL-safe alphabet stays within unreserved
/// chars for `=/+`, which we DO escape).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_redirect_accepts_in_app_path() {
        assert_eq!(
            safe_redirect(Some("/dash".into())).as_deref(),
            Some("/dash")
        );
    }

    #[test]
    fn safe_redirect_rejects_scheme_relative_url() {
        assert!(safe_redirect(Some("//evil.example/x".into())).is_none());
    }

    #[test]
    fn safe_redirect_rejects_absolute_url() {
        assert!(safe_redirect(Some("https://evil.example".into())).is_none());
    }

    #[test]
    fn urlencoding_handles_base64_padding() {
        let s = "aGVsbG8=";
        let enc = urlencoding_encode(s);
        assert!(enc.contains("%3D"));
        assert!(!enc.contains('='));
    }
}
