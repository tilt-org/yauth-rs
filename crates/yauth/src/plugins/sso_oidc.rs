//! User-facing SSO OIDC login routes (issue #93, Phase B).
//!
//! These are the public endpoints a user-agent hits during a
//! federated sign-in. The admin-side CRUD for SSO connections lives
//! in [`super::organizations`]; this module is intentionally separate
//! to keep that file legible and to confine the public surface for
//! the federated login flow in one spot.
//!
//! Routes mounted under the `organizations` feature:
//!
//! | Method | Path                                  | Effect                                       |
//! |--------|---------------------------------------|----------------------------------------------|
//! | `GET`  | `/sso/login?org=<slug>`               | Redirect to IdP authorize URL                |
//! | `GET`  | `/sso/login?domain=<acme.com>`        | HRD by verified domain → org → connection    |
//! | `GET`  | `/sso/callback?code=&state=`          | Callback from the IdP                        |
//!
//! Both endpoints are public (no auth required) and feature-gated on
//! `organizations`.

#![cfg(feature = "organizations")]

use axum::{
    Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use chrono::{Duration as ChronoDuration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{
    oidc_client::{
        self, ChaCha20Poly1305Cipher, IdTokenError, JwksCache, OidcFetchError, PassthroughCipher,
        SecretCipher, TokenExchangeError, claims_to_json, exchange_code,
        extract_identity_from_claims, id_token_kid, validate_id_token,
    },
    rbac::{self, roles},
    session,
    session::session_set_cookie,
};
use crate::error::{ApiError, api_err};
use crate::state::YAuthState;
use yauth_entity::{
    ConnectionKind, ConnectionStatus, DomainStatus, NewExternalIdentity, NewMembership,
    NewSsoLoginState, NewUser, SsoConnection, oidc_provider,
};

/// Mount the public `/sso/login` + `/sso/callback` routes onto the
/// router. Public — no auth middleware.
pub(crate) fn public_routes() -> Router<YAuthState> {
    Router::new()
        .route("/sso/login", get(login))
        .route("/sso/callback", get(callback))
        // OIDC Back-Channel Logout 1.0 RP endpoint: the upstream IdP POSTs a
        // signed logout_token here when a federated user is logged out at the
        // IdP, so the suspension propagates to this relying party.
        .route(
            "/sso/backchannel-logout",
            axum::routing::post(backchannel_logout),
        )
}

// ──────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────

/// Build the SSO callback URL from `state.config.base_url`. All
/// callbacks land on a fixed in-app path so the admin doesn't have to
/// configure a per-connection redirect URI on the IdP side beyond
/// `<base_url>/sso/callback`.
fn callback_url(state: &YAuthState) -> String {
    format!(
        "{}/sso/callback",
        state.config.base_url.trim_end_matches('/')
    )
}

/// Decide which cipher to use for the at-rest `client_secret`. If
/// the deployment supplied a 32-byte AEAD key via `YAUTH_SSO_AEAD_KEY`,
/// use the real cipher; otherwise fall back to the passthrough one
/// (which keeps the shape uniform but offers no confidentiality —
/// suitable for local dev only). Operators are expected to set the
/// env var in any non-dev deployment.
fn cipher_for_state(_state: &YAuthState) -> Box<dyn SecretCipher> {
    if let Ok(hex_key) = std::env::var("YAUTH_SSO_AEAD_KEY")
        && let Ok(bytes) = hex::decode(hex_key.trim())
        && let Some(c) = ChaCha20Poly1305Cipher::new(&bytes)
    {
        return Box::new(c);
    }
    Box::new(PassthroughCipher)
}

/// Shared HTTP client (per-process). reqwest pools internally so a
/// single instance is cheap. We re-build it per call here because
/// caching it would require touching the state struct — fine for
/// Phase B; tune in a follow-up if benchmarks demand.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(concat!("yauth/", env!("CARGO_PKG_VERSION"), " (+sso-oidc)"))
        .build()
        .unwrap_or_default()
}

/// Process-global JWKS cache. Cloning is cheap (Arc inside).
fn jwks_cache() -> JwksCache {
    use std::sync::OnceLock;
    static CACHE: OnceLock<JwksCache> = OnceLock::new();
    CACHE.get_or_init(JwksCache::new).clone()
}

/// Sanitize a `redirect_to` query parameter — only in-app paths.
fn safe_redirect(input: Option<String>) -> Option<String> {
    let candidate = input?;
    if candidate.starts_with('/') && !candidate.starts_with("//") {
        Some(candidate)
    } else {
        None
    }
}

// ──────────────────────────────────────────────
// /sso/login
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Sign in to a specific org slug.
    #[serde(default)]
    pub org: Option<String>,
    /// HRD: pick the org via verified email domain.
    #[serde(default)]
    pub domain: Option<String>,
    /// Where to send the user after a successful sign-in. Bounded to
    /// in-app paths (`/foo/bar`) by [`safe_redirect`].
    #[serde(default)]
    pub redirect_to: Option<String>,
}

async fn login(
    State(state): State<YAuthState>,
    Query(q): Query<LoginQuery>,
) -> Result<axum::response::Response, ApiError> {
    let conn = resolve_connection(&state, &q).await?;
    let cfg = conn
        .oidc_config()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "connection is not an OIDC client"))?;

    // Discover.
    let client = http_client();
    let cache = jwks_cache();
    let doc = cache
        .discover(&client, &cfg.discovery_url)
        .await
        .map_err(|e| {
            crate::otel::record_error("sso_oidc_discovery_failed", &e);
            api_err(StatusCode::BAD_GATEWAY, "IdP discovery failed")
        })?;

    // Build state + PKCE + nonce.
    let state_token = oidc_client::generate_state_token();
    let nonce = oidc_client::generate_nonce();
    let pkce = oidc_client::pkce_generate();
    let now = Utc::now().naive_utc();
    state
        .repos
        .sso_login_states
        .create(NewSsoLoginState {
            state: state_token.clone(),
            connection_id: conn.id,
            issuer: doc.issuer.clone(),
            nonce: nonce.clone(),
            pkce_verifier: pkce.verifier.clone(),
            redirect_to: safe_redirect(q.redirect_to.clone()),
            created_at: now,
            expires_at: now + ChronoDuration::seconds(yauth_entity::STATE_TTL_SECS),
        })
        .await?;

    let redirect_uri = callback_url(&state);
    let url = oidc_client::build_authorize_url(
        &doc.authorization_endpoint,
        &cfg,
        &redirect_uri,
        &state_token,
        &nonce,
        &pkce.challenge,
    );

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, url)],
        axum::body::Body::empty(),
    )
        .into_response())
}

/// Decide which `SsoConnection` to use, given the `/sso/login` query.
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
            // HRD: look up an *active* verified domain → org → connection.
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
        .find_active_oidc_for_org(org_id)
        .await?
        .ok_or_else(|| {
            api_err(
                StatusCode::NOT_FOUND,
                "organization has no active OIDC connection",
            )
        })?;
    if conn.kind != ConnectionKind::OidcClient || conn.status != ConnectionStatus::Active {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "connection is not an active OIDC client",
        ));
    }
    Ok(conn)
}

// ──────────────────────────────────────────────
// /sso/callback
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// IdP returned an explicit error (e.g. user denied consent).
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

async fn callback(
    State(state): State<YAuthState>,
    Query(q): Query<CallbackQuery>,
) -> Result<axum::response::Response, ApiError> {
    // IdP-side error first.
    if let Some(err) = q.error {
        let detail = q.error_description.unwrap_or_default();
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            &format!("IdP returned error `{err}`: {detail}"),
        ));
    }
    let code = q
        .code
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "missing `code` query param"))?;
    let state_token = q
        .state
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "missing `state` query param"))?;

    // Look up + consume the state row.
    let row = state
        .repos
        .sso_login_states
        .find_and_delete(&state_token)
        .await?
        .ok_or_else(|| {
            api_err(
                StatusCode::BAD_REQUEST,
                "state is unknown, expired, or already used",
            )
        })?;

    // Pull the connection — it must still exist + still be active.
    let conn = state
        .repos
        .sso_connections
        .find_by_id(row.connection_id)
        .await?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "connection no longer exists"))?;
    if conn.status != ConnectionStatus::Active || conn.kind != ConnectionKind::OidcClient {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "connection is not an active OIDC client",
        ));
    }
    let cfg = conn
        .oidc_config()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "connection has no OIDC config"))?;

    // Decrypt client_secret.
    let cipher = cipher_for_state(&state);
    let client_secret = cipher.decrypt(&cfg.client_secret).map_err(|e| {
        crate::otel::record_error("sso_oidc_secret_decrypt_failed", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Discovery + token exchange + JWKS validation.
    let client = http_client();
    let cache = jwks_cache();
    let doc = cache
        .discover(&client, &cfg.discovery_url)
        .await
        .map_err(|e| {
            crate::otel::record_error("sso_oidc_discovery_failed", &e);
            api_err(StatusCode::BAD_GATEWAY, "IdP discovery failed")
        })?;

    // Issuer must match what we recorded at /sso/login. Defeats
    // cross-IdP token replay (attacker can't swap a state from IdP-A
    // with a callback from IdP-B).
    if doc.issuer != row.issuer {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "issuer mismatch between authorize and callback",
        ));
    }

    let token = exchange_code(
        &client,
        &doc.token_endpoint,
        &code,
        &callback_url(&state),
        &cfg.client_id,
        &client_secret,
        &row.pkce_verifier,
    )
    .await
    .map_err(|e| match e {
        TokenExchangeError::Network(msg) => {
            crate::otel::record_error("sso_oidc_token_exchange_network", &msg);
            api_err(StatusCode::BAD_GATEWAY, "token exchange failed")
        }
        TokenExchangeError::BadResponse { status, .. } => api_err(
            StatusCode::BAD_GATEWAY,
            &format!("IdP token error {status}"),
        ),
        TokenExchangeError::BadFormat(msg) => {
            crate::otel::record_error("sso_oidc_token_exchange_format", &msg);
            api_err(StatusCode::BAD_GATEWAY, "IdP token response malformed")
        }
    })?;

    let kid = id_token_kid(&token.id_token).map_err(map_id_token_error)?;
    let jwk = cache
        .key_for_kid(&client, &doc.issuer, &doc.jwks_uri, &kid)
        .await
        .map_err(|e| match e {
            OidcFetchError::RateLimited => {
                api_err(StatusCode::TOO_MANY_REQUESTS, "JWKS refresh rate-limited")
            }
            OidcFetchError::Network(msg) => {
                crate::otel::record_error("sso_oidc_jwks_fetch_failed", &msg);
                api_err(StatusCode::BAD_GATEWAY, "JWKS fetch failed")
            }
            OidcFetchError::BadJwks(msg) => {
                crate::otel::record_error("sso_oidc_jwks_bad", &msg);
                api_err(StatusCode::BAD_GATEWAY, "JWKS malformed")
            }
            OidcFetchError::BadDiscovery(msg) => {
                crate::otel::record_error("sso_oidc_discovery_bad", &msg);
                api_err(StatusCode::BAD_GATEWAY, "discovery malformed")
            }
        })?;

    let now = Utc::now().timestamp();
    let claims = validate_id_token(
        &token.id_token,
        &jwk,
        &doc.issuer,
        &cfg.client_id,
        &row.nonce,
        now,
    )
    .map_err(map_id_token_error)?;

    // Apply ClaimMappings.
    let claims_json = claims_to_json(&claims);
    let extracted = extract_identity_from_claims(&cfg.claim_mappings, &claims_json)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, &format!("claim extraction: {e}")))?;
    if extracted.missing_email() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "IdP did not return an email claim — required for JIT provisioning",
        ));
    }
    let provider = oidc_provider(&doc.issuer);
    let now_dt = Utc::now().naive_utc();

    // 1) Existing external identity → log in.
    let user_id = if let Some(ext) = state
        .repos
        .external_identities
        .find_by_provider_external_id(&provider, &extracted.external_id)
        .await?
    {
        // Anti-takeover: if the IdP rotates the email claim to one
        // that doesn't match the linked yauth user, refuse to merge.
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
        // 2) JIT provisioning.
        if !conn.jit_provisioning_enabled {
            return Err(api_err(
                StatusCode::FORBIDDEN,
                "JIT provisioning is disabled for this connection — ask your admin to invite you",
            ));
        }
        provision_user(&state, &conn, &extracted, &provider).await?
    };

    // Issue a yauth session.
    let session_ttl = state.config.session_ttl;
    let (token_str, _sid) = session::create_session(&state, user_id, None, None, session_ttl)
        .await
        .map_err(|e| {
            crate::otel::record_error("sso_oidc_session_create_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    state
        .write_audit_log(
            Some(user_id),
            "sso_oidc_login_succeeded",
            Some(serde_json::json!({
                "connection_id": conn.id,
                "organization_id": conn.organization_id,
                "issuer": doc.issuer,
                "provider": provider,
                "external_id": extracted.external_id,
            })),
            None,
        )
        .await;

    let cookie = session_set_cookie(&state, &token_str, session_ttl);
    let redirect_to = row.redirect_to.unwrap_or_else(|| "/".to_string());

    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, redirect_to),
            (header::SET_COOKIE, cookie),
        ],
        axum::body::Body::empty(),
    )
        .into_response())
}

async fn provision_user(
    state: &YAuthState,
    conn: &SsoConnection,
    extracted: &oidc_client::ExtractedIdentity,
    provider: &str,
) -> Result<Uuid, ApiError> {
    let now = Utc::now().naive_utc();
    let email = extracted.email.clone().unwrap_or_default();

    // Account-takeover prevention: if an existing yauth user has the
    // same email but NO link to this IdP, do NOT silently merge — that
    // would let an attacker who controls an email mailbox steal an
    // existing yauth account via a fresh IdP enrollment.
    if let Some(existing) = state.repos.users.find_by_email(&email).await? {
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
        // Has a link to this IdP already — that means the
        // (provider, external_id) lookup above should have hit. If we
        // got here, the IdP rotated `external_id` for an existing
        // user, which we also treat as a takeover attempt.
        return Err(api_err(
            StatusCode::CONFLICT,
            "IdP returned a new external_id for an existing linked account; re-link required",
        ));
    }

    // Create the yauth user.
    let user_id = Uuid::now_v7();
    state
        .repos
        .users
        .create(NewUser {
            id: user_id,
            email: email.clone(),
            display_name: extracted.display_name.clone(),
            email_verified: true, // IdP is the source of truth
            role: "user".to_string(),
            banned: false,
            banned_reason: None,
            banned_until: None,
            suspended_at: None,
            suspended_reason: None,
            activates_at: None,
            created_at: now,
            updated_at: now,
        })
        .await?;

    // Link the external identity.
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

    // Pick the most-privileged matched role; otherwise fall back to
    // the connection's default.
    let role = if extracted.mapped_roles.is_empty() {
        conn.default_role_on_jit.clone()
    } else {
        let refs: Vec<&str> = extracted.mapped_roles.iter().map(|s| s.as_str()).collect();
        rbac::most_privileged_role(&refs)
            .unwrap_or(roles::MEMBER)
            .to_string()
    };

    // Add membership.
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

    Ok(user_id)
}

fn map_id_token_error(e: IdTokenError) -> ApiError {
    crate::otel::record_error("sso_oidc_id_token_invalid", &e);
    let code = match e {
        IdTokenError::Expired
        | IdTokenError::NotYetValid
        | IdTokenError::NonceMismatch
        | IdTokenError::AudienceMismatch { .. }
        | IdTokenError::IssuerMismatch { .. } => StatusCode::BAD_REQUEST,
        IdTokenError::BadSignature => StatusCode::UNAUTHORIZED,
        IdTokenError::MissingKid
        | IdTokenError::UnsupportedAlg(_)
        | IdTokenError::Malformed(_)
        | IdTokenError::JwksLookup(_) => StatusCode::BAD_REQUEST,
    };
    api_err(code, &e.to_string())
}

// ──────────────────────────────────────────────
// OIDC Back-Channel Logout 1.0 — RP consumer
// ──────────────────────────────────────────────

/// The OIDC BCL 1.0 event identifier that MUST be present (as a key with an
/// empty-object value) in a logout_token's `events` claim.
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Process-local single-use store for logout_token `jti` values, enforcing
/// OIDC BCL §2.6's replay rejection. Process-local: in a multi-replica
/// deployment each replica dedups its own traffic, acceptable for an idempotent
/// "kill all sessions" action.
struct JtiReplayCache {
    seen: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    ttl: std::time::Duration,
}

impl JtiReplayCache {
    fn new(ttl: std::time::Duration) -> Self {
        Self {
            seen: std::sync::Mutex::new(std::collections::HashMap::new()),
            ttl,
        }
    }

    /// Record `jti` and report whether it was already present (a replay).
    fn seen(&self, jti: &str) -> bool {
        let now = std::time::Instant::now();
        let mut map = self.seen.lock().unwrap();
        // Opportunistic GC of expired entries.
        map.retain(|_, exp| *exp > now);
        if map.contains_key(jti) {
            return true;
        }
        map.insert(jti.to_string(), now + self.ttl);
        false
    }
}

fn jti_cache() -> &'static JtiReplayCache {
    use std::sync::OnceLock;
    static CACHE: OnceLock<JtiReplayCache> = OnceLock::new();
    CACHE.get_or_init(|| JtiReplayCache::new(std::time::Duration::from_secs(600)))
}

#[derive(Deserialize)]
struct BackchannelLogoutForm {
    #[serde(default)]
    logout_token: Option<String>,
}

/// `POST /sso/backchannel-logout` — OIDC BCL 1.0 RP endpoint.
///
/// The request is unsolicited and org-less, so we match it to one of our active
/// OIDC SSO connections by (issuer, audience=client_id), verify the signature
/// against that connection's published JWKS, then map the token's `sub` back to
/// the local user via the stored external identity and revoke their sessions.
/// Always returns 200 on a valid token (BCL §2.8); structural/verification
/// failures return 400.
async fn backchannel_logout(
    State(state): State<YAuthState>,
    axum::extract::Form(form): axum::extract::Form<BackchannelLogoutForm>,
) -> impl IntoResponse {
    // BCL §2.8: the response must not be cached.
    let no_store = [(header::CACHE_CONTROL, "no-store")];

    let Some(raw) = form.logout_token.filter(|s| !s.is_empty()) else {
        return (StatusCode::BAD_REQUEST, no_store, "missing logout_token").into_response();
    };

    // Unverified peek to learn iss + aud so we can pick a connection (and thus
    // the JWKS) to verify against.
    let unverified = match peek_logout_token(&raw) {
        Some(v) => v,
        None => {
            return (StatusCode::BAD_REQUEST, no_store, "malformed logout_token").into_response();
        }
    };
    let Some(iss) = unverified
        .get("iss")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            no_store,
            "logout_token missing iss",
        )
            .into_response();
    };

    let client = http_client();
    let cache = jwks_cache();

    // Find an active OIDC connection whose discovery `issuer` == the token's iss
    // and whose client_id == the token's aud.
    let conns = match state.repos.sso_connections.list_all().await {
        Ok(c) => c,
        Err(e) => {
            crate::otel::record_error("bcl_list_connections_failed", &e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                no_store,
                "internal error",
            )
                .into_response();
        }
    };

    let mut matched: Option<(crate::auth::oidc_client::DiscoveryDocument, String)> = None;
    for conn in conns {
        if conn.kind != ConnectionKind::OidcClient || conn.status != ConnectionStatus::Active {
            continue;
        }
        let Some(cfg) = conn.oidc_config() else {
            continue;
        };
        if !crate::auth::oidc_client::logout_token_audience_matches(
            unverified.get("aud"),
            &cfg.client_id,
        ) {
            continue;
        }
        // Resolve the connection's actual issuer via discovery, then compare to
        // the token's iss (trailing-slash-insensitive).
        let Ok(doc) = cache.discover(&client, &cfg.discovery_url).await else {
            continue;
        };
        if normalize_issuer(&doc.issuer) == normalize_issuer(iss) {
            matched = Some((doc, cfg.client_id.clone()));
            break;
        }
    }
    let Some((doc, client_id)) = matched else {
        return (
            StatusCode::BAD_REQUEST,
            no_store,
            "no connection matches logout_token issuer/audience",
        )
            .into_response();
    };

    // Verify the signature against the matched connection's JWKS.
    let kid = match id_token_kid(&raw) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                no_store,
                "logout_token missing kid",
            )
                .into_response();
        }
    };
    let jwk = match cache
        .key_for_kid(&client, &doc.issuer, &doc.jwks_uri, &kid)
        .await
    {
        Ok(j) => j,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, no_store, "JWKS fetch failed").into_response();
        }
    };
    let claims =
        match crate::auth::oidc_client::verify_logout_token(&raw, &jwk, &doc.issuer, &client_id) {
            Ok(c) => c,
            Err(e) => {
                crate::otel::record_error("bcl_verify_logout_token_failed", &e);
                return (
                    StatusCode::BAD_REQUEST,
                    no_store,
                    "logout_token verification failed",
                )
                    .into_response();
            }
        };

    // BCL §2.4 structural validation against the *verified* claims.
    if claims.contains_key("nonce") {
        return (
            StatusCode::BAD_REQUEST,
            no_store,
            "logout_token must not contain nonce",
        )
            .into_response();
    }
    let has_event = claims
        .get("events")
        .and_then(|v| v.as_object())
        .map(|evs| evs.contains_key(BACKCHANNEL_LOGOUT_EVENT))
        .unwrap_or(false);
    if !has_event {
        return (
            StatusCode::BAD_REQUEST,
            no_store,
            "logout_token events missing backchannel-logout",
        )
            .into_response();
    }
    let Some(jti) = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            no_store,
            "logout_token missing jti",
        )
            .into_response();
    };
    // We support sub-based logout (kill all the user's sessions); a sid-only
    // token can't be mapped without per-session sid tracking.
    let Some(sub) = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            no_store,
            "logout_token missing sub",
        )
            .into_response();
    };

    // Replay protection: a re-sent jti is an idempotent success.
    if jti_cache().seen(jti) {
        return (StatusCode::OK, no_store, "").into_response();
    }

    // Map the IdP sub to the local user and revoke their sessions.
    let provider = oidc_provider(&doc.issuer);
    if let Ok(Some(ext)) = state
        .repos
        .external_identities
        .find_by_provider_external_id(&provider, sub)
        .await
    {
        let _ = session::delete_all_user_sessions(&state, ext.user_id).await;
        let _ = state
            .repos
            .refresh_tokens
            .revoke_all_user_refresh_tokens(ext.user_id)
            .await;
    }

    // Always 200 on a valid token even if no local session existed — the OP
    // only needs to know the token was accepted.
    (StatusCode::OK, no_store, "").into_response()
}

/// Decode a JWT's claims without verifying the signature, for the
/// issuer/audience peek that selects which connection to verify against.
fn peek_logout_token(raw: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    use base64::Engine;
    let payload_b64 = raw.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Trim a trailing slash so issuer comparisons are robust to the common
/// "with/without trailing slash" discrepancy.
fn normalize_issuer(s: &str) -> &str {
    s.trim().trim_end_matches('/')
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
    fn safe_redirect_passes_none() {
        assert!(safe_redirect(None).is_none());
    }
}
