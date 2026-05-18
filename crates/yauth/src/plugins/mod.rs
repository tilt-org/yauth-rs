#[cfg(feature = "email-password")]
pub mod email_password;

#[cfg(feature = "passkey")]
pub mod passkey;

#[cfg(feature = "mfa")]
pub mod mfa;

#[cfg(feature = "oauth")]
pub mod oauth;

#[cfg(feature = "bearer")]
pub mod bearer;

#[cfg(feature = "api-key")]
pub mod api_key;

#[cfg(feature = "magic-link")]
pub mod magic_link;

#[cfg(feature = "admin")]
pub mod admin;
#[cfg(all(feature = "admin", feature = "oauth2-server"))]
pub mod oauth2_admin;

#[cfg(feature = "oauth2-server")]
pub mod oauth2_server;

#[cfg(feature = "account-lockout")]
pub mod account_lockout;

#[cfg(feature = "webhooks")]
pub mod webhooks;

#[cfg(feature = "oidc")]
pub mod oidc;

#[cfg(feature = "status")]
pub mod status;

#[cfg(feature = "organizations")]
pub mod organizations;

use axum::{
    Extension, Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, patch, post},
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::crypto;
use crate::middleware::{AuthMethod, AuthUser};
use crate::plugin::PluginContext;
use crate::state::YAuthState;

pub fn core_routes(_ctx: &PluginContext) -> Router<YAuthState> {
    Router::new()
        .route("/session", get(get_session))
        .route("/logout", post(logout))
        .route("/me", patch(update_profile))
}

/// Public routes that don't require authentication.
///
/// Currently exposes `GET /config` for frontends to discover server-side
/// auth configuration (e.g., whether signups are enabled).
pub fn core_public_routes() -> Router<YAuthState> {
    Router::new().route("/config", get(get_config))
}

/// Server-side auth configuration exposed to frontends via `GET /config`.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthConfigResponse {
    /// Whether new user registration is allowed.
    pub allow_signups: bool,
    /// Whether newly registered users must verify their email before logging in.
    pub require_email_verification: bool,
}

/// Envelope returned by `GET /session` — wraps the authenticated user and
/// surfaces session expiry. Matches the yauth-go `EmailPasswordSessionResponse`
/// shape so a single TypeScript client serves both backends.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionResponse {
    pub user: AuthUser,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Envelope returned by `PATCH /me`. Mirrors yauth-go's
/// `EmailPasswordPatchMeResponse`.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PatchMeResponse {
    pub user: AuthUser,
}

/// 1-based pagination clamp shared by list endpoints. `max_per_page` differs
/// between admin (100) and per-user lists (200) to mirror yauth-go.
pub(crate) fn paginate(page: Option<u64>, per_page: Option<u64>, max_per_page: u64) -> (u64, u64) {
    let per_page = per_page.unwrap_or(50).clamp(1, max_per_page);
    let page = page.unwrap_or(1).max(1);
    (page, per_page)
}

/// Slice an in-memory `Vec<T>` for a 1-based `(page, per_page)` window.
/// Returned tuple is `(items, total)`. Used by list endpoints whose repo
/// trait does not expose a paginated query.
pub(crate) fn paginate_vec<T>(items: Vec<T>, page: u64, per_page: u64) -> (Vec<T>, u64) {
    let total = items.len() as u64;
    let start = (page.saturating_sub(1) * per_page) as usize;
    let end = (start + per_page as usize).min(items.len());
    let window = if start >= items.len() {
        Vec::new()
    } else {
        items.into_iter().skip(start).take(end - start).collect()
    };
    (window, total)
}

async fn get_config(State(state): State<YAuthState>) -> Json<AuthConfigResponse> {
    #[cfg(feature = "email-password")]
    let require_email_verification = state.email_password_config.require_email_verification;
    #[cfg(not(feature = "email-password"))]
    let require_email_verification = false;

    Json(AuthConfigResponse {
        allow_signups: state.config.allow_signups,
        require_email_verification,
    })
}

async fn get_session(
    State(state): State<YAuthState>,
    jar: CookieJar,
    Extension(user): Extension<AuthUser>,
) -> Json<SessionResponse> {
    let expires_at = match user.auth_method {
        AuthMethod::Session => session_expires_at(&state, &jar).await,
        _ => None,
    };
    Json(SessionResponse { user, expires_at })
}

async fn session_expires_at(state: &YAuthState, jar: &CookieJar) -> Option<DateTime<Utc>> {
    let cookie = jar.get(&state.config.session_cookie_name)?;
    let token_hash = crypto::hash_token(cookie.value());
    let session = state
        .repos
        .session_ops
        .validate_session(&token_hash)
        .await
        .ok()??;
    Some(Utc.from_utc_datetime(&session.expires_at))
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
}

async fn update_profile(
    axum::extract::State(state): axum::extract::State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Json(input): Json<UpdateProfileRequest>,
) -> impl axum::response::IntoResponse {
    let display_name = input
        .display_name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());

    let changes = crate::domain::UpdateUser {
        display_name: Some(display_name),
        updated_at: Some(Utc::now().naive_utc()),
        ..Default::default()
    };

    match state.repos.users.update(user.id, changes).await {
        Ok(updated) => (
            StatusCode::OK,
            Json(
                serde_json::to_value(PatchMeResponse {
                    user: AuthUser {
                        id: updated.id,
                        email: updated.email,
                        display_name: updated.display_name,
                        email_verified: updated.email_verified,
                        role: updated.role,
                        banned: updated.banned,
                        auth_method: user.auth_method,
                        scopes: user.scopes,
                    },
                })
                .unwrap_or_else(|_| serde_json::json!({})),
            ),
        ),
        Err(e) => {
            crate::otel::record_error("profile_update_db_error", &e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Internal error" })),
            )
        }
    }
}

async fn logout(
    axum::extract::State(state): axum::extract::State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> impl axum::response::IntoResponse {
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let _ = crate::auth::session::delete_session(&state, cookie.value()).await;
    }

    state
        .write_audit_log(Some(user.id), "logout", None, None)
        .await;

    let clear_cookie = format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        state.config.session_cookie_name
    );

    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, clear_cookie)],
        Json(serde_json::json!({ "success": true })),
    )
}
