//! # YAuth Cross-IdP Example Server
//!
//! Slim variant of `examples/server.rs` that pins the **memory backend**
//! and is used by the cross-IdP federation walkthrough at
//! `examples/cross-idp/`. See that README for the full picture.
//!
//! The same binary serves both roles in the demo:
//!   - Server A (IdP): plugins below + `oauth2-server`/`oidc` produce a
//!     compliant OpenID Connect Identity Provider.
//!   - Server B (App): plugins below + the `organizations` feature pull
//!     in the `sso-oidc` plugin that federates against Server A.
//!
//! Differences from `server.rs`:
//!   - No `diesel-pg-backend` dependency (and so no database setup).
//!   - No libsql/mysql branches.
//!   - `auto_admin_first_user: true` so `scripts/seed.sh` can create
//!     the admin in one POST without manual escalation.
//!
//! Environment is identical to `server.rs` — see that file for the
//! full table. Required env: `PORT`, `BASE_URL`, `JWT_SECRET`.

#![forbid(unsafe_code)]

use axum::{Extension, Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use serde_json::json;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

use yauth::middleware::AuthUser;
use yauth::prelude::*;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| format!("http://localhost:{}", port));
    let session_cookie_name = env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "session".into());
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-change-me".into());
    let passkey_rp_id = env::var("PASSKEY_RP_ID").unwrap_or_else(|_| "localhost".into());
    let passkey_rp_origin = env::var("PASSKEY_RP_ORIGIN").unwrap_or_else(|_| base_url.clone());
    let passkey_rp_name = env::var("PASSKEY_RP_NAME").unwrap_or_else(|_| "YAuth Dev".into());
    let mfa_issuer = env::var("MFA_ISSUER").unwrap_or_else(|_| "YAuth Dev".into());
    let allow_signups = env::var("ALLOW_SIGNUPS")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    log::info!(
        "cross-idp example server: backend=memory, base_url={}, port={}",
        base_url,
        port
    );

    let backend: Box<dyn yauth::repo::DatabaseBackend> =
        Box::new(yauth::backends::memory::InMemoryBackend::new());

    let builder = YAuthBuilder::new(
        backend,
        yauth::config::YAuthConfig {
            base_url: base_url.clone(),
            session_cookie_name,
            session_ttl: Duration::from_secs(7 * 24 * 3600),
            cookie_domain: env::var("COOKIE_DOMAIN").ok().into(),
            // Server B's backend will call the IdP over the docker network
            // (http://idp:8080). Don't gate cookies on https for the demo.
            secure_cookies: false,
            trusted_origins: vec![
                base_url.clone(),
                "http://localhost:5173".into(),
                "http://localhost:5174".into(),
            ],
            smtp: None,
            auto_admin_first_user: true,
            allow_signups,
            ..Default::default()
        },
    )
    .with_email_password(yauth::config::EmailPasswordConfig {
        min_password_length: 8,
        // No SMTP in the demo, so don't gate behind email verification.
        require_email_verification: false,
        hibp_check: false,
        ..Default::default()
    })
    .with_passkey(yauth::config::PasskeyConfig {
        rp_id: passkey_rp_id,
        rp_origin: passkey_rp_origin,
        rp_name: passkey_rp_name,
    })
    .with_mfa(yauth::config::MfaConfig {
        issuer: mfa_issuer,
        backup_code_count: 10,
    })
    .with_bearer(yauth::config::BearerConfig {
        jwt_secret,
        access_token_ttl: Duration::from_secs(15 * 60),
        refresh_token_ttl: Duration::from_secs(30 * 24 * 3600),
        audience: None,
        #[cfg(feature = "asymmetric-jwt")]
        signing_algorithm: Default::default(),
        #[cfg(feature = "asymmetric-jwt")]
        signing_key_pem: None,
        #[cfg(feature = "asymmetric-jwt")]
        kid: None,
    })
    .with_api_key()
    .with_admin()
    .with_magic_link(yauth::config::MagicLinkConfig::default())
    .with_account_lockout(yauth::config::AccountLockoutConfig::default())
    .with_webhooks(yauth::config::WebhookConfig::default())
    // ── Server A's role: the OIDC IdP ─────────────────────────────────
    // Optional consent UI: set `CONSENT_UI_URL` only on the IdP so the
    // browser is redirected to a real HTML consent page during the
    // federation flow. The App side leaves it unset (the field is unused
    // there because the App is the OIDC client, not the OIDC server).
    .with_oauth2_server(yauth::config::OAuth2ServerConfig {
        issuer: base_url.clone(),
        authorization_code_ttl: Duration::from_secs(60),
        scopes_supported: vec!["openid".into(), "email".into(), "profile".into()],
        // Demo-only: the seed script registers Server B via the dynamic
        // registration endpoint. Disable in production.
        allow_dynamic_registration: true,
        consent_ui_url: env::var("CONSENT_UI_URL").ok(),
        ..Default::default()
    })
    .with_oidc(yauth::config::OidcConfig {
        issuer: base_url.clone(),
        ..Default::default()
    })
    // ── Server B's role: federated SSO via the sso-oidc plugin, which
    //    is feature-gated on `organizations`. Both sides safely enable
    //    organizations — it's a no-op on the IdP for this demo. ──────
    .with_organizations()
    .with_status();

    let auth = builder.build().await.expect("Failed to build YAuth");

    let auth_state = auth.state().clone();

    let app_protected = Router::new().route("/api/me", get(me_handler)).layer(
        axum::middleware::from_fn_with_state(
            auth_state.clone(),
            yauth::middleware::auth_middleware,
        ),
    );

    let app = Router::new()
        .route("/api/health", get(health_handler))
        .merge(app_protected)
        .nest("/api/auth", auth.router())
        .with_state(auth_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.expect("Failed to bind port");
    log::info!("cross-idp server listening on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await.expect("Server error");
}

async fn health_handler() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

async fn me_handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "email_verified": user.email_verified,
            "role": user.role,
            "auth_method": format!("{:?}", user.auth_method),
        })),
    )
}
