//! OIDC Back-Channel Logout 1.0 — OP-side emitter.
//!
//! Proves the producer→emitter wiring end-to-end: a mock RP stands up an HTTP
//! server, a client registers it as its `backchannel_logout_uri`, the user
//! consents to that client, and then suspending the user causes the OP to POST
//! a spec-shaped, signed logout_token to the mock RP. The mock RP decodes the
//! token (HS256 with the bearer secret, since the test app has no asym key) and
//! asserts the §2.4 shape: NO nonce, NO exp, the backchannel-logout event key,
//! and matching iss/aud/sub.
//!
//! Memory backend only.

#![cfg(all(
    feature = "memory-backend",
    feature = "oauth2-server",
    feature = "oidc"
))]

use std::sync::Arc;
use std::time::Duration;

use axum::{Router, extract::State as AxState, http::StatusCode, routing::post};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use yauth::backends::memory::InMemoryBackend;
use yauth::plugin::AuthEvent;
use yauth::prelude::*;
use yauth::state::YAuthState;
use yauth_entity::{NewConsent, NewOauth2Client, NewUser};

const BASE_URL: &str = "http://127.0.0.1:9997";
const SECRET: &str = "test-secret-bcl-emit";
const ISSUER: &str = "http://127.0.0.1:9997";

// ── Mock RP that captures the POSTed logout_token ──────────────────────────

#[derive(Clone)]
struct RpState {
    tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<String>>>>,
}

#[derive(Deserialize)]
struct LogoutForm {
    logout_token: String,
}

async fn rp_backchannel(
    AxState(s): AxState<RpState>,
    axum::extract::Form(form): axum::extract::Form<LogoutForm>,
) -> StatusCode {
    if let Some(tx) = s.tx.lock().await.take() {
        let _ = tx.send(form.logout_token);
    }
    StatusCode::OK
}

struct MockRp {
    uri: String,
    rx: tokio::sync::oneshot::Receiver<String>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MockRp {
    async fn start() -> Self {
        let (token_tx, token_rx) = tokio::sync::oneshot::channel::<String>();
        let state = RpState {
            tx: Arc::new(tokio::sync::Mutex::new(Some(token_tx))),
        };
        let app = Router::new()
            .route("/backchannel-logout", post(rp_backchannel))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sd_tx, sd_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = sd_rx.await;
                })
                .await;
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        Self {
            uri: format!("http://{addr}/backchannel-logout"),
            rx: token_rx,
            _shutdown: sd_tx,
        }
    }
}

// ── yauth app ──────────────────────────────────────────────────────────────

async fn build_app() -> (Router, YAuthState) {
    let backend = InMemoryBackend::new();
    let auth = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: BASE_URL.into(),
            session_cookie_name: "session".into(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            ..Default::default()
        },
    )
    .with_email_password(yauth::config::EmailPasswordConfig {
        min_password_length: 8,
        require_email_verification: false,
        hibp_check: false,
        ..Default::default()
    })
    .with_bearer(yauth::config::BearerConfig {
        jwt_secret: SECRET.into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: Default::default(),
        signing_key_pem: None,
        kid: None,
    })
    .with_oauth2_server(yauth::config::OAuth2ServerConfig {
        issuer: ISSUER.into(),
        ..Default::default()
    })
    .with_oidc(yauth::config::OidcConfig {
        issuer: ISSUER.into(),
        ..Default::default()
    })
    .build()
    .await
    .expect("build YAuth");

    let state = auth.state().clone();
    let router = auth.router().with_state(state.clone());
    (router, state)
}

/// Register a client with a backchannel_logout_uri and a user that consented to
/// it. Returns (user_id, client_id).
async fn seed(state: &YAuthState, bcl_uri: &str) -> (Uuid, String) {
    let now = Utc::now().naive_utc();
    let client_id = format!("client-{}", Uuid::now_v7());
    state
        .repos
        .oauth2_clients
        .create(NewOauth2Client {
            id: Uuid::now_v7(),
            client_id: client_id.clone(),
            client_secret_hash: None,
            redirect_uris: serde_json::json!(["http://localhost/cb"]),
            client_name: Some("RP".into()),
            grant_types: serde_json::json!(["authorization_code"]),
            scopes: None,
            is_public: true,
            created_at: now,
            token_endpoint_auth_method: Some("none".into()),
            public_key_pem: None,
            jwks_uri: None,
            dynamically_registered: false,
        })
        .await
        .unwrap();
    // Register the back-channel logout URI via the repo's logout-config writer.
    let updated = state
        .repos
        .oauth2_clients
        .set_logout_config(&client_id, None, Some(bcl_uri.to_string()), false)
        .await
        .unwrap();
    assert!(updated, "set_logout_config should update the client");

    let user = state
        .repos
        .users
        .create(NewUser {
            id: Uuid::now_v7(),
            email: "rp-user@example.com".into(),
            email_verified: true,
            display_name: None,
            role: "member".into(),
            banned: false,
            banned_reason: None,
            banned_until: None,
            suspended_at: None,
            suspended_reason: None,
            activates_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    state
        .repos
        .consents
        .create(NewConsent {
            id: Uuid::now_v7(),
            user_id: user.id,
            client_id: client_id.clone(),
            scopes: None,
            created_at: now,
        })
        .await
        .unwrap();

    (user.id, client_id)
}

/// Decode a JWT payload without verifying.
fn decode_payload(jwt: &str) -> serde_json::Map<String, Value> {
    use base64::Engine;
    let part = jwt.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_emits_spec_shaped_logout_token_to_consented_rp() {
    let mut rp = MockRp::start().await;
    let (_router, state) = build_app().await;
    let (user_id, client_id) = seed(&state, &rp.uri).await;

    // Offboard the user (the path the admin suspend handler / SCIM emit drives).
    let _ = state.emit_event(&AuthEvent::UserSuspended { user_id });

    // The fan-out is spawned (and nests another spawn for delivery); await the
    // mock RP's capture with a timeout.
    let token = tokio::time::timeout(Duration::from_secs(5), &mut rp.rx)
        .await
        .expect("mock RP should receive a logout_token within 5s")
        .expect("oneshot not dropped");

    // Signature: HS256 with the bearer secret (no asym key configured).
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<serde_json::Map<String, Value>>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(SECRET.as_bytes()),
        &validation,
    )
    .expect("logout_token must verify under the bearer secret");

    // §2.4 shape.
    let claims = decode_payload(&token);
    assert_eq!(claims["iss"], serde_json::json!(ISSUER));
    assert_eq!(claims["aud"], serde_json::json!(client_id));
    assert_eq!(claims["sub"], serde_json::json!(user_id.to_string()));
    assert!(claims.contains_key("jti"), "logout_token needs a jti");
    assert!(claims.contains_key("iat"), "logout_token needs iat");
    assert!(
        !claims.contains_key("nonce"),
        "logout_token must NOT carry nonce"
    );
    assert!(
        !claims.contains_key("exp"),
        "logout_token must NOT carry exp"
    );
    let events = claims["events"].as_object().expect("events object");
    assert!(
        events.contains_key("http://schemas.openid.net/event/backchannel-logout"),
        "events must carry the backchannel-logout key"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ban_also_emits() {
    let mut rp = MockRp::start().await;
    let (_router, state) = build_app().await;
    let (user_id, _client_id) = seed(&state, &rp.uri).await;

    let _ = state.emit_event(&AuthEvent::UserBanned { user_id });

    let token = tokio::time::timeout(Duration::from_secs(5), &mut rp.rx)
        .await
        .expect("ban must also fan out a logout_token")
        .expect("oneshot not dropped");
    assert!(!token.is_empty());
}
