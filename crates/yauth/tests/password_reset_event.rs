//! Password-RESET completion publishes `AuthEvent::PasswordChanged` — fork
//! patch 2026-08-10 (BiggyBet issue #263, finding S20).
//!
//! `change_password` has always emitted the event. `reset_password` — the
//! forgot-password completion — stored the new hash, deleted every session and
//! wrote its audit log without publishing anything, so a host that hangs its
//! out-of-band "your password was changed" alert off the bus stayed silent for
//! the one flow an account takeover actually uses. The two sites now emit the
//! same event with the same payload at the same point in the sequence, and
//! these tests hold them there.
//!
//! Everything is asserted through the real HTTP surface against the in-memory
//! backend, so what is proved is what a subscriber can actually observe.
//!
//! ```text
//! cargo test --features memory-backend,mfa --test password_reset_event
//! ```

#![cfg(all(feature = "memory-backend", feature = "email-password"))]

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use yauth::auth::crypto::hash_token;
use yauth::backends::memory::InMemoryBackend;
use yauth::domain::NewPasswordReset;
use yauth::prelude::*;

const PASSWORD: &str = "correct-horse-battery-staple";
const NEW_PASSWORD: &str = "recovered-horse-battery-staple";

// ---------------------------------------------------------------------------
// Event recorder
// ---------------------------------------------------------------------------

/// The `user_id`s carried by every `PasswordChanged` seen on the bus, in order.
#[derive(Clone, Default)]
struct EventLog(Arc<Mutex<Vec<Uuid>>>);

impl EventLog {
    fn password_changes(&self) -> Vec<Uuid> {
        self.0.lock().unwrap().clone()
    }
}

struct RecorderPlugin(EventLog);

impl YAuthPlugin for RecorderPlugin {
    fn name(&self) -> &'static str {
        "test-password-changed-recorder"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn on_event(&self, event: &AuthEvent, _ctx: &PluginContext) -> EventResponse {
        if let AuthEvent::PasswordChanged { user_id } = event {
            self.0.0.lock().unwrap().push(*user_id);
        }
        EventResponse::Continue
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    app: Router,
    state: YAuthState,
    events: EventLog,
}

async fn harness() -> Harness {
    let events = EventLog::default();
    let backend = InMemoryBackend::new();

    let auth = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "http://localhost:3000".to_string(),
            session_cookie_name: "session".to_string(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            ..Default::default()
        },
    )
    .with_email_password(EmailPasswordConfig {
        min_password_length: 8,
        require_email_verification: false,
        hibp_check: false,
        ..Default::default()
    })
    .with_plugin(Box::new(RecorderPlugin(events.clone())))
    .build()
    .await
    .expect("failed to build YAuth");

    let state = auth.state().clone();
    let app = Router::new()
        .nest("/auth", auth.router())
        .with_state(state.clone());

    Harness { app, state, events }
}

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }

    let body_str = body.map(|b| serde_json::to_string(&b).unwrap());
    let req = req
        .body(axum::body::Body::from(body_str.unwrap_or_default()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_string())
        .map(|c| c.split(';').next().unwrap().to_string());

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    (status, parsed, set_cookie)
}

/// Register, log in, and return `(user_id, session_cookie)`.
async fn register(h: &Harness, email: &str) -> (Uuid, String) {
    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/register",
        Some(json!({ "email": email, "password": PASSWORD })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {body}");

    let (status, body, cookie) = login(h, email, PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    let cookie = cookie.expect("login must set a session cookie");

    let (status, body, _) = request(&h.app, "GET", "/auth/session", None, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "session failed: {body}");
    let user_id = body["user"]["id"].as_str().unwrap().parse().unwrap();
    (user_id, cookie)
}

async fn login(h: &Harness, email: &str, password: &str) -> (StatusCode, Value, Option<String>) {
    request(
        &h.app,
        "POST",
        "/auth/login",
        Some(json!({ "email": email, "password": password })),
        None,
    )
    .await
}

/// Put a reset token on file the way `forgot_password` does.
///
/// The handler mails the raw token and stores only its hash, so a test cannot
/// read one back out of the repository — it has to write the row it would have
/// written. Everything downstream of the token (lookup, expiry, hash upsert,
/// session sweep, event) is then the real handler.
async fn mint_reset_token(h: &Harness, user_id: Uuid, token: &str, valid_for: chrono::Duration) {
    let now = chrono::Utc::now();
    h.state
        .repos
        .password_resets
        .create(NewPasswordReset {
            id: Uuid::now_v7(),
            user_id,
            token_hash: hash_token(token),
            expires_at: (now + valid_for).naive_utc(),
            created_at: now.naive_utc(),
        })
        .await
        .expect("store the reset row");
}

async fn reset_password(h: &Harness, token: &str, password: &str) -> (StatusCode, Value) {
    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/reset-password",
        Some(json!({ "token": token, "password": password })),
        None,
    )
    .await;
    (status, body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The patch itself: a completed reset publishes exactly one `PasswordChanged`
/// for the account that was reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completing_a_reset_publishes_password_changed() {
    let h = harness().await;
    let (user_id, _) = register(&h, "reset-event@example.com").await;
    assert!(
        h.events.password_changes().is_empty(),
        "register + login must not look like a password change"
    );

    mint_reset_token(
        &h,
        user_id,
        "reset-token-happy-path",
        chrono::Duration::hours(1),
    )
    .await;
    let (status, body) = reset_password(&h, "reset-token-happy-path", NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "reset-password failed: {body}");

    assert_eq!(
        h.events.password_changes(),
        vec![user_id],
        "exactly one PasswordChanged, carrying the reset account's id"
    );

    // The event describes a change that actually happened: the new password
    // authenticates and the old one does not.
    let (status, body, cookie) = login(&h, "reset-event@example.com", NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "new password must work: {body}");
    assert!(cookie.is_some(), "a fresh login still issues a session");
    let (status, _, _) = login(&h, "reset-event@example.com", PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the superseded password must not work"
    );
}

/// A reset that never completes publishes nothing: the emit sits on the success
/// path, after the hash is stored, not next to the token lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_reset_publishes_nothing() {
    let h = harness().await;
    let (user_id, _) = register(&h, "reset-refused@example.com").await;

    // Unknown token.
    let (status, body) = reset_password(&h, "no-such-token", NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Known token, already expired.
    mint_reset_token(
        &h,
        user_id,
        "reset-token-stale",
        chrono::Duration::hours(-1),
    )
    .await;
    let (status, body) = reset_password(&h, "reset-token-stale", NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Known, live token — but a password the policy refuses.
    mint_reset_token(&h, user_id, "reset-token-weak", chrono::Duration::hours(1)).await;
    let (status, body) = reset_password(&h, "reset-token-weak", "short").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    assert!(
        h.events.password_changes().is_empty(),
        "no refused reset may look like a completed one: {:?}",
        h.events.password_changes()
    );

    // …and none of them moved the password.
    let (status, body, _) = login(&h, "reset-refused@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "original password intact: {body}");
}

/// The two sites stay mirror images: same event, same payload, one per call.
/// A subscriber cannot tell which flow it came from, which is the point — both
/// mean "this account's password is now something else".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_and_change_publish_the_same_event() {
    let h = harness().await;
    let (user_id, cookie) = register(&h, "reset-mirror@example.com").await;

    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/change-password",
        Some(json!({ "current_password": PASSWORD, "new_password": NEW_PASSWORD })),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "change-password failed: {body}");
    assert_eq!(h.events.password_changes(), vec![user_id]);

    mint_reset_token(
        &h,
        user_id,
        "reset-token-mirror",
        chrono::Duration::hours(1),
    )
    .await;
    let (status, body) = reset_password(&h, "reset-token-mirror", PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "reset-password failed: {body}");

    assert_eq!(
        h.events.password_changes(),
        vec![user_id, user_id],
        "the reset added one more event of the same shape"
    );
}
