//! Shared in-memory HTTP harness for the two BiggyBet fork suites
//! (`mfa_hardening`, `password_reset_event`) — review finding 57.
//!
//! Both suites drive the real router over `InMemoryBackend` with
//! `tower::ServiceExt::oneshot`, and both had their own byte-identical copy of
//! `Harness` and `request()` plus a `harness()`/`register()`/`login()` trio that
//! differed by one clause each. Upstream is archived, so that duplication could
//! only drift in-house.
//!
//! **Why a new module and not `tests/helpers/`.** `tests/helpers/` has never
//! held an HTTP harness — the per-suite copy is the upstream convention, and
//! `tests/memory_backend.rs` still carries its own `request()`. More
//! practically, 22 test binaries declare `mod helpers;` under the default
//! feature set; anything added there that touches `InMemoryBackend` would have
//! to be `cfg`-gated on `memory-backend` or it breaks all 22. This module is
//! declared by the two suites that want it and by nothing else, so it is only
//! ever compiled under their own crate-level `cfg` gates.
//!
//! The suite-specific halves stay in the suites: each keeps its own event
//! recorder (they watch different events), its own password constant, and its
//! own thin wrappers where a fixed argument reads better than a parameter.

// Two consumers with overlapping but not identical needs: whichever helper one
// suite leaves alone is dead code in that binary. Same reason `helpers/mod.rs`
// carries the annotation.
#![allow(dead_code)]

use axum::Router;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use yauth::backends::memory::InMemoryBackend;
use yauth::prelude::*;

/// A built router plus the state behind it, and whatever the suite is recording
/// off the event bus.
pub struct Harness<E> {
    pub app: Router,
    pub state: YAuthState,
    pub events: E,
}

/// Build the shared app: in-memory backend, signups open, email verification
/// off, HIBP off, one session cookie named `session`, and `recorder` on the bus.
///
/// `configure` is the one seam the two suites need — it receives the builder
/// after the common configuration and before `build()`, so a suite can add the
/// plugin it is actually testing (`with_mfa`, and whatever comes next) without
/// this module having to know about it or `cfg`-gate on its feature.
pub async fn harness<E>(
    events: E,
    recorder: Box<dyn YAuthPlugin>,
    configure: impl FnOnce(YAuthBuilder) -> YAuthBuilder,
) -> Harness<E> {
    let backend = InMemoryBackend::new();

    let builder = YAuthBuilder::new(
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
    });

    // Under `full` — the feature set CI builds every suite with — the `bearer`
    // feature is on, and `build()` refuses to run without a bearer config. The
    // upstream in-memory suites satisfy that guard with a throwaway secret;
    // this harness does the same. Neither consumer mints or presents a token.
    #[cfg(feature = "bearer")]
    let builder = builder.with_bearer(yauth::config::BearerConfig {
        jwt_secret: "test-secret-for-memory-http-harness".to_string(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        #[cfg(feature = "asymmetric-jwt")]
        signing_algorithm: Default::default(),
        #[cfg(feature = "asymmetric-jwt")]
        signing_key_pem: None,
        #[cfg(feature = "asymmetric-jwt")]
        kid: None,
    });

    let auth = configure(builder)
        .with_plugin(recorder)
        .build()
        .await
        .expect("failed to build YAuth");

    let state = auth.state().clone();
    let app = Router::new()
        .nest("/auth", auth.router())
        .with_state(state.clone());

    Harness { app, state, events }
}

/// One JSON request through the real router.
///
/// Returns the status, the parsed body (`Value::Null` when there is none), and
/// the `name=value` head of any `Set-Cookie`, which is what the callers pass
/// back as a session.
pub async fn request(
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

/// Register and log in, returning `(user_id, session_cookie)`.
///
/// The account has no second factor yet, so the login hands back a session
/// rather than an MFA challenge.
pub async fn register<E>(h: &Harness<E>, email: &str, password: &str) -> (Uuid, String) {
    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/register",
        Some(json!({ "email": email, "password": password })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {body}");

    let (status, body, cookie) = login(h, email, password).await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    let cookie = cookie.expect("login must set a session cookie");

    let (status, body, _) = request(&h.app, "GET", "/auth/session", None, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "session failed: {body}");
    let user_id = body["user"]["id"].as_str().unwrap().parse().unwrap();
    (user_id, cookie)
}

/// `POST /auth/login`, asserting nothing — callers decide what the outcome
/// should be, and both a session and an MFA challenge are valid ones.
pub async fn login<E>(
    h: &Harness<E>,
    email: &str,
    password: &str,
) -> (StatusCode, Value, Option<String>) {
    request(
        &h.app,
        "POST",
        "/auth/login",
        Some(json!({ "email": email, "password": password })),
        None,
    )
    .await
}
