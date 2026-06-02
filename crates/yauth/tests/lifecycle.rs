//! End-to-end tests for the user-lifecycle feature (yauth-go v0.14.0 parity):
//! global suspend + scheduled start (staged) + the admin kill switch + login
//! enforcement + lifecycle-aware introspection + the api-key gate.
//!
//! These verify the security *behavior* (rejection + instant termination), not
//! just that columns persist (that's covered by repo_conformance).

#![cfg(all(feature = "memory-backend", feature = "admin", feature = "bearer"))]

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use yauth::backends::memory::InMemoryBackend;
use yauth::config::{BearerConfig, EmailPasswordConfig, YAuthConfig};
use yauth::{YAuthBuilder, state::YAuthState};
use yauth_entity::NewApiKey;

struct TestApp {
    router: Router,
    state: YAuthState,
}

async fn build_app() -> TestApp {
    let backend = InMemoryBackend::new();
    let auth = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "https://idp.test".into(),
            session_cookie_name: "session".into(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            // First registered user becomes admin (bootstrap).
            auto_admin_first_user: true,
            ..Default::default()
        },
    )
    .with_email_password(EmailPasswordConfig {
        min_password_length: 8,
        require_email_verification: false,
        hibp_check: false,
        ..Default::default()
    })
    .with_bearer(BearerConfig {
        jwt_secret: "test-secret-lifecycle".into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: Default::default(),
        signing_key_pem: None,
        kid: None,
    })
    .with_api_key()
    .with_admin()
    .build()
    .await
    .expect("build YAuth");

    let state = auth.state().clone();
    let router = Router::new().nest("/api/auth", auth.router().with_state(state.clone()));
    TestApp { router, state }
}

async fn req(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    let body_str = body
        .map(|v| serde_json::to_string(&v).unwrap())
        .unwrap_or_default();
    let resp = app
        .clone()
        .oneshot(b.body(Body::from(body_str)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, set_cookie)
}

/// Registers a user and returns (id, session-cookie). The first call also makes
/// that user an admin (`auto_admin_first_user`).
async fn register_and_login(app: &Router, email: &str) -> (Uuid, String) {
    let (status, _, _) = req(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({"email": email, "password": "password123"})),
        None,
    )
    .await;
    assert!(status.is_success(), "register {email} failed: {status}");
    let (status, body, set_cookie) = req(
        app,
        "POST",
        "/api/auth/login",
        Some(json!({"email": email, "password": "password123"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login {email} failed: {body}");
    let cookie = set_cookie.expect("login should set a session cookie");
    let cookie = cookie.split(';').next().unwrap().to_string();
    let id: Uuid = body["user_id"].as_str().unwrap().parse().unwrap();
    (id, cookie)
}

#[tokio::test]
async fn suspend_sets_suspended_at_and_trips_kill_switch() {
    let app = build_app().await;
    let (_admin_id, admin_cookie) = register_and_login(&app.router, "admin@test.com").await;
    let (target_id, target_cookie) = register_and_login(&app.router, "target@test.com").await;

    // Mint a refresh token for the target so we can prove the kill switch revokes it.
    let (status, token_body, _) = req(
        &app.router,
        "POST",
        "/api/auth/token",
        Some(json!({"email": "target@test.com", "password": "password123"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token grant failed: {token_body}");
    let refresh = token_body["refresh_token"].as_str().unwrap().to_string();

    // Target has a live session before suspend.
    let (status, _, _) = req(
        &app.router,
        "GET",
        "/api/auth/session",
        None,
        Some(&target_cookie),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "target session should be valid pre-suspend"
    );

    // Admin suspends the target.
    let (status, body, _) = req(
        &app.router,
        "POST",
        &format!("/api/auth/admin/users/{target_id}/suspend"),
        Some(json!({"reason": "offboarded"})),
        Some(&admin_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "suspend failed: {body}");
    assert_eq!(body["suspended"], json!(true));
    assert_eq!(body["suspended_reason"], json!("offboarded"));

    // suspended_at is set + user can no longer authenticate.
    let user = app
        .state
        .repos
        .users
        .find_by_id(target_id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.suspended_at.is_some());
    assert!(!user.can_authenticate(chrono::Utc::now().naive_utc()));

    // Kill switch: the session is gone (cookie no longer authenticates).
    let (status, _, _) = req(
        &app.router,
        "GET",
        "/api/auth/session",
        None,
        Some(&target_cookie),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "suspended user's session must be terminated"
    );

    // Kill switch: the refresh token is revoked (cannot mint a new access token).
    let (status, _, _) = req(
        &app.router,
        "POST",
        "/api/auth/token/refresh",
        Some(json!({"refresh_token": refresh})),
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "suspended user's refresh token must be revoked"
    );
}

#[tokio::test]
async fn unsuspend_clears_suspension() {
    let app = build_app().await;
    let (_admin, admin_cookie) = register_and_login(&app.router, "admin2@test.com").await;
    let (target_id, _) = register_and_login(&app.router, "t2@test.com").await;

    req(
        &app.router,
        "POST",
        &format!("/api/auth/admin/users/{target_id}/suspend"),
        Some(json!({})),
        Some(&admin_cookie),
    )
    .await;
    let (status, body, _) = req(
        &app.router,
        "POST",
        &format!("/api/auth/admin/users/{target_id}/unsuspend"),
        None,
        Some(&admin_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unsuspend failed: {body}");
    assert_eq!(body["suspended"], json!(false));

    let user = app
        .state
        .repos
        .users
        .find_by_id(target_id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.suspended_at.is_none());
    assert!(user.can_authenticate(chrono::Utc::now().naive_utc()));
}

#[tokio::test]
async fn suspended_user_cannot_log_in() {
    let app = build_app().await;
    let (_admin, admin_cookie) = register_and_login(&app.router, "admin3@test.com").await;
    let (target_id, _) = register_and_login(&app.router, "t3@test.com").await;

    req(
        &app.router,
        "POST",
        &format!("/api/auth/admin/users/{target_id}/suspend"),
        Some(json!({})),
        Some(&admin_cookie),
    )
    .await;

    let (status, body, _) = req(
        &app.router,
        "POST",
        "/api/auth/login",
        Some(json!({"email": "t3@test.com", "password": "password123"})),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "suspended user must not be able to log in"
    );
    // Distinct message from a ban (USER_SUSPENDED).
    let msg = body["error"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.to_lowercase().contains("deactivat"),
        "expected a suspended-specific message, got: {body}"
    );
}

#[tokio::test]
async fn schedule_start_stages_user_and_blocks_login() {
    let app = build_app().await;
    let (_admin, admin_cookie) = register_and_login(&app.router, "admin4@test.com").await;
    let (target_id, _) = register_and_login(&app.router, "t4@test.com").await;

    // Schedule a start one hour in the future → staged.
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (status, body, _) = req(
        &app.router,
        "POST",
        &format!("/api/auth/admin/users/{target_id}/schedule-start"),
        Some(json!({"activates_at": future})),
        Some(&admin_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "schedule-start failed: {body}");

    let now = chrono::Utc::now().naive_utc();
    let user = app
        .state
        .repos
        .users
        .find_by_id(target_id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.activates_at.is_some());
    assert!(
        user.staged(now),
        "future activates_at must make the user staged"
    );
    assert!(!user.can_authenticate(now));

    // Login is rejected with the not-started message.
    let (status, body, _) = req(
        &app.router,
        "POST",
        "/api/auth/login",
        Some(json!({"email": "t4@test.com", "password": "password123"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let msg = body["error"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.to_lowercase().contains("not active"),
        "expected a not-started message, got: {body}"
    );

    // Clearing the schedule (null) reactivates.
    req(
        &app.router,
        "POST",
        &format!("/api/auth/admin/users/{target_id}/schedule-start"),
        Some(json!({"activates_at": null})),
        Some(&admin_cookie),
    )
    .await;
    let user = app
        .state
        .repos
        .users
        .find_by_id(target_id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.activates_at.is_none());
    assert!(user.can_authenticate(chrono::Utc::now().naive_utc()));
}

#[tokio::test]
async fn suspended_user_access_token_is_rejected_per_request() {
    let app = build_app().await;
    let (_admin, admin_cookie) = register_and_login(&app.router, "admin5@test.com").await;
    let (target_id, _) = register_and_login(&app.router, "t5@test.com").await;

    // Mint an access token for the target.
    let (status, token_body, _) = req(
        &app.router,
        "POST",
        "/api/auth/token",
        Some(json!({"email": "t5@test.com", "password": "password123"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token grant failed: {token_body}");
    let access = token_body["access_token"].as_str().unwrap().to_string();

    // The access token works before suspend.
    let pre = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/session")
                .header("authorization", format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        pre.status(),
        StatusCode::OK,
        "access token should work pre-suspend"
    );

    // Suspend the target.
    req(
        &app.router,
        "POST",
        &format!("/api/auth/admin/users/{target_id}/suspend"),
        Some(json!({})),
        Some(&admin_cookie),
    )
    .await;

    // The still-valid (unexpired) access token must now be rejected per-request.
    let post = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/session")
                .header("authorization", format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        post.status(),
        StatusCode::OK,
        "a suspended user's unexpired access token must be rejected per-request"
    );
}

/// The api-key resolver is the SOLE lifecycle gate for api-key requests (the
/// middleware short-circuits its session gate once AuthUser is set, and the kill
/// switch does not revoke API keys). This deliberately diverges from yauth-go's
/// banned-only api-key resolver; prove the divergence closes the bypass.
#[tokio::test]
async fn suspended_user_api_key_is_rejected() {
    let app = build_app().await;
    let (_admin, admin_cookie) = register_and_login(&app.router, "admin6@test.com").await;
    let (target_id, _) = register_and_login(&app.router, "t6@test.com").await;

    // Mint a usable user-scoped API key directly in the store.
    let now = chrono::Utc::now().naive_utc();
    let prefix = "lifecyc8"; // resolver requires an exactly-8-char prefix
    let secret = "lifecyclesecret";
    let full_key = format!("yauth_{prefix}_{secret}");
    app.state
        .repos
        .api_keys
        .create(NewApiKey {
            id: Uuid::now_v7(),
            user_id: Some(target_id),
            organization_id: None,
            key_prefix: prefix.into(),
            key_hash: yauth::auth::crypto::hash_token(&full_key),
            name: "personal".into(),
            scopes: None,
            role: None,
            expires_at: None,
            created_at: now,
            created_by_user_id: target_id,
        })
        .await
        .unwrap();

    // The key authenticates before suspend.
    let pre = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/session")
                .header("x-api-key", &full_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        pre.status(),
        StatusCode::OK,
        "api key should work pre-suspend"
    );

    // Suspend the owner.
    req(
        &app.router,
        "POST",
        &format!("/api/auth/admin/users/{target_id}/suspend"),
        Some(json!({})),
        Some(&admin_cookie),
    )
    .await;

    // The api key must now be rejected (the kill switch doesn't revoke keys,
    // so the resolver's can_authenticate gate is what closes the bypass).
    let post = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/session")
                .header("x-api-key", &full_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        post.status(),
        StatusCode::OK,
        "a suspended user's API key must be rejected"
    );
}
