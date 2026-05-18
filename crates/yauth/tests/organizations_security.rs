//! Route-level security tests for the organizations plugin (PR #98).
//!
//! Covers the high-severity findings from the PR #98 security review:
//!
//! - **H-2**: `accept_invitation` must reject users whose email is not
//!   verified, even when the invitation email matches the authenticated
//!   user's email (case-insensitively).
//! - **H-3**: state-changing org endpoints and the member-list endpoint
//!   are rate-limited per-user / per-org to prevent enumeration and DoS.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password"
))]

use axum::{Router, http::StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

use yauth::backends::memory::InMemoryBackend;
use yauth::prelude::*;

const ISSUER: &str = "http://localhost:3000";

struct TestApp {
    router: Router,
    state: yauth::state::YAuthState,
}

async fn build_app() -> TestApp {
    let backend = InMemoryBackend::new();
    let auth = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: ISSUER.into(),
            session_cookie_name: "session".into(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            // Don't auto-promote the first user — the security tests need to
            // exercise unverified-user flows where the first registered user
            // is a regular tenant.
            auto_admin_first_user: false,
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
        jwt_secret: "test-secret-organizations-security".into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: Default::default(),
        signing_key_pem: None,
        kid: None,
    })
    .with_organizations()
    .build()
    .await
    .expect("build YAuth");

    let state = auth.state().clone();
    let router = auth.router().with_state(state.clone());
    TestApp { router, state }
}

impl TestApp {
    /// Register + log in. When `require_email_verification` was set at build
    /// time, the registered user starts with `email_verified=false` and the
    /// returned cookie is for that unverified session.
    async fn register_and_login(&self, email: &str, password: &str) -> String {
        let body = json!({ "email": email, "password": password });
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "register failed: {}",
            resp.status()
        );

        // Register may auto-login (returns Set-Cookie). If it didn't, login
        // explicitly. Try the register cookie first.
        let register_cookies: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .map(|s| s.split(';').next().unwrap().to_string())
            .filter(|c| c.starts_with("session="))
            .collect();
        if let Some(c) = register_cookies.into_iter().next() {
            return c;
        }

        // Fall back to explicit login.
        let body = json!({ "email": email, "password": password });
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "login failed");
        let cookies: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .map(|s| s.split(';').next().unwrap().to_string())
            .collect();
        cookies
            .into_iter()
            .find(|c| c.starts_with("session="))
            .expect("login should set a session cookie")
    }

    async fn post(&self, path: &str, cookie: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("cookie", cookie)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    async fn get(&self, path: &str, cookie: &str) -> StatusCode {
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(path)
                    .header("cookie", cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.status()
    }
}

// ──────────────────────────────────────────────
// H-2: invitation accept requires email verification
// ──────────────────────────────────────────────

#[tokio::test]
async fn accept_invitation_rejects_unverified_email_user() {
    let app = build_app().await;
    let admin_cookie = app
        .register_and_login("admin@example.com", "admin-password-123")
        .await;
    let invitee_cookie = app
        .register_and_login("invitee@example.com", "invitee-password-123")
        .await;

    // Flip the invitee's `email_verified` flag to false directly on the
    // repo. The route handler reads it fresh through the auth middleware
    // on every request, so this takes effect on the very next call. This
    // simulates the realistic attack scenario where an attacker registers
    // an email but never completes verification.
    let invitee = app
        .state
        .repos
        .users
        .find_by_email("invitee@example.com")
        .await
        .unwrap()
        .expect("invitee should exist");
    app.state
        .repos
        .users
        .update(
            invitee.id,
            yauth_entity::UpdateUser {
                email_verified: Some(false),
                updated_at: Some(chrono::Utc::now().naive_utc()),
                ..Default::default()
            },
        )
        .await
        .expect("flip email_verified");

    // Admin creates an org.
    let (status, body) = app
        .post(
            "/organizations",
            &admin_cookie,
            json!({"name": "acme", "slug": "acme"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create_org failed: {body:?}");
    let org_id = body["id"].as_str().unwrap();

    // Admin invites the invitee.
    let (status, body) = app
        .post(
            &format!("/organizations/{org_id}/invitations"),
            &admin_cookie,
            json!({"email": "invitee@example.com"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create_invitation failed: {body:?}"
    );
    let token = body["token"].as_str().unwrap().to_string();

    // Unverified invitee attempts to accept. Must be rejected with 403.
    let (status, body) = app
        .post(
            "/invitations/accept",
            &invitee_cookie,
            json!({"token": token}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unverified user must not accept invitation; body: {body:?}"
    );

    // Now verify the invitee and the accept should succeed (regression
    // guard: don't over-tighten the gate to lock out verified users).
    app.state
        .repos
        .users
        .update(
            invitee.id,
            yauth_entity::UpdateUser {
                email_verified: Some(true),
                updated_at: Some(chrono::Utc::now().naive_utc()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (status, body) = app
        .post(
            "/invitations/accept",
            &invitee_cookie,
            json!({"token": token}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "verified user accept failed: {body:?}"
    );
}

// ──────────────────────────────────────────────
// H-3: rate limiting
// ──────────────────────────────────────────────

#[tokio::test]
async fn create_org_rate_limited_per_user() {
    let app = build_app().await;
    let cookie = app
        .register_and_login("a@example.com", "password-12345")
        .await;

    // The configured limit is 20 / hour (see RATE_LIMIT_ORG_CREATE in
    // plugins/organizations.rs). Burst above the limit; the first batch
    // succeeds, then a 429 must appear.
    let mut seen_429 = false;
    for i in 0..30 {
        let (status, _body) = app
            .post(
                "/organizations",
                &cookie,
                json!({"name": format!("org-{i}"), "slug": format!("org-{i}")}),
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            seen_429 = true;
            break;
        }
    }
    assert!(
        seen_429,
        "expected 429 Too Many Requests once the org-create burst exceeded the per-user budget"
    );
}

#[tokio::test]
async fn create_invitation_rate_limited_per_org() {
    let app = build_app().await;
    let cookie = app
        .register_and_login("admin@example.com", "password-12345")
        .await;

    // Create an org first.
    let (status, body) = app
        .post(
            "/organizations",
            &cookie,
            json!({"name": "acme", "slug": "acme"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create_org: {body:?}");
    let org_id = body["id"].as_str().unwrap();

    // The configured limit is 50 / hour. Burst above it.
    let mut seen_429 = false;
    for i in 0..70 {
        let (status, _body) = app
            .post(
                &format!("/organizations/{org_id}/invitations"),
                &cookie,
                json!({"email": format!("user-{i}@example.com")}),
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            seen_429 = true;
            break;
        }
    }
    assert!(
        seen_429,
        "expected 429 once the per-org invitation burst exceeded the budget"
    );
}

#[tokio::test]
async fn list_members_rate_limited_per_user() {
    let app = build_app().await;
    let cookie = app
        .register_and_login("admin@example.com", "password-12345")
        .await;

    let (status, body) = app
        .post(
            "/organizations",
            &cookie,
            json!({"name": "acme", "slug": "acme"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create_org: {body:?}");
    let org_id = body["id"].as_str().unwrap();

    // The configured limit is 100 / minute. Burst above it.
    let mut seen_429 = false;
    for _ in 0..120 {
        let status = app
            .get(&format!("/organizations/{org_id}/members"), &cookie)
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            seen_429 = true;
            break;
        }
    }
    assert!(
        seen_429,
        "expected 429 once the per-user member-list burst exceeded the budget"
    );
}
