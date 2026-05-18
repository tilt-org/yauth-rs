//! HTTP-level integration tests for org-scoped RBAC (issue #88).
//!
//! Covers the acceptance criteria from #88:
//!
//! - Role/permission helpers reject `viewer` from privileged actions.
//! - Role-change endpoint requires admin/owner.
//! - Cross-org leakage: an admin in org A cannot mutate org B.
//! - Owner-protection: the last owner cannot be demoted or removed.
//! - Transfer-ownership endpoint promotes target and demotes current owner.
//! - `GET /organizations/:id/permissions` returns the caller's effective
//!   permission set.

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
            // Tests need predictable user roles; don't auto-promote the
            // first user to a global admin.
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
        jwt_secret: "test-secret-organizations-rbac".into(),
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
    /// Register a new user OR log into an existing one with the given
    /// password. Returns a session cookie.
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

        if resp.status().is_success() {
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
        }

        // Existing user or register didn't auto-login — use /login.
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
        assert!(
            resp.status().is_success(),
            "login failed for {email}: {}",
            resp.status()
        );
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

    async fn user_id(&self, email: &str) -> uuid::Uuid {
        self.state
            .repos
            .users
            .find_by_email(email)
            .await
            .unwrap()
            .expect("user exists")
            .id
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

    async fn delete(&self, path: &str, cookie: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(path)
                    .header("cookie", cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    async fn get(&self, path: &str, cookie: &str) -> (StatusCode, Value) {
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
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    /// Create an org as the given cookie (the cookie's user becomes the
    /// owner). Returns the org id.
    async fn create_org(&self, cookie: &str, slug: &str) -> String {
        let (status, body) = self
            .post(
                "/organizations",
                cookie,
                json!({"name": slug, "slug": slug}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create_org: {body:?}");
        body["id"].as_str().unwrap().to_string()
    }

    /// Invite a user and accept the invitation, returning the invited
    /// user's membership row.
    async fn add_member(&self, admin_cookie: &str, org_id: &str, email: &str, role: &str) -> Value {
        let (status, body) = self
            .post(
                &format!("/organizations/{org_id}/invitations"),
                admin_cookie,
                json!({"email": email, "role": role}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "invite: {body:?}");
        let token = body["token"].as_str().unwrap().to_string();

        let invitee_cookie = self.register_and_login(email, "password-12345").await;
        let (status, body) = self
            .post(
                "/invitations/accept",
                &invitee_cookie,
                json!({"token": token}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "accept: {body:?}");
        body
    }
}

// ──────────────────────────────────────────────
// Built-in role grants
// ──────────────────────────────────────────────

#[tokio::test]
async fn create_org_promotes_caller_to_owner() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;

    let (status, body) = app
        .get(
            &format!("/organizations/{org_id}/permissions"),
            &owner_cookie,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"].as_str(), Some("owner"));
    let perms: Vec<&str> = body["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for must in [
        "members:invite",
        "members:remove",
        "members:change_role",
        "billing:view",
        "billing:update",
        "billing:cancel",
        "settings:read",
        "settings:write",
    ] {
        assert!(
            perms.contains(&must),
            "owner missing perm {must}: {perms:?}"
        );
    }
}

#[tokio::test]
async fn viewer_has_no_mutating_permissions() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;
    app.add_member(&owner_cookie, &org_id, "viewer@example.com", "viewer")
        .await;
    let viewer_cookie = app
        .register_and_login("viewer@example.com", "password-12345")
        .await;

    let (status, body) = app
        .get(
            &format!("/organizations/{org_id}/permissions"),
            &viewer_cookie,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"].as_str(), Some("viewer"));
    let perms: Vec<&str> = body["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(perms, vec!["settings:read"], "viewer perms: {perms:?}");
}

// ──────────────────────────────────────────────
// Role-change enforcement
// ──────────────────────────────────────────────

#[tokio::test]
async fn viewer_cannot_change_member_role() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;

    app.add_member(&owner_cookie, &org_id, "viewer@example.com", "viewer")
        .await;
    app.add_member(&owner_cookie, &org_id, "victim@example.com", "member")
        .await;

    let viewer_cookie = app
        .register_and_login("viewer@example.com", "password-12345")
        .await;
    let victim_id = app.user_id("victim@example.com").await;

    let (status, body) = app
        .post(
            &format!("/organizations/{org_id}/members/{victim_id}/role"),
            &viewer_cookie,
            json!({"role": "admin"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer escalation must be 403: {body:?}"
    );
}

#[tokio::test]
async fn member_cannot_change_member_role() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;

    app.add_member(&owner_cookie, &org_id, "alice@example.com", "member")
        .await;
    app.add_member(&owner_cookie, &org_id, "bob@example.com", "member")
        .await;

    let alice_cookie = app
        .register_and_login("alice@example.com", "password-12345")
        .await;
    let bob_id = app.user_id("bob@example.com").await;

    let (status, _) = app
        .post(
            &format!("/organizations/{org_id}/members/{bob_id}/role"),
            &alice_cookie,
            json!({"role": "admin"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_change_member_role() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;

    app.add_member(&owner_cookie, &org_id, "admin@example.com", "admin")
        .await;
    app.add_member(&owner_cookie, &org_id, "member@example.com", "member")
        .await;

    let admin_cookie = app
        .register_and_login("admin@example.com", "password-12345")
        .await;
    let member_id = app.user_id("member@example.com").await;

    let (status, body) = app
        .post(
            &format!("/organizations/{org_id}/members/{member_id}/role"),
            &admin_cookie,
            json!({"role": "viewer"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "admin role change failed: {body:?}");
    assert_eq!(body["role"].as_str(), Some("viewer"));
}

#[tokio::test]
async fn role_change_cannot_promote_to_owner() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;
    app.add_member(&owner_cookie, &org_id, "alice@example.com", "member")
        .await;
    let alice_id = app.user_id("alice@example.com").await;

    let (status, body) = app
        .post(
            &format!("/organizations/{org_id}/members/{alice_id}/role"),
            &owner_cookie,
            json!({"role": "owner"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "promote-to-owner must be rejected: {body:?}"
    );
}

// ──────────────────────────────────────────────
// Owner-protection invariant
// ──────────────────────────────────────────────

#[tokio::test]
async fn last_owner_cannot_be_demoted() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;
    let owner_id = app.user_id("owner@example.com").await;

    let (status, body) = app
        .post(
            &format!("/organizations/{org_id}/members/{owner_id}/role"),
            &owner_cookie,
            json!({"role": "admin"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "last-owner demote must be rejected: {body:?}"
    );
}

#[tokio::test]
async fn last_owner_cannot_be_removed() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;
    let owner_id = app.user_id("owner@example.com").await;

    let (status, body) = app
        .delete(
            &format!("/organizations/{org_id}/members/{owner_id}"),
            &owner_cookie,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "last-owner remove must be rejected: {body:?}"
    );
}

#[tokio::test]
async fn transfer_ownership_swaps_roles() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;
    app.add_member(&owner_cookie, &org_id, "successor@example.com", "admin")
        .await;
    let successor_id = app.user_id("successor@example.com").await;

    let (status, _) = app
        .post(
            &format!("/organizations/{org_id}/transfer-ownership"),
            &owner_cookie,
            json!({"new_owner_user_id": successor_id}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let successor_cookie = app
        .register_and_login("successor@example.com", "password-12345")
        .await;
    let (_, body) = app
        .get(
            &format!("/organizations/{org_id}/permissions"),
            &successor_cookie,
        )
        .await;
    assert_eq!(body["role"].as_str(), Some("owner"));

    let (_, body) = app
        .get(
            &format!("/organizations/{org_id}/permissions"),
            &owner_cookie,
        )
        .await;
    assert_eq!(body["role"].as_str(), Some("admin"));
}

#[tokio::test]
async fn transfer_ownership_requires_current_owner() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;
    app.add_member(&owner_cookie, &org_id, "admin@example.com", "admin")
        .await;
    app.add_member(&owner_cookie, &org_id, "target@example.com", "member")
        .await;
    let target_id = app.user_id("target@example.com").await;

    let admin_cookie = app
        .register_and_login("admin@example.com", "password-12345")
        .await;
    let (status, _) = app
        .post(
            &format!("/organizations/{org_id}/transfer-ownership"),
            &admin_cookie,
            json!({"new_owner_user_id": target_id}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn transfer_ownership_requires_target_membership() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;

    let _outsider_cookie = app
        .register_and_login("outsider@example.com", "password-12345")
        .await;
    let outsider_id = app.user_id("outsider@example.com").await;

    let (status, _) = app
        .post(
            &format!("/organizations/{org_id}/transfer-ownership"),
            &owner_cookie,
            json!({"new_owner_user_id": outsider_id}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ──────────────────────────────────────────────
// Cross-org isolation
// ──────────────────────────────────────────────

#[tokio::test]
async fn admin_in_org_a_cannot_change_roles_in_org_b() {
    let app = build_app().await;
    let owner_a_cookie = app
        .register_and_login("owner-a@example.com", "password-12345")
        .await;
    let org_a = app.create_org(&owner_a_cookie, "alpha").await;

    let owner_b_cookie = app
        .register_and_login("owner-b@example.com", "password-12345")
        .await;
    let org_b = app.create_org(&owner_b_cookie, "beta").await;

    app.add_member(&owner_a_cookie, &org_a, "alice@example.com", "admin")
        .await;
    app.add_member(&owner_b_cookie, &org_b, "bob@example.com", "member")
        .await;

    let alice_cookie = app
        .register_and_login("alice@example.com", "password-12345")
        .await;
    let bob_id = app.user_id("bob@example.com").await;

    let (status, body) = app
        .post(
            &format!("/organizations/{org_b}/members/{bob_id}/role"),
            &alice_cookie,
            json!({"role": "viewer"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-org role change must be 403: {body:?}"
    );
}

#[tokio::test]
async fn permissions_endpoint_requires_membership() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;

    let outsider_cookie = app
        .register_and_login("outsider@example.com", "password-12345")
        .await;
    let (status, _) = app
        .get(
            &format!("/organizations/{org_id}/permissions"),
            &outsider_cookie,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ──────────────────────────────────────────────
// Member removal
// ──────────────────────────────────────────────

#[tokio::test]
async fn admin_can_remove_member() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;
    app.add_member(&owner_cookie, &org_id, "bob@example.com", "member")
        .await;
    let bob_id = app.user_id("bob@example.com").await;

    let (status, _) = app
        .delete(
            &format!("/organizations/{org_id}/members/{bob_id}"),
            &owner_cookie,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let bob_cookie = app
        .register_and_login("bob@example.com", "password-12345")
        .await;
    let (status, _) = app
        .get(&format!("/organizations/{org_id}/permissions"), &bob_cookie)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn viewer_cannot_remove_member() {
    let app = build_app().await;
    let owner_cookie = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner_cookie, "acme").await;
    app.add_member(&owner_cookie, &org_id, "viewer@example.com", "viewer")
        .await;
    app.add_member(&owner_cookie, &org_id, "victim@example.com", "member")
        .await;
    let viewer_cookie = app
        .register_and_login("viewer@example.com", "password-12345")
        .await;
    let victim_id = app.user_id("victim@example.com").await;

    let (status, _) = app
        .delete(
            &format!("/organizations/{org_id}/members/{victim_id}"),
            &viewer_cookie,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
