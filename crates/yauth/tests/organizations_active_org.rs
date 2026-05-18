//! HTTP-level integration tests for the active-org claim (issue #89).
//!
//! Covers the acceptance criteria from #89:
//!
//! - Login with one membership auto-selects that org as active.
//! - Login with zero memberships leaves `active_org_id = None`.
//! - Login with multiple memberships picks deterministically (oldest first
//!   until `most_recently_used_org_id` lands as a follow-up).
//! - `POST /sessions/active-org` switches into a membership.
//! - Switching into an org the caller is not a member of returns 403
//!   (pentest acceptance criterion).
//! - `DELETE /sessions/active-org` clears the claim.
//! - Bearer flow re-issues a JWT carrying the new `org` claim.
//! - JWT claims include `org`, `role`, `orgs` when the user has memberships.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password",
    feature = "bearer"
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
        jwt_secret: "test-secret-active-org-claim".into(),
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
        assert!(resp.status().is_success(), "login failed for {email}");
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

    async fn post_bearer(&self, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
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

    async fn post_unauth(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
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
// Selection rules on login (issue #89)
// ──────────────────────────────────────────────

#[tokio::test]
async fn zero_memberships_leaves_active_org_none() {
    let app = build_app().await;
    let cookie = app
        .register_and_login("solo@example.com", "password-12345")
        .await;
    let (status, body) = app.get("/sessions/active-org", &cookie).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert!(
        body["active_org_id"].is_null(),
        "expected no active org: {body:?}"
    );
    assert_eq!(body["orgs"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn single_membership_auto_selects_active_org() {
    let app = build_app().await;
    let owner = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org_id = app.create_org(&owner, "acme").await;

    // Owner has exactly one membership — the org they just created.
    // We need a *new* session post-membership to exercise the selection
    // rule, so log in again.
    let owner = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let (status, body) = app.get("/sessions/active-org", &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active_org_id"].as_str(), Some(org_id.as_str()));
    assert_eq!(body["orgs"].as_array().map(|a| a.len()), Some(1));
}

#[tokio::test]
async fn multiple_memberships_pick_oldest_deterministically() {
    let app = build_app().await;
    let owner = app
        .register_and_login("multi@example.com", "password-12345")
        .await;
    // create_org both creates the org AND promotes the caller to owner via
    // a membership row created at `now`. The first-created membership
    // should win under the deterministic fallback rule.
    let first = app.create_org(&owner, "first-org").await;
    let _second = app.create_org(&owner, "second-org").await;
    let _third = app.create_org(&owner, "third-org").await;

    // Fresh login picks active org per the selection rules.
    let owner = app
        .register_and_login("multi@example.com", "password-12345")
        .await;
    let (status, body) = app.get("/sessions/active-org", &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active_org_id"].as_str(), Some(first.as_str()));
    assert_eq!(body["orgs"].as_array().map(|a| a.len()), Some(3));
}

// ──────────────────────────────────────────────
// Switcher endpoints — cookie auth
// ──────────────────────────────────────────────

#[tokio::test]
async fn cookie_switch_changes_active_org_without_rotating_cookie() {
    let app = build_app().await;
    let owner = app
        .register_and_login("switcher@example.com", "password-12345")
        .await;
    let first = app.create_org(&owner, "first-org").await;
    let second = app.create_org(&owner, "second-org").await;

    let (status, body) = app
        .post(
            "/sessions/active-org",
            &owner,
            json!({"organization_id": second}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "switch: {body:?}");
    assert_eq!(body["active_org_id"].as_str(), Some(second.as_str()));
    // Cookie path does NOT re-issue a bearer token.
    assert!(
        body["bearer_access_token"].is_null(),
        "cookie switch must not return a bearer token: {body:?}"
    );

    // The same cookie continues to work and now reports the new active org.
    let (status, body) = app.get("/sessions/active-org", &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active_org_id"].as_str(), Some(second.as_str()));

    // Switching back to `first` works too.
    let (status, body) = app
        .post(
            "/sessions/active-org",
            &owner,
            json!({"organization_id": first}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active_org_id"].as_str(), Some(first.as_str()));
}

#[tokio::test]
async fn cookie_switch_to_non_member_org_is_403() {
    // PENTEST acceptance criterion from issue #89.
    let app = build_app().await;
    let alice = app
        .register_and_login("alice@example.com", "password-12345")
        .await;
    let bob = app
        .register_and_login("bob@example.com", "password-12345")
        .await;
    let _ = alice;
    // Bob owns an org. Alice tries to switch into it.
    let bob_org = app.create_org(&bob, "bobs-org").await;

    let alice = app
        .register_and_login("alice@example.com", "password-12345")
        .await;
    let (status, body) = app
        .post(
            "/sessions/active-org",
            &alice,
            json!({"organization_id": bob_org}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-member switch must be 403: {body:?}"
    );
}

#[tokio::test]
async fn cookie_clear_active_org_returns_to_none() {
    let app = build_app().await;
    let owner = app
        .register_and_login("clear@example.com", "password-12345")
        .await;
    let _org = app.create_org(&owner, "acme").await;
    let owner = app
        .register_and_login("clear@example.com", "password-12345")
        .await;

    // The selection rule populated active_org_id at login.
    let (status, body) = app.get("/sessions/active-org", &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["active_org_id"].is_null());

    let (status, body) = app.delete("/sessions/active-org", &owner).await;
    assert_eq!(status, StatusCode::OK, "clear: {body:?}");
    assert!(body["active_org_id"].is_null());

    let (status, body) = app.get("/sessions/active-org", &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["active_org_id"].is_null());
}

#[tokio::test]
async fn switching_into_suspended_membership_is_forbidden() {
    use yauth_entity::{MembershipStatus, UpdateMembership};
    let app = build_app().await;
    let owner = app
        .register_and_login("owner@example.com", "password-12345")
        .await;
    let org = app.create_org(&owner, "acme").await;
    app.add_member(&owner, &org, "victim@example.com", "member")
        .await;

    // Suspend victim's membership directly via the repo.
    let victim_id = app
        .state
        .repos
        .users
        .find_by_email("victim@example.com")
        .await
        .unwrap()
        .unwrap()
        .id;
    let org_uuid: uuid::Uuid = org.parse().unwrap();
    let m = app
        .state
        .repos
        .memberships
        .find_by_org_user(org_uuid, victim_id)
        .await
        .unwrap()
        .unwrap();
    app.state
        .repos
        .memberships
        .update(
            m.id,
            UpdateMembership {
                status: Some(MembershipStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let victim = app
        .register_and_login("victim@example.com", "password-12345")
        .await;
    let (status, body) = app
        .post(
            "/sessions/active-org",
            &victim,
            json!({"organization_id": org}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "suspended membership cannot switch: {body:?}"
    );
}

// ──────────────────────────────────────────────
// Switcher endpoints — bearer JWT
// ──────────────────────────────────────────────

async fn token_for(app: &TestApp, email: &str, password: &str) -> String {
    let (status, body) = app
        .post_unauth("/token", json!({"email": email, "password": password}))
        .await;
    assert_eq!(status, StatusCode::OK, "token: {body:?}");
    body["access_token"].as_str().unwrap().to_string()
}

fn decode_claims(token: &str) -> Value {
    use base64::Engine;
    let mut parts = token.splitn(3, '.');
    let _h = parts.next();
    let payload = parts.next().expect("jwt payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn jwt_includes_org_claims_when_user_has_memberships() {
    let app = build_app().await;
    let cookie = app
        .register_and_login("bearer@example.com", "password-12345")
        .await;
    let org = app.create_org(&cookie, "acme").await;

    let token = token_for(&app, "bearer@example.com", "password-12345").await;
    let claims = decode_claims(&token);
    assert_eq!(claims["org"].as_str(), Some(org.as_str()), "{claims:?}");
    assert_eq!(claims["org_role"].as_str(), Some("owner"));
    let orgs = claims["orgs"].as_array().expect("orgs");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].as_str(), Some(org.as_str()));
}

#[tokio::test]
async fn jwt_omits_org_claims_when_user_has_no_memberships() {
    let app = build_app().await;
    let _cookie = app
        .register_and_login("plain@example.com", "password-12345")
        .await;
    let token = token_for(&app, "plain@example.com", "password-12345").await;
    let claims = decode_claims(&token);
    // Older clients see no new fields — backwards compatibility.
    assert!(claims.get("org").is_none(), "{claims:?}");
    assert!(claims.get("org_role").is_none(), "{claims:?}");
    assert!(claims.get("orgs").is_none(), "{claims:?}");
}

#[tokio::test]
async fn bearer_switch_reissues_jwt_with_new_org_claim() {
    let app = build_app().await;
    let cookie = app
        .register_and_login("switch-bearer@example.com", "password-12345")
        .await;
    let first = app.create_org(&cookie, "first-bearer").await;
    let second = app.create_org(&cookie, "second-bearer").await;

    // Get a token — its `org` claim should be one of the two orgs (oldest
    // by selection rule = `first`).
    let initial = token_for(&app, "switch-bearer@example.com", "password-12345").await;
    let initial_claims = decode_claims(&initial);
    assert_eq!(initial_claims["org"].as_str(), Some(first.as_str()));

    // Switch via bearer auth — must come back with a NEW token whose
    // `org` is now `second`.
    let (status, body) = app
        .post_bearer(
            "/sessions/active-org",
            &initial,
            json!({"organization_id": second}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let new_token = body["bearer_access_token"]
        .as_str()
        .expect("bearer flow should issue a fresh token");
    assert_ne!(new_token, initial, "must rotate to a fresh JWT");
    let new_claims = decode_claims(new_token);
    assert_eq!(new_claims["org"].as_str(), Some(second.as_str()));
    assert_eq!(new_claims["org_role"].as_str(), Some("owner"));

    // Old token still works (back-compat with the active session) but
    // still carries the OLD claim — clients must adopt the new one.
    let old_claims = decode_claims(&initial);
    assert_eq!(old_claims["org"].as_str(), Some(first.as_str()));
}

#[tokio::test]
async fn bearer_switch_to_non_member_is_403() {
    let app = build_app().await;
    let _ = app
        .register_and_login("alice@example.com", "password-12345")
        .await;
    let bob = app
        .register_and_login("bob@example.com", "password-12345")
        .await;
    let bob_org = app.create_org(&bob, "bobs-only").await;

    let alice_token = token_for(&app, "alice@example.com", "password-12345").await;
    let (status, body) = app
        .post_bearer(
            "/sessions/active-org",
            &alice_token,
            json!({"organization_id": bob_org}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body:?}");
}

#[tokio::test]
async fn refresh_token_re_runs_selection_rules() {
    // A user who joins an org AFTER login should see the new claim on
    // their next access token (issued via /token/refresh).
    let app = build_app().await;
    let cookie = app
        .register_and_login("late-joiner@example.com", "password-12345")
        .await;

    // Token before any org exists.
    let (status, body) = app
        .post_unauth(
            "/token",
            json!({"email": "late-joiner@example.com", "password": "password-12345"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let refresh = body["refresh_token"].as_str().unwrap().to_string();
    let initial_access = body["access_token"].as_str().unwrap().to_string();
    let initial_claims = decode_claims(&initial_access);
    assert!(initial_claims.get("org").is_none());

    // Create org → new membership.
    let org = app.create_org(&cookie, "joined-late").await;

    // Refresh issues a new access token, which should now carry the org
    // claim.
    let (status, body) = app
        .post_unauth("/token/refresh", json!({"refresh_token": refresh}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let refreshed = body["access_token"].as_str().unwrap();
    let claims = decode_claims(refreshed);
    assert_eq!(claims["org"].as_str(), Some(org.as_str()));
}
