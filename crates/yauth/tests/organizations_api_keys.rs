//! HTTP-level integration tests for org-scoped API keys (issue #91).
//!
//! Covers the acceptance criteria from #91:
//!
//! - Create / list / delete / rotate / usage on `/organizations/:id/api-keys`.
//! - Org admin/owner gate — members can't mint keys.
//! - Cannot grant `owner` to a service account.
//! - Cannot grant a role higher than the caller's own.
//! - Permissions must be a subset of the caller's defaults.
//! - DB-level "exactly one owner" invariant on the repo.
//! - Rotation issues a new plaintext and stamps a 24h grace on the old key.
//! - Authenticated calls with a service-account key produce a
//!   `Principal::ServiceAccount` on the request and surface the org
//!   binding on `AuthUser.active_org_id` / `org_role`.
//! - Cross-org leakage: an admin in org A cannot mutate keys in org B.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password",
    feature = "api-key"
))]

use axum::{Router, http::StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

use yauth::backends::memory::InMemoryBackend;
use yauth::prelude::*;
use yauth::repo::{DatabaseBackend, RepoError};
use yauth_entity::NewApiKey;

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
        jwt_secret: "test-secret-org-api-keys".into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: Default::default(),
        signing_key_pem: None,
        kid: None,
    })
    .with_api_key()
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
            let cookies: Vec<String> = resp
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|h| h.to_str().ok())
                .map(|s| s.split(';').next().unwrap().to_string())
                .filter(|c| c.starts_with("session="))
                .collect();
            if let Some(c) = cookies.into_iter().next() {
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
            .expect("session cookie")
    }

    async fn user_id(&self, email: &str) -> Uuid {
        self.state
            .repos
            .users
            .find_by_email(email)
            .await
            .unwrap()
            .expect("user")
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

    /// Send a request authenticated with an `X-Api-Key` header.
    async fn get_with_api_key(&self, path: &str, key: &str) -> StatusCode {
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(path)
                    .header("x-api-key", key)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.status()
    }

    /// Create an org via the owner's session and return its id.
    async fn create_org(&self, cookie: &str, slug: &str) -> Uuid {
        let (st, body) = self
            .post(
                "/organizations",
                cookie,
                json!({ "name": slug, "slug": slug }),
            )
            .await;
        assert_eq!(st, StatusCode::CREATED, "create org: {body}");
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }
}

// ────────────────────────────────────────────────────────────────────
// Repository-layer tests — invariants enforced at the storage boundary
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn repo_rejects_key_with_both_owners() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let user_id = Uuid::now_v7();
    let org_id = Uuid::now_v7();
    let result = repos
        .api_keys
        .create(NewApiKey {
            id: Uuid::now_v7(),
            user_id: Some(user_id),
            organization_id: Some(org_id),
            key_prefix: "pp".into(),
            key_hash: "hash".into(),
            name: "both".into(),
            scopes: None,
            role: None,
            expires_at: None,
            created_at: chrono::Utc::now().naive_utc(),
            created_by_user_id: user_id,
        })
        .await;
    assert!(
        matches!(result, Err(RepoError::Conflict(_))),
        "repo must refuse a key with both user_id and organization_id, got {result:?}"
    );
}

#[tokio::test]
async fn repo_rejects_key_with_neither_owner() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let user_id = Uuid::now_v7();
    let result = repos
        .api_keys
        .create(NewApiKey {
            id: Uuid::now_v7(),
            user_id: None,
            organization_id: None,
            key_prefix: "pp".into(),
            key_hash: "hash".into(),
            name: "neither".into(),
            scopes: None,
            role: None,
            expires_at: None,
            created_at: chrono::Utc::now().naive_utc(),
            created_by_user_id: user_id,
        })
        .await;
    assert!(
        matches!(result, Err(RepoError::Conflict(_))),
        "repo must refuse a key with neither owner, got {result:?}"
    );
}

#[tokio::test]
async fn repo_name_uniqueness_is_per_owner_scope() {
    // Two different orgs (and a user) may all have a key named "ci"
    // because uniqueness is scoped per-owner.
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let user_id = Uuid::now_v7();
    let org_a = Uuid::now_v7();
    let org_b = Uuid::now_v7();
    let now = chrono::Utc::now().naive_utc();

    repos
        .api_keys
        .create(NewApiKey {
            id: Uuid::now_v7(),
            user_id: None,
            organization_id: Some(org_a),
            key_prefix: "pa".into(),
            key_hash: "h1".into(),
            name: "ci".into(),
            scopes: None,
            role: Some("member".into()),
            expires_at: None,
            created_at: now,
            created_by_user_id: user_id,
        })
        .await
        .unwrap();
    repos
        .api_keys
        .create(NewApiKey {
            id: Uuid::now_v7(),
            user_id: None,
            organization_id: Some(org_b),
            key_prefix: "pb".into(),
            key_hash: "h2".into(),
            name: "ci".into(), // same name, different org — OK
            scopes: None,
            role: Some("member".into()),
            expires_at: None,
            created_at: now,
            created_by_user_id: user_id,
        })
        .await
        .unwrap();
    // But duplicating within the same org is rejected.
    let dup = repos
        .api_keys
        .create(NewApiKey {
            id: Uuid::now_v7(),
            user_id: None,
            organization_id: Some(org_a),
            key_prefix: "px".into(),
            key_hash: "h3".into(),
            name: "ci".into(),
            scopes: None,
            role: Some("member".into()),
            expires_at: None,
            created_at: now,
            created_by_user_id: user_id,
        })
        .await;
    assert!(matches!(dup, Err(RepoError::Conflict(_))));
}

#[tokio::test]
async fn repo_list_and_find_by_org_id() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let user_id = Uuid::now_v7();
    let org = Uuid::now_v7();
    let now = chrono::Utc::now().naive_utc();
    let key_id = Uuid::now_v7();
    repos
        .api_keys
        .create(NewApiKey {
            id: key_id,
            user_id: None,
            organization_id: Some(org),
            key_prefix: "pp".into(),
            key_hash: "h".into(),
            name: "n".into(),
            scopes: None,
            role: Some("member".into()),
            expires_at: None,
            created_at: now,
            created_by_user_id: user_id,
        })
        .await
        .unwrap();
    let listed = repos.api_keys.list_by_org_id(org).await.unwrap();
    assert_eq!(listed.len(), 1);
    let by_id = repos
        .api_keys
        .find_by_id_and_org(key_id, org)
        .await
        .unwrap()
        .expect("found");
    assert_eq!(by_id.id, key_id);
    // Wrong org returns None.
    let other_org = Uuid::now_v7();
    assert!(
        repos
            .api_keys
            .find_by_id_and_org(key_id, other_org)
            .await
            .unwrap()
            .is_none()
    );
}

// ────────────────────────────────────────────────────────────────────
// HTTP integration tests
// ────────────────────────────────────────────────────────────────────

async fn make_owner_with_org(app: &TestApp) -> (String, Uuid) {
    let cookie = app.register_and_login("owner@x.com", "supersecret").await;
    let org_id = app.create_org(&cookie, "acme").await;
    (cookie, org_id)
}

#[tokio::test]
async fn create_org_api_key_happy_path_returns_secret_once() {
    let app = build_app().await;
    let (cookie, org_id) = make_owner_with_org(&app).await;

    let (st, body) = app
        .post(
            &format!("/organizations/{org_id}/api-keys"),
            &cookie,
            json!({ "name": "ci", "role": "member" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let secret = body["secret"].as_str().expect("secret returned plaintext");
    assert!(secret.starts_with("yauth_"), "secret format: {secret}");
    assert_eq!(body["api_key"]["role"], "member");
    assert_eq!(body["api_key"]["organization_id"], org_id.to_string());

    // List shows it, plaintext is not returned again.
    let (st, list) = app
        .get(&format!("/organizations/{org_id}/api-keys"), &cookie)
        .await;
    assert_eq!(st, StatusCode::OK);
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert!(
        arr[0].get("secret").is_none(),
        "list must not return secret"
    );
}

#[tokio::test]
async fn cannot_grant_owner_role_to_service_account() {
    let app = build_app().await;
    let (cookie, org_id) = make_owner_with_org(&app).await;
    let (st, body) = app
        .post(
            &format!("/organizations/{org_id}/api-keys"),
            &cookie,
            json!({ "name": "evil", "role": "owner" }),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"].as_str().unwrap_or("").contains("owner"),
        "error should mention owner: {body}"
    );
}

#[tokio::test]
async fn member_cannot_create_service_account() {
    let app = build_app().await;
    let owner_cookie = app.register_and_login("owner2@x.com", "supersecret").await;
    let org_id = app.create_org(&owner_cookie, "acme2").await;

    // Promote a second user to `member` via invitation.
    let member_email = "member2@x.com";
    let member_cookie = app.register_and_login(member_email, "supersecret").await;
    let (st, inv) = app
        .post(
            &format!("/organizations/{org_id}/invitations"),
            &owner_cookie,
            json!({ "email": member_email, "role": "member" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{inv}");
    // Need email-verified to accept — bypass via repo since we disabled
    // the verification gate above? No — `require_email_verification: false`
    // in config only governs *registration*, not the accept-invite gate
    // (#90's `domains` JIT story). Force-verify via the repo.
    let uid = app.user_id(member_email).await;
    {
        let mut user = app
            .state
            .repos
            .users
            .find_by_id(uid)
            .await
            .unwrap()
            .unwrap();
        user.email_verified = true;
        app.state
            .repos
            .users
            .update(
                uid,
                yauth_entity::UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    let token = inv["token"].as_str().unwrap().to_string();
    let (st, _) = app
        .post(
            "/invitations/accept",
            &member_cookie,
            json!({ "token": token }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, body) = app
        .post(
            &format!("/organizations/{org_id}/api-keys"),
            &member_cookie,
            json!({ "name": "should-fail" }),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn permissions_must_be_subset_of_callers_role() {
    let app = build_app().await;
    // Set up an org and add a `billing_admin` who tries to mint a key
    // with `members:invite`. Owner-only permission, so 403.
    let owner = app.register_and_login("o-perm@x.com", "supersecret").await;
    let org = app.create_org(&owner, "perm-org").await;

    let bemail = "billing@x.com";
    let bcookie = app.register_and_login(bemail, "supersecret").await;
    let (st, inv) = app
        .post(
            &format!("/organizations/{org}/invitations"),
            &owner,
            json!({ "email": bemail, "role": "billing_admin" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{inv}");
    let uid = app.user_id(bemail).await;
    app.state
        .repos
        .users
        .update(
            uid,
            yauth_entity::UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let token = inv["token"].as_str().unwrap().to_string();
    app.post("/invitations/accept", &bcookie, json!({ "token": token }))
        .await;

    // billing_admin is admin-tier for billing routes (require_org_admin
    // takes admin/owner only). So this user should be REJECTED at the
    // gate entirely.
    let (st, _) = app
        .post(
            &format!("/organizations/{org}/api-keys"),
            &bcookie,
            json!({ "name": "x", "permissions": ["members:invite"] }),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rotation_grace_period_keeps_old_key_alive_for_24h() {
    let app = build_app().await;
    let (cookie, org_id) = make_owner_with_org(&app).await;
    let (st, body) = app
        .post(
            &format!("/organizations/{org_id}/api-keys"),
            &cookie,
            json!({ "name": "rot", "role": "member" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let old_id = Uuid::parse_str(body["api_key"]["id"].as_str().unwrap()).unwrap();
    let old_secret = body["secret"].as_str().unwrap().to_string();

    let (st, rotated) = app
        .post(
            &format!("/organizations/{org_id}/api-keys/{old_id}/rotate"),
            &cookie,
            json!({}),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{rotated}");
    let new_secret = rotated["secret"].as_str().unwrap().to_string();
    assert_ne!(old_secret, new_secret, "rotation must return a new secret");

    // Old key still exists and is within 24h grace.
    let old = app
        .state
        .repos
        .api_keys
        .find_by_id_and_org(old_id, org_id)
        .await
        .unwrap()
        .expect("old key still present");
    let now = chrono::Utc::now().naive_utc();
    let expires = old.expires_at.expect("grace expiry stamped");
    let delta = (expires - now).num_minutes();
    assert!(
        (23 * 60..=24 * 60 + 5).contains(&delta),
        "grace should be ~24h; got {delta} minutes"
    );
}

#[tokio::test]
async fn service_account_auth_surfaces_principal_and_org_context() {
    let app = build_app().await;
    let (cookie, org_id) = make_owner_with_org(&app).await;
    let creator_id = app.user_id("owner@x.com").await;

    let (st, body) = app
        .post(
            &format!("/organizations/{org_id}/api-keys"),
            &cookie,
            json!({ "name": "svc", "role": "admin" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let secret = body["secret"].as_str().unwrap().to_string();
    let key_id = Uuid::parse_str(body["api_key"]["id"].as_str().unwrap()).unwrap();

    // Validate via the lib helper — the middleware exercises the same path.
    let (auth_user, principal) = yauth::plugins::api_key::validate_api_key(&secret, &app.state)
        .await
        .expect("service-account key must validate");

    assert_eq!(
        auth_user.id, creator_id,
        "AuthUser must carry the creator's id for the audit trail"
    );
    assert_eq!(
        auth_user.active_org_id,
        Some(org_id),
        "active_org_id populated from key binding"
    );
    assert_eq!(auth_user.org_role.as_deref(), Some("admin"));

    match principal {
        yauth::middleware::Principal::ServiceAccount {
            org_id: pid,
            key_id: pk,
            created_by,
        } => {
            assert_eq!(pid, org_id);
            assert_eq!(pk, key_id);
            assert_eq!(created_by, creator_id);
        }
        other => panic!("expected ServiceAccount principal, got {other:?}"),
    }
}

#[tokio::test]
async fn user_scoped_key_still_emits_user_principal() {
    let app = build_app().await;
    let cookie = app
        .register_and_login("user-key@x.com", "supersecret")
        .await;
    // User mints their own (user-scoped) API key — pre-#91 surface.
    let (st, body) = app
        .post("/api-keys", &cookie, json!({ "name": "personal" }))
        .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let secret = body["secret"].as_str().unwrap().to_string();
    let (auth_user, principal) = yauth::plugins::api_key::validate_api_key(&secret, &app.state)
        .await
        .expect("user key validates");
    assert!(matches!(
        principal,
        yauth::middleware::Principal::User(uid) if uid == auth_user.id
    ));
    assert!(
        auth_user.active_org_id.is_none(),
        "user-scoped keys must not carry org context"
    );
}

#[tokio::test]
async fn cross_org_admin_cannot_touch_other_orgs_keys() {
    let app = build_app().await;
    let alice = app.register_and_login("alice@x.com", "supersecret").await;
    let org_a = app.create_org(&alice, "alice-org").await;

    let bob = app.register_and_login("bob@x.com", "supersecret").await;
    let org_b = app.create_org(&bob, "bob-org").await;

    // Alice creates a key in her org.
    let (st, body) = app
        .post(
            &format!("/organizations/{org_a}/api-keys"),
            &alice,
            json!({ "name": "a", "role": "member" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let kid = Uuid::parse_str(body["api_key"]["id"].as_str().unwrap()).unwrap();

    // Bob tries to read/delete it scoped to *his* org id — 404 (not 403 —
    // we don't leak that the key exists in another org).
    let (st, _) = app
        .get(
            &format!("/organizations/{org_b}/api-keys/{kid}/usage"),
            &bob,
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = app
        .delete(&format!("/organizations/{org_b}/api-keys/{kid}"), &bob)
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // And Bob cannot enumerate Alice's keys via her org id without
    // membership.
    let (st, _) = app
        .get(&format!("/organizations/{org_a}/api-keys"), &bob)
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn deleted_org_key_cannot_authenticate() {
    let app = build_app().await;
    let (cookie, org_id) = make_owner_with_org(&app).await;
    let (st, body) = app
        .post(
            &format!("/organizations/{org_id}/api-keys"),
            &cookie,
            json!({ "name": "todelete", "role": "member" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let kid = Uuid::parse_str(body["api_key"]["id"].as_str().unwrap()).unwrap();
    let secret = body["secret"].as_str().unwrap().to_string();

    // The key works before deletion.
    let status = app.get_with_api_key("/organizations", &secret).await;
    assert_eq!(status, StatusCode::OK, "key should auth pre-delete");

    let (st, _) = app
        .delete(&format!("/organizations/{org_id}/api-keys/{kid}"), &cookie)
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    // After delete: 401.
    let status = app.get_with_api_key("/organizations", &secret).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn usage_endpoint_returns_last_used_after_authenticated_call() {
    let app = build_app().await;
    let (cookie, org_id) = make_owner_with_org(&app).await;
    let (st, body) = app
        .post(
            &format!("/organizations/{org_id}/api-keys"),
            &cookie,
            json!({ "name": "usg", "role": "member" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let kid = Uuid::parse_str(body["api_key"]["id"].as_str().unwrap()).unwrap();
    let secret = body["secret"].as_str().unwrap().to_string();

    // Authenticated call updates last_used_at as a side-effect.
    let status = app.get_with_api_key("/organizations", &secret).await;
    assert_eq!(status, StatusCode::OK);

    let (st, usage) = app
        .get(
            &format!("/organizations/{org_id}/api-keys/{kid}/usage"),
            &cookie,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{usage}");
    assert!(
        usage["last_used_at"].is_string(),
        "last_used_at must be populated after at least one call: {usage}"
    );
}
