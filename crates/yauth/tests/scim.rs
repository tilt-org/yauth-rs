//! SCIM 2.0 integration tests (issue #95).
//!
//! Exercises the happy-path CRUD on Users + Groups + meta endpoints
//! against an in-memory backend. Pentest/edge cases live in
//! `scim_pentest.rs`.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password",
    feature = "api-key",
    feature = "scim",
))]

use axum::{Router, http::StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

use yauth::backends::memory::InMemoryBackend;
use yauth::prelude::*;
use yauth_entity::{NewApiKey, NewMembership, NewOrganization, NewUser};

const ISSUER: &str = "http://localhost:3000";

struct TestApp {
    router: Router,
    state: yauth::state::YAuthState,
    org_id: Uuid,
    api_key: String,
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
        jwt_secret: "test-secret-scim".into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: Default::default(),
        signing_key_pem: None,
        kid: None,
    })
    .with_api_key()
    .with_organizations()
    .with_scim()
    .build()
    .await
    .expect("build YAuth");

    let state = auth.state().clone();
    let router = auth.router().with_state(state.clone());

    // Seed: an org + an admin user + an org-scoped API key bound to scim:*.
    let now = chrono::Utc::now().naive_utc();
    let org_id = Uuid::now_v7();
    state
        .repos
        .organizations
        .create(NewOrganization {
            id: org_id,
            name: "Acme".into(),
            slug: format!("acme-{}", &org_id.simple().to_string()[..6]),
            display_name: None,
            avatar_url: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    let admin_id = Uuid::now_v7();
    state
        .repos
        .users
        .create(NewUser {
            id: admin_id,
            email: format!("admin-{admin_id}@example.com"),
            display_name: Some("Admin".into()),
            email_verified: true,
            role: "admin".into(),
            banned: false,
            banned_reason: None,
            banned_until: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    state
        .repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org_id,
            user_id: admin_id,
            role: "owner".into(),
            status: yauth_entity::MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    // Mint an org-scoped API key (issue #91) bound to this org.
    let prefix = "scimtest";
    let secret = "scimtestsecret";
    let full_key = format!("yauth_{prefix}_{secret}");
    let key_hash = yauth::auth::crypto::hash_token(&full_key);
    state
        .repos
        .api_keys
        .create(NewApiKey {
            id: Uuid::now_v7(),
            user_id: None,
            organization_id: Some(org_id),
            key_prefix: prefix.to_string(),
            key_hash,
            name: "SCIM connector".into(),
            scopes: Some(json!(["scim:read", "scim:write"])),
            role: Some("admin".into()),
            expires_at: None,
            created_at: now,
            created_by_user_id: admin_id,
        })
        .await
        .unwrap();

    TestApp {
        router,
        state,
        org_id,
        api_key: full_key,
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn req_post(path: &str, key: &str, body: Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/scim+json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

fn req_get(path: &str, key: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {key}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

fn req_put(path: &str, key: &str, body: Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("PUT")
        .uri(path)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/scim+json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

fn req_patch(path: &str, key: &str, body: Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("PATCH")
        .uri(path)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/scim+json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

fn req_delete(path: &str, key: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("DELETE")
        .uri(path)
        .header("authorization", format!("Bearer {key}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

#[tokio::test]
async fn service_provider_config_returns_capabilities() {
    let app = build_app().await;
    let path = format!(
        "/api/scim/v2/organizations/{}/ServiceProviderConfig",
        app.org_id
    );
    let resp = app
        .router
        .clone()
        .oneshot(req_get(&path, &app.api_key))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["patch"]["supported"], json!(true));
    assert_eq!(body["bulk"]["supported"], json!(false));
    assert_eq!(body["filter"]["supported"], json!(true));
    assert_eq!(
        body["authenticationSchemes"][0]["type"],
        json!("oauthbearertoken")
    );
}

#[tokio::test]
async fn schemas_and_resource_types_include_user_and_group() {
    let app = build_app().await;
    for endpoint in ["Schemas", "ResourceTypes"] {
        let path = format!("/api/scim/v2/organizations/{}/{}", app.org_id, endpoint);
        let resp = app
            .router
            .clone()
            .oneshot(req_get(&path, &app.api_key))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let s = body.to_string();
        assert!(s.contains("User"), "{endpoint}: expected User in {s}");
        assert!(s.contains("Group"), "{endpoint}: expected Group in {s}");
    }
}

#[tokio::test]
async fn create_user_then_get_then_list() {
    let app = build_app().await;
    let create = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice@acme.com",
        "displayName": "Alice Wonderland",
        "externalId": "okta-001",
        "emails": [{"value": "alice@acme.com", "primary": true}],
        "active": true,
    });
    let path = format!("/api/scim/v2/organizations/{}/Users", app.org_id);
    let resp = app
        .router
        .clone()
        .oneshot(req_post(&path, &app.api_key, create))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let uid = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["userName"], "alice@acme.com");
    assert_eq!(body["externalId"], "okta-001");
    assert_eq!(body["active"], json!(true));

    // GET by id
    let get_path = format!("{path}/{uid}");
    let resp = app
        .router
        .clone()
        .oneshot(req_get(&get_path, &app.api_key))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["userName"], "alice@acme.com");

    // List → should contain our new user
    let resp = app
        .router
        .clone()
        .oneshot(req_get(&path, &app.api_key))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["totalResults"].as_u64().unwrap() >= 1);
    assert!(
        body["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["id"] == json!(uid))
    );
}

#[tokio::test]
async fn post_with_same_external_id_returns_200_idempotent() {
    let app = build_app().await;
    let create = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bob@acme.com",
        "externalId": "okta-bob",
        "emails": [{"value": "bob@acme.com", "primary": true}],
    });
    let path = format!("/api/scim/v2/organizations/{}/Users", app.org_id);
    let first = app
        .router
        .clone()
        .oneshot(req_post(&path, &app.api_key, create.clone()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let id1 = body_json(first).await["id"].as_str().unwrap().to_string();

    let second = app
        .router
        .clone()
        .oneshot(req_post(&path, &app.api_key, create))
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "idempotent POST must be 200"
    );
    let id2 = body_json(second).await["id"].as_str().unwrap().to_string();
    assert_eq!(id1, id2);
}

#[tokio::test]
async fn patch_active_false_suspends_membership() {
    let app = build_app().await;
    let path = format!("/api/scim/v2/organizations/{}/Users", app.org_id);
    let create = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "carol@acme.com",
        "emails": [{"value": "carol@acme.com", "primary": true}],
    });
    let resp = app
        .router
        .clone()
        .oneshot(req_post(&path, &app.api_key, create))
        .await
        .unwrap();
    let uid = body_json(resp).await["id"].as_str().unwrap().to_string();

    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": false}],
    });
    let resp = app
        .router
        .clone()
        .oneshot(req_patch(&format!("{path}/{uid}"), &app.api_key, patch))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["active"], json!(false));

    // Confirm via state that the membership is suspended.
    let uid_p: Uuid = uid.parse().unwrap();
    let m = app
        .state
        .repos
        .memberships
        .find_by_org_user(app.org_id, uid_p)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(m.status, yauth_entity::MembershipStatus::Suspended);
}

#[tokio::test]
async fn delete_removes_membership_keeps_user() {
    let app = build_app().await;
    let path = format!("/api/scim/v2/organizations/{}/Users", app.org_id);
    let create = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dave@acme.com",
        "emails": [{"value": "dave@acme.com", "primary": true}],
    });
    let resp = app
        .router
        .clone()
        .oneshot(req_post(&path, &app.api_key, create))
        .await
        .unwrap();
    let uid_str = body_json(resp).await["id"].as_str().unwrap().to_string();
    let uid: Uuid = uid_str.parse().unwrap();

    let del = app
        .router
        .clone()
        .oneshot(req_delete(&format!("{path}/{uid_str}"), &app.api_key))
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    // Membership gone…
    let m = app
        .state
        .repos
        .memberships
        .find_by_org_user(app.org_id, uid)
        .await
        .unwrap();
    assert!(m.is_none(), "membership must be removed");
    // …user remains for audit.
    let u = app.state.repos.users.find_by_id(uid).await.unwrap();
    assert!(u.is_some(), "user row must persist for audit retention");

    // Re-DELETE must 404 (not 204) — the spec is strict on “user is not in scope”.
    let del2 = app
        .router
        .clone()
        .oneshot(req_delete(&format!("{path}/{uid_str}"), &app.api_key))
        .await
        .unwrap();
    assert_eq!(del2.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_filter_eq_username() {
    let app = build_app().await;
    let path = format!("/api/scim/v2/organizations/{}/Users", app.org_id);
    for name in &["alice@acme.com", "alice2@acme.com", "bob@acme.com"] {
        let create = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": name,
            "emails": [{"value": name, "primary": true}],
        });
        let _ = app
            .router
            .clone()
            .oneshot(req_post(&path, &app.api_key, create))
            .await
            .unwrap();
    }
    let filtered_path = format!(
        "/api/scim/v2/organizations/{}/Users?filter=userName%20eq%20%22alice@acme.com%22",
        app.org_id
    );
    let resp = app
        .router
        .clone()
        .oneshot(req_get(&filtered_path, &app.api_key))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["totalResults"], json!(1));
    assert_eq!(body["Resources"][0]["userName"], "alice@acme.com");
}

#[tokio::test]
async fn list_groups_returns_builtin_roles() {
    let app = build_app().await;
    let path = format!("/api/scim/v2/organizations/{}/Groups", app.org_id);
    let resp = app
        .router
        .clone()
        .oneshot(req_get(&path, &app.api_key))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let resources = body["Resources"].as_array().unwrap();
    // 5 built-in roles.
    assert_eq!(resources.len(), 5);
    let names: Vec<&str> = resources
        .iter()
        .filter_map(|g| g["displayName"].as_str())
        .collect();
    for r in ["owner", "admin", "billing_admin", "member", "viewer"] {
        assert!(
            names.contains(&r),
            "group {r} should be listed; got {names:?}"
        );
    }
}

#[tokio::test]
async fn put_user_changes_display_name() {
    let app = build_app().await;
    let path = format!("/api/scim/v2/organizations/{}/Users", app.org_id);
    let create = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "eve@acme.com",
        "displayName": "Eve",
        "emails": [{"value": "eve@acme.com", "primary": true}],
    });
    let resp = app
        .router
        .clone()
        .oneshot(req_post(&path, &app.api_key, create))
        .await
        .unwrap();
    let uid = body_json(resp).await["id"].as_str().unwrap().to_string();
    let put = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "eve@acme.com",
        "displayName": "Eve Renamed",
        "emails": [{"value": "eve@acme.com", "primary": true}],
        "active": true,
    });
    let resp = app
        .router
        .clone()
        .oneshot(req_put(&format!("{path}/{uid}"), &app.api_key, put))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["displayName"], "Eve Renamed");
}
