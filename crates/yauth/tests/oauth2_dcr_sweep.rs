//! Tests for the stale-DCR-client sweep + access_ttl config (yauth-go parity).
//!
//! Covers:
//! - `purge_stale_dynamic_clients` predicate: a dynamically-registered client
//!   unused past the TTL is swept; an admin-provisioned (non-dynamic) client is
//!   never swept; a recently-`touch_last_used`'d client survives; dependent
//!   consents are cascade-deleted.
//! - DCR registration sets `dynamically_registered` and writes a durable
//!   `oauth2.client.registered` audit event.
//! - `oauth2_server.access_ttl`: a token's advertised `expires_in` AND its JWT
//!   `exp` claim both reflect the configured TTL (not the bearer fallback).
//!
//! Runs against the memory backend.

#![cfg(all(
    feature = "memory-backend",
    feature = "bearer",
    feature = "oauth2-server",
    feature = "email-password"
))]

use std::time::Duration;

use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use yauth::backends::memory::InMemoryBackend;
use yauth::config::DurationSecs;
use yauth::prelude::*;
use yauth::repo::AuditLogFilter;

mod helpers;

/// Build an app with DCR enabled and an optional explicit `access_ttl`.
async fn build_app(access_ttl: Option<Duration>) -> yauth::YAuth {
    let backend = InMemoryBackend::new();
    YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "http://localhost:3000".to_string(),
            session_cookie_name: "session".to_string(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            auto_admin_first_user: true,
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
        jwt_secret: "test-secret-dcr-sweep-integration".to_string(),
        // Deliberately long so a configured access_ttl visibly diverges.
        access_token_ttl: Duration::from_secs(3600),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        #[cfg(feature = "asymmetric-jwt")]
        signing_algorithm: Default::default(),
        #[cfg(feature = "asymmetric-jwt")]
        signing_key_pem: None,
        #[cfg(feature = "asymmetric-jwt")]
        kid: None,
    })
    .with_oauth2_server(yauth::config::OAuth2ServerConfig {
        allow_dynamic_registration: true,
        dcr_allow_confidential_clients: true,
        access_ttl: access_ttl.map(DurationSecs),
        ..Default::default()
    })
    .build()
    .await
    .expect("build YAuth")
}

fn now() -> chrono::NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

fn new_client(
    client_id: &str,
    dynamic: bool,
    created_at: chrono::NaiveDateTime,
) -> NewOauth2Client {
    NewOauth2Client {
        id: uuid::Uuid::now_v7(),
        client_id: client_id.to_string(),
        client_secret_hash: None,
        redirect_uris: json!(["http://localhost/cb"]),
        client_name: Some("sweep-test".to_string()),
        grant_types: json!(["authorization_code"]),
        scopes: None,
        is_public: true,
        created_at,
        token_endpoint_auth_method: Some("none".to_string()),
        public_key_pem: None,
        jwks_uri: None,
        dynamically_registered: dynamic,
    }
}

use yauth::domain::{NewConsent, NewOauth2Client};

// ── Sweep predicate + cascade ───────────────────────────────────────────────

#[tokio::test]
async fn sweep_reclaims_stale_dynamic_clients_only() {
    let app = build_app(None).await;
    let repos = &app.state().repos;
    let old = now() - chrono::Duration::days(60);
    let fresh = now();

    // (1) DCR client created 60d ago, never used → should be swept.
    repos
        .oauth2_clients
        .create(new_client("dcr-stale", true, old))
        .await
        .unwrap();
    // (2) Admin-provisioned client created 60d ago → never swept.
    repos
        .oauth2_clients
        .create(new_client("admin-old", false, old))
        .await
        .unwrap();
    // (3) DCR client created 60d ago but touched just now → survives.
    repos
        .oauth2_clients
        .create(new_client("dcr-active", true, old))
        .await
        .unwrap();
    repos
        .oauth2_clients
        .touch_last_used("dcr-active", fresh)
        .await
        .unwrap();
    // (4) DCR client created just now → survives (recent).
    repos
        .oauth2_clients
        .create(new_client("dcr-new", true, fresh))
        .await
        .unwrap();

    // Seed a consent for the stale DCR client (known user id) to verify cascade.
    let consent_user = uuid::Uuid::now_v7();
    repos
        .consents
        .create(NewConsent {
            id: uuid::Uuid::now_v7(),
            user_id: consent_user,
            client_id: "dcr-stale".to_string(),
            scopes: None,
            created_at: old,
        })
        .await
        .unwrap();
    assert!(
        repos
            .consents
            .find_by_user_and_client(consent_user, "dcr-stale")
            .await
            .unwrap()
            .is_some(),
        "consent exists before the sweep"
    );

    // Cutoff = 30d ago: only "dcr-stale" predates it on COALESCE(last_used, created).
    let cutoff = now() - chrono::Duration::days(30);
    let mut swept = repos
        .oauth2_clients
        .purge_stale_dynamic_clients(cutoff)
        .await
        .unwrap();
    swept.sort();

    assert_eq!(
        swept,
        vec!["dcr-stale".to_string()],
        "only the stale DCR client is swept"
    );

    // Swept client is gone; the others remain.
    assert!(
        repos
            .oauth2_clients
            .find_by_client_id("dcr-stale")
            .await
            .unwrap()
            .is_none(),
        "stale DCR client removed"
    );
    for survivor in ["admin-old", "dcr-active", "dcr-new"] {
        assert!(
            repos
                .oauth2_clients
                .find_by_client_id(survivor)
                .await
                .unwrap()
                .is_some(),
            "{survivor} must survive the sweep"
        );
    }

    // Dependent consent was cascade-deleted.
    assert!(
        repos
            .consents
            .find_by_user_and_client(consent_user, "dcr-stale")
            .await
            .unwrap()
            .is_none(),
        "consent for the swept client was cascade-deleted"
    );
}

#[tokio::test]
async fn sweep_never_touches_banned_dynamic_clients() {
    let app = build_app(None).await;
    let repos = &app.state().repos;
    let old = now() - chrono::Duration::days(60);

    repos
        .oauth2_clients
        .create(new_client("dcr-banned", true, old))
        .await
        .unwrap();
    repos
        .oauth2_clients
        .set_banned("dcr-banned", Some((Some("abuse".into()), now())))
        .await
        .unwrap();

    let cutoff = now() - chrono::Duration::days(30);
    let swept = repos
        .oauth2_clients
        .purge_stale_dynamic_clients(cutoff)
        .await
        .unwrap();
    assert!(
        swept.is_empty(),
        "banned clients are excluded from the sweep"
    );
    assert!(
        repos
            .oauth2_clients
            .find_by_client_id("dcr-banned")
            .await
            .unwrap()
            .is_some(),
        "banned DCR client is preserved"
    );
}

// ── DCR registration audit + dynamically_registered flag ────────────────────

#[tokio::test]
async fn dcr_registration_marks_dynamic_and_audits() {
    let app = build_app(None).await;
    let router = app.router().with_state(app.state().clone());

    let body = json!({
        "redirect_uris": ["http://localhost/cb"],
        "client_name": "dcr-audit-test",
        "token_endpoint_auth_method": "none",
    });
    let resp = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let client_id = v["client_id"].as_str().unwrap().to_string();

    // The persisted client is flagged dynamically_registered.
    let stored = app
        .state()
        .repos
        .oauth2_clients
        .find_by_client_id(&client_id)
        .await
        .unwrap()
        .expect("client persisted");
    assert!(stored.dynamically_registered, "DCR client flagged dynamic");
    assert!(
        stored.last_used_at.is_none(),
        "last_used_at unset at creation"
    );

    // A durable oauth2.client.registered audit event was written.
    let events = app
        .state()
        .repos
        .audit
        .list(
            AuditLogFilter {
                user_id: None,
                event_type: Some("oauth2.client.registered".to_string()),
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(events.len(), 1, "exactly one registration audit event");
    let meta = events[0].metadata.as_ref().expect("audit metadata");
    assert_eq!(meta["client_id"], json!(client_id));
    assert_eq!(meta["source"], json!("dcr"));
    assert_eq!(meta["is_public"], json!(true));
}

// ── access_ttl reflected in expires_in + JWT exp ────────────────────────────

fn decode_jwt_exp(token: &str) -> i64 {
    use base64::Engine;
    let payload_seg = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_seg)
        .unwrap();
    let claims: Value = serde_json::from_slice(&bytes).unwrap();
    claims["exp"].as_i64().unwrap()
}

#[tokio::test]
async fn access_ttl_overrides_expires_in_and_jwt_exp() {
    // Configure a short 120s access_ttl; bearer fallback is 3600s.
    let app = build_app(Some(Duration::from_secs(120))).await;
    let router = app.router().with_state(app.state().clone());

    // Register a confidential client so we can use the client_credentials grant.
    let reg_body = json!({
        "redirect_uris": ["http://localhost/cb"],
        "client_name": "ttl-test",
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_post",
    });
    let resp = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(reg_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let cid = v["client_id"].as_str().unwrap().to_string();
    let csec = v["client_secret"].as_str().unwrap().to_string();

    let form = helpers::form_urlencoded(&[
        ("grant_type", "client_credentials".to_string()),
        ("client_id", cid),
        ("client_secret", csec),
    ]);
    let before = chrono::Utc::now().timestamp();
    let resp = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();

    // Advertised expires_in reflects access_ttl (120s), not the 3600s fallback.
    assert_eq!(
        v["expires_in"].as_u64().unwrap(),
        120,
        "expires_in == access_ttl"
    );

    // The JWT exp claim also reflects ~120s (not 3600s) — they must agree.
    let exp = decode_jwt_exp(v["access_token"].as_str().unwrap());
    let lifetime = exp - before;
    assert!(
        (115..=125).contains(&lifetime),
        "JWT exp lifetime {lifetime}s should be ~120s (access_ttl), not the 3600s bearer fallback"
    );
}
