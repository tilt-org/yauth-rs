//! OIDC Back-Channel Logout 1.0 — RP consumer (`POST /sso/backchannel-logout`).
//!
//! Reuses the phase-B mock-IdP pattern: a mock IdP serving discovery + JWKS
//! with a fixed RSA signer, and an active OIDC SSO connection pointing at it.
//! We mint RSA-signed logout_tokens (verify_logout_token is asymmetric-only)
//! and assert the security properties: a valid token revokes the mapped
//! session, a nonce-bearing token is rejected, and a replayed jti is an
//! idempotent 200.
//!
//! Memory backend only — SQL backends stub SsoConnection create/list_all.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "oidc"
))]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{Router, extract::State as AxState, http::StatusCode, response::Json, routing::get};
use base64::Engine;
use chrono::Utc;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use yauth::auth::crypto;
use yauth::auth::oidc_client::{ChaCha20Poly1305Cipher, RemoteJwk, RemoteJwks, SecretCipher};
use yauth::backends::memory::InMemoryBackend;
use yauth::prelude::*;
use yauth::state::YAuthState;
use yauth_entity::{
    ConnectionKind, ConnectionStatus, NewExternalIdentity, NewOrganization, NewSsoConnection,
    NewUser, OidcConnectionConfig, oidc_provider,
};

const TEST_RSA_PEM: &str = include_str!("fixtures/test_rsa_pkcs8.pem");
const BASE_URL: &str = "http://127.0.0.1:9998";
const CLIENT_ID: &str = "test-client";
const KID: &str = "kid-1";

// ── Mock IdP (discovery + JWKS only) ──────────────────────────────────────

#[derive(Clone)]
struct IdpState {
    issuer: Arc<Mutex<String>>,
}

fn rsa_jwks() -> RemoteJwks {
    let priv_key = rsa::RsaPrivateKey::from_pkcs8_pem(TEST_RSA_PEM).expect("valid pem");
    let pub_key = priv_key.to_public_key();
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    RemoteJwks {
        keys: vec![RemoteJwk {
            kid: Some(KID.into()),
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            n: Some(n),
            e: Some(e),
        }],
    }
}

/// Sign a logout_token-shaped claim set with the IdP's RSA key + kid.
fn sign_rsa(claims: &Value) -> String {
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::RS256,
        kid: Some(KID.into()),
        ..Default::default()
    };
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).expect("rsa pem");
    jsonwebtoken::encode(&header, claims, &key).expect("sign")
}

async fn idp_discovery(AxState(s): AxState<IdpState>) -> Json<Value> {
    let issuer = s.issuer.lock().unwrap().clone();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}

async fn idp_jwks() -> Json<Value> {
    Json(serde_json::to_value(rsa_jwks()).unwrap())
}

struct FixtureIdp {
    issuer: String,
    discovery_url: String,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FixtureIdp {
    async fn start() -> Self {
        let state = IdpState {
            issuer: Arc::new(Mutex::new(String::new())),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(idp_discovery))
            .route("/jwks", get(idp_jwks))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        *state.issuer.lock().unwrap() = issuer.clone();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        Self {
            discovery_url: format!("http://{addr}/.well-known/openid-configuration"),
            issuer,
            _shutdown: tx,
        }
    }
}

// ── yauth app + seeded user/connection/session ────────────────────────────

struct TestApp {
    router: Router,
    state: YAuthState,
}

async fn build_app(idp: &FixtureIdp) -> TestApp {
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
        jwt_secret: "test-secret-bcl-consume".into(),
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

    // Active OIDC connection pointing at the mock IdP.
    let cipher = ChaCha20Poly1305Cipher::new(&[42u8; 32]).unwrap();
    let cfg = OidcConnectionConfig {
        discovery_url: idp.discovery_url.clone(),
        client_id: CLIENT_ID.into(),
        client_secret: cipher.encrypt("client-shh"),
        scopes: OidcConnectionConfig::default_scopes(),
        claim_mappings: yauth_entity::ClaimMappings::default(),
    };
    let now = Utc::now().naive_utc();
    let org = state
        .repos
        .organizations
        .create(NewOrganization {
            id: Uuid::now_v7(),
            name: "acme".into(),
            slug: "acme".into(),
            display_name: None,
            avatar_url: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    state
        .repos
        .sso_connections
        .create(NewSsoConnection {
            id: Uuid::now_v7(),
            organization_id: org.id,
            kind: ConnectionKind::OidcClient,
            name: "Fixture".into(),
            status: ConnectionStatus::Active,
            config: serde_json::to_value(&cfg).unwrap(),
            jit_provisioning_enabled: true,
            default_role_on_jit: "member".into(),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    TestApp { router, state }
}

/// Seed a user + external identity (provider derived from the IdP issuer) and
/// an active session. Returns (user_id, sub, session_token).
async fn seed_user_with_session(app: &TestApp, idp: &FixtureIdp, sub: &str) -> (Uuid, String) {
    let now = Utc::now().naive_utc();
    let user = app
        .state
        .repos
        .users
        .create(NewUser {
            id: Uuid::now_v7(),
            email: format!("{sub}@example.com"),
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

    let provider = oidc_provider(&idp.issuer);
    app.state
        .repos
        .external_identities
        .create(NewExternalIdentity {
            id: Uuid::now_v7(),
            user_id: user.id,
            provider,
            external_id: sub.to_string(),
            linked_at: now,
            last_login_at: now,
        })
        .await
        .unwrap();

    let (token, _sid) = yauth::auth::session::create_session(
        &app.state,
        user.id,
        None,
        None,
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    (user.id, token)
}

async fn post_logout_token(app: &TestApp, token: &str) -> StatusCode {
    // A compact-JWS is `[A-Za-z0-9_-]` + `.` only — all form-safe, no escaping
    // needed.
    let body = format!("logout_token={token}");
    let resp = app
        .router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/sso/backchannel-logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

async fn session_alive(app: &TestApp, token: &str) -> bool {
    let hash = crypto::hash_token(token);
    app.state
        .repos
        .session_ops
        .validate_session(&hash)
        .await
        .unwrap()
        .is_some()
}

fn logout_token_claims(issuer: &str, sub: &str, jti: &str) -> Value {
    json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "sub": sub,
        "iat": Utc::now().timestamp(),
        "jti": jti,
        "events": {
            "http://schemas.openid.net/event/backchannel-logout": {}
        }
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn valid_logout_token_revokes_mapped_session() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;
    let sub = "user-revoke";
    let (_uid, token) = seed_user_with_session(&app, &idp, sub).await;
    assert!(
        session_alive(&app, &token).await,
        "session should start alive"
    );

    let jti = crypto::generate_token();
    let lt = sign_rsa(&logout_token_claims(&idp.issuer, sub, &jti));
    assert_eq!(post_logout_token(&app, &lt).await, StatusCode::OK);

    assert!(
        !session_alive(&app, &token).await,
        "session must be revoked after a valid logout_token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nonce_bearing_token_is_rejected() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;
    let sub = "user-nonce";
    let (_uid, token) = seed_user_with_session(&app, &idp, sub).await;

    let jti = crypto::generate_token();
    let mut claims = logout_token_claims(&idp.issuer, sub, &jti);
    // BCL §2.4 forbids nonce; a validly-signed token carrying one must 400.
    claims["nonce"] = json!("should-not-be-here");
    let lt = sign_rsa(&claims);

    assert_eq!(post_logout_token(&app, &lt).await, StatusCode::BAD_REQUEST);
    assert!(
        session_alive(&app, &token).await,
        "a rejected token must not revoke the session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_jti_is_idempotent_200() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;
    let sub = "user-replay";
    let (_uid, _token) = seed_user_with_session(&app, &idp, sub).await;

    let jti = crypto::generate_token();
    let lt = sign_rsa(&logout_token_claims(&idp.issuer, sub, &jti));

    // First delivery: accepted + processed.
    assert_eq!(post_logout_token(&app, &lt).await, StatusCode::OK);
    // Replay of the same jti: idempotent 200, no error.
    assert_eq!(post_logout_token(&app, &lt).await, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_events_claim_is_rejected() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;
    let sub = "user-noevent";
    seed_user_with_session(&app, &idp, sub).await;

    let jti = crypto::generate_token();
    let mut claims = logout_token_claims(&idp.issuer, sub, &jti);
    claims.as_object_mut().unwrap().remove("events");
    let lt = sign_rsa(&claims);

    assert_eq!(post_logout_token(&app, &lt).await, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn unmatched_issuer_is_rejected() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;
    let sub = "user-badiss";
    seed_user_with_session(&app, &idp, sub).await;

    let jti = crypto::generate_token();
    // An iss that matches no connection → 400 (no connection to verify against).
    let lt = sign_rsa(&logout_token_claims("https://evil.example", sub, &jti));
    assert_eq!(post_logout_token(&app, &lt).await, StatusCode::BAD_REQUEST);
}
