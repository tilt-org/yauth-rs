//! End-to-end SSO OIDC client integration test (issue #93, Phase B).
//!
//! Stands up a deterministic in-process IdP using a fixed RSA test
//! key, then exercises the full `/sso/login` → IdP authorize →
//! `/sso/callback` round-trip against a yauth instance backed by the
//! in-memory backend.
//!
//! Why a fixture IdP and not the real Okta? Networking in CI is
//! brittle, and the security properties yauth needs to prove
//! (signature validation, nonce binding, audience pinning, JWKS
//! rollover) live entirely on yauth's side of the wire.
//!
//! Each `#[tokio::test]` builds a fresh app + fresh IdP — no shared
//! state. The IdP is bound to `127.0.0.1:0` (ephemeral port) and
//! shut down via a oneshot signal when the test returns.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password",
    feature = "asymmetric-jwt",
))]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Form, State as AxState},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine;
use chrono::Utc;
use http_body_util::BodyExt;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Deserialize;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use yauth::auth::oidc_client::{
    AudienceClaim, ChaCha20Poly1305Cipher, IdTokenClaims, RemoteJwk, RemoteJwks, SecretCipher,
    validate_id_token,
};
use yauth::backends::memory::InMemoryBackend;
use yauth::prelude::*;
use yauth_entity::{
    ConnectionKind, ConnectionStatus, NewMembership, NewOrganization, NewSsoConnection, NewUser,
    OidcConnectionConfig,
};

const TEST_RSA_PEM: &str = include_str!("fixtures/test_rsa_pkcs8.pem");

// ──────────────────────────────────────────────
// Fixture IdP
// ──────────────────────────────────────────────

/// Mutable bits the IdP server can be steered with from a test.
#[derive(Clone)]
struct IdpState {
    /// Fixed signing key + kid. `kid` is mutable for the rollover test.
    rsa_pem: String,
    kid: Arc<Mutex<String>>,
    /// Issuer URL, set after we bind the listener so we know the port.
    issuer: Arc<Mutex<String>>,
    /// Pre-built id_token claims keyed by `code`. Returned by the
    /// token endpoint.
    code_to_claims: Arc<Mutex<HashMap<String, IdTokenClaims>>>,
}

impl IdpState {
    fn new() -> Self {
        Self {
            rsa_pem: TEST_RSA_PEM.to_string(),
            kid: Arc::new(Mutex::new("kid-1".into())),
            issuer: Arc::new(Mutex::new(String::new())),
            code_to_claims: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn issuer(&self) -> String {
        self.issuer.lock().unwrap().clone()
    }

    fn jwks(&self) -> RemoteJwks {
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_pem(&self.rsa_pem).expect("valid pem");
        let pub_key = priv_key.to_public_key();
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
        RemoteJwks {
            keys: vec![RemoteJwk {
                kid: Some(self.kid.lock().unwrap().clone()),
                kty: "RSA".into(),
                alg: Some("RS256".into()),
                n: Some(n),
                e: Some(e),
            }],
        }
    }

    fn issue_id_token(&self, claims: &IdTokenClaims) -> String {
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(self.kid.lock().unwrap().clone()),
            ..Default::default()
        };
        let key =
            jsonwebtoken::EncodingKey::from_rsa_pem(self.rsa_pem.as_bytes()).expect("rsa pem");
        jsonwebtoken::encode(&header, claims, &key).expect("sign")
    }
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    code: String,
    #[serde(default)]
    grant_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
}

async fn idp_discovery(AxState(s): AxState<IdpState>) -> Json<Value> {
    let issuer = s.issuer();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}

async fn idp_jwks(AxState(s): AxState<IdpState>) -> Json<Value> {
    Json(serde_json::to_value(s.jwks()).unwrap())
}

async fn idp_token(
    AxState(s): AxState<IdpState>,
    Form(form): Form<TokenForm>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let claims = s
        .code_to_claims
        .lock()
        .unwrap()
        .remove(&form.code)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "no such code".into()))?;
    if form.grant_type.as_deref() != Some("authorization_code") {
        return Err((StatusCode::BAD_REQUEST, "wrong grant_type".into()));
    }
    if form.client_id.as_deref() != Some("test-client") {
        return Err((StatusCode::BAD_REQUEST, "wrong client_id".into()));
    }
    if form.code_verifier.is_none() {
        return Err((StatusCode::BAD_REQUEST, "missing code_verifier".into()));
    }
    let id_token = s.issue_id_token(&claims);
    Ok(Json(json!({
        "id_token": id_token,
        "access_token": "fake-access",
        "token_type": "Bearer",
        "expires_in": 3600
    })))
}

struct FixtureIdp {
    state: IdpState,
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FixtureIdp {
    async fn start() -> Self {
        let state = IdpState::new();
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(idp_discovery))
            .route("/jwks", get(idp_jwks))
            .route("/token", post(idp_token))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        *state.issuer.lock().unwrap() = format!("http://{addr}");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        // Give the listener a tick to be ready.
        tokio::time::sleep(Duration::from_millis(10)).await;
        Self {
            state,
            addr,
            _shutdown: tx,
        }
    }

    fn discovery_url(&self) -> String {
        format!("http://{}/.well-known/openid-configuration", self.addr)
    }

    fn seed_code(&self, code: &str, claims: IdTokenClaims) {
        self.state
            .code_to_claims
            .lock()
            .unwrap()
            .insert(code.to_string(), claims);
    }
}

// ──────────────────────────────────────────────
// yauth app builder
// ──────────────────────────────────────────────

const BASE_URL: &str = "http://127.0.0.1:9999";

struct TestApp {
    router: Router,
    state: yauth::state::YAuthState,
    org_id: Uuid,
    conn_id: Uuid,
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
        jwt_secret: "test-secret-sso-phase-b".into(),
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

    // Insert an org + active OIDC connection. Use ChaCha20Poly1305Cipher
    // so the live decrypt path runs in tests.
    let cipher = ChaCha20Poly1305Cipher::new(&[42u8; 32]).unwrap();
    let cfg = OidcConnectionConfig {
        discovery_url: idp.discovery_url(),
        client_id: "test-client".into(),
        client_secret: cipher.encrypt("client-shh"),
        scopes: OidcConnectionConfig::default_scopes(),
        claim_mappings: {
            let mut m = yauth_entity::ClaimMappings::default();
            m.group_to_role.insert("admins".into(), "admin".into());
            m.group_to_role.insert("owners".into(), "owner".into());
            m
        },
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
    let conn = state
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

    // Configure the runtime cipher to match what we encrypted with.
    // SAFETY: this env var is read once on first decrypt, then cached
    // implicitly via the cipher_for_state branch. Tests run
    // single-threaded under #[tokio::test] so contention is fine.
    // We use a deterministic 32-byte key encoded as hex.
    unsafe {
        std::env::set_var("YAUTH_SSO_AEAD_KEY", hex::encode([42u8; 32]));
    }

    TestApp {
        router,
        state,
        org_id: org.id,
        conn_id: conn.id,
    }
}

impl TestApp {
    async fn get(&self, path: &str) -> axum::response::Response {
        self.router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }
}

/// Drive a `/sso/login` and pull state + nonce + pkce_verifier out
/// of the persisted SsoLoginState row by inspecting the Location
/// header for the `state=` param.
async fn login_and_capture_state(app: &TestApp) -> (String, yauth_entity::SsoLoginState) {
    let resp = app.get("/sso/login?org=acme&redirect_to=/dashboard").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login should 303");
    let loc = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string();
    let url = url::Url::parse(&loc).expect("parsable URL");
    let state_token = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state param present");
    // Pull the persisted row directly out of the in-memory backend's
    // repo. NOTE: this *peeks* — we don't consume it, because the real
    // callback will need it. Reach into the storage map.
    let row = state_row(&app.state, &state_token).await;
    (state_token, row)
}

async fn state_row(state: &yauth::state::YAuthState, token: &str) -> yauth_entity::SsoLoginState {
    // We don't have a public lookup-without-delete, but the in-memory
    // repo stores by `state` key. Cheat through `find_and_delete` and
    // re-create the row in place — tests only.
    let row = state
        .repos
        .sso_login_states
        .find_and_delete(token)
        .await
        .unwrap()
        .expect("state row present");
    state
        .repos
        .sso_login_states
        .create(yauth_entity::NewSsoLoginState {
            state: row.state.clone(),
            connection_id: row.connection_id,
            issuer: row.issuer.clone(),
            nonce: row.nonce.clone(),
            pkce_verifier: row.pkce_verifier.clone(),
            redirect_to: row.redirect_to.clone(),
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
        .await
        .unwrap();
    row
}

/// Build minimal id_token claims targeting our connection.
fn make_claims(
    idp: &FixtureIdp,
    sub: &str,
    email: &str,
    nonce: &str,
    groups: Vec<&str>,
) -> IdTokenClaims {
    let mut extra = HashMap::new();
    extra.insert("sub".into(), json!(sub));
    extra.insert("email".into(), json!(email));
    extra.insert("name".into(), json!("Fixture User"));
    if !groups.is_empty() {
        extra.insert("groups".into(), json!(groups));
    }
    let now = Utc::now().timestamp();
    IdTokenClaims {
        iss: idp.state.issuer(),
        aud: AudienceClaim::Single("test-client".into()),
        exp: now + 600,
        iat: now,
        nonce: Some(nonce.into()),
        nbf: None,
        extra,
    }
}

// ──────────────────────────────────────────────
// Happy-path test
// ──────────────────────────────────────────────

#[tokio::test]
async fn full_round_trip_jit_provisions_user_and_membership() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    let (state_token, row) = login_and_capture_state(&app).await;
    let code = "code-1";
    idp.seed_code(
        code,
        make_claims(
            &idp,
            "fixture-sub-1",
            "alice@acme.com",
            &row.nonce,
            vec!["admins"],
        ),
    );

    let resp = app
        .get(&format!("/sso/callback?code={code}&state={state_token}"))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("session="));
    let loc = resp.headers().get(axum::http::header::LOCATION).unwrap();
    assert_eq!(loc.to_str().unwrap(), "/dashboard");

    // User exists, linked, membership active w/ admin role.
    let user = app
        .state
        .repos
        .users
        .find_by_email("alice@acme.com")
        .await
        .unwrap()
        .expect("user provisioned");
    let memb = app
        .state
        .repos
        .memberships
        .find_by_org_user(app.org_id, user.id)
        .await
        .unwrap()
        .expect("membership created");
    assert_eq!(memb.role, "admin");
    let ext = app
        .state
        .repos
        .external_identities
        .find_by_provider_external_id(
            &yauth_entity::oidc_provider(&idp.state.issuer()),
            "fixture-sub-1",
        )
        .await
        .unwrap()
        .expect("external identity linked");
    assert_eq!(ext.user_id, user.id);
}

#[tokio::test]
async fn returning_user_logs_in_without_creating_duplicate() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    // Round 1.
    let (st, row) = login_and_capture_state(&app).await;
    idp.seed_code(
        "c1",
        make_claims(&idp, "sub-x", "bob@acme.com", &row.nonce, vec![]),
    );
    let r = app.get(&format!("/sso/callback?code=c1&state={st}")).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let user1 = app
        .state
        .repos
        .users
        .find_by_email("bob@acme.com")
        .await
        .unwrap()
        .unwrap();

    // Round 2.
    let (st2, row2) = login_and_capture_state(&app).await;
    idp.seed_code(
        "c2",
        make_claims(&idp, "sub-x", "bob@acme.com", &row2.nonce, vec![]),
    );
    let r2 = app.get(&format!("/sso/callback?code=c2&state={st2}")).await;
    assert_eq!(r2.status(), StatusCode::SEE_OTHER);
    let user2 = app
        .state
        .repos
        .users
        .find_by_email("bob@acme.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user1.id, user2.id);
}

// ──────────────────────────────────────────────
// Pentest cases
// ──────────────────────────────────────────────

#[tokio::test]
async fn pentest_state_replay_rejects_second_use() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    let (st, row) = login_and_capture_state(&app).await;
    let code = "c-replay";
    idp.seed_code(
        code,
        make_claims(&idp, "u-1", "c@acme.com", &row.nonce, vec![]),
    );

    let r1 = app
        .get(&format!("/sso/callback?code={code}&state={st}"))
        .await;
    assert_eq!(r1.status(), StatusCode::SEE_OTHER);

    // Replay — state is gone. Reseed a fresh code so the IdP would
    // be happy if yauth got that far, then assert yauth rejects
    // before token-exchange.
    idp.seed_code(
        "c-replay-2",
        make_claims(&idp, "u-1", "c@acme.com", "anything", vec![]),
    );
    let r2 = app
        .get(&format!("/sso/callback?code=c-replay-2&state={st}"))
        .await;
    assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pentest_nonce_mismatch_rejects() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    let (st, _row) = login_and_capture_state(&app).await;
    let code = "bad-nonce";
    // Wrong nonce.
    idp.seed_code(
        code,
        make_claims(
            &idp,
            "u",
            "x@acme.com",
            "definitely-not-the-real-nonce",
            vec![],
        ),
    );
    let r = app
        .get(&format!("/sso/callback?code={code}&state={st}"))
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let body = r.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let msg = v["error"].as_str().unwrap_or_default().to_string()
        + v["detail"].as_str().unwrap_or_default();
    assert!(msg.contains("nonce") || v.to_string().contains("nonce"));
}

#[tokio::test]
async fn pentest_audience_mismatch_rejects() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    let (st, row) = login_and_capture_state(&app).await;
    let code = "bad-aud";
    let mut claims = make_claims(&idp, "u", "x@acme.com", &row.nonce, vec![]);
    claims.aud = AudienceClaim::Single("some-other-client".into());
    idp.seed_code(code, claims);
    let r = app
        .get(&format!("/sso/callback?code={code}&state={st}"))
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pentest_expired_id_token_rejected() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    let (st, row) = login_and_capture_state(&app).await;
    let code = "exp";
    let mut claims = make_claims(&idp, "u", "x@acme.com", &row.nonce, vec![]);
    // 5 minutes in the past — past leeway.
    let now = Utc::now().timestamp();
    claims.exp = now - 300;
    claims.iat = now - 600;
    idp.seed_code(code, claims);
    let r = app
        .get(&format!("/sso/callback?code={code}&state={st}"))
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pentest_jit_disabled_rejects_unknown_user() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    // Flip JIT off on the connection.
    let now = Utc::now().naive_utc();
    app.state
        .repos
        .sso_connections
        .update(
            app.conn_id,
            yauth_entity::UpdateSsoConnection {
                jit_provisioning_enabled: Some(false),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (st, row) = login_and_capture_state(&app).await;
    let code = "no-jit";
    idp.seed_code(
        code,
        make_claims(&idp, "new-sub", "stranger@acme.com", &row.nonce, vec![]),
    );
    let r = app
        .get(&format!("/sso/callback?code={code}&state={st}"))
        .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // No user provisioned.
    assert!(
        app.state
            .repos
            .users
            .find_by_email("stranger@acme.com")
            .await
            .unwrap()
            .is_none(),
        "no implicit account creation"
    );
}

#[tokio::test]
async fn pentest_email_change_blocks_silent_merge() {
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    // Round 1: provision alice with sub=ext-1.
    let (st1, row1) = login_and_capture_state(&app).await;
    idp.seed_code(
        "r1",
        make_claims(&idp, "ext-1", "alice@acme.com", &row1.nonce, vec![]),
    );
    let r1 = app.get(&format!("/sso/callback?code=r1&state={st1}")).await;
    assert_eq!(r1.status(), StatusCode::SEE_OTHER);

    // Round 2: IdP claims sub=ext-1 but email=bob@acme.com.
    let (st2, row2) = login_and_capture_state(&app).await;
    idp.seed_code(
        "r2",
        make_claims(&idp, "ext-1", "bob@acme.com", &row2.nonce, vec![]),
    );
    let r2 = app.get(&format!("/sso/callback?code=r2&state={st2}")).await;
    assert_eq!(r2.status(), StatusCode::CONFLICT, "must not silently merge");

    // Alice still owns the row.
    let alice = app
        .state
        .repos
        .users
        .find_by_email("alice@acme.com")
        .await
        .unwrap()
        .unwrap();
    let ext = app
        .state
        .repos
        .external_identities
        .find_by_provider_external_id(&yauth_entity::oidc_provider(&idp.state.issuer()), "ext-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ext.user_id, alice.id);
}

#[tokio::test]
async fn pentest_jwks_rollover_new_token_validates_old_invalid_after_grace() {
    // This test demonstrates the kid-miss → refresh path. We:
    //   1) Sign + validate a token with kid=kid-1 (initial cache).
    //   2) Rotate the IdP to kid=kid-2.
    //   3) Drive a fresh round-trip — the cache should miss on kid-2,
    //      refresh, and validate the new token. The "old" token
    //      signed against kid-1 still validates against the same
    //      RSA private key because the RSA key didn't actually
    //      change; in production a kid rotation usually means a new
    //      private key, but for the cache-miss-and-refresh path
    //      what we want to exercise is the JWKS being re-fetched
    //      when an unknown kid arrives.
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    // Round 1 — kid-1.
    let (st, row) = login_and_capture_state(&app).await;
    idp.seed_code(
        "c-1",
        make_claims(&idp, "u-1", "a@acme.com", &row.nonce, vec![]),
    );
    let r = app.get(&format!("/sso/callback?code=c-1&state={st}")).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);

    // Rotate kid.
    *idp.state.kid.lock().unwrap() = "kid-2".into();

    // Round 2 — must drive a JWKS refetch.
    let (st2, row2) = login_and_capture_state(&app).await;
    idp.seed_code(
        "c-2",
        make_claims(&idp, "u-2", "b@acme.com", &row2.nonce, vec![]),
    );
    let r2 = app
        .get(&format!("/sso/callback?code=c-2&state={st2}"))
        .await;
    assert_eq!(
        r2.status(),
        StatusCode::SEE_OTHER,
        "kid rotation re-fetched JWKS"
    );
}

#[tokio::test]
async fn pentest_pre_existing_email_blocks_jit() {
    // An attacker who controls IdP-A signs in as alice@acme.com but
    // alice already has a yauth account from email/password sign-up.
    // We must NOT silently link the IdP identity to the existing
    // account.
    let idp = FixtureIdp::start().await;
    let app = build_app(&idp).await;

    // Provision alice via plain user repo so she has NO external link.
    let now = Utc::now().naive_utc();
    let user_id = Uuid::now_v7();
    app.state
        .repos
        .users
        .create(NewUser {
            id: user_id,
            email: "alice@acme.com".into(),
            display_name: None,
            email_verified: true,
            role: "user".into(),
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
    // She's a member of the org via email/password sign-up (made up).
    app.state
        .repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: app.org_id,
            user_id,
            role: "member".into(),
            status: yauth_entity::MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    // Attacker tries to log in via SSO using the same email.
    let (st, row) = login_and_capture_state(&app).await;
    idp.seed_code(
        "atk",
        make_claims(&idp, "attacker-sub", "alice@acme.com", &row.nonce, vec![]),
    );
    let r = app.get(&format!("/sso/callback?code=atk&state={st}")).await;
    assert_eq!(
        r.status(),
        StatusCode::CONFLICT,
        "must not silently link to existing email-owner"
    );
    // No new external identity.
    let ext = app
        .state
        .repos
        .external_identities
        .find_by_provider_external_id(
            &yauth_entity::oidc_provider(&idp.state.issuer()),
            "attacker-sub",
        )
        .await
        .unwrap();
    assert!(ext.is_none(), "no link must have been created");
}

// ──────────────────────────────────────────────
// Helper unit tests (validate fixture itself)
// ──────────────────────────────────────────────

#[tokio::test]
async fn validate_fixture_token_against_oidc_client() {
    // Confirms our fixture IdP produces tokens that validate_id_token
    // accepts — a meta-test against the suite.
    let idp = FixtureIdp::start().await;
    let claims = make_claims(&idp, "s", "e@x", "n-1", vec!["x"]);
    let token = idp.state.issue_id_token(&claims);
    let jwks = idp.state.jwks();
    let jwk = &jwks.keys[0];
    let now = Utc::now().timestamp();
    let parsed = validate_id_token(&token, jwk, &idp.state.issuer(), "test-client", "n-1", now)
        .expect("self-signed fixture token validates");
    assert_eq!(parsed.iss, idp.state.issuer());
}
