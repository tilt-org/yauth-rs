//! SAML IdP-initiated Single Logout receiver (`GET/POST /sso/saml/slo`).
//!
//! Mirrors yauth-go's `slo_test.go` 1:1: a correctly-signed
//! HTTP-Redirect-binding LogoutRequest revokes the mapped user's local
//! session server-side; a wrong-key signature is rejected and the
//! session survives; an unsigned request is refused.
//!
//! The signature is over the RAW, still-percent-encoded query octet
//! string (SAML Bindings §3.4.4.1) — getting the encoding wrong is a
//! signature bypass, so the signing helper reproduces exactly what a
//! real IdP (and yauth-go's test) sends.
//!
//! Memory backend only — SQL backends stub SsoConnection create/list_all.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password"
))]
#![forbid(unsafe_code)]

mod helpers;

use std::time::Duration;

use axum::Router;
use base64::Engine;
use chrono::Utc;
use helpers::saml_idp_fixture::FixtureIdp;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use tower::ServiceExt;
use uuid::Uuid;

use yauth::auth::crypto;
use yauth::backends::memory::InMemoryBackend;
use yauth::prelude::*;
use yauth::state::YAuthState;
use yauth_entity::{
    ConnectionKind, ConnectionStatus, NewExternalIdentity, NewOrganization, NewSsoConnection,
    NewUser, SamlAttributeMappings, SamlConnectionConfig, saml_provider,
};

const BASE_URL: &str = "http://127.0.0.1:9997";
const SP_ENTITY: &str = "https://app.example/sso/saml/metadata/abc";
const SP_ACS: &str = "https://app.example/sso/saml/acs";
const IDP_ENTITY: &str = "https://idp.example.com/saml/metadata";
const NAME_ID: &str = "user-nameid-1";
const SIG_ALG: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

// ── application/x-www-form-urlencoded percent encoder ─────────────────────
// Mirrors Go's url.QueryEscape for the base64 payload: unreserved chars
// stay literal, everything else (notably `=`, `+`, `/`) is %-escaped.

fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn deflate_raw(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;
    let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Build a SAML HTTP-Redirect-binding LogoutRequest query string signed
/// with `signing_key` (RSA-SHA256), mirroring what a real IdP sends and
/// yauth-go's `signedRedirectLogoutRequest`.
fn signed_redirect_logout_request(idp: &FixtureIdp, name_id: &str) -> String {
    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{id}" Version="2.0" IssueInstant="{instant}"><saml:Issuer>{issuer}</saml:Issuer><saml:NameID>{name_id}</saml:NameID></samlp:LogoutRequest>"#,
        id = Uuid::now_v7().simple(),
        instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        issuer = idp.issuer,
        name_id = name_id,
    );
    let saml_request =
        base64::engine::general_purpose::STANDARD.encode(deflate_raw(xml.as_bytes()));

    // Signed octet string: SAMLRequest=<enc>&SigAlg=<enc> (no RelayState).
    let signed = format!(
        "SAMLRequest={}&SigAlg={}",
        query_escape(&saml_request),
        query_escape(SIG_ALG),
    );
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::<Sha256>::new(idp.private_key.clone());
    let sig = signing_key.sign_with_rng(&mut rng, signed.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    format!(
        "SAMLRequest={}&SigAlg={}&Signature={}",
        query_escape(&saml_request),
        query_escape(SIG_ALG),
        query_escape(&sig_b64),
    )
}

// ── yauth app + seeded org/connection/user/session ────────────────────────

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
        jwt_secret: "test-secret-saml-slo".into(),
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

    // Active SAML connection whose IdP cert is the fixture's key.
    let cfg = SamlConnectionConfig {
        idp_entity_id: IDP_ENTITY.into(),
        idp_sso_url: "https://idp.example.com/sso".into(),
        idp_slo_url: None,
        idp_x509_cert: idp.cert_pem(),
        sp_entity_id: SP_ENTITY.into(),
        sp_acs_url: SP_ACS.into(),
        sp_private_key: None,
        idp_initiated_sso_allowed: false,
        assertion_signed_required: true,
        response_signed_required: false,
        want_encrypted_assertions: false,
        attribute_mappings: SamlAttributeMappings::default(),
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
            kind: ConnectionKind::SamlSp,
            name: "Test SAML".into(),
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

/// Seed a user + external identity (provider from the IdP entity id,
/// external_id = NameID) and an active session. Returns the session token.
async fn seed_user_with_session(app: &TestApp) -> String {
    let now = Utc::now().naive_utc();
    let user = app
        .state
        .repos
        .users
        .create(NewUser {
            id: Uuid::now_v7(),
            email: "u@example.com".into(),
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

    let provider = saml_provider(IDP_ENTITY);
    app.state
        .repos
        .external_identities
        .create(NewExternalIdentity {
            id: Uuid::now_v7(),
            user_id: user.id,
            provider,
            external_id: NAME_ID.into(),
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
    token
}

async fn slo_get(app: &TestApp, query: &str) -> axum::http::StatusCode {
    let resp = app
        .router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!("/sso/saml/slo?{query}"))
                .body(axum::body::Body::empty())
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

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn verified_request_revokes_session() {
    let idp = FixtureIdp::new(IDP_ENTITY);
    let app = build_app(&idp).await;
    let token = seed_user_with_session(&app).await;
    assert!(
        session_alive(&app, &token).await,
        "session should start alive"
    );

    let q = signed_redirect_logout_request(&idp, NAME_ID);
    let status = slo_get(&app, &q).await;
    assert!(
        status == axum::http::StatusCode::OK || status == axum::http::StatusCode::FOUND,
        "expected 200/302 for a verified LogoutRequest, got {status}"
    );

    assert!(
        !session_alive(&app, &token).await,
        "session must be revoked after a verified SAML SLO"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_signature_is_rejected_and_session_survives() {
    let idp = FixtureIdp::new(IDP_ENTITY);
    let app = build_app(&idp).await;
    let token = seed_user_with_session(&app).await;

    // Sign with an attacker key, not the connection's IdP key.
    let attacker = FixtureIdp::new(IDP_ENTITY);
    let q = signed_redirect_logout_request(&attacker, NAME_ID);
    let status = slo_get(&app, &q).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "a wrong-key LogoutRequest must be rejected"
    );
    assert!(
        session_alive(&app, &token).await,
        "session must NOT be revoked by an unverified LogoutRequest"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unsigned_request_is_refused() {
    let idp = FixtureIdp::new(IDP_ENTITY);
    let app = build_app(&idp).await;
    let token = seed_user_with_session(&app).await;

    let status = slo_get(&app, "SAMLRequest=abc").await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "an unsigned LogoutRequest must be refused"
    );
    assert!(
        session_alive(&app, &token).await,
        "session must survive an unsigned request"
    );
}
