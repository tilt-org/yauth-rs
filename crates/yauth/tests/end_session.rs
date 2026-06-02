//! OIDC RP-Initiated Logout 1.0 — `/oauth/end_session` integration tests.
//!
//! Crypto-sensitive: the redirect is honored ONLY for a URI exactly registered
//! on the client identified by a *validly-signed* id_token_hint (or client_id),
//! and a present-but-invalid hint must block the redirect entirely.

#![cfg(all(
    feature = "memory-backend",
    feature = "admin",
    feature = "oauth2-server",
    feature = "oidc",
    feature = "email-password"
))]

use axum::{Router, http::StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

use yauth::backends::memory::InMemoryBackend;
use yauth::prelude::*;
use yauth::state::YAuthState;

mod helpers;

const ISSUER: &str = "http://localhost:3000";
const SECRET: &str = "test-secret-end-session";

struct TestApp {
    router: Router,
    state: YAuthState,
    admin_session: Option<String>,
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
        jwt_secret: SECRET.into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: Default::default(),
        signing_key_pem: None,
        kid: None,
    })
    .with_oauth2_server(yauth::config::OAuth2ServerConfig {
        issuer: ISSUER.into(),
        allow_dynamic_registration: true,
        dcr_allow_confidential_clients: true,
        ..Default::default()
    })
    .with_oidc(yauth::config::OidcConfig {
        issuer: ISSUER.into(),
        ..Default::default()
    })
    .with_admin()
    .build()
    .await
    .expect("build YAuth");

    let state = auth.state().clone();
    let router = Router::new().merge(auth.router()).with_state(state.clone());
    TestApp {
        router,
        state,
        admin_session: None,
    }
}

impl TestApp {
    async fn create_admin(&mut self) {
        let body = json!({ "email": "admin@example.com", "password": "test-password-123" });
        let resp = self
            .router
            .clone()
            .oneshot(req("POST", "/register", None, Some(body.to_string())))
            .await
            .unwrap();
        assert!(resp.status().is_success(), "register failed");

        let login = json!({ "email": "admin@example.com", "password": "test-password-123" });
        let resp = self
            .router
            .clone()
            .oneshot(req("POST", "/login", None, Some(login.to_string())))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let session = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .map(|s| s.split(';').next().unwrap().to_string())
            .find(|c| c.starts_with("session="));
        self.admin_session = session;
    }

    /// Create a confidential client, then PATCH its logout config. Returns the
    /// generated client_id.
    async fn create_client_with_logout(&self, post_logout: &[&str], bcl: Option<&str>) -> String {
        let cookie = self.admin_session.as_deref().unwrap();
        let create = json!({
            "redirect_uris": ["http://localhost/cb"],
            "grant_types": ["authorization_code"],
        });
        let resp = self
            .router
            .clone()
            .oneshot(req("POST", "/oauth2/clients", Some(cookie), Some(create.to_string())))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "client create failed");
        let body = body_json(resp).await;
        let client_id = body["client"]["client_id"].as_str().unwrap().to_string();

        let mut patch = json!({ "post_logout_redirect_uris": post_logout });
        if let Some(b) = bcl {
            patch["backchannel_logout_uri"] = json!(b);
        }
        let resp = self
            .router
            .clone()
            .oneshot(req(
                "PATCH",
                &format!("/oauth2/clients/{client_id}"),
                Some(cookie),
                Some(patch.to_string()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "logout patch failed");
        let view = body_json(resp).await;
        // The view should echo the registered URIs.
        assert_eq!(view["post_logout_redirect_uris"], json!(post_logout));
        client_id
    }

    fn id_token_hint(&self, aud: &str, expired: bool) -> String {
        let now = chrono::Utc::now().timestamp();
        let exp = if expired { now - 3600 } else { now + 3600 };
        let claims = json!({
            "iss": ISSUER,
            "sub": "user-123",
            "aud": aud,
            "exp": exp,
            "iat": now - 10,
        });
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap()
    }
}

fn req(method: &str, uri: &str, cookie: Option<&str>, body: Option<String>) -> axum::http::Request<axum::body::Body> {
    let mut b = axum::http::Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    b.body(axum::body::Body::from(body.unwrap_or_default()))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn get_end_session(app: &TestApp, query: &str) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(req("GET", &format!("/oauth/end_session?{query}"), None, None))
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_advertises_end_session_and_bcl() {
    let app = build_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(req("GET", "/.well-known/openid-configuration", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(
        doc["end_session_endpoint"],
        json!(format!("{ISSUER}/oauth/end_session"))
    );
    assert_eq!(doc["backchannel_logout_supported"], json!(true));
    assert_eq!(doc["backchannel_logout_session_supported"], json!(false));
}

#[tokio::test]
async fn no_redirect_renders_logged_out_page() {
    let app = build_app().await;
    let resp = get_end_session(&app, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.starts_with("text/html"), "expected html, got {ct}");
    // Always clears the session cookie.
    let sc = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(sc.contains("session=") && sc.contains("Max-Age=0"));
}

#[tokio::test]
async fn valid_hint_redirects_to_registered_uri_with_state() {
    let mut app = build_app().await;
    app.create_admin().await;
    let cid = app
        .create_client_with_logout(&["http://rp.example/done"], None)
        .await;
    let hint = app.id_token_hint(&cid, false);
    let resp = get_end_session(
        &app,
        &format!(
            "id_token_hint={hint}&post_logout_redirect_uri=http%3A%2F%2Frp.example%2Fdone&state=xyz"
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with("http://rp.example/done"), "got {loc}");
    assert!(loc.contains("state=xyz"), "state not echoed: {loc}");
}

#[tokio::test]
async fn expired_hint_still_redirects() {
    // RP-Initiated Logout §2: an expired id_token_hint is permitted.
    let mut app = build_app().await;
    app.create_admin().await;
    let cid = app
        .create_client_with_logout(&["http://rp.example/done"], None)
        .await;
    let hint = app.id_token_hint(&cid, true);
    let resp = get_end_session(
        &app,
        &format!("id_token_hint={hint}&post_logout_redirect_uri=http%3A%2F%2Frp.example%2Fdone"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "expired-but-valid hint must redirect"
    );
}

#[tokio::test]
async fn unregistered_uri_is_rejected_open_redirect_guard() {
    let mut app = build_app().await;
    app.create_admin().await;
    let cid = app
        .create_client_with_logout(&["http://rp.example/done"], None)
        .await;
    let hint = app.id_token_hint(&cid, false);
    let resp = get_end_session(
        &app,
        &format!("id_token_hint={hint}&post_logout_redirect_uri=http%3A%2F%2Fevil.example%2Fsteal"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unregistered URI must never redirect"
    );
}

#[tokio::test]
async fn invalid_hint_blocks_redirect() {
    let mut app = build_app().await;
    app.create_admin().await;
    let cid = app
        .create_client_with_logout(&["http://rp.example/done"], None)
        .await;
    // Tamper with the signature: a present-but-invalid hint must NOT authorize
    // a redirect even though the URI is registered.
    let mut hint = app.id_token_hint(&cid, false);
    hint.push_str("tampered");
    let resp = get_end_session(
        &app,
        &format!("id_token_hint={hint}&post_logout_redirect_uri=http%3A%2F%2Frp.example%2Fdone"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn client_id_param_without_hint_redirects() {
    // id_token_hint is RECOMMENDED, not required: client_id param + a
    // registered URI is enough.
    let mut app = build_app().await;
    app.create_admin().await;
    let cid = app
        .create_client_with_logout(&["http://rp.example/done"], None)
        .await;
    let resp = get_end_session(
        &app,
        &format!("client_id={cid}&post_logout_redirect_uri=http%3A%2F%2Frp.example%2Fdone"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn redirect_requested_without_client_is_refused() {
    let app = build_app().await;
    let resp = get_end_session(
        &app,
        "post_logout_redirect_uri=http%3A%2F%2Frp.example%2Fdone",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
