//! Tests for the `mcpauth` root-level OAuth discovery helper: the
//! protected-resource document (RFC 9728), the patched authorization-server
//! metadata (RFC 8414), and the discoverable 401 on a guarded MCP endpoint.
#![cfg(all(feature = "oauth2-server", feature = "memory-backend"))]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    middleware::{from_fn, from_fn_with_state},
    routing::get,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use yauth::backends::memory::InMemoryBackend;
use yauth::mcpauth::{self, McpAuthConfig, Scope};
use yauth::middleware::auth_middleware;
use yauth::prelude::*;

async fn app() -> Router {
    let backend = InMemoryBackend::new();
    let auth = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "https://mcp.test".into(),
            session_cookie_name: "yauth_session".into(),
            allow_signups: true,
            ..Default::default()
        },
    )
    .with_email_password(EmailPasswordConfig {
        min_password_length: 8,
        require_email_verification: false,
        hibp_check: false,
        ..Default::default()
    })
    .with_bearer(BearerConfig {
        jwt_secret: "test-secret-mcpauth-please-change-32b".into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        #[cfg(feature = "asymmetric-jwt")]
        signing_algorithm: Default::default(),
        #[cfg(feature = "asymmetric-jwt")]
        signing_key_pem: None,
        #[cfg(feature = "asymmetric-jwt")]
        kid: None,
    })
    .with_oauth2_server(OAuth2ServerConfig {
        issuer: "https://mcp.test/api/auth".into(),
        allow_dynamic_registration: true,
        scopes_supported: vec!["openid".into()],
        ..Default::default()
    })
    .build()
    .await
    .expect("build YAuth");

    let state = auth.state().clone();

    let mcp = Router::new()
        .route("/mcp", get(|| async { "ok" }))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .layer(from_fn(mcpauth::discovery_challenge));

    let cfg = McpAuthConfig {
        auth_base_path: "/api/auth".into(),
        public_url: None,
        consent_path: "/authorize".into(),
        resource_name: Some("Test MCP".into()),
        scopes: vec![
            Scope {
                name: "query:read".into(),
                description: "Read".into(),
            },
            Scope {
                name: "alerts:write".into(),
                description: "Write".into(),
            },
        ],
    };

    Router::new()
        .nest("/api/auth", auth.router())
        .merge(mcpauth::router(cfg))
        .merge(mcp)
        .with_state(state)
}

async fn get_json(app: &Router, path: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("host", "mcp.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn protected_resource_metadata() {
    let app = app().await;
    let (status, doc) = get_json(&app, "/.well-known/oauth-protected-resource").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["resource"], "https://mcp.test");
    assert_eq!(doc["authorization_servers"][0], "https://mcp.test/api/auth");
    assert_eq!(doc["resource_name"], "Test MCP");
    // scopes_supported comes from the app catalog, in order.
    assert_eq!(doc["scopes_supported"][0], "query:read");
    assert_eq!(doc["scopes_supported"][1], "alerts:write");
}

#[tokio::test]
async fn authorization_server_metadata_patched() {
    let app = app().await;
    let (status, doc) = get_json(&app, "/.well-known/oauth-authorization-server").await;
    assert_eq!(status, StatusCode::OK);
    // authorization_endpoint points at the SPA consent route, not yauth's
    // JSON /oauth/authorize endpoint.
    assert_eq!(doc["authorization_endpoint"], "https://mcp.test/authorize");
    // token_endpoint is proxied straight from yauth (proves we patched a real doc).
    assert_eq!(
        doc["token_endpoint"],
        "https://mcp.test/api/auth/oauth/token"
    );
    // scopes_supported is overridden with the app catalog (not yauth's "openid").
    assert_eq!(doc["scopes_supported"][0], "query:read");
    assert_eq!(doc["scopes_supported"][1], "alerts:write");
}

async fn post_json(app: &Router, path: &str, body: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("host", "mcp.test")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn dcr_rejects_dangerous_redirect_scheme() {
    let app = app().await;
    for uri in [
        "javascript:alert(1)",
        "data:text/html,x",
        "http://evil.example/cb", // non-loopback plaintext http
    ] {
        let body = format!(r#"{{"redirect_uris":["{uri}"],"token_endpoint_auth_method":"none"}}"#);
        let status = post_json(&app, "/api/auth/oauth/register", &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "uri {uri} should be rejected"
        );
    }
    // Loopback http (what MCP clients use) is allowed.
    let ok = post_json(
        &app,
        "/api/auth/oauth/register",
        r#"{"redirect_uris":["http://127.0.0.1:9999/cb"],"token_endpoint_auth_method":"none"}"#,
    )
    .await;
    assert_eq!(ok, StatusCode::CREATED, "loopback http should be allowed");
}

#[tokio::test]
async fn dcr_rejects_confidential_client_by_default() {
    let app = app().await;
    // Confidential auth methods are rejected (public-only by default).
    for m in ["client_secret_basic", "client_secret_post"] {
        let body = format!(
            r#"{{"redirect_uris":["http://127.0.0.1:9999/cb"],"token_endpoint_auth_method":"{m}"}}"#
        );
        let status = post_json(&app, "/api/auth/oauth/register", &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "method {m} should be rejected"
        );
    }
    // Public client (none) is accepted.
    let ok = post_json(
        &app,
        "/api/auth/oauth/register",
        r#"{"redirect_uris":["http://127.0.0.1:9999/cb"],"token_endpoint_auth_method":"none"}"#,
    )
    .await;
    assert_eq!(ok, StatusCode::CREATED, "public client should be allowed");
}

#[tokio::test]
async fn guarded_mcp_returns_discoverable_401() {
    let app = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/mcp")
                .header("host", "mcp.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp
        .headers()
        .get("www-authenticate")
        .expect("WWW-Authenticate header present")
        .to_str()
        .unwrap();
    assert_eq!(
        www,
        r#"Bearer resource_metadata="https://mcp.test/.well-known/oauth-protected-resource""#
    );
    // yauth answers 401s as JSON, so MCP clients can parse the body.
    let ct = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(ct.contains("application/json"), "content-type = {ct}");
}
