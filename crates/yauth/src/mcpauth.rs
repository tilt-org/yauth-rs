//! Root-level OAuth 2.1 discovery surface for putting an [MCP](https://modelcontextprotocol.io)
//! server in front of a yauth authorization server.
//!
//! # Why this module exists
//!
//! yauth's router is meant to be nested under a prefix
//! (`Router::new().nest("/api/auth", auth.router())`), so the `oauth2-server`
//! plugin serves its RFC 8414 metadata at
//! `"/api/auth/.well-known/oauth-authorization-server"`. But the MCP
//! authorization spec — and the OAuth clients that implement it (Claude Code,
//! Claude Desktop) — discover the authorization server from two documents that
//! MUST live at the resource server's **root**:
//!
//! ```text
//! GET /.well-known/oauth-protected-resource     (RFC 9728)
//! GET /.well-known/oauth-authorization-server   (RFC 8414)
//! ```
//!
//! yauth can't serve these from a plugin (a plugin's routes are nested under
//! the mount prefix), and it emits no protected-resource document at all. This
//! module supplies both at the root, plus a middleware that turns the 401 on a
//! guarded MCP endpoint into a *discoverable* one (RFC 9728 `WWW-Authenticate`).
//!
//! This is the Rust counterpart of yauth-go's `mcpauth` package; see
//! `yauth-go/docs/mcp` for the full walkthrough. The SolidJS/Vue `ConsentScreen`
//! and `OAuthConsentPage` components in `@yackey-labs/yauth-ui-*` render the
//! browser consent step.
//!
//! # Usage
//!
//! ```ignore
//! use yauth::mcpauth::{self, McpAuthConfig, Scope};
//!
//! let mcp_cfg = McpAuthConfig {
//!     auth_base_path: "/api/auth".into(),
//!     consent_path: "/authorize".into(), // your SPA route rendering OAuthConsentPage
//!     resource_name: Some("Example MCP".into()),
//!     scopes: vec![
//!         Scope { name: "mcp:read".into(), description: "Read your data".into() },
//!         Scope { name: "mcp:write".into(), description: "Make changes".into() },
//!     ],
//! };
//!
//! // The guarded MCP endpoint: auth_middleware authenticates; discovery_challenge
//! // turns its 401 into a discoverable one.
//! let mcp = Router::new()
//!     .route("/mcp", get(mcp_handler))
//!     .layer(axum::middleware::from_fn_with_state(state.clone(), yauth::middleware::auth_middleware))
//!     .layer(axum::middleware::from_fn(mcpauth::discovery_challenge));
//!
//! let app = Router::new()
//!     .nest("/api/auth", auth.router())
//!     .merge(mcpauth::router(mcp_cfg))   // root discovery
//!     .merge(mcp)
//!     .with_state(state);
//! ```

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::Response,
    routing::get,
};
use serde_json::{Value, json};

use crate::state::YAuthState;

/// One OAuth scope the resource understands, paired with the human-readable
/// description shown on the consent screen. Mirror this catalog in the frontend
/// (`scopeDescriptions`) so users see plain language, not raw scope strings.
pub struct Scope {
    pub name: String,
    pub description: String,
}

/// Configures the root discovery documents.
pub struct McpAuthConfig {
    /// Path prefix the yauth router is nested under, e.g. `"/api/auth"`. It is
    /// advertised as the authorization server in the protected-resource
    /// metadata, so it must match the `nest()` mount exactly.
    pub auth_base_path: String,
    /// Canonical external origin of this resource server, e.g.
    /// `"https://mcp.example.com"` (scheme + host, no trailing slash). When set,
    /// the discovery documents are built from it instead of the request `Host`
    /// header — immune to Host-header spoofing / response cache-poisoning, and
    /// kept consistent with the oauth2-server `issuer`. Leave `None` to fall
    /// back to the request host (local dev). Set it in production.
    pub public_url: Option<String>,
    /// In-app route that renders the consent UI (e.g. `"/authorize"`). The
    /// patched authorization-server metadata points `authorization_endpoint`
    /// here so a browser lands on the consent page instead of yauth's JSON
    /// authorize endpoint. If empty, the endpoint is left unchanged.
    pub consent_path: String,
    /// Optional `resource_name` (RFC 9728 §2) shown in some client consent UIs.
    pub resource_name: Option<String>,
    /// The app's scope catalog. When non-empty, the names are advertised in
    /// both discovery documents' `scopes_supported`, overriding yauth's
    /// generic default; the descriptions feed the consent UI.
    pub scopes: Vec<Scope>,
}

/// Returns a `Router` carrying the root-level discovery endpoints:
///
/// ```text
/// GET /.well-known/oauth-protected-resource     (RFC 9728)
/// GET /.well-known/oauth-authorization-server   (RFC 8414, patched)
/// ```
///
/// `merge` this into your app router at the root. Both endpoints are public —
/// no credential required — as the discovery spec mandates.
pub fn router(cfg: McpAuthConfig) -> Router<YAuthState> {
    let cfg = Arc::new(cfg);
    let prm_cfg = cfg.clone();
    let as_cfg = cfg.clone();
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(move |headers: HeaderMap| {
                let cfg = prm_cfg.clone();
                async move { protected_resource(&headers, &cfg) }
            }),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(move |state: State<YAuthState>, headers: HeaderMap| {
                let cfg = as_cfg.clone();
                async move { authorization_server(state, &headers, &cfg) }
            }),
        )
}

/// `discovery_challenge` is a middleware for the guarded MCP endpoint: when the
/// inner stack (yauth's `auth_middleware`) answers 401, it appends
/// `WWW-Authenticate: Bearer resource_metadata="…"` so the client auto-discovers
/// the authorization server (RFC 9728 §5.1). yauth already answers 401s as JSON,
/// so only the header is added. Layer it *outside* `auth_middleware`.
pub async fn discovery_challenge(req: Request, next: Next) -> Response {
    let origin = external_origin(req.headers());
    let mut resp = next.run(req).await;
    if resp.status() == StatusCode::UNAUTHORIZED {
        let rm = format!("{origin}/.well-known/oauth-protected-resource");
        if let Ok(val) = format!("Bearer resource_metadata=\"{rm}\"").parse() {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, val);
        }
    }
    resp
}

fn protected_resource(headers: &HeaderMap, cfg: &McpAuthConfig) -> Json<Value> {
    let origin = origin_for(cfg, headers);
    let base = cfg.auth_base_path.trim_end_matches('/');
    let mut doc = json!({
        "resource": origin,
        "authorization_servers": [format!("{origin}{base}")],
        "bearer_methods_supported": ["header"],
    });
    let names = scope_names(cfg);
    if !names.is_empty() {
        doc["scopes_supported"] = json!(names);
    }
    if let Some(name) = &cfg.resource_name {
        doc["resource_name"] = json!(name);
    }
    Json(doc)
}

fn authorization_server(
    State(state): State<YAuthState>,
    headers: &HeaderMap,
    cfg: &McpAuthConfig,
) -> Json<Value> {
    let meta = crate::plugins::oauth2_server::build_as_metadata(&state);
    let mut doc = serde_json::to_value(&meta).unwrap_or_else(|_| json!({}));
    if !cfg.consent_path.is_empty() {
        let authz = format!(
            "{}/{}",
            origin_for(cfg, headers),
            cfg.consent_path.trim_start_matches('/')
        );
        doc["authorization_endpoint"] = json!(authz);
    }
    let names = scope_names(cfg);
    if !names.is_empty() {
        doc["scopes_supported"] = json!(names);
    }
    Json(doc)
}

/// The canonical origin for the discovery documents: the configured
/// `public_url` when set (spoofing-immune), otherwise the request Host.
fn origin_for(cfg: &McpAuthConfig, headers: &HeaderMap) -> String {
    match &cfg.public_url {
        Some(u) if !u.is_empty() => u.trim_end_matches('/').to_string(),
        _ => external_origin(headers),
    }
}

fn scope_names(cfg: &McpAuthConfig) -> Vec<String> {
    cfg.scopes.iter().map(|s| s.name.clone()).collect()
}

/// Reconstructs the scheme://host the client reached, honoring
/// `X-Forwarded-Proto` so URLs are correct behind a TLS-terminating proxy.
/// Without that header, loopback hosts default to http and everything else to
/// https — matching how these servers are actually deployed and tested.
fn external_origin(headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if host.starts_with("localhost") || host.starts_with("127.") {
                "http".into()
            } else {
                "https".into()
            }
        });
    format!("{scheme}://{host}")
}
