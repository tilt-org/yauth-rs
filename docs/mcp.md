# Standing up an MCP server on yauth (Rust/Axum)

This wires an [MCP](https://modelcontextprotocol.io) server so an MCP client
(Claude Code, Claude Desktop, …) authenticates against a yauth authorization
server with the OAuth 2.1 + PKCE browser flow. The [`yauth::mcpauth`] module
(behind the `oauth2-server` feature) supplies the root-level discovery surface
yauth can't serve from a plugin, and the SolidJS/Vue `OAuthConsentPage` /
`ConsentScreen` components render the consent step.

> This is the Rust counterpart of [`yauth-go/docs/mcp`](https://github.com/yackey-labs/yauth-go/blob/main/docs/mcp/README.md).
> The footgun analysis there applies verbatim; this page covers the Axum wiring
> and the few places Rust differs.

## The one thing to understand

yauth's router is nested under a prefix:

```rust
Router::new().nest("/api/auth", auth.router())
```

so the `oauth2-server` plugin serves its RFC 8414 metadata at
`/api/auth/.well-known/oauth-authorization-server`. But MCP clients discover the
authorization server from two documents that **must be at the resource-server
root** — and a plugin can't reach the root:

| Document | Path (root) | Who emits it |
|---|---|---|
| Protected Resource Metadata (RFC 9728) | `/.well-known/oauth-protected-resource` | **nobody** — yauth has no such endpoint |
| Authorization Server Metadata (RFC 8414) | `/.well-known/oauth-authorization-server` | yauth, but under the nest prefix |

`yauth::mcpauth` mounts the missing root endpoints, patches
`authorization_endpoint` to your consent UI, and makes the guarded `/mcp` 401
discoverable.

## Wiring

```rust
use axum::{Router, routing::get, middleware::{from_fn, from_fn_with_state}};
use yauth::mcpauth::{self, McpAuthConfig, Scope};
use yauth::middleware::auth_middleware;
use yauth::prelude::*;

let auth = YAuthBuilder::new(backend, YAuthConfig {
        // Rust convention: issuer carries the base path so token_endpoint and
        // the metadata `issuer` resolve to the nested mount. It MUST be the
        // exact public origin clients reach (scheme + host), or strict clients
        // reject the metadata.
        base_url: "https://mcp.example.com".into(),
        ..Default::default()
    })
    .with_email_password(EmailPasswordConfig::default())
    .with_bearer(BearerConfig { /* resolves the access token on /mcp */ ..bearer })
    .with_oauth2_server(OAuth2ServerConfig {
        issuer: "https://mcp.example.com/api/auth".into(),
        allow_dynamic_registration: true,  // opt in — off by default; MCP clients self-register (RFC 7591)
        scopes_supported: vec!["mcp:read".into(), "mcp:write".into()],
        ..Default::default()
    })
    .build().await?;

let state = auth.state().clone();

// Guarded MCP endpoint: auth_middleware authenticates + injects AuthUser;
// discovery_challenge turns its 401 into an RFC 9728-discoverable one.
let mcp = Router::new()
    .route("/mcp", get(mcp_handler))
    .layer(from_fn_with_state(state.clone(), auth_middleware))
    .layer(from_fn(mcpauth::discovery_challenge));

let mcp_cfg = McpAuthConfig {
    auth_base_path: "/api/auth".into(),
    public_url: Some("https://mcp.example.com".into()), // pin discovery URLs (anti-spoof; matches issuer)
    consent_path: "/authorize".into(),     // your SPA route rendering OAuthConsentPage
    resource_name: Some("Example MCP".into()),
    scopes: vec![
        Scope { name: "mcp:read".into(),  description: "Read your data through MCP tools".into() },
        Scope { name: "mcp:write".into(), description: "Make changes through MCP tools".into() },
    ],
};

let app = Router::new()
    .nest("/api/auth", auth.router())   // yauth itself
    .merge(mcpauth::router(mcp_cfg))    // root discovery (PRM + patched AS metadata)
    .merge(mcp)                         // the guarded /mcp endpoint
    .with_state(state);
```

`mcp_handler` recovers the caller via `Extension<AuthUser>` (or
`Option<Extension<AuthUser>>`) — `auth_middleware` injects it on success.

## Per-app scopes

`McpAuthConfig.scopes` is the single source of truth for which scopes the
resource understands and what each means. `mcpauth::router` advertises the names
in both discovery documents' `scopes_supported` (overriding yauth's generic
default), and the descriptions feed the consent UI. Mirror the same catalog in
the frontend's `scopeDescriptions`.

## Consent UI

yauth's `GET /oauth/authorize` returns a JSON consent payload, not a page. Mount
the SPA `OAuthConsentPage` at the same path you set as `consent_path`
(`/authorize`):

```tsx
// SolidJS
import { OAuthConsentPage } from "@yackey-labs/yauth-ui-solidjs";
<Route path="/authorize" component={() => <OAuthConsentPage scopeDescriptions={SCOPES} />} />
```

```ts
// Vue
import { OAuthConsentPage } from "@yackey-labs/yauth-ui-vue";
{ path: "/authorize", component: OAuthConsentPage, props: { scopeDescriptions: SCOPES } }
```

The components handle the two-step flow (GET `/oauth/authorize` → POST
`/oauth2/consent` with `{request_id, csrf_token, approved}`) and normalize the
consent-payload shape across Rust yauth and yauth-go.

## Where Rust differs from yauth-go

These are the same flow with a few behavioral differences worth knowing. DCR is
now **off by default on both** (secure by default — enabling it is the opt-in);
the rest differ only in spelling:

| | Rust yauth | yauth-go |
|---|---|---|
| **DCR enable** | Off by default; one flag: `allow_dynamic_registration: true` | Off by default; `DCREnabled: true` + `DCRRequireInitialAccessToken: &false` for anonymous |
| **`issuer` convention** | Carries the base path (`https://host/api/auth`, `consent_path` aside) | Either `Issuer=host` + `BasePath=/api/auth`, or the Rust spelling |
| **Consent GET payload** | Flat: `client_id`, `client_name`, `scope` (space string) | Nested: `client: {id, name}`, `scopes: []` |
| **Register auto-login** | `POST /register` does **not** set a session — call `/login` after | `/register` sets the session cookie |

The `OAuthConsentPage` component absorbs the payload-shape difference, so the
same frontend works against both.

## Verify it

```bash
curl -s https://mcp.example.com/.well-known/oauth-protected-resource | jq
curl -s https://mcp.example.com/.well-known/oauth-authorization-server | jq .authorization_endpoint   # -> ".../authorize"
curl -i https://mcp.example.com/mcp   # 401 + WWW-Authenticate: Bearer resource_metadata="…"
claude mcp add --transport http example https://mcp.example.com/mcp
```

## Security

The OWASP review of this surface (shared by both stacks) lives in the yauth-go
repo: [docs/mcp/SECURITY.md](https://github.com/yackey-labs/yauth-go/blob/main/docs/mcp/SECURITY.md).
Highlights that affect Rust apps: DCR now rejects dangerous `redirect_uri`
schemes (`javascript:`/`data:`/non-loopback `http`); set `public_url` to pin the
discovery documents; and rate-limit `/oauth/register`. The `ConsentScreen` /
`OAuthConsentPage` components block non-`http(s)` redirect targets as defense in
depth.

## Reference

- [`yauth::mcpauth`](../crates/yauth/src/mcpauth.rs) — `router`, `discovery_challenge`, `McpAuthConfig`, `Scope`
- [MCP security review (yauth-go)](https://github.com/yackey-labs/yauth-go/blob/main/docs/mcp/SECURITY.md)
- [yauth-go MCP guide](https://github.com/yackey-labs/yauth-go/blob/main/docs/mcp/README.md) — the full footgun walkthrough
- RFC 9728 (Protected Resource Metadata), RFC 8414 (AS Metadata), RFC 7591 (Dynamic Client Registration)
