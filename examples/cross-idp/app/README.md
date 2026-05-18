# Server B — yauth as the federated App

Same `cargo run --example server --features full` binary as Server A,
different env (`config.env`) and seed data.

Plugins relevant to the federation:
- `organizations` — required by `sso-oidc` (the plugin is feature-gated
  on `organizations` — see `crates/yauth/Cargo.toml`).
- `bearer` — federated users walk away with a JWT.
- `email-password` — bootstrap admin to call the seed endpoints.
- `api-key` — used by `../scripts/seed.sh` to authenticate as the admin
  non-interactively.

Backend: **memory**. The `sso_connections`, `sso_login_states`, and
`external_identities` repos all have working in-memory implementations
(`crates/yauth/src/backends/memory/organization_repo.rs`). The diesel-pg
backend currently ships a `StubSsoConnectionRepo` — see the production
hardening notes in the parent `README.md`.

## What the seed step produces

After `bash ../scripts/seed.sh` finishes, the App holds:

| Object | Value |
|--------|-------|
| Admin user | `admin@example.com` / `adminpasswd1` |
| Organization | name `Acme App` / slug `acme` |
| SSO connection | kind `oidc_client`, status `Active` |
| `discovery_url` | `http://idp:8080/.well-known/openid-configuration` |
| `client_id` / `client_secret` | from the IdP seed step |
| Claim mappings | `sub → external_id`, `email → email`, `name → display_name` |
| Callback | `http://localhost:8081/api/auth/sso/callback` |

The SolidJS App UI then renders `<SsoLoginButton orgSlug="acme" />`,
which links to `/api/auth/sso/login?org=acme` and starts the OIDC dance.
