# Server A — yauth as the OpenID Connect IdP

Server A runs the **same** `cargo run --example server --features full`
binary as Server B and as the other yauth examples — see
`crates/yauth/examples/server.rs`. The only thing that differs is the
environment (`config.env`) and the seed data, which is applied
post-boot by `../scripts/seed.sh`.

Plugins enabled (via the `full` feature on yauth):
- `email-password` — interactive login at the IdP UI.
- `oauth2-server` — `/authorize`, `/token`, dynamic `/oauth/register`.
- `oidc` — `/.well-known/openid-configuration`, `/.well-known/jwks.json`,
  `/userinfo` (extends `oauth2-server`).
- `organizations` — adds the `org` claim that Server B mirrors.
- `bearer`, `api-key`, `admin`, `mfa`, `passkey`, `magic-link`,
  `account-lockout`, `webhooks`, `status` — included by `full`.

Backend: **memory**. No database required. Wipe-on-restart is fine for the demo.

## What the seed step produces

After `bash ../scripts/seed.sh` finishes, the IdP holds:

| Object | Value |
|--------|-------|
| User   | `alice@example.com` / `alicepasswd1` |
| User   | `bob@example.com` / `bobpasswd123`   |
| OAuth client | `client_id=<random>` / `client_secret=<random>` |
| Redirect URI | `http://localhost:8081/api/auth/sso/callback` |

The OAuth client's `client_id` + `client_secret` are written to
`../.seed/idp-client.json` so the App-side seed can pick them up.
