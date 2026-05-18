# Cross-IdP Federation Example

A runnable demo where **one yauth deployment acts as an OpenID Connect Identity
Provider (IdP)** and **a second yauth deployment uses the `sso-oidc` plugin to
federate against it**. The same Rust binary (`cargo run --example server
--features full`) powers both sides — the only thing that changes is the
environment, the seed data, and the UI bundled in front of it.

This is the example that backs the standing user goal of
["one yauth as the IdP and another as the app auth"][issue-93].

[issue-93]: https://github.com/yackey-labs/yauth/issues/93

## Architecture

```
                            ┌───────────────────────────────┐
                            │ Browser                       │
                            │  http://localhost:5174        │
                            │  (App UI – SolidJS)           │
                            └──────────────┬────────────────┘
                                           │ 1. Click "Sign in via Server A IdP"
                                           ▼
                            ┌───────────────────────────────┐
                            │ Server B  (App)               │
                            │  http://localhost:8081        │
                            │  yauth + sso-oidc plugin      │
                            │  (memory backend)             │
                            └──────────────┬────────────────┘
                                           │ 2. 302 → IdP /authorize?...
                                           ▼
                            ┌───────────────────────────────┐
                            │ Browser                       │
                            │  http://localhost:5173        │
                            │  (IdP UI – Vue)               │
                            └──────────────┬────────────────┘
                                           │ 3. alice signs in + consents
                                           ▼
                            ┌───────────────────────────────┐
                            │ Server A  (IdP)               │
                            │  http://localhost:8080        │
                            │  yauth + oauth2-server +      │
                            │  oidc plugins                 │
                            │  (memory backend)             │
                            └──────────────┬────────────────┘
                                           │ 4. 302 → http://localhost:8081/sso/callback?code=...
                                           ▼
                            ┌───────────────────────────────┐
                            │ Server B  (App)               │
                            │  POST  http://idp:8080/token  │ ◀── 5. exchange code
                            │  GET   http://idp:8080/userinfo│ ◀── 6. fetch claims
                            │  JIT-provisions user          │      7. JIT
                            │  issues bearer JWT            │      8. JWT
                            └──────────────┬────────────────┘
                                           │ 9. 302 → App UI dashboard
                                           ▼
                            ┌───────────────────────────────┐
                            │ App UI – logged-in dashboard  │
                            │ shows alice@example.com + JWT │
                            └───────────────────────────────┘
```

## What's in this folder

| Path                       | Purpose                                                   |
|---------------------------|-----------------------------------------------------------|
| `docker-compose.yml`       | Spins up IdP (8080), App (8081), IdP-UI (5173), App-UI (5174) |
| `idp/`                     | Server A startup env + seed script (creates alice + oauth client) |
| `app/`                     | Server B startup env + seed script (creates org + SSO connection) |
| `ui-idp/`                  | Vue UI for the IdP — login + consent pages                |
| `ui-app/`                  | SolidJS UI for the App — `SsoLoginButton` + dashboard     |
| `scripts/seed.sh`          | Idempotent orchestrator that seeds both servers           |
| `tests/end_to_end.sh`      | Headless, curl-based smoke test of the full federation    |
| `tests/playwright.config.ts` + `tests/sso.spec.ts` | Browser-driven e2e test            |

Both servers use the **memory backend** so no Postgres is required for this
demo — see "Known gaps" at the bottom for the production-hardening checklist.

## Quick start

Prerequisites: Docker, Docker Compose, [Bun] (for the UIs).

[Bun]: https://bun.sh

```bash
cd examples/cross-idp

# 1. Boot the two yauth servers (memory backend, ~5s)
docker compose up -d idp app

# 2. Seed users + oauth client + SSO connection
bash scripts/seed.sh

# 3. Boot the UIs
docker compose up -d idp-ui app-ui

# 4. Open the App UI and click "Sign in via Server A IdP"
xdg-open http://localhost:5174   # or open http://localhost:5174
```

After step 4 you should land back on `http://localhost:5174/dashboard` with
`alice@example.com` shown and a JWT decoded in the page body.

### Programmatic test (no browser)

```bash
bash tests/end_to_end.sh
```

This script:
1. Hits `GET http://localhost:8081/api/auth/sso/login?org=<slug>` and follows
   the redirect to the IdP's `/authorize` endpoint.
2. Logs alice in on the IdP via `POST /api/auth/login`.
3. Replays the `/authorize` request with the session cookie and captures
   the auth-code redirect back to the App.
4. Asserts the App's `/sso/callback` issues a session cookie + JWT.
5. Decodes the JWT and asserts `sub`, `email`, and `org` claims.

### Browser-driven test

```bash
cd ui-app && bun install && bunx playwright install chromium
bunx playwright test --config=../tests/playwright.config.ts
```

## How it works under the hood

### Server A — the IdP

The IdP enables three yauth plugins that together form a compliant OIDC
provider:

- `email-password` — alice/bob register with passwords.
- `oauth2-server` — exposes `/authorize`, `/token`, and dynamic
  `/oauth/register` (so the seed script can register Server B as a client).
- `oidc` — extends `oauth2-server` with `/.well-known/openid-configuration`,
  `/.well-known/jwks.json`, and `/userinfo`. (`oidc` automatically pulls
  `oauth2-server` + `bearer`.)
- `organizations` — included so the issued ID-token carries an `org` claim
  that Server B will mirror when it JIT-provisions the user.

Seed data created by `scripts/seed.sh`:
- One organization (`Acme Inc.`, slug `acme`).
- One user `alice@example.com` (password `alicepasswd1`).
- One OAuth client registered for Server B, with
  `redirect_uri = http://localhost:8081/api/auth/sso/callback`.

### Server B — the App

The App enables:

- `bearer` — so federated users walk away with a JWT.
- `organizations` — required to host SSO connections (the `sso-oidc` plugin
  lives behind the `organizations` feature flag — see
  `crates/yauth/Cargo.toml`).
- `email-password` — kept on so an admin can bootstrap the SSO connection.
- `api-key` — used by the seed script to make admin calls non-interactively.

Seed data:
- One organization (`Acme App`, slug `acme`).
- One SSO connection of kind `oidc_client` with the IdP's
  `discovery_url = http://idp:8080/.well-known/openid-configuration`, the
  client_id/secret from step "IdP" above, and claim mappings
  `sub → external_id`, `email → email`, `name → display_name`.

The federation login URL surfaced by the SolidJS `<SsoLoginButton orgSlug="acme" />`
component is:

```
http://localhost:8081/api/auth/sso/login?org=acme
```

That route is exposed by `sso_oidc::public_routes()` in
`crates/yauth/src/plugins/sso_oidc.rs`. It looks up the connection on the
target org, redirects the browser to the IdP's `/authorize` URL with PKCE,
and persists short-lived state in `sso_login_states` (memory-backed here).

## Production hardening notes

This is a **dev-mode** example. Before you put anything like this in
production:

1. **HTTPS everywhere.** The compose file uses `http://` for both sides.
   In production the IdP issuer URL **must** be `https://`, and the
   `secure_cookies` flag in `YAuthConfig` is on by default whenever
   `BASE_URL` isn't `http://localhost`.
2. **Asymmetric ID tokens.** This demo signs ID tokens with HS256. In
   production turn on the `asymmetric-jwt` feature so the IdP signs with
   an RSA or EC key — the JWKS endpoint then publishes the public half
   and clients verify locally without a shared secret.
3. **JWKS rotation.** Add a rotation policy that flips the active `kid`
   periodically and keeps the previous public key in the JWKS during the
   rotation window so in-flight tokens still verify.
4. **Audience scoping.** Set `BearerConfig::audience` on Server A to the
   intended audience (e.g. `https://app.example.com`) and have Server B
   verify it in `oidc_client::validate_id_token`.
5. **PKCE always-on.** The `sso-oidc` plugin already generates and
   verifies a PKCE pair on every federation login — leave that in place.
6. **AEAD-protected client secret at rest.** Set `YAUTH_SSO_AEAD_KEY` to a
   32-byte hex-encoded key on the App side. The example leaves it unset
   so the `PassthroughCipher` is used — that is **not** safe for
   production. See `crates/yauth/src/plugins/sso_oidc.rs::cipher_for_state`.
7. **Real database.** Both sides here use the memory backend. Swap in
   `diesel-pg-backend` (Postgres) or `sqlx-pg-backend` and run the
   `yauth-migration` crate to apply the SSO tables. (As of writing,
   diesel-pg ships a `StubSsoConnectionRepo` — SSO support against
   Postgres requires the migration set that lands alongside #93.)
8. **Disable dynamic client registration on the IdP** after seeding.
   The example flips `allow_dynamic_registration: true` so the seed
   script can call `POST /api/auth/oauth/register` without an admin
   credential. In production, register clients manually via the admin
   API and set `allow_dynamic_registration: false`.

## Known gaps in this example

- **Memory backend only.** The diesel-pg backend's SSO repo is a stub on
  this branch (`StubSsoConnectionRepo`). The example uses the memory
  backend so the federation flow actually works end-to-end. The
  README's hardening section documents the swap.
- **No HTTPS, no real domain.** Everything is `http://localhost:*` or
  `http://idp:8080` on the docker network. Sufficient for a demo, not
  for production.
- **`PassthroughCipher` for the at-rest client secret.** Set
  `YAUTH_SSO_AEAD_KEY` to enable the real ChaCha20-Poly1305 cipher (see
  hardening note 6).
- **The IdP UI's "consent" screen is a stub.** OAuth2 server in yauth
  currently auto-approves once the user is logged in; the consent page
  in `ui-idp` is a wireframe placeholder so the architecture diagram
  matches the typical OIDC flow. Wiring an explicit consent endpoint is
  tracked separately.
