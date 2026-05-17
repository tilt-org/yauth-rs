# SSO OIDC client (issue #93)

yauth can act as an **OIDC Relying Party** against an external IdP (Okta, Entra ID, Auth0, Keycloak, Google, generic OIDC). One [`SsoConnection`](../../crates/yauth-entity/src/sso_connection.rs) row attaches one IdP to one organization.

> **Status**: Phase A + Phase B landed. Live `/sso/login` + `/sso/callback`, JWKS cache with rate-limited refresh, id_token validation (RS256/384/512), JIT provisioning with group→role mapping, AEAD (ChaCha20-Poly1305) at-rest encryption for `client_secret`, and the full IdP-in-the-loop pentest suite are all in place.

## Quick reference

### Admin (per-org) endpoints

| Method | Path                                              | Effect                                        |
|--------|---------------------------------------------------|-----------------------------------------------|
| `POST` | `/api/auth/organizations/:id/sso/connections`     | Create a `draft` connection                   |
| `GET`  | `/api/auth/organizations/:id/sso/connections`     | List connections (members only)               |
| `PATCH`| `/api/auth/organizations/:id/sso/connections/:cid`| Update (rename, change status, replace config)|
| `DELETE`| `/api/auth/organizations/:id/sso/connections/:cid`| Hard delete (use `status=disabled` to retain)|
| `POST` | `/api/auth/organizations/:id/sso/connections/:cid/test` | Structural round-trip test           |

### User endpoints

| Method | Path                                       | Effect                                          |
|--------|--------------------------------------------|-------------------------------------------------|
| `GET`  | `/api/auth/sso/login?org=<slug>`           | 303 redirect to IdP authorize URL               |
| `GET`  | `/api/auth/sso/login?domain=<acme.com>`    | HRD by verified domain → org → connection       |
| `GET`  | `/api/auth/sso/callback?code=&state=`      | IdP returns here; mints a yauth session cookie  |

`/sso/login` also accepts `redirect_to=/path` to land the user on a specific in-app page after sign-in. Only `/`-prefixed paths are accepted (no `//evil.example` or absolute URLs).

## Security model

The implementation follows OIDC Core §3.1 and RFC 7636 PKCE:

- **PKCE required**. Every authorize request carries an `S256` `code_challenge`. The verifier is persisted alongside the state row and replayed at token-exchange time.
- **State + nonce**. Both are short-lived (10 minutes), one-shot. The id_token's `nonce` claim MUST match the state row's `nonce`. The state row is deleted on lookup (`find_and_delete`) so a second use returns 400.
- **Issuer pinning**. The state row captures the IdP's `issuer` at authorize-time and the callback validates the id_token's `iss` against it. Defeats cross-IdP token replay.
- **Audience check**. `aud` must contain the configured `client_id`.
- **Signature**. RS256 / RS384 / RS512 only — `none` and `HS*` are rejected. Public key resolved via JWKS cache keyed by `kid`.
- **JWKS cache**. Per-issuer, TTL 15 m default (1 h ceiling). On `kid`-miss the cache refreshes — but at most once per minute per issuer, so a stream of bad tokens can't DDoS the IdP's JWKS endpoint.
- **`client_secret` encrypted at rest**. Via [`ChaCha20Poly1305Cipher`](../../crates/yauth/src/auth/oidc_client.rs). Operators set a 32-byte hex key in `YAUTH_SSO_AEAD_KEY`; without it the build falls back to `PassthroughCipher` (dev only — `cargo run` won't crash but secrets aren't encrypted at rest).
- **Email-claim rotation MUST NOT silently merge accounts**. The callback looks up `(provider, external_id)` first. If it matches a user whose email differs from the new claim → 409. If no match exists and JIT is on but the IdP's email matches an existing yauth user with no link to this IdP → 409. Re-linking is an explicit user-driven action.
- **JIT disabled = no auto-create**. Unknown user + JIT off → 403 with a clear "ask your admin" message.

## Configuration

### Deployment secret

Set a 32-byte hex-encoded AEAD key:

```sh
export YAUTH_SSO_AEAD_KEY=$(openssl rand -hex 32)
```

Persist this in your secret manager (Vault, AWS Secrets Manager, GCP Secret Manager). Rotating requires:

1. Deploy a new build that holds both the old + the new key as a `KeyRotatingCipher`.
2. Backfill every `SsoConnection.config.client_secret` by decrypt-old + encrypt-new on each row (one-off script via the admin API or direct DB job).
3. Deploy the next build that drops the old key.

The cipher's marker is `yauth-aead-v1:` so a future v2 stays format-stable.

### Per-IdP setup

Per-IdP integration guides live in this directory:

| IdP            | Guide                              |
|----------------|------------------------------------|
| Okta           | [okta.md](./okta.md)               |
| Entra ID       | [entra.md](./entra.md)             |
| Auth0          | [auth0.md](./auth0.md)             |
| Keycloak       | [keycloak.md](./keycloak.md)       |
| Google Workspace | [google.md](./google.md)         |

The redirect URI to register on the IdP side is always `<your-base-url>/api/auth/sso/callback`.

## Test coverage

| Test                                                                                  | What it proves                                                            |
|---------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `full_round_trip_jit_provisions_user_and_membership`                                  | End-to-end OIDC login + group→role mapping picks the most-privileged role |
| `returning_user_logs_in_without_creating_duplicate`                                   | `(provider, external_id)` lookup wins over JIT                            |
| `pentest_state_replay_rejects_second_use`                                             | State row is consumed on first callback                                   |
| `pentest_nonce_mismatch_rejects`                                                      | id_token with wrong `nonce` → 400                                         |
| `pentest_audience_mismatch_rejects`                                                   | `aud` not containing `client_id` → 400                                    |
| `pentest_expired_id_token_rejected`                                                   | `exp` past now-leeway → 400                                               |
| `pentest_jit_disabled_rejects_unknown_user`                                           | JIT off + unknown user → 403, no implicit account                         |
| `pentest_email_change_blocks_silent_merge`                                            | Same `external_id` + different email → 409                                |
| `pentest_pre_existing_email_blocks_jit`                                               | yauth user owns email but no IdP link → 409 (no silent attach)            |
| `pentest_jwks_rollover_new_token_validates_old_invalid_after_grace`                   | IdP rotates `kid` → cache re-fetches on miss, new token validates         |

Run locally:

```sh
cargo test -p yauth \
  --features full,organizations,memory-backend,asymmetric-jwt \
  --test sso_oidc_phase_b
```

The fixture IdP is an in-process axum sub-app bound to `127.0.0.1:0`; tests never touch the network.
