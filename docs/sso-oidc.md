# SSO OIDC client (issue #93)

yauth can act as an **OIDC Relying Party** against an external IdP (Okta, Entra ID, Auth0, Keycloak, Google, generic OIDC). One [`SsoConnection`](../crates/yauth-entity/src/sso_connection.rs) row attaches one IdP to one organization.

> **Status**: Phase A landed — admin CRUD for connections + the OIDC primitives (PKCE, state, claim extraction, encrypt-at-rest cipher). The user-facing `/sso/login` + `/sso/callback` flow lands in Phase B (live JWKS, token exchange, id_token validation, JIT provisioning).

## Quick reference

### Admin (per-org) endpoints

| Method | Path                                              | Effect                                        |
|--------|---------------------------------------------------|-----------------------------------------------|
| `POST` | `/api/auth/organizations/:id/sso/connections`     | Create a `draft` connection                   |
| `GET`  | `/api/auth/organizations/:id/sso/connections`     | List connections (members only)               |
| `PATCH`| `/api/auth/organizations/:id/sso/connections/:cid`| Update (rename, change status, replace config)|
| `DELETE`| `/api/auth/organizations/:id/sso/connections/:cid`| Hard delete (use `status=disabled` to retain)|
| `POST` | `/api/auth/organizations/:id/sso/connections/:cid/test` | Structural round-trip test           |

### User endpoints (Phase B)

| Method | Path                                  | Effect                                          |
|--------|---------------------------------------|-------------------------------------------------|
| `GET`  | `/api/auth/sso/login?org=<slug>`      | Redirect to IdP authorize URL                   |
| `GET`  | `/api/auth/sso/login?domain=<acme.com>`| HRD by verified domain → org → connection       |
| `GET`  | `/api/auth/sso/callback`              | IdP returns here with `code` + `state`          |

## Security model

The implementation follows OIDC Core §3.1 and RFC 7636 PKCE:

- **PKCE required**. Every authorize request carries an `S256` `code_challenge`. The verifier is persisted alongside the state blob and replayed at token-exchange time.
- **State + nonce**. Both are short-lived (10 minutes), one-shot. The id_token's `nonce` claim MUST match the state blob's `nonce`.
- **Issuer pinning**. The state blob captures the connection's `issuer` and the callback validates the id_token's `iss` against it. Defeats cross-IdP token replay.
- **Audience check**. `aud` must include the configured `client_id` (Phase B).
- **client_secret encrypted at rest**. Stored via [`SecretCipher`](../crates/yauth/src/auth/oidc_client.rs). Default is a base64-marker passthrough; apps with real KMS plug their own implementation in via the same trait.
- **Email-claim rotation MUST NOT silently merge accounts**. The callback looks up `(provider, external_id)` first. JIT provisioning fires only when *no* `ExternalIdentity` row matches and the connection's `jit_provisioning_enabled` flag is on.

## Per-IdP integration notes

These are stubs. Each will grow into a copy-pastable runbook as Phase B lands and the team integrates a real IdP per row.

### Okta

```
discovery_url: https://<your-domain>.okta.com/.well-known/openid-configuration
scopes:        ["openid", "email", "profile", "groups"]
claim_mappings.external_id: "sub"
claim_mappings.email:       "email"
claim_mappings.groups:      "groups"
```

The `groups` claim requires the **Groups** scope to be added on the Okta app authorization-server config; without it the claim is absent and yauth treats the user as un-grouped (no `group_to_role` matches).

### Entra ID (Azure AD)

```
discovery_url: https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration
scopes:        ["openid", "email", "profile"]
claim_mappings.external_id: "oid"   # NOT `sub` — Entra rotates `sub` per app
```

Use `oid` for `external_id` — `sub` is a per-app-pairwise identifier and changes when the app registration is rebuilt, which would break every existing link. For groups, request the `User.Read.All` Graph permission and add the `groups` optional claim on the app registration.

### Auth0

```
discovery_url: https://<tenant>.auth0.com/.well-known/openid-configuration
scopes:        ["openid", "email", "profile"]
claim_mappings.external_id: "sub"
```

Auth0 prefixes federated identities (`google-oauth2|...`, `samlp|...`) on `sub`. The prefix is stable per-IdP-per-user so it's safe to use as `external_id`.

### Keycloak

```
discovery_url: https://<host>/realms/<realm>/.well-known/openid-configuration
scopes:        ["openid", "email", "profile", "groups"]
claim_mappings.external_id: "sub"
claim_mappings.groups:      "groups"
```

Add a `groups` mapper on the client (Mappers → Group Membership) to populate the `groups` claim — Keycloak does NOT send groups by default.

### Google Workspace

```
discovery_url: https://accounts.google.com/.well-known/openid-configuration
scopes:        ["openid", "email", "profile"]
claim_mappings.external_id: "sub"
```

Google does not expose Workspace groups in OIDC id_tokens. Use the Admin SDK + a custom IDP relay to enrich, OR map roles per-user via the admin UI rather than per-group.

## Deferred to Phase B

- Live discovery doc fetch + cache (RFC 5861, hard ceiling 1 h, refresh on `kid` miss).
- JWKS fetch + cache + signature verification (RS256/ES256).
- id_token claim validation (`iss`, `aud`, `nonce`, `exp`, `iat`, `nbf`).
- Token exchange + JIT provisioning.
- `/sso/login` + `/sso/callback` handlers.
- Fixture-IdP end-to-end test harness.
- Pentest: state replay, nonce replay, audience mismatch, JWKS rollover, claim injection (group→role escalation).
