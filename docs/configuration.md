# Configuration Reference

## Session Binding

Detects session hijacking by binding sessions to client IP and/or User-Agent. Configure in `YAuthConfig`:

- `bind_ip: true` — track client IP at session creation
- `bind_user_agent: true` — track User-Agent at session creation
- `BindingAction::Warn` — log mismatch but allow access
- `BindingAction::Invalidate` — destroy session on mismatch (forces re-auth)

**When to use:** Enable `Warn` by default; use `Invalidate` for high-security applications. Note that `bind_ip` may cause issues with mobile users or VPN changes.

## Remember Me

Set `remember_me_ttl` on `YAuthConfig` to enable longer sessions when users opt in. The login request accepts a `remember_me: true` field.

**When to use:** When you want short default sessions (e.g., 24h) with opt-in long sessions (e.g., 30d) via a "keep me logged in" checkbox.

## Password Policy

Configure `PasswordPolicyConfig` on `EmailPasswordConfig`:

- `min_length` — minimum password length in bytes (default: 8)
- `max_length` — maximum password length in bytes (default: 128)
- `character_requirements` — `CharacterRequirements::AnyCharacters` (default: no class requirement), `DigitOrSpecial` (at least one digit or one ASCII special character), or `Complex` (an uppercase letter, a lowercase letter, a digit and a special character). Serialises as `any_characters` / `digit_or_special` / `complex`.
- `disallow_common_passwords` — reject top common passwords
- `password_history_count` — prevent reuse of last N passwords (0 = disabled)

Violations come back as one sentence in the `400` body's `error` field — for example `Password must be at least 8 characters long and include a number or a special character.` — built by `yauth::auth::password_policy::compose_message` from the individual fragments, so a client that mirrors the policy can show the same wording per rule.

**When to use:** When regulatory compliance or security policy requires specific password complexity rules beyond minimum length + HIBP checking.

## MFA (`mfa` feature)

Configure `MfaConfig`:

- `issuer` — name shown in authenticator apps
- `backup_code_count` — codes issued at enrolment and on regeneration (default: 10)
- `secret_cipher` — `Option<Arc<dyn TotpSecretCipher>>`: the host-provided envelope cipher for the TOTP shared secret at rest. Not serialisable (`#[serde(skip)]`); `Debug` prints only whether one is set.

`TotpSecretCipher` (re-exported as `yauth::config::TotpSecretCipher` and via the prelude) has two synchronous halves, `seal(user_id, secret)` and `open(user_id, sealed)`. `seal` must return a versioned, self-describing string; `open` must reject anything `seal` did not produce, including a bare base32 secret; both receive the `user_id` so the ciphertext can be bound to its owner. Keep them cheap — they run on the request path. The trait's rustdoc carries a runnable example implementation.

With `secret_cipher: None` (the default) the plugin **fails closed**: `POST /mfa/totp/setup`, `POST /mfa/totp/confirm` and `POST /mfa/backup-codes/regenerate` answer `503 {"error": "MFA is temporarily unavailable"}`, and `POST /mfa/verify` skips the TOTP factor and accepts only backup codes. The same fall-through applies when the configured cipher cannot open a stored secret (rotated or lost key): the user recovers with a backup code and re-enrols. There is no re-seal path, so treat the key as being as durable as the enrolled population.

Behaviour to keep in mind when tuning rate limits: a TOTP code is single-use at login for 120 seconds; a pending login challenge allows five wrong codes and is then deleted; enrolment and regeneration hash `backup_code_count` codes with Argon2id concurrently, so keep both routes rate-limited; enabling TOTP revokes the user's other sessions. Every rejected verification logs `mfa_verification_failed` (`target: "yauth::mfa"`, fields `user_id`, `reason`) and publishes `AuthEvent::MfaVerificationFailed` (webhook type `mfa.verification_failed`). See [UPGRADING.md](../UPGRADING.md) for the storage cutover and the per-backend status of the two challenge-repository primitives the login path relies on.

**When to use:** Always set `secret_cipher` in any deployment that enables the `mfa` feature; leave it `None` only where enrolment is meant to be refused.

## Email delivery (SMTP)

`YAuthConfig::smtp` (`Option<SmtpConfig>`) turns on verification, magic-link, password-reset, unlock and already-registered mail:

- `host`, `port`, `from`
- `username`, `password` — `Some` for an authenticated STARTTLS relay (for example the AWS SES SMTP endpoint); `None` (default) sends over an unauthenticated plaintext relay such as the docker-compose mailpit.

Sends go through lettre's `AsyncSmtpTransport<Tokio1Executor>`. Two additive builder seams, both effective only when `smtp` is `Some`:

- `YAuthBuilder::with_email_transport(transport)` — inject a transport you built at boot so yauth shares one connection pool with the rest of your application.
- `YAuthBuilder::with_email_templates(Arc<dyn AuthEmailTemplates>)` — brand the five mails. Each trait method receives the action URL and returns the subject and body; the built-in unbranded templates remain the default.

## Account Lockout

Configure `AccountLockoutConfig`:

- `max_failed_attempts` — threshold before lockout (default: 5)
- `lockout_duration` — base lockout time (default: 5 minutes)
- `exponential_backoff` — double duration on each lockout
- `max_lockout_duration` — cap for backoff (default: 24 hours)
- `auto_unlock` — auto-unlock after duration expires

**When to use:** When you need per-account brute-force protection that works across IPs. Rate limiting is per-IP; account lockout is per-account. Use both together for defense in depth.

## Webhooks

Configure `WebhookConfig`:

- `max_retries` — retry failed deliveries (default: 3)
- `retry_delay` — delay between retries (default: 30s)
- `timeout` — HTTP timeout per delivery (default: 10s)
- `max_webhooks` — limit per user (default: 10)

Payloads are signed with HMAC-SHA256 via the `X-Webhook-Signature` header. Admin routes at `/webhooks` manage webhook CRUD.

**When to use:** When external systems (Slack bots, CRMs, analytics) need real-time notifications of auth events without polling.

## OIDC

Configure `OidcConfig`:

- `issuer` — OIDC issuer URL (must match `iss` claim)
- `id_token_ttl` — id_token expiry (default: 1 hour)
- `claims_supported` — advertised claims (default: sub, email, email_verified, name)

**When to use:** When yauth is the identity provider and downstream apps need OIDC-compliant SSO. Automatically enables `bearer` + `oauth2-server`.

## Asymmetric JWT Signing (`asymmetric-jwt` feature)

Publish a verifiable JWKS so resource servers in *other* trust domains can
validate yauth-issued tokens without holding the shared HS256 secret.
Configure via `BearerConfig`:

- `signing_algorithm: SigningAlgorithm` — `Hs256` (default) / `Rs256` / `Es256`
- `signing_key_pem: Option<String>` — PKCS#8 PEM private key (required for RS256/ES256)
- `kid: Option<String>` — optional explicit key ID; defaults to the RFC 7638 thumbprint of the public key

HS256 tokens remain byte-identical to pre-asymmetric output (no `kid`
header emitted) — upgrading is a single config field.

**Fail-fast:** PEMs are parsed at `YAuthBuilder::build()` time. A bad PEM
produces an actionable error before the server starts, not a 500 on the
first token minted.

**Never serialized:** `signing_key_pem` has `#[serde(skip_serializing)]`;
config snapshots do not leak the private key.

**PKCS#1 rejected:** users must convert `-----BEGIN RSA PRIVATE KEY-----`
to `-----BEGIN PRIVATE KEY-----` (PKCS#8). The error message guides them.

**When to use:** when external resource servers validate yauth tokens, or
when you need `private_key_jwt` client authentication (see below).

## Admin Plugin (`admin` feature)

The `admin` plugin gates admin-only routes behind `require_admin`. Default
behavior is *human-only*: a request with a `MachineCaller` extension
(M2M token) gets 403 on admin routes.

Configure `AdminConfig`:

- `allow_machine_callers: bool` (default `false`) — when `true`, a
  `MachineCaller` with scope `admin` satisfies `require_admin`.

```rust
.with_admin()
.with_admin_config(AdminConfig {
    allow_machine_callers: true, // ⚠ opt-in only
})
```

**When to use:** ops automation tightly scoped to a narrow client_id.
Enabling this dramatically expands the blast radius of a compromised
credential — document the decision in your runbook. Every admin call by
a machine caller emits a span event `admin_machine_call_allowed` with
`client.id` for auditability.

## OAuth 2.0 M2M — `client_credentials` + `private_key_jwt`

With `oauth2-server` enabled, yauth:

- Issues `client_credentials` JWTs (RFC 6749 §4.4) signed with the
  configured `signing_algorithm`
- Validates them at `auth_middleware`, populating `Extension<MachineCaller>`
- Enforces scopes via `require_scope` (credential-source-agnostic)
- Checks JTI revocation + client `banned_at` on every request

With `asymmetric-jwt` **also** enabled, yauth accepts `private_key_jwt`
client authentication at the token endpoint (RFC 7523):

- Dynamic client registration accepts `token_endpoint_auth_method=private_key_jwt`
  with a `public_key_pem` (PKCS#8 SPKI PEM)
- The token endpoint accepts `client_assertion_type` +
  `client_assertion` instead of `client_secret`
- Replayed assertions are rejected (JTI in the revocations store for the
  assertion's lifetime)
- Accepted assertion algs are **only** RS256 / ES256 — `none` / HS*
  are rejected upfront to defeat alg-confusion attacks

The discovery doc at `/.well-known/oauth-authorization-server`
advertises `private_key_jwt` + supported signing algs + `jwks_uri` only
when the features are enabled.

See [examples/m2m_auth.rs](../crates/yauth/examples/m2m_auth.rs) for an
end-to-end walkthrough (register → mint → validate via JWKS → admin ban).

## Organizations (multi-tenancy primitive)

Enable with `--features organizations`. **Default OFF** — flipping the flag
on must not change any existing single-tenant behavior. With the flag off,
no org tables are touched, no new routes mount, and `Repositories` does
not expose the org repos.

Wire it up via the builder:

```rust
let yauth = YAuthBuilder::new(backend, config)
    .with_email_password(ep)
    .with_organizations()       // mounts the org routes
    .build()
    .await?;
```

Routes mounted (all under `/api/auth` and require an authenticated session):

| Method | Path | Notes |
|---|---|---|
| `POST` | `/organizations` | Caller becomes **owner** of the new org |
| `GET` | `/organizations` | Lists only orgs the caller is a member of |
| `GET` | `/organizations/{id}` | Member-only |
| `PATCH` | `/organizations/{id}` | Admin/owner-only |
| `DELETE` | `/organizations/{id}` | Admin/owner-only; cascades to memberships + invitations |
| `GET` | `/organizations/{id}/members` | Member-only |
| `POST` | `/organizations/{id}/members/{user_id}/role` | Requires `members:change_role`; cannot demote the last owner |
| `DELETE` | `/organizations/{id}/members/{user_id}` | Requires `members:remove`; cannot remove the last owner |
| `POST` | `/organizations/{id}/transfer-ownership` | Owner-only; promotes target to `owner`, demotes self to `admin` |
| `GET` | `/organizations/{id}/permissions` | Member-only; returns caller\'s role + effective permissions |
| `POST` | `/organizations/{id}/invitations` | Admin/owner-only; returns the plaintext token **once** |
| `POST` | `/invitations/accept` | Caller\'s email must match the invite |

**Backend status:** the in-memory backend ships a complete implementation;
SQL backends are stubbed (any call returns `RepoError::Internal` with a
"not yet implemented for this backend" message). Migration files for every
SQL backend are generated and committed — concrete repository impls land in
follow-up issues.

## Org-scoped RBAC (#88)

The `organizations` feature ships with org-scoped RBAC primitives in
[`yauth::auth::rbac`]:

```rust
use yauth::auth::rbac::{self, roles, Permission, MemberPerm};

// In a route handler:
rbac::require_org_role(&state.repos, &user, org_id, roles::OWNER).await?;
rbac::require_org_permission(
    &state.repos, &user, org_id,
    Permission::Members(MemberPerm::Invite),
).await?;
```

### Built-in roles

| Role | Default permissions |
|---|---|
| `owner` | All members + billing + settings perms; **exactly one per org** |
| `admin` | All members perms; billing view; settings read+write |
| `billing_admin` | Billing view+update+cancel; settings read |
| `member` | Settings read |
| `viewer` | Settings read |

Custom role strings are permitted on `Membership.role`; they receive no
permissions by default and must be wired up by the calling application.

### Owner-protection invariant

Every org has exactly one user with `role = "owner"`. The owner cannot be
demoted or removed without first transferring ownership via
`POST /organizations/{id}/transfer-ownership`. This is enforced:

- In the change-role and remove-member handlers via
  `rbac::guard_role_change` / `rbac::guard_delete`.
- As defense-in-depth inside the in-memory `MembershipRepository` —
  attempts to demote the last owner return
  `RepoError::Conflict(..)` which maps to HTTP 409.

### Relationship to `User.role`

`User.role` (the global yauth deployment role) is **independent** of
`Membership.role` (the per-org role). A user can be a deployment admin
and an org viewer at the same time, or vice versa.

See [docs/plans/organizations/README.md](plans/organizations/README.md) for
the full design + open work.

## Per-org auth policy (#92)

When the `organizations` feature is on, each org gets a 1:1 policy row that
**tightens** the deployment-wide `YAuthConfig`. Defaults are "no
restriction" — orgs opt into stricter posture; nothing changes for orgs
that never set a policy.

### Routes

| Method | Path | Notes |
|---|---|---|
| `GET` | `/organizations/{id}/policy` | Member-only; returns defaults if no row set |
| `PATCH` | `/organizations/{id}/policy` | Admin/owner-only; partial update |

### Fields

| Field | Type | Meaning |
|---|---|---|
| `max_session_duration_secs` | `Option<i64>` | Clamps session lifetime at create time |
| `idle_timeout_secs` | `Option<i64>` | 401 + session-purge after this much inactivity |
| `mfa_required` | `bool` | Force MFA enrollment for all members |
| `mfa_grace_period_days` | `i32` | Grace before MFA-required gates fire (default 14) |
| `ip_allowlist` | `Vec<String>` | Allowed client IPs; empty = no restriction |
| `max_concurrent_sessions` | `Option<i32>` | Per-user session cap; oldest revoked at overflow |
| `allowed_auth_methods` | `Vec<AuthMethod>` | `password`, `passkey`, `oauth`, `sso_saml`, `sso_oidc`, etc. Empty = all |
| `session_binding` | `"none" \| "ip" \| "user_agent" \| "both"` | Refuse session if dimension changes |

### Resolution order

The **effective policy** for a request is the merge of the org policy over
the global `YAuthConfig`:

- **Numeric fields** — the **stricter** value wins. If both global and
  org set a value, the smaller cap is used. The org can only *tighten*.
- **Booleans / enums** — the org's **explicit setting** wins. An org
  with `mfa_required = true` forces MFA even if the global default is
  off.
- **Lists** — empty list = inherit global (no restriction). Non-empty
  list = strict subset (only listed entries permitted).

### Cross-org users

When a user switches active org (`POST /sessions/active-org`), the **next
request** is re-evaluated against the new org's policy — there is no
caching. If the new org is stricter on `idle_timeout_secs`, the request
will 401 sooner; if it's wider, no extension of the existing session is
granted (the session's stored `expires_at` was already clamped at create
time).

### Enforcement points

The policy enforcer (`yauth::auth::policy_enforcer`) implements one
helper per field; they are wired into the auth middleware and the
plugin login routes:

| Policy | Where it fires | Failure mode |
|---|---|---|
| `max_session_duration_secs` | Session create | Clamps `expires_at` |
| `idle_timeout_secs` | Every authenticated request | 401 + session purge |
| `mfa_required` | Login + protected routes | Force MFA enrollment screen |
| `ip_allowlist` | Login + every request | 403 |
| `max_concurrent_sessions` | Session create | Revoke oldest active session |
| `allowed_auth_methods` | Login plugin routes | 405 Method Not Allowed |
| `session_binding` | Token validation | 401 |

### Backend status

The in-memory backend ships a complete implementation. SQL backends are
stubbed (HTTP 501 `feature not implemented on this backend`); per-backend
impls land in follow-up issues. Migration files for
`yauth_organization_policies` are generated and committed.
