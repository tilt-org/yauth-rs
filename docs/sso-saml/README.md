# SSO SAML 2.0 Service Provider (issue #94)

yauth can act as a **SAML 2.0 Service Provider** against an external IdP (Okta, Entra ID, OneLogin, ADFS, Ping, Auth0). One [`SsoConnection`](../../crates/yauth-entity/src/sso_connection.rs) row attaches one IdP to one organization. SAML support is a stacked PR on top of the OIDC client work (#93) and reuses the same `SsoConnection` schema, `ExternalIdentity` repo, AEAD secret cipher, and JIT-provisioning helpers.

> **Status**: backend MVP shipped — SP-initiated + IdP-initiated (opt-in) flows, signed-assertion verification with the 11-case pentest suite from yauth-go PR #26, JIT provisioning with group → role mapping, AEAD encryption for `sp_private_key`. UI parity (`packages/ui-vue/`, `packages/ui-solidjs/`) shipped via `SamlConnectionForm`, `SamlLoginButton`, and the SAML branch of `SsoConnectionList` (which adds a one-click SP metadata download link).

## Why not `samael`?

The issue body originally recommended the `samael` crate. Two adversarial reviews concluded that 0.0.20 is **not** safe to ship on:

- It **fails to compile** on `aarch64-unknown-linux-gnu` (upstream PR #85 merged but unreleased — our homelab cluster has two ARM control-plane nodes).
- It carries an **open signature-verification bug** with xmlsec 1.2.3x ([samael #82](https://github.com/njaremko/samael/issues/82)) in the exact code path we'd use for assertion-inside-response — that's the signature-wrapping attack class this PR has to defend against.
- It drags in libxml2 + xmlsec1 C dependencies (heavy build infra, bloats the container, libxml CVEs become our problem).

The chosen alternative is a narrow Rust-pure SP-side implementation behind a [`SamlProvider`](../../crates/yauth/src/auth/saml_sp.rs#L67-L88) trait facade. Swap-in is a single-trait-impl change once samael ships a fix (or a different crate becomes viable).

## Quick reference

### Admin (per-org) endpoints — reused from #93

The OIDC admin CRUD now accepts `kind: "saml_sp"` and a `saml: { … }` payload. The route shape is unchanged:

| Method | Path                                                              | Effect                                        |
|--------|-------------------------------------------------------------------|-----------------------------------------------|
| `POST` | `/api/auth/organizations/:id/sso/connections`                     | Create a `draft` SAML connection              |
| `GET`  | `/api/auth/organizations/:id/sso/connections`                     | List connections (members only)               |
| `PATCH`| `/api/auth/organizations/:id/sso/connections/:cid`                | Update (rename, change status, replace config)|
| `DELETE`| `/api/auth/organizations/:id/sso/connections/:cid`               | Hard delete (use `status=disabled` to retain) |
| `POST` | `/api/auth/organizations/:id/sso/connections/:cid/test`           | Structural round-trip test                    |

Example create request body:

```json
{
  "name": "Acme Okta",
  "kind": "saml_sp",
  "saml": {
    "idp_entity_id": "http://www.okta.com/exk1abcd",
    "idp_sso_url": "https://acme.okta.com/app/.../sso/saml",
    "idp_x509_cert": "-----BEGIN CERTIFICATE-----\nMII…\n-----END CERTIFICATE-----",
    "assertion_signed_required": true,
    "response_signed_required": true,
    "idp_initiated_sso_allowed": false,
    "attribute_mappings": {
      "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "external_id": "NameID",
      "groups": "http://schemas.xmlsoap.org/claims/Group",
      "group_to_role": { "yauth-admins": "admin" }
    }
  },
  "jit_provisioning_enabled": true,
  "default_role_on_jit": "member"
}
```

The response masks `idp_x509_cert` and `sp_private_key` to `"********"` — admins re-fetch the cert from the IdP if they need to re-import.

### User endpoints

| Method | Path                                                | Effect                                            |
|--------|-----------------------------------------------------|---------------------------------------------------|
| `GET`  | `/api/auth/sso/saml/login?org=<slug>`               | 303 redirect to IdP SSO URL with `SAMLRequest`    |
| `GET`  | `/api/auth/sso/saml/login?domain=<acme.com>`        | HRD by verified domain → org → SAML connection    |
| `POST` | `/api/auth/sso/saml/acs`                            | Assertion Consumer Service                        |
| `GET`  | `/api/auth/sso/saml/metadata/{cid}`                 | SP metadata XML for the IdP admin to import       |
| `GET`  | `/api/auth/sso/saml/logout?org=<slug>`              | SP-initiated SLO (best-effort)                    |
| `POST` | `/api/auth/sso/saml/slo`                            | IdP-initiated SLO receiver (best-effort)          |

`RelayState` shapes accepted at `/sso/saml/acs`:

1. **Opaque random token** — produced by `/sso/saml/login`. Treated as SP-initiated; ties the assertion back to the stored `SsoLoginState` row via `InResponseTo`.
2. **`cid:<uuid>`** — explicit IdP-initiated hint. Resolves to the matching SAML connection. Only honoured when that connection's `idp_initiated_sso_allowed == true`.
3. **Missing / empty** — rejected. yauth never accepts an IdP-initiated assertion without an explicit connection hint; cross-tenant assertion replay starts here.

## Security model

This is the security-critical part. The defences below are exercised in [`sso_saml_pentest.rs`](../../crates/yauth/tests/sso_saml_pentest.rs) — every commit on this branch runs the 11-case suite from yauth-go PR #26.

### Signature verification

- Enveloped XML signatures only. RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`) with SHA-256 digest method.
- The signature's `Reference URI="#…"` MUST match the assertion's `ID`. The verifier re-extracts the signed element by ID, strips the `<ds:Signature>` subtree (the enveloped-signature transform), digests, and only then accepts the rest of the assertion as trusted.
- Anything outside the signed envelope is **discarded** — no attributes are read from unsigned siblings.
- Both `assertion_signed_required` and `response_signed_required` default to `true`. Setting either to `false` is a knowingly accepted footgun and is logged in the audit trail.

### Replay defence

In-process `(issuer, assertion_id) → expires_at` cache with TTL clamped between 60 s and 900 s of the assertion's `NotOnOrAfter` window. Second submission of the same `(issuer, AssertionID)` returns 409.

### Audience + Recipient + Issuer pinning

- `Audience` must include the connection's `sp_entity_id`. Derived per-connection (`<base_url>/sso/saml/metadata/<connection-uuid>`) so two connections on the same yauth deployment cannot be cross-confused — defeats the CVE-2022-class issue.
- `SubjectConfirmationData.Recipient` must equal `sp_acs_url`.
- Assertion `Issuer` must equal the configured `idp_entity_id`.

### NotBefore / NotOnOrAfter

Clock-skew slack: 60 s either way. `NotOnOrAfter` is mandatory; missing → 400.

### NameID character filter

NameID values containing `<`, `>`, or `\x00` are **rejected** outright. This defeats the comment-injection attack class where an IdP returns `alice@example.com<!--evil@attacker.com-->` and a buggy XML-text-normalising library splits the address on the comment delimiters.

### IdP-initiated gating

`idp_initiated_sso_allowed` defaults to `false`. When off, ACS requests without a valid SP-side `InResponseTo` are rejected. When on, the assertion still has to validate against `cid:<uuid>` RelayState (no bare IdP-initiated assertions are accepted).

### Encrypted assertions

`<EncryptedAssertion>` returns `EncryptedAssertionNotSupported` (400). Explicit failure — never silently dropped.

### `sp_private_key` at rest

Encrypted via [`ChaCha20Poly1305Cipher`](../../crates/yauth/src/auth/oidc_client.rs). Operators set a 32-byte hex key in `YAUTH_SSO_AEAD_KEY` (same env var that protects OIDC `client_secret`). Without it the build falls back to `PassthroughCipher` (dev only — never deploy without the AEAD key).

### Key rotation runbook

The IdP-side X.509 signing cert rotates ~yearly on managed IdPs. yauth has **no automatic discovery** — admins push the new cert via the admin CRUD before the IdP cuts over:

1. Get the new PEM from the IdP admin console (Okta → Applications → … → Sign On → "Signing Certificates").
2. `PATCH /api/auth/organizations/:id/sso/connections/:cid` with the new cert in `saml.idp_x509_cert`. The plaintext-on-the-wire concern is the same as creating the connection — TLS terminates at the load balancer, never logged.
3. Both old and new cert are NOT supported simultaneously (single-key design). Coordinate the cutover: rotate at the IdP, immediately rotate at yauth, expect a 1–2 minute window of failed logins, then we're back.
4. Audit log emits `sso_connection_updated`.

To rotate the **AEAD key** (`YAUTH_SSO_AEAD_KEY`) you have to re-write the `sp_private_key` ciphertext via the same `PATCH` endpoint. The CLI walkthrough lives in `docs/sso-oidc/README.md#aead-rotation` — the procedure is identical between OIDC and SAML because both go through the same `SecretCipher` round-trip.

## Audit events

Every SAML round-trip writes an audit row:

| Event                      | When                                        | Payload                                          |
|----------------------------|---------------------------------------------|--------------------------------------------------|
| `sso_connection_created`   | Admin POST                                  | `{ kind, organization_id, connection_id }`       |
| `sso_connection_updated`   | Admin PATCH                                 | `{ status, organization_id, connection_id }`     |
| `sso_connection_deleted`   | Admin DELETE                                | `{ organization_id, connection_id }`             |
| `sso_saml_login_initiated` | User hits `/sso/saml/login`                 | `{ idp_entity_id, organization_id, connection_id }` |
| `sso_saml_login_succeeded` | ACS verified, session minted                | `{ idp_entity_id, provider, external_id, assertion_id, idp_initiated }` |
| `sso_saml_jit_provisioned` | JIT created a fresh yauth user              | `{ provider, organization_id, connection_id }`   |

`sso_saml_assertion_invalid` is recorded as an OTel error span (not an audit row — failures arrive over the public ACS endpoint and writing audit rows for every bad request would be a 1-byte-per-row DoS vector).

## Limitations / non-goals

- **Encrypted assertions** are flagged in the config schema but the verifier returns an explicit error. Most IdPs don't require them; turn on the regulatory regime that does and we'll add it as a follow-up.
- **HoK profile** (Holder-of-Key): not implemented.
- **SAML 1.x / WS-Fed**: not implemented; even ADFS users have largely migrated.
- **SLO** is implemented as best-effort: the SP-initiated redirect ships, and the IdP-initiated receiver accepts the request and returns 204, but we don't sign the LogoutRequest or verify a back-channel LogoutResponse. SLO is famously brittle across IdPs; documenting this clearly is more honest than pretending to support it.

## Per-IdP integration guides

- [`okta.md`](okta.md) — Okta Workforce Identity (most-asked in 2026 procurement).
- [`entra.md`](entra.md) — Microsoft Entra ID (formerly Azure AD).
- [`onelogin.md`](onelogin.md) — OneLogin (now One Identity).
- [`adfs.md`](adfs.md) — Active Directory Federation Services (on-prem).
- [`ping.md`](ping.md) — PingFederate / PingOne.
- [`auth0.md`](auth0.md) — Auth0 (Okta CIC) — when Auth0 is the IdP rather than the SP.

Every guide assumes a yauth deployment at `https://app.example.com` and an Acme tenant slug. The Okta guide is the canonical shape — the rest cross-link to it for anything they don't restate.
