# Ping (PingFederate / PingOne) — SAML 2.0 integration

Cookbook for setting up the **Ping Identity** stack as the IdP for a yauth-managed app. The Ping product line has two SAML-capable IdPs — pick the right section:

- **PingOne for Workforce** — SaaS, "PingOne Console" at `console.pingone.com`. New deployments default here.
- **PingFederate** — on-prem or customer-managed cloud, admin UI on port 9999. Used by larger enterprises with custom adapters.

The on-the-wire shape is identical to Okta; see [`okta.md`](okta.md) for the yauth-side request body.

## Prerequisites

- Ping role: **Identity Data Admin** (PingOne) or **Admin** (PingFederate).
- yauth org owner or admin.

## PingOne — create the SAML application

1. **PingOne Console → Applications → Applications → +** → choose **SAML Application** → Next.
2. Name: `yauth-acme` → Next.
3. **SAML Configuration → Manually Enter**:
   - **ACS URL**: `https://app.example.com/sso/saml/acs`.
   - **Entity ID**: yauth's `sp_entity_id` (two-pass: create yauth side first, paste back).
   - **SLO Endpoint**: `https://app.example.com/sso/saml/slo` (optional).
   - **Signing Key**: leave default (PingOne auto-generates an RSA-2048 key).
4. **Attribute Mappings**:
   - `saml_subject` (NameID) → PingOne user attribute `email`.
   - `email` → `email`.
   - `givenName` → `name.given`.
   - `familyName` → `name.family`.
   - `groups` → `memberOfGroupNames` (PingOne 2024+) or a custom attribute that's been populated via the PingOne Directory.
5. **Configuration → Download Metadata** — that's the SP-importable XML for the IdP side. For the yauth side, expand **Connection Details** and copy:
   - `Issuer ID` → `idp_entity_id`.
   - `Single Signon Service` → `idp_sso_url`.
   - `IDP Signing Certificate → Download` (DER) → convert to PEM with `openssl x509 -inform der -in cert.der -out cert.pem` → paste into `idp_x509_cert`.

## PingFederate — create the SP Connection

1. **PingFederate admin → Applications → SP Connections → Create Connection**.
2. **Connection Type**: Browser SSO Profiles, SAML 2.0.
3. **Connection Options**: Browser SSO.
4. **Import Metadata**: pick **File** and upload `sp-metadata-<cid>.xml` from yauth (`GET /sso/saml/metadata/<cid>`). Most fields autofill.
5. **General Info**: confirm **Partner's Entity ID** equals yauth's `sp_entity_id`.
6. **Browser SSO → Configure Browser SSO**:
   - **SAML Profiles**: check **SP-Initiated SSO** and **IdP-Initiated SSO** (only enable IdP-init if yauth's connection is configured for it).
   - **Assertion Lifetime**: 5 minutes (PingFederate's default; yauth's clock skew is ±60s).
   - **Assertion Creation → Identity Mapping**: Standard.
   - **Attribute Contract**: add `email`, `groups`, `name`.
   - **Attribute Sources**: pick the LDAP/JDBC source for your directory.
7. **Protocol Settings → Signature Policy**: check **Always sign Assertion** and **Always sign Response**. **Signature Algorithm**: `RSA SHA256`.
8. **Credentials → Digital Signature Settings**: select the signing cert.
9. Save → **Export Metadata** if you want to re-import it into yauth's connection update later.

For yauth-side, copy from PingFederate's **System → Server → Server Configuration → SAML 2.0**:
- **SAML 2.0 Entity ID** → `idp_entity_id`.
- **Single Sign-On Service URL** (HTTP-Redirect binding) → `idp_sso_url`.
- **Signing Certificate** (export as PEM) → `idp_x509_cert`.

## Group → role mapping

- **PingOne**: groups are flat string names from the PingOne Directory. Paste directly:
  ```json
  "group_to_role": { "yauth-admins": "admin" }
  ```
- **PingFederate**: groups come from whatever LDAP/JDBC source you wired in. Most commonly they're AD `sAMAccountName`s or LDAP CNs. Same flat-string mapping.

## Common gotchas

- **PingFederate's "Always sign Assertion" is OFF by default** for new SP connections — many teams ship without it and then get bitten when yauth refuses the unsigned assertion. Check the Protocol Settings page twice.
- **PingOne's certificate signing key rotates on demand only** (no auto-rotation schedule). Coordinate with the PingOne admin if you ever see `BadAssertionSignature` errors.
- **Audience URI in PingFederate** is set under **Protocol Settings → Service URLs → Audience**, NOT under General Info. It's a separate field from Entity ID, and it has to match yauth's `sp_entity_id`.
- **PingOne Worker Apps** (the API-side machine-to-machine apps) are a different product and don't apply here — don't confuse them with PingOne SAML applications.
- **PingFederate's "PingAccess" plugin** intercepts the SAML POST before it reaches your SP. If you're behind PingAccess, the assertion arrives at yauth's `/sso/saml/acs` with extra headers (`PA-Token`, `PA-User`); yauth ignores them but PingAccess can decide to drop the POST entirely if it thinks the SP doesn't need SSO. Disable PingAccess for the yauth host or whitelist `/sso/saml/acs`.
