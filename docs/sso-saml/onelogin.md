# OneLogin — SAML 2.0 integration

Cookbook for setting up OneLogin (now One Identity) as the IdP for a yauth-managed app. The on-the-wire shape is identical to Okta — see [`okta.md`](okta.md) for the yauth-side request body. This guide covers only the OneLogin-side clicks.

## Prerequisites

- OneLogin role: **Super User** or **Account Owner**.
- yauth org owner or admin.

## OneLogin side — create the SAML app

1. **Apps → Add App → search for "SAML Custom Connector (Advanced)"** → Add. (Don't use "SAML Custom Connector (SP Shibboleth)" — its assertion shape isn't what yauth expects.)
2. **Display name**: `yauth-acme`.
3. **Configuration** tab:
   - **Audience (EntityID)**: yauth's `sp_entity_id` — get it back from the yauth create response.
   - **Recipient**: `https://app.example.com/sso/saml/acs`.
   - **ACS (Consumer) URL Validator**: `^https:\/\/app\.example\.com\/sso\/saml\/acs$` (regex form; OneLogin tests every assertion against this).
   - **ACS (Consumer) URL**: `https://app.example.com/sso/saml/acs`.
   - **Single Logout URL**: `https://app.example.com/sso/saml/slo` (optional).
   - **SAML signature element**: **Both** (signs both the response and the assertion — matches yauth's strict defaults).
   - **SAML signature algorithm**: **SHA-256**. (SHA-1 is still selectable for legacy IdPs — never pick it.)
   - **SAML nameID format**: **Email**.
4. **Parameters** tab:
   - `email` → value `Email`, **Include in SAML assertion** checked.
   - `name` → `First Name + Last Name`.
   - `groups` (custom): create a new field of type **SAML Custom**; flag matches **member of** and pick the OneLogin role(s) to surface. The attribute name on the wire is whatever you call it here — use `http://schemas.xmlsoap.org/claims/Group` for compatibility with the yauth defaults.
5. **SSO** tab:
   - **X.509 Certificate**: click **View Details**, then copy the PEM into `idp_x509_cert`.
   - **SAML 2.0 Endpoint (HTTP)**: copy into `idp_sso_url`.
   - **Issuer URL**: copy into `idp_entity_id`. (Format: `https://app.onelogin.com/saml/metadata/<numeric-app-id>`.)

## Two-pass create

OneLogin needs the `Audience` value before yauth has minted it. Same workaround as Entra:

1. Create the yauth connection first with the IdP fields you have. Copy back `saml.sp_entity_id` and paste it into OneLogin's **Audience (EntityID)** field.
2. Alternatively, OneLogin supports **Upload Metadata** under the More Actions menu — fetch `https://app.example.com/sso/saml/metadata/<cid>` and import.

## Group → role mapping

OneLogin groups are flat strings, not GUIDs. Paste them straight into `attribute_mappings.group_to_role`:

```json
"group_to_role": {
  "OneLogin-Admins": "admin",
  "OneLogin-Engineers": "member"
}
```

## Common gotchas

- **App-key vs connector-key** — OneLogin's "Custom Connector" is a template; cloning it creates a new app with its own signing cert. The IdP cert belongs to the **app**, not the connector. If you re-clone the connector, every connected SP has to re-pin the new cert.
- **ACS URL Validator regex** — if you omit the trailing `$`, OneLogin happily accepts `https://app.example.com/sso/saml/acs?next=https://evil.com` as a valid ACS URL, which is a phishing vector. Always end with `$`.
- **NameID `Email` is per-user**: each OneLogin user must have an email set in their profile. If a user's email is blank, the assertion fails on the OneLogin side with `Email is not unique` before it ever reaches yauth.
- **Certificate rotation**: OneLogin → **Security → Certificates → Generate New**. Same procedure as Okta — pre-stage the new cert at yauth, then activate at OneLogin.
- **SAML Test connector (yet another distinct app type)** is a useful sandbox but doesn't honor the **Audience** validator; don't test the cross-tenant defence against it.
