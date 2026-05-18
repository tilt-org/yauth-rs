# Auth0 (Okta CIC) — SAML 2.0 integration

Cookbook for setting up **Auth0** (now branded as Okta Customer Identity Cloud) as the IdP for a yauth-managed app. Auth0 is most commonly the SP, not the IdP — this guide is for the inverse case where an enterprise tenant has standardised on Auth0 and yauth needs to federate **out** to it.

## Prerequisites

- Auth0 tenant role: **Admin** (or a role with `update:clients` and `update:connections`).
- yauth org owner or admin.

## Auth0 side — create the SAML2 application

1. **Auth0 Dashboard → Applications → Applications → + Create Application**.
2. Name: `yauth-acme`. Type: **Regular Web Application** → Create.
3. Skip the Quick Start; go to **Addons** tab.
4. Find **SAML2 WEB APP** → toggle on. The Settings modal opens.
5. **Application Callback URL**: `https://app.example.com/sso/saml/acs`.
6. **Settings (JSON)** — Auth0's SAML config is JSON, not a click-through. Paste:
   ```jsonc
   {
     "audience": "<paste yauth's sp_entity_id here>",
     "recipient": "https://app.example.com/sso/saml/acs",
     "destination": "https://app.example.com/sso/saml/acs",
     "mappings": {
       "email":       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
       "name":        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
       "given_name":  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
       "family_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
       "groups":      "http://schemas.xmlsoap.org/claims/Group"
     },
     "nameIdentifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
     "nameIdentifierProbes": ["email"],
     "signatureAlgorithm":  "rsa-sha256",
     "digestAlgorithm":     "sha256",
     "signResponse":  true,
     "includeAttributeNameFormat": true,
     "typedAttributes": true
   }
   ```
   - `signResponse: true` is critical — without it, only the assertion is signed and yauth's `response_signed_required` (default `true`) will reject it.
7. **Usage** tab — copy:
   - **Identity Provider Login URL** → `idp_sso_url`.
   - **Identity Provider Certificate → Download** → that's the PEM for `idp_x509_cert`.
   - **Identity Provider SAML Metadata → Download** if you want the full metadata XML.
   - The **Issuer** value (`urn:<tenant>.auth0.com`) → `idp_entity_id`.
8. **Save & Enable** the addon.

## Rules / Actions for group claims

Auth0 doesn't surface group membership by default. The cleanest route is an **Action** on the Login flow:

```js
exports.onExecutePostLogin = async (event, api) => {
  const groups = (event.user.app_metadata?.groups ?? []);
  api.samlResponse.setAttribute(
    "http://schemas.xmlsoap.org/claims/Group",
    groups
  );
};
```

Wire this Action into the **Login → Add Action → Custom** trigger in the Auth0 dashboard.

## yauth-side config

```jsonc
{
  "name": "Acme Auth0",
  "kind": "saml_sp",
  "saml": {
    "idp_entity_id": "urn:acme.auth0.com",
    "idp_sso_url":   "https://acme.auth0.com/samlp/<auth0-app-client-id>",
    "idp_x509_cert": "-----BEGIN CERTIFICATE-----\n...",
    "assertion_signed_required": true,
    "response_signed_required":  true,
    "attribute_mappings": {
      "email":       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "external_id": "NameID",
      "groups":      "http://schemas.xmlsoap.org/claims/Group",
      "group_to_role": { "yauth-admins": "admin" }
    }
  }
}
```

## Common gotchas

- **`signResponse` defaults to `false` in Auth0's SAML2 addon**. Always set it to `true` and confirm `response_signed_required: true` on the yauth side. Mismatched expectations here are the #1 Auth0-as-IdP failure.
- **`destination` and `recipient` are separate fields** in Auth0's JSON but yauth treats them equivalently (both must equal the ACS URL). Set both.
- **NameID format**: Auth0 defaults to `unspecified`. Override to `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` (step 6 above) — otherwise yauth's NameID character filter may reject random Auth0-generated identifiers.
- **Auth0's "Connections"** (database, social, enterprise) are unrelated to yauth's `SsoConnection`. The Auth0 *Application* is what yauth federates to; the Connections are how Auth0 itself authenticates users.
- **Cert rotation**: Auth0 → **Settings → Advanced → Signing Keys → Rotate Signing Key**. The rotation is **immediate** — there's no overlap window. Pre-stage the new cert at yauth then click Rotate; expect <60 s of failed logins.
- **Tenant-level vs application-level certs**: Auth0 has one signing cert per tenant; rotating it affects every SAML2 app in the tenant. If yauth shares the Auth0 tenant with other SPs, coordinate the rotation.
