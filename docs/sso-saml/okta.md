# Okta — SAML 2.0 integration

Cookbook for setting up Okta as the IdP for a yauth-managed app. Covers a single org's SAML connection end-to-end. Most fields default to safe values — the only one that's load-bearing per-tenant is the IdP signing certificate.

## Prerequisites

- Okta org admin (Super-Admin or App-Admin).
- yauth org owner or admin in the target organization.
- yauth deployment running at a stable `base_url` (we'll use `https://app.example.com` in the examples).

## Okta side — create the SAML 2.0 app

1. Admin console → **Applications → Applications → Create App Integration**.
2. Sign-in method: **SAML 2.0** → Next.
3. **General Settings**
   - App name: `yauth-acme` (free-form).
   - App logo: optional.
4. **Configure SAML**
   - **Single sign on URL**: `https://app.example.com/api/auth/sso/saml/acs`. Check "Use this for Recipient URL and Destination URL".
   - **Audience URI (SP Entity ID)**: this is where it gets per-connection. Leave it blank for now — after the next step we'll fill it in with the connection's UUID.
   - **Name ID format**: `EmailAddress`.
   - **Application username**: `Email`.
   - **Attribute Statements** (Add three):
     - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` → `user.email`
     - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` → `user.firstName + " " + user.lastName`
     - (optional) `http://schemas.xmlsoap.org/claims/Group` → matches regex `.*` (Filter: Matches regex), basic group claim type.
5. **Feedback** → finish.
6. On the new app's page → **Sign On** tab → **View SAML setup instructions**. Copy the:
   - **Identity Provider Single Sign-On URL** (call it `IDP_SSO_URL`).
   - **Identity Provider Issuer** (call it `IDP_ENTITY_ID`).
   - **X.509 Certificate** PEM block (call it `IDP_CERT_PEM`).

## yauth side — create the connection

`curl` (replace the org id + the bearer token of an org admin):

```bash
curl -X POST 'https://app.example.com/api/auth/organizations/$ORG_ID/sso/connections' \
  -H "Authorization: Bearer $YAUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name": "Acme Okta SAML",
    "kind": "saml_sp",
    "saml": {
      "idp_entity_id": "'"$IDP_ENTITY_ID"'",
      "idp_sso_url":   "'"$IDP_SSO_URL"'",
      "idp_x509_cert": "'"$IDP_CERT_PEM"'",
      "assertion_signed_required": true,
      "response_signed_required":  true,
      "idp_initiated_sso_allowed": false,
      "attribute_mappings": {
        "email":       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "display_name":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "external_id": "NameID",
        "groups":      "http://schemas.xmlsoap.org/claims/Group",
        "group_to_role": {
          "yauth-admins": "admin",
          "yauth-members":"member"
        }
      }
    },
    "jit_provisioning_enabled": true,
    "default_role_on_jit": "member"
  }'
```

Response carries the connection's `id` (a UUIDv7). yauth derived two URLs from it:

- `sp_entity_id = https://app.example.com/sso/saml/metadata/<id>`
- `sp_acs_url   = https://app.example.com/sso/saml/acs`

Hit `GET /sso/saml/metadata/<id>` to fetch the SP metadata XML and paste it back into Okta if you want metadata-import flow. Otherwise just paste `sp_entity_id` into the Okta app's **Audience URI** field and save.

## Smoke test

```bash
curl -i 'https://app.example.com/api/auth/sso/saml/login?org=acme'
# → HTTP/1.1 303 See Other
# → Location: https://acme.okta.com/app/.../sso/saml?SAMLRequest=…&RelayState=…
```

Click through in a browser, log in with an Okta user that's assigned to the app, and yauth should mint a session cookie + 303-redirect to `/`.

## Activating the connection

Initial state is `draft`. Flip to `active`:

```bash
curl -X PATCH 'https://app.example.com/api/auth/organizations/$ORG_ID/sso/connections/$CID' \
  -H "Authorization: Bearer $YAUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "status": "active" }'
```

Now `/sso/saml/login?org=acme` will resolve to this connection. Until the connection is active, `find_active_saml_for_org` returns `None` and the login endpoint 404s — useful safety net while you're iterating on the IdP-side config.

## Rotating the Okta signing certificate

Okta rotates the signing certificate every ~2 years (or sooner if the admin clicks "Generate new certificate"). yauth has no auto-discovery; admins push the new cert:

1. Okta → **Applications → … → Sign On → Settings → SAML Signing Certificates → Generate new certificate**.
2. **DO NOT** activate the new cert in Okta yet. Download its PEM.
3. PATCH yauth with the new PEM in `saml.idp_x509_cert`.
4. Activate the new cert in Okta.
5. Expect 0–60 s of failed logins while the change propagates.

If you forget step 3, logins fail with `BadAssertionSignature` (HTTP 401) and yauth's audit log records `sso_saml_assertion_invalid` for each attempt.

## Gotchas

- **Audience URI must match `sp_entity_id` EXACTLY.** Trailing slashes count. Okta's UI does not trim them; yauth's verifier does string equality.
- **`Recipient` is auto-set to the ACS URL by Okta.** No knob; if you see a `RecipientMismatch` error, you put the wrong ACS URL in the app config.
- **Group claim is multi-valued in Okta but yauth's regex defaults to no groups**. Add the `Group` attribute statement OR pass `groups: null` in `attribute_mappings` to skip group-based role assignment.
- **NameID rotation between sessions** = the user gets a fresh yauth account every login. Okta defaults to a stable `NameID` (the user's email), but custom apps sometimes flip this to `Transient` — leave it on `EmailAddress` unless you know exactly what you're doing.
- **IdP-initiated tile**: if you turn on Okta's "User can sign on without entering a username and password" / IdP-initiated, the IdP will POST to `/sso/saml/acs` with no `RelayState`. yauth rejects that by default. To allow it, set `idp_initiated_sso_allowed: true` AND configure Okta's RelayState to literally `cid:<connection-uuid>`. Anything else is rejected; that's the cross-tenant defence.
