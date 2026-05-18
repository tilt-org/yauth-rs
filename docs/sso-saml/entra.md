# Microsoft Entra ID (Azure AD) — SAML 2.0 integration

Cookbook for setting up Microsoft Entra ID (formerly Azure Active Directory) as the IdP for a yauth-managed app. Cross-references [`okta.md`](okta.md) for the yauth-side request shape.

## Prerequisites

- Entra ID role: **Application Administrator** (or **Cloud Application Administrator**) on the tenant.
- yauth org owner or admin in the target organization.

## Entra side — create the Enterprise Application

1. **Entra admin center → Enterprise applications → New application → Create your own application**.
2. Name: `yauth-acme`. Pick **"Integrate any other application you don't find in the gallery (Non-gallery)"**. Hit **Create** (Entra takes ~30 s to provision the SP-side object).
3. **Single sign-on → SAML**.
4. **Basic SAML Configuration → Edit**:
   - **Identifier (Entity ID)**: paste the yauth connection's `sp_entity_id` (`https://app.example.com/sso/saml/metadata/<cid>`). You'll get this back from yauth after the create call — see "Two-pass create" below.
   - **Reply URL (Assertion Consumer Service URL)**: `https://app.example.com/sso/saml/acs`.
   - **Sign on URL**: leave blank (yauth is SP-initiated).
   - **Relay State**: leave blank.
   - **Logout URL**: `https://app.example.com/sso/saml/slo`.
5. **Attributes & Claims → Edit**:
   - Default `Unique User Identifier (Name ID)` maps to `user.userprincipalname` — change to **`user.mail`** so NameID matches the email yauth uses for JIT lookup.
   - **Add new claim** for `http://schemas.xmlsoap.org/claims/Group` → Source attribute `user.groups` → Group claim type **`Group ID`** (or `sAMAccountName` if you're synced from on-prem AD and want human-readable names — see "Group naming" below).
   - `givenname`, `surname`, `emailaddress`, `name` come pre-mapped; leave them.
6. **SAML Signing Certificate → Download "Certificate (Base64)"** — that's the PEM you'll paste into `idp_x509_cert`. Also note **App Federation Metadata URL** (`https://login.microsoftonline.com/<tenant-id>/federationmetadata/...`) if you'd rather pull the cert programmatically.
7. **Set up yauth-acme** section → copy:
   - **Login URL** → `idp_sso_url`.
   - **Azure AD Identifier** → `idp_entity_id` (looks like `https://sts.windows.net/<tenant-id>/`).

## Two-pass create on the yauth side

Entra needs the `sp_entity_id` before yauth has minted it. Two options:

1. **Create yauth side first, then paste back**: `POST /api/auth/organizations/:id/sso/connections` with the IdP fields you have; copy the returned `saml.sp_entity_id` and paste it into Entra's **Identifier (Entity ID)** field.
2. **Use the SP metadata import**: hit `GET https://app.example.com/sso/saml/metadata/<cid>` after creating the yauth connection, save the XML, then in Entra click **Upload metadata file** at the top of the Single sign-on page.

The yauth admin UI's SAML connection list exposes a one-click **SP metadata** download link for each row.

## Group → role mapping

Entra returns groups as **Object IDs** (GUIDs) by default, not display names. Two options:

- Paste GUIDs directly into `attribute_mappings.group_to_role`. Painful but portable.
- Switch the group claim source to **`sAMAccountName`** (only works for groups synced from on-prem AD via Entra Connect — pure cloud groups have no sAMAccountName and won't appear in the claim).

## Common gotchas

- **Entra strips XML comments** before signing — this matters if you've manually authored an assertion for testing; you won't reproduce the comment-injection class against a live Entra tenant.
- **Group claims are capped at 150 group memberships** by default. If a user is in >150 groups, Entra emits a `hasgroups: true` claim instead, and yauth ignores it. Move to **Application Roles** in that case (out of scope for this guide).
- **NameID = userprincipalname is the Microsoft default** and is `<user>@<tenant>.onmicrosoft.com` for guests. Switch to `user.mail` (step 5) unless you're sure every user has a UPN that matches their work email.
- **Token signing certificate rotation** — Entra rotates the signing cert every ~3 years (or on demand via the **SAML Signing Certificate → New Certificate** button). Same rotation procedure as Okta; see [`okta.md#rotating-the-okta-signing-certificate`](okta.md#rotating-the-okta-signing-certificate).
- **Single Logout** in Entra requires the **Logout URL** to be set (step 4); yauth's SLO is best-effort and won't block on the IdP response.
