# ADFS — SAML 2.0 integration

Cookbook for setting up **Active Directory Federation Services** (Windows Server 2016+) as the IdP for a yauth-managed app. ADFS is on-prem, and unlike the SaaS IdPs in this folder you control both the schema and the signing key, which removes some classes of bug and introduces others.

## Prerequisites

- ADFS admin on the AD DS forest you're federating from.
- Network reachability from yauth to the ADFS federation endpoint (typically `https://fs.example.com/adfs/ls/`).
- yauth org owner or admin.

## ADFS side — create the Relying Party Trust

Use **AD FS Management** (the MMC snap-in) or the PowerShell cmdlets — the GUI is faster for one-shot setup.

1. **AD FS Management → Relying Party Trusts → Add Relying Party Trust** → **Claims aware** → Start.
2. **Select Data Source** → **Import data about the relying party from a file**. Save the yauth SP metadata XML (`https://app.example.com/sso/saml/metadata/<cid>` — fetch after creating the yauth connection) to a local file and point ADFS at it. If you can't reach the yauth endpoint from the ADFS host, fall back to **Enter data about the relying party manually**:
   - Display name: `yauth-acme`.
   - Configure URL → check **Enable support for the SAML 2.0 WebSSO protocol** → URL: `https://app.example.com/sso/saml/acs`.
   - Configure Identifiers → add the connection's `sp_entity_id` (e.g. `https://app.example.com/sso/saml/metadata/<cid>`).
3. **Access Control Policy** → **Permit everyone** (or scope to a specific AD group; ADFS gates assertion issuance, not yauth).
4. Finish → **Edit Claim Issuance Policy**.

## Claim issuance rules

Add three rules, in this order:

1. **Send LDAP Attributes as Claims** — claim store: Active Directory.
   - `E-Mail-Addresses` → `E-Mail Address` (built-in claim type, maps to the `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` URI).
   - `Display-Name` → `Name`.
   - `Token-Groups - Unqualified Names` → `Group` (the `http://schemas.xmlsoap.org/claims/Group` URI).
2. **Transform an Incoming Claim** — incoming `E-Mail Address` → outgoing **Name ID**, format **Email**. This makes ADFS emit the user's email as `NameID`, which is what yauth uses for JIT lookup.
3. (Optional) **Send Claims Using a Custom Rule** — for additional attribute mapping.

## ADFS-side certificate

```
AD FS → Service → Certificates → Token-signing → View → Export
```

Export as **Base-64 encoded X.509 (.CER)**. Open in a text editor, paste into `idp_x509_cert`.

The token-signing cert rotates **annually** by default (configurable via `Set-AdfsProperties -CertificateRolloverInterval`). ADFS auto-creates a new cert ~20 days before expiry; the primary stays the same until you call `Set-AdfsCertificate -CertificateType Token-Signing -Thumbprint <new>`. Pre-stage the new cert at yauth (see [`README.md#key-rotation-runbook`](README.md#key-rotation-runbook)) before flipping the primary at ADFS.

## yauth-side config

```jsonc
{
  "name": "Acme ADFS",
  "kind": "saml_sp",
  "saml": {
    "idp_entity_id": "http://fs.example.com/adfs/services/trust",
    "idp_sso_url":   "https://fs.example.com/adfs/ls/",
    "idp_x509_cert": "-----BEGIN CERTIFICATE-----\n...",
    "assertion_signed_required": true,
    "response_signed_required":  true,
    "idp_initiated_sso_allowed": false,
    "attribute_mappings": {
      "email":       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "display_name":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
      "external_id": "NameID",
      "groups":      "http://schemas.xmlsoap.org/claims/Group",
      "group_to_role": { "Domain Admins": "admin" }
    }
  }
}
```

## Common gotchas

- **ADFS uses SHA-256 by default but SHA-1 is selectable on legacy farms.** Run `Get-AdfsRelyingPartyTrust -Name 'yauth-acme' | Select SignatureAlgorithm` and set it explicitly: `Set-AdfsRelyingPartyTrust -TargetName 'yauth-acme' -SignatureAlgorithm http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`. yauth rejects SHA-1 assertions.
- **`idp_entity_id` is `http://fs.example.com/adfs/services/trust`, NOT `https://`.** ADFS's issuer URI is a *URN* that happens to look like a URL; copy it verbatim from **AD FS → Service → Edit Federation Service Properties → Federation Service Identifier**. Getting the scheme wrong is the #1 ADFS integration failure.
- **Group names are AD names, not Object SIDs.** The `Token-Groups - Unqualified Names` claim returns the group's `sAMAccountName` (e.g. `Domain Admins`). Paste those into `group_to_role`.
- **Single Logout** in ADFS requires the relying party to publish a SLO endpoint in its metadata. yauth does; ADFS will SLO best-effort.
- **HRD (Home Realm Discovery)** is an ADFS-side concept and doesn't apply here — yauth picks the IdP by org slug.
