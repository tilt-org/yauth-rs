# Entra ID (Azure AD) — SSO OIDC integration

## Entra-side setup

1. **App registrations** → New registration.
2. **Redirect URI**: Web → `https://<your-yauth-host>/api/auth/sso/callback`.
3. **Certificates & secrets** → New client secret. Copy the value (it's only shown once).
4. **Token configuration** → Add optional claim:
   - For groups → `groups` (ID token + Access token). Choose "Group ID" for unique IDs or "sAMAccountName" for names.
   - If you choose "Group ID", your `group_to_role` keys will be Entra group OIDs (UUIDs), not display names.
5. **API permissions** → grant `openid`, `email`, `profile`. For groups also grant `Directory.Read.All` if you used the optional claim approach.

Copy the **Application (client) ID** and the **Directory (tenant) ID**.

## yauth-side connection

```json
POST /api/auth/organizations/:id/sso/connections
{
  "name": "Entra ID",
  "kind": "oidc_client",
  "oidc": {
    "discovery_url": "https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration",
    "client_id": "<application-client-id>",
    "client_secret": "<client-secret-value>",
    "scopes": ["openid", "email", "profile"],
    "claim_mappings": {
      "external_id": "oid",
      "email": "email",
      "display_name": "name",
      "groups": "groups",
      "group_to_role": {
        "00000000-0000-0000-0000-000000000000": "admin"
      }
    }
  },
  "jit_provisioning_enabled": true,
  "default_role_on_jit": "member"
}
```

## Why `oid` instead of `sub`?

Entra's `sub` claim is a **per-app pairwise** identifier — it changes when the app registration is rebuilt or migrated. Use `oid` (the user's object ID in the tenant's directory), which is stable across app registrations.

## Multi-tenant apps

For an app that accepts users from any Entra tenant, use `common` instead of the tenant ID in the discovery URL:

```
https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
```

Then enforce tenant membership at the application layer — yauth doesn't currently filter by `tid`.
