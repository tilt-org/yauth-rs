# Okta — SSO OIDC integration

Set up a yauth `SsoConnection` against an Okta tenant.

## Okta-side setup

1. **Create an OIDC app**: Okta Admin → Applications → Create App Integration → OIDC – Web Application.
2. **Sign-in redirect URI**: `https://<your-yauth-host>/api/auth/sso/callback`.
3. **Sign-out redirect URI**: `https://<your-yauth-host>/` (optional).
4. **Grant type**: Authorization Code (the default).
5. **Assignments**: pick the user group(s) that should be allowed to sign in via yauth. Anyone not assigned will get an Okta-side 403.
6. **Groups claim** (optional, only if you want group→role mapping):
   - Authorization Servers → default (or your custom AS) → Claims → Add Claim
   - Name: `groups`
   - Include in token type: ID Token (Always)
   - Value type: Groups
   - Filter: Matches regex `.*` (or a more specific filter if you want to limit which groups Okta sends)

Copy the **Client ID** and **Client Secret** from the General tab.

## yauth-side connection

```json
POST /api/auth/organizations/:id/sso/connections
{
  "name": "Okta",
  "kind": "oidc_client",
  "oidc": {
    "discovery_url": "https://<your-domain>.okta.com/.well-known/openid-configuration",
    "client_id": "<copied from Okta>",
    "client_secret": "<copied from Okta>",
    "scopes": ["openid", "email", "profile", "groups"],
    "claim_mappings": {
      "external_id": "sub",
      "email": "email",
      "display_name": "name",
      "groups": "groups",
      "group_to_role": {
        "yauth-admins": "admin",
        "yauth-owners": "owner"
      }
    }
  },
  "jit_provisioning_enabled": true,
  "default_role_on_jit": "member"
}
```

After creation the connection is `draft`. Run the **Test** action; on green, `PATCH` `status: "active"`.

## Notes

- The `groups` claim only appears if both (a) the `groups` scope is in the request *and* (b) the AS has a claim mapping that surfaces it. Without it, yauth treats the user as having an empty group list and falls back to `default_role_on_jit`.
- Okta's `sub` claim is stable per-user-per-app — safe to use as `external_id`.
- For custom domains (`auth.<yourcompany>.com`), use the full custom-domain URL in `discovery_url`.

## Discovery URL examples

```
https://example.okta.com/.well-known/openid-configuration
https://example.oktapreview.com/.well-known/openid-configuration
https://auth.example.com/oauth2/default/.well-known/openid-configuration   # custom AS
```
