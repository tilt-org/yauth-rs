# Google Workspace — SSO OIDC integration

## Google-side setup

1. **Google Cloud Console** → APIs & Services → Credentials → Create Credentials → **OAuth client ID**.
2. **Application type**: Web application.
3. **Authorized redirect URIs**: `https://<your-yauth-host>/api/auth/sso/callback`.
4. Copy the **Client ID** and **Client secret**.
5. **OAuth consent screen**:
   - User Type: **Internal** (only your Workspace can sign in) or **External** (anyone with a Google account).
   - Add the scopes: `openid`, `email`, `profile`.
6. (Optional) If you want to restrict sign-in to a specific Workspace domain, you'll need to enforce that yourself at the application layer — yauth doesn't currently filter by `hd` claim.

## yauth-side connection

```json
POST /api/auth/organizations/:id/sso/connections
{
  "name": "Google Workspace",
  "kind": "oidc_client",
  "oidc": {
    "discovery_url": "https://accounts.google.com/.well-known/openid-configuration",
    "client_id": "<google-client-id>.apps.googleusercontent.com",
    "client_secret": "<google-client-secret>",
    "scopes": ["openid", "email", "profile"],
    "claim_mappings": {
      "external_id": "sub",
      "email": "email",
      "display_name": "name"
    }
  },
  "jit_provisioning_enabled": true,
  "default_role_on_jit": "member"
}
```

## Notes

- **Google does NOT expose Workspace groups in OIDC id_tokens.** If you need group→role mapping you have two options:
  1. **Per-user roles**: leave `group_to_role` empty, let users JIT in as `default_role_on_jit`, and bump them up via the admin API or the `/organizations/:id/members/:uid/role` endpoint.
  2. **Custom IdP relay**: stand up a Keycloak / Authentik / Auth0 broker in front of Google that fetches groups via the Admin SDK and surfaces them in a `groups` claim. yauth then connects to the broker, not Google directly.
- Google's `sub` is a stable per-user-per-app-pairwise identifier; safe as `external_id`.
- For Workspace tenancy enforcement, validate the `hd` claim downstream (it's exposed in `IdTokenClaims.extra["hd"]`). A future yauth setting can promote this to a first-class check.

## Discovery URL

Always:

```
https://accounts.google.com/.well-known/openid-configuration
```
