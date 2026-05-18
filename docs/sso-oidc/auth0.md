# Auth0 — SSO OIDC integration

## Auth0-side setup

1. **Applications** → Create Application → Regular Web Application.
2. **Settings** tab:
   - **Allowed Callback URLs**: `https://<your-yauth-host>/api/auth/sso/callback`
   - **Allowed Logout URLs**: `https://<your-yauth-host>/` (optional)
3. Copy the **Domain**, **Client ID**, **Client Secret** from the same Settings tab.
4. **Advanced Settings → OAuth → JsonWebToken Signature Algorithm**: RS256 (the default).
5. For groups → use an **Action** (formerly called a Rule) under Actions → Library → Build Custom. Pseudocode:
   ```js
   exports.onExecutePostLogin = async (event, api) => {
     const ns = "https://yauth.example.com/groups";
     api.idToken.setCustomClaim(ns, event.user.app_metadata?.groups ?? []);
   };
   ```
   Then reference the namespaced claim in `claim_mappings.groups`.

## yauth-side connection

```json
POST /api/auth/organizations/:id/sso/connections
{
  "name": "Auth0",
  "kind": "oidc_client",
  "oidc": {
    "discovery_url": "https://<your-tenant>.auth0.com/.well-known/openid-configuration",
    "client_id": "<auth0-client-id>",
    "client_secret": "<auth0-client-secret>",
    "scopes": ["openid", "email", "profile"],
    "claim_mappings": {
      "external_id": "sub",
      "email": "email",
      "display_name": "name",
      "groups": "https://yauth.example.com/groups",
      "group_to_role": {
        "admins": "admin"
      }
    }
  },
  "jit_provisioning_enabled": true,
  "default_role_on_jit": "member"
}
```

## Notes

- Auth0's `sub` is prefixed with the connection type (`google-oauth2|...`, `samlp|...`, `auth0|...`). The prefix is stable per-user-per-IdP — safe to use as `external_id`.
- Custom claims **must** be namespaced (Auth0 strips unprefixed custom claims). The above uses `https://yauth.example.com/groups` as the namespace; pick anything unique to your deployment.
- For social logins via Auth0 (e.g. "Sign in with Google → through Auth0 → into yauth"), yauth treats it as one OIDC connection. The provider chain is opaque from yauth's side.

## Discovery URL

```
https://<your-tenant>.auth0.com/.well-known/openid-configuration
```

For custom domains:

```
https://auth.<your-company>.com/.well-known/openid-configuration
```
