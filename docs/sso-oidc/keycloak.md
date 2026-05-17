# Keycloak — SSO OIDC integration

## Keycloak-side setup

1. **Clients** → Create client.
   - Client type: **OpenID Connect**
   - Client ID: e.g. `yauth`
2. **Capability config**:
   - Client authentication: **On** (this makes it confidential, so it gets a secret).
   - Authentication flow: **Standard flow** (Authorization Code) only.
3. **Login settings**:
   - **Valid redirect URIs**: `https://<your-yauth-host>/api/auth/sso/callback`
   - **Web origins**: `https://<your-yauth-host>` (only if you need CORS for browser-side OIDC; not required for the redirect flow)
4. **Credentials** tab → copy the **Client secret**.
5. **Client scopes** → click your client → Add a `groups` scope:
   - **Scope** tab → Assign the `groups` client scope as a **Default** scope. (If you don't have one, create it as a Client Scope with a "Group Membership" mapper that has Token Claim Name = `groups`.)
6. **Realm settings** → **Tokens** → confirm signing algorithm is RS256 (default).

## yauth-side connection

```json
POST /api/auth/organizations/:id/sso/connections
{
  "name": "Keycloak",
  "kind": "oidc_client",
  "oidc": {
    "discovery_url": "https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration",
    "client_id": "yauth",
    "client_secret": "<from Credentials tab>",
    "scopes": ["openid", "email", "profile", "groups"],
    "claim_mappings": {
      "external_id": "sub",
      "email": "email",
      "display_name": "name",
      "groups": "groups",
      "group_to_role": {
        "/Admins": "admin",
        "/Owners": "owner"
      }
    }
  },
  "jit_provisioning_enabled": true,
  "default_role_on_jit": "member"
}
```

## Notes

- Keycloak's group claim values are **path-like** (`/Admins`, `/Team/Engineers`) by default. The `group_to_role` keys must match exactly. If you want flat names, configure the Group Membership mapper with **Full group path: Off**.
- `sub` is a stable per-user UUID; safe as `external_id`.
- For multi-realm setups, create one yauth `SsoConnection` per realm — the discovery URL embeds the realm.

## Discovery URL

```
https://<keycloak-host>/realms/<realm-name>/.well-known/openid-configuration
```

For self-hosted Keycloak ≥ 17 the URL no longer includes `/auth/` prefix. For older versions it's:

```
https://<keycloak-host>/auth/realms/<realm-name>/.well-known/openid-configuration
```
