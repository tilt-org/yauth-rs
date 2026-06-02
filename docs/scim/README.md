# SCIM 2.0 provisioning (issue #95)

yauth speaks SCIM 2.0 (RFC 7643 + RFC 7644) so IdPs (Okta, Entra ID, OneLogin) can push user lifecycle events into a yauth tenant out-of-band of SSO sign-in. This complements the federated SSO flow from issue #93/#94 — SSO handles "this user logged in", SCIM handles "this user joined / changed roles / left the company".

> **Status**: shipped. Memory backend is canonical. SQL backends inherit SCIM via the existing organization + membership + external-identity repos (no new schema in this PR); backends that still stub those traits return HTTP 501 with `RepoError::NotImplemented` until per-backend impls land.

## Endpoint surface

All endpoints live under `/api/scim/v2/organizations/{org_id}/...`. Every request authenticates via `Authorization: Bearer <key>` where `<key>` is an **org-scoped API key** (issue #91) bound to that same `{org_id}`.

| Method  | Path                              | Effect                                                                   |
|---------|-----------------------------------|--------------------------------------------------------------------------|
| `POST`  | `/Users`                          | Create or attach (idempotent on `externalId` → 200 with existing record) |
| `GET`   | `/Users`                          | Paginated list of users with an active membership in this org            |
| `GET`   | `/Users/{id}`                     | Fetch one (404 if not a member of this org)                              |
| `PUT`   | `/Users/{id}`                     | Full replace — display name, active, role-via-groups                     |
| `PATCH` | `/Users/{id}`                     | RFC 7644 §3.5.2 add/replace/remove                                       |
| `DELETE`| `/Users/{id}`                     | Remove the user's membership; the user row persists for audit retention  |
| `POST`  | `/Groups`                         | Set membership for a built-in role                                       |
| `GET`   | `/Groups`                         | List built-in roles as virtual groups                                    |
| `GET`   | `/Groups/{id}`                    | Fetch one virtual group + its members                                    |
| `PUT`   | `/Groups/{id}`                    | Replace group membership (demotes any user not in payload)               |
| `PATCH` | `/Groups/{id}`                    | Add / remove members                                                     |
| `DELETE`| `/Groups/{id}`                    | Demote all members of the group to `member`                              |
| `GET`   | `/ServiceProviderConfig`          | Server capabilities                                                      |
| `GET`   | `/Schemas`                        | Core User + Core Group schema descriptors                                |
| `GET`   | `/ResourceTypes`                  | Resource type descriptors                                                |

All responses carry `Content-Type: application/scim+json` (RFC 7644 §3.8). All error responses use the RFC 7644 §3.12 error envelope:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "401",
  "scimType": "invalidCredentials",
  "detail": "missing Authorization header"
}
```

## Mapping

| SCIM concept           | yauth concept                                                              |
|------------------------|----------------------------------------------------------------------------|
| `User`                 | `User` + `Membership` in this org                                          |
| `User.externalId`      | `ExternalIdentity` keyed by `(provider="scim:<org_id>", external_id=<...>)`|
| `User.active: false`   | **Global suspend** — sets the user's `suspended_at` (reason `"SCIM deprovisioned"`) and trips the kill switch (terminate all sessions + revoke all refresh tokens) for an instant lockout *everywhere*. The org membership is also flipped to `suspended`. NOT a user delete. `active: true` reverses it, but only for SCIM-originated suspensions (so a manual admin offboard is never silently undone by a routine sync). |
| `User.groups[]`        | Via `SsoConnection.attribute_mappings.group_to_role` (most-privileged wins). If no connection, accept the literal built-in role name. |
| `DELETE /Users/{id}`   | Remove the org membership **and trip the kill switch** (terminate sessions + revoke refresh tokens). The user row persists for audit; `suspended_at` is **not** set, so a later re-`POST` provisions a clean, usable account. |
| `Group`                | A built-in role (owner / admin / billing_admin / member / viewer) — virtual; not a first-class entity |
| `Group.id`             | `role:<rolename>` (e.g. `role:admin`)                                      |

## Idempotency

- `POST /Users` with a previously-seen `externalId` returns the existing record as **200 OK** (not 409, not 201). IdPs retry aggressively; this prevents duplicate provisioning.
- `PUT` / `PATCH` are naturally idempotent.
- `DELETE` on a user not in this org returns **404**, not 204. Returning 204 on out-of-scope users would silently mask wrong-org IdP misconfigurations.

## Filter syntax

Supported subset of RFC 7644 §3.4.2.2:

| Operator | Example                                       | Notes                       |
|----------|-----------------------------------------------|-----------------------------|
| `eq`     | `userName eq "alice@acme.com"`                | Case-insensitive on strings |
| `co`     | `displayName co "Alice"`                      | Substring contains          |
| `sw`     | `userName sw "al"`                            | Starts-with                 |
| `and`    | `userName sw "a" and active eq true`          | Conjunction (no `or`)       |

Unsupported tokens (`or`, `pr`, `gt`, parenthesised groups, complex multi-valued filters like `emails[type eq "work"].value`) are rejected with `400 invalidFilter` so callers can detect missing capability rather than silently get partial results.

## Pagination (RFC 7644 §3.4)

```
GET /Users?startIndex=1&count=100
```

- `startIndex` is 1-based. Values < 1 clamp to 1.
- `count` defaults to **100**, capped at **500**.
- Response envelope: `{ schemas, totalResults, startIndex, itemsPerPage, Resources }`.
- Wildly large `startIndex` (e.g. `99999999999`) returns 200 OK with an empty `Resources` array — never 500.

## Security

- Each org-scoped API key MUST match the URL's `{org_id}` exactly. Mismatches return 403 `invalidValue`, NEVER 200. (Pentest case 1.)
- An email change that would collide with another existing yauth user returns 409 `uniqueness`. We NEVER silently merge accounts. (Pentest case 2.)
- Unknown schema URNs in `schemas[]` are rejected with 400 `invalidSyntax` rather than passed through. Arbitrary extension JSON does NOT get persisted. (Pentest cases 3 + 4.)
- DELETE on a user not a member of the URL's org returns 404, not 204. (Pentest case 5.)
- Audit events fire on every SCIM operation. The actor is `scim_api_key:<key_uuid>` — yauth NEVER logs the bearer token, even masked. (Pentest cases 6 + 7.)

## Operator setup (high level)

1. **Enable** the `scim` Cargo feature (requires `organizations` + `api-key`).
2. **Mount** the plugin: `.with_api_key().with_organizations().with_scim()`.
3. **Mint** an org-scoped API key with `scim:read` and `scim:write` scopes — the org admin gets a `yauth_<prefix>_<secret>` plaintext at the moment of creation; this is what they paste into their IdP.
4. **Give** the IdP admin the **SCIM Base URL** for their org: `{base}/api/scim/v2/organizations/{org_id}`.
5. **Per-IdP config**: see [`okta.md`](./okta.md), [`entra.md`](./entra.md), [`onelogin.md`](./onelogin.md).

## Deliberate non-features (MVP)

- **Bulk endpoint** (RFC 7644 §3.7) — declared unsupported on `/ServiceProviderConfig`.
- **ETag concurrency** — last-writer-wins; concurrent `PATCH` ops both succeed and the last one wins. Documented to admins.
- **Sort** — `?sortBy` is tolerated but ignored.
- **Enterprise extension persistence** — `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` is recognised in `schemas[]` but its fields (employeeNumber, department, etc.) are NOT persisted. The response strips them.

## Verifying with curl

```bash
ORG=11111111-1111-7111-8111-111111111111
KEY=yauth_<prefix>_<secret>
BASE=https://yauth.example.com

# Discover capabilities
curl -H "Authorization: Bearer $KEY" \
     -H "Accept: application/scim+json" \
     "$BASE/api/scim/v2/organizations/$ORG/ServiceProviderConfig"

# Create a user
curl -H "Authorization: Bearer $KEY" \
     -H "Content-Type: application/scim+json" \
     -X POST "$BASE/api/scim/v2/organizations/$ORG/Users" \
     -d '{
       "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
       "userName": "alice@acme.com",
       "displayName": "Alice",
       "externalId": "okta-001",
       "emails": [{"value": "alice@acme.com", "primary": true}],
       "active": true
     }'

# List users
curl -H "Authorization: Bearer $KEY" \
     "$BASE/api/scim/v2/organizations/$ORG/Users?count=10"

# Filter
curl -H "Authorization: Bearer $KEY" \
     "$BASE/api/scim/v2/organizations/$ORG/Users?filter=userName%20eq%20%22alice@acme.com%22"
```

## Audit events

| `event_type`                  | Fires on                       |
|-------------------------------|--------------------------------|
| `scim_user_created`           | POST /Users (new record)       |
| `scim_user_create_idempotent` | POST /Users (existing record)  |
| `scim_user_replaced`          | PUT /Users/{id}                |
| `scim_user_patched`           | PATCH /Users/{id}              |
| `scim_user_deleted`           | DELETE /Users/{id}             |

Every event records `actor = "scim_api_key:<key_uuid>"`, `target = <user id>`, `org_id = <org_id>`. The bearer token itself never appears.
