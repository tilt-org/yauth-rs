# Organizations Primitive (issue #87)

Status: **foundation merged; per-backend SQL impls deferred to follow-up
issues.** Default OFF.

This plan tracks the multi-tenancy primitive added by issue #87.

## What the primitive provides

Three additive entities — `Organization`, `Membership`, `Invitation` —
plus three repository traits (`OrganizationRepository`,
`MembershipRepository`, `InvitationRepository`) and a minimal route
surface mounted by the new `OrganizationsPlugin`.

| Entity | Role |
|---|---|
| `Organization` | Multi-tenant boundary. Slug-addressable, globally unique. |
| `Membership` | Many-to-many `(user, org)` with per-membership role + status. |
| `Invitation` | Pending join request. Single-use token, time-limited. |

The primitive is intentionally minimal — RBAC enforcement, the active-org
session claim, verified domains, and SCIM/SAML federation all consume this
entity in follow-up issues.

## Feature flag — "additive, gated"

The new functionality lives behind `--features organizations` on the
`yauth` crate. Default off. With the flag off:

- No new entities are linked into `Repositories`.
- No new routes mount.
- No new tables are touched (migrations exist but only run when applied).
- All existing single-tenant code paths are byte-identical to pre-#87.

This mirrors the `audit-log` style "additive, gated" pattern: flipping
the feature flag from off to on must not break any existing test or
deployment.

## Routes (only mounted with the feature on)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/auth/organizations` | session | Create org; caller becomes admin |
| `GET` | `/api/auth/organizations` | session | List orgs the caller belongs to |
| `GET` | `/api/auth/organizations/{id}` | session + member | Fetch one |
| `PATCH` | `/api/auth/organizations/{id}` | session + admin | Rename / update |
| `DELETE` | `/api/auth/organizations/{id}` | session + admin | Hard delete (cascades) |
| `GET` | `/api/auth/organizations/{id}/members` | session + member | List memberships |
| `POST` | `/api/auth/organizations/{id}/invitations` | session + admin | Mint invite token |
| `POST` | `/api/auth/invitations/accept` | session | Accept invite by token |

Plaintext invitation tokens are returned **once** at creation and never
stored — only the SHA-256 hash hits the database. The caller is
responsible for emailing the plaintext to the invitee. (A built-in mailer
that calls into `auth::email::EmailService` is on the deferred list.)

## Backend support status

Memory backend ships the full primitive impl and powers the conformance
suite. SQL backends compile cleanly with the feature on but route every
repo method to `StubOrganizationRepo` / `StubMembershipRepo` /
`StubInvitationRepo` — those return `RepoError::Internal` with a
descriptive message. Concrete SQL impls land in follow-up issues, one per
backend family:

| Backend | Status |
|---|---|
| `memory` | Complete |
| `diesel-pg` | Stubbed — follow-up |
| `diesel-mysql` | Stubbed — follow-up |
| `diesel-sqlite` | Stubbed — follow-up |
| `diesel-libsql` | Stubbed — follow-up |
| `sqlx-pg` | Stubbed — follow-up |
| `sqlx-mysql` | Stubbed — follow-up |
| `sqlx-sqlite` | Stubbed — follow-up |
| `seaorm-pg` | Stubbed — follow-up |
| `seaorm-mysql` | Stubbed — follow-up |
| `seaorm-sqlite` | Stubbed — follow-up |
| `toasty` | Stubbed — follow-up |

The migration files are generated for every backend and are committed —
the schema is identical across SQL backends, only the DDL dialect differs.
Once a concrete impl lands, the existing migration just works.

## Acceptance criteria status

- [x] `Organization`, `Membership`, `Invitation` entities in `yauth-entity`
- [x] Three new repository traits + memory impls
- [ ] Three new repository traits + SQL impls (stubbed — concrete impls
      tracked in follow-ups)
- [x] Migrations generated via `cargo yauth generate` for every dialect
- [x] `organizations` feature flag (default OFF)
- [x] Routes mount conditionally on the feature flag
- [x] Default OFF — no behavior change to existing deployments
- [x] Tests: repo-level coverage on memory; cross-org isolation probe
- [ ] Tests: SQL backend coverage (gated on concrete impls)
- [x] Docs: this plan, `docs/configuration.md` section
- [ ] TypeScript client + Vue + SolidJS UI components (separate sweep
      because client generation is gated on `openapi` + the openapi.json
      regen; running it raises orval churn unrelated to this issue)
- [x] No regressions in the existing pentest suite

## Out of scope (separate issues)

- Active-org session/JWT claim — issue #89
- RBAC enforcement helpers — issue #88
- Verified domain auto-join — issue #90
- Org-scoped API keys — issue #91
- Org-scoped audit log filtering
- SCIM / SAML federation
