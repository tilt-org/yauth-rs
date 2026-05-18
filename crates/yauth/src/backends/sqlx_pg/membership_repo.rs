//! sqlx-PG implementation of `MembershipRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`).
//!
//! Notes:
//! - The schema has `organization_id` and `user_id` as nullable `UUID` because
//!   the cross-dialect plugin schema generator emits nullable FKs with
//!   `ON DELETE CASCADE`. The domain types are non-nullable; a NULL from a
//!   query is treated as data corruption.
//! - `(organization_id, user_id)` uniqueness is NOT enforced by a composite
//!   UNIQUE in the migration today. The repo enforces it with a preflight
//!   `SELECT` inside `create`, matching the memory + diesel-pg backends. The
//!   preflight gives a typed `Conflict` instead of a 500.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{naive_to_utc, opt_naive_to_utc, sqlx_conflict, sqlx_err};
use crate::domain;
use crate::repo::{MembershipRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Row type
// ──────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct MembershipRow {
    id: Uuid,
    organization_id: Option<Uuid>,
    user_id: Option<Uuid>,
    role: String,
    status: String,
    invited_at: Option<DateTime<Utc>>,
    joined_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl MembershipRow {
    fn into_domain(self) -> Result<domain::Membership, RepoError> {
        let organization_id = self.organization_id.ok_or_else(|| {
            RepoError::Internal("membership row has NULL organization_id (data corruption)".into())
        })?;
        let user_id = self.user_id.ok_or_else(|| {
            RepoError::Internal("membership row has NULL user_id (data corruption)".into())
        })?;
        let status = domain::MembershipStatus::parse(&self.status).ok_or_else(|| {
            RepoError::Internal(format!("unknown membership status: {:?}", self.status).into())
        })?;
        Ok(domain::Membership {
            id: self.id,
            organization_id,
            user_id,
            role: self.role,
            status,
            invited_at: self.invited_at.map(|dt| dt.naive_utc()),
            joined_at: self.joined_at.map(|dt| dt.naive_utc()),
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
        })
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxPgMembershipRepo {
    pool: PgPool,
}

impl SqlxPgMembershipRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxPgMembershipRepo {}

impl MembershipRepository for SqlxPgMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let row = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, \
                        invited_at, joined_at, created_at, updated_at \
                 FROM yauth_memberships WHERE id = $1",
                id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            row.map(MembershipRow::into_domain).transpose()
        })
    }

    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let row = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, \
                        invited_at, joined_at, created_at, updated_at \
                 FROM yauth_memberships \
                 WHERE organization_id = $1 AND user_id = $2",
                organization_id,
                user_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            row.map(MembershipRow::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            // Preflight uniqueness: the migration doesn't carry a composite
            // UNIQUE on (organization_id, user_id), so look up first and
            // surface a typed Conflict if the pair already exists. Matches
            // the memory + diesel-pg contract.
            let existing = sqlx::query!(
                "SELECT id FROM yauth_memberships \
                 WHERE organization_id = $1 AND user_id = $2 LIMIT 1",
                input.organization_id,
                input.user_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            let status = input.status.as_str().to_string();
            let row = sqlx::query_as!(
                MembershipRow,
                "INSERT INTO yauth_memberships \
                 (id, organization_id, user_id, role, status, invited_at, joined_at, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 RETURNING id, organization_id, user_id, role, status, \
                           invited_at, joined_at, created_at, updated_at",
                input.id,
                input.organization_id,
                input.user_id,
                input.role,
                status,
                opt_naive_to_utc(input.invited_at) as Option<DateTime<Utc>>,
                opt_naive_to_utc(input.joined_at) as Option<DateTime<Utc>>,
                naive_to_utc(input.created_at),
                naive_to_utc(input.updated_at),
            )
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_conflict)?;
            row.into_domain()
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            // Dynamic SET clause — runtime query for the same reason as
            // user_repo's update().
            let mut sets: Vec<String> = Vec::new();
            let mut param_idx = 1u32;

            macro_rules! push_set {
                ($field:expr, $col:expr) => {
                    if $field.is_some() {
                        param_idx += 1;
                        sets.push(format!("{} = ${}", $col, param_idx));
                    }
                };
            }

            push_set!(changes.role, "role");
            push_set!(changes.status, "status");
            push_set!(changes.joined_at, "joined_at");
            push_set!(changes.updated_at, "updated_at");

            if sets.is_empty() {
                return self.find_by_id(id).await?.ok_or(RepoError::NotFound);
            }

            let sql = format!(
                "UPDATE yauth_memberships SET {} WHERE id = $1 \
                 RETURNING id, organization_id, user_id, role, status, \
                           invited_at, joined_at, created_at, updated_at",
                sets.join(", ")
            );

            let mut query = sqlx::query_as::<_, MembershipRow>(&sql).bind(id);

            if let Some(ref role) = changes.role {
                query = query.bind(role.clone());
            }
            if let Some(status) = changes.status {
                query = query.bind(status.as_str().to_string());
            }
            if let Some(joined_at) = changes.joined_at {
                query = query.bind(joined_at.map(|dt| dt.and_utc()));
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(updated_at.and_utc());
            }

            let row = query
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?
                .ok_or(RepoError::NotFound)?;
            row.into_domain()
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Idempotent — deleting a missing membership returns Ok(()),
            // matching memory + diesel-pg.
            sqlx::query!("DELETE FROM yauth_memberships WHERE id = $1", id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let rows = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, \
                        invited_at, joined_at, created_at, updated_at \
                 FROM yauth_memberships \
                 WHERE organization_id = $1 \
                 ORDER BY created_at ASC",
                organization_id
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            rows.into_iter().map(MembershipRow::into_domain).collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let rows = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, \
                        invited_at, joined_at, created_at, updated_at \
                 FROM yauth_memberships \
                 WHERE user_id = $1 \
                 ORDER BY created_at ASC",
                user_id
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            rows.into_iter().map(MembershipRow::into_domain).collect()
        })
    }
}
