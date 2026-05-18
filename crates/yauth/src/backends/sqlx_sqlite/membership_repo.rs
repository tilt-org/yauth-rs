//! sqlx-SQLite implementation of `MembershipRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`) and the
//! sqlx-pg idiom, with SQLite-specific divergences:
//!
//! - **UUIDs** stored as `TEXT`; converted at the repo boundary via
//!   `str_to_uuid` / `uuid_to_str`.
//! - **Timestamps** stored as ISO-8601 `TEXT` via `dt_to_str`.
//! - **`MembershipStatus`** stored as TEXT (`active` / `invited` /
//!   `suspended`); parsed via `MembershipStatus::parse` at the boundary.
//! - **Nullable FKs**: `organization_id` and `user_id` are declared
//!   nullable in the cross-dialect schema generator (a quirk of how
//!   `ON DELETE CASCADE` is emitted). Domain types are non-nullable; a
//!   NULL from a query is treated as data corruption.
//! - **`(organization_id, user_id)` uniqueness** is NOT enforced by a
//!   composite UNIQUE in the migration today. The repo enforces it with
//!   a preflight `SELECT` inside `create`, matching the memory, diesel-pg
//!   and sqlx-pg backends. The preflight gives a typed `Conflict` instead
//!   of a 500.
//! - **Cascade delete** of memberships when the parent org is removed
//!   relies on `ON DELETE CASCADE` plus `PRAGMA foreign_keys = ON` on the
//!   connection.
//! - **Runtime queries** (`sqlx::query`, `sqlx::query_as::<_, Row>`) are
//!   used here instead of the `query!()` / `query_as!()` macros so this
//!   file does not require an offline sqlx cache entry.

use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{
    dt_to_str, opt_dt_to_str, opt_str_to_dt, sqlx_conflict, sqlx_err, str_to_dt, str_to_uuid,
    uuid_to_str,
};
use crate::domain;
use crate::repo::{MembershipRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Row type
// ──────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct MembershipRow {
    id: String,
    organization_id: Option<String>,
    user_id: Option<String>,
    role: String,
    status: String,
    invited_at: Option<String>,
    joined_at: Option<String>,
    created_at: String,
    updated_at: String,
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
            id: str_to_uuid(&self.id),
            organization_id: str_to_uuid(&organization_id),
            user_id: str_to_uuid(&user_id),
            role: self.role,
            status,
            invited_at: opt_str_to_dt(self.invited_at),
            joined_at: opt_str_to_dt(self.joined_at),
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        })
    }
}

const SELECT_COLS: &str = "id, organization_id, user_id, role, status, \
     invited_at, joined_at, created_at, updated_at";

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxSqliteMembershipRepo {
    pool: SqlitePool,
}

impl SqlxSqliteMembershipRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxSqliteMembershipRepo {}

impl MembershipRepository for SqlxSqliteMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let id_str = uuid_to_str(id);
            let sql = format!("SELECT {SELECT_COLS} FROM yauth_memberships WHERE id = ?");
            let row = sqlx::query_as::<_, MembershipRow>(&sql)
                .bind(id_str)
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
            let org_id_str = uuid_to_str(organization_id);
            let user_id_str = uuid_to_str(user_id);
            let sql = format!(
                "SELECT {SELECT_COLS} FROM yauth_memberships \
                 WHERE organization_id = ? AND user_id = ?"
            );
            let row = sqlx::query_as::<_, MembershipRow>(&sql)
                .bind(org_id_str)
                .bind(user_id_str)
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
            // the memory + diesel-pg + sqlx-pg contract.
            let org_id_str = uuid_to_str(input.organization_id);
            let user_id_str = uuid_to_str(input.user_id);
            let existing = sqlx::query(
                "SELECT id FROM yauth_memberships \
                 WHERE organization_id = ? AND user_id = ? LIMIT 1",
            )
            .bind(&org_id_str)
            .bind(&user_id_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            let id_str = uuid_to_str(input.id);
            let status_str = input.status.as_str().to_string();
            let invited_at_str = opt_dt_to_str(input.invited_at);
            let joined_at_str = opt_dt_to_str(input.joined_at);
            let created_str = dt_to_str(input.created_at);
            let updated_str = dt_to_str(input.updated_at);
            let sql = format!(
                "INSERT INTO yauth_memberships \
                 (id, organization_id, user_id, role, status, invited_at, joined_at, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 RETURNING {SELECT_COLS}"
            );
            let row = sqlx::query_as::<_, MembershipRow>(&sql)
                .bind(id_str)
                .bind(org_id_str)
                .bind(user_id_str)
                .bind(input.role)
                .bind(status_str)
                .bind(invited_at_str)
                .bind(joined_at_str)
                .bind(created_str)
                .bind(updated_str)
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
            // Dynamic SET — column set is conditional.
            let mut sets: Vec<&'static str> = Vec::new();
            if changes.role.is_some() {
                sets.push("role = ?");
            }
            if changes.status.is_some() {
                sets.push("status = ?");
            }
            if changes.joined_at.is_some() {
                sets.push("joined_at = ?");
            }
            if changes.updated_at.is_some() {
                sets.push("updated_at = ?");
            }

            if sets.is_empty() {
                return self.find_by_id(id).await?.ok_or(RepoError::NotFound);
            }

            let sql = format!(
                "UPDATE yauth_memberships SET {} WHERE id = ? RETURNING {SELECT_COLS}",
                sets.join(", ")
            );

            let mut query = sqlx::query_as::<_, MembershipRow>(&sql);

            if let Some(ref role) = changes.role {
                query = query.bind(role.clone());
            }
            if let Some(status) = changes.status {
                query = query.bind(status.as_str().to_string());
            }
            if let Some(joined_at) = changes.joined_at {
                query = query.bind(opt_dt_to_str(joined_at));
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(dt_to_str(updated_at));
            }

            let row = query
                .bind(uuid_to_str(id))
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
            // matching memory + diesel-pg + sqlx-pg.
            let id_str = uuid_to_str(id);
            sqlx::query("DELETE FROM yauth_memberships WHERE id = ?")
                .bind(id_str)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let org_id_str = uuid_to_str(organization_id);
            let sql = format!(
                "SELECT {SELECT_COLS} FROM yauth_memberships \
                 WHERE organization_id = ? ORDER BY created_at ASC"
            );
            let rows = sqlx::query_as::<_, MembershipRow>(&sql)
                .bind(org_id_str)
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;
            rows.into_iter().map(MembershipRow::into_domain).collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let user_id_str = uuid_to_str(user_id);
            let sql = format!(
                "SELECT {SELECT_COLS} FROM yauth_memberships \
                 WHERE user_id = ? ORDER BY created_at ASC"
            );
            let rows = sqlx::query_as::<_, MembershipRow>(&sql)
                .bind(user_id_str)
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;
            rows.into_iter().map(MembershipRow::into_domain).collect()
        })
    }
}
