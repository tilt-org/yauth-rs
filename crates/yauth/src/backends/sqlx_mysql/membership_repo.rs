//! sqlx-MySQL implementation of `MembershipRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`) with MySQL
//! dialect adaptations:
//!
//! - **CHAR(36) UUIDs** stored as `String`; conversions via `str_to_uuid`.
//! - **Nullable FK columns** on the schema (`organization_id`, `user_id`) for
//!   cross-dialect cascade support — logically required, so `NULL` is treated
//!   as data corruption (matches diesel-pg).
//! - **Preflight uniqueness** for `(organization_id, user_id)` since the
//!   migration does not (yet) carry a composite UNIQUE. Surfaces a typed
//!   `RepoError::Conflict` instead of relying on a DB error.

use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{sqlx_conflict, sqlx_err, str_to_uuid};
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
    invited_at: Option<NaiveDateTime>,
    joined_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl MembershipRow {
    fn into_domain(self) -> Result<domain::Membership, RepoError> {
        // Migration declares the FKs as nullable for cross-dialect cascade
        // support, but logically every membership row carries both keys.
        // A NULL here means data corruption — surface it as Internal rather
        // than silently dropping the row.
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
            invited_at: self.invited_at,
            joined_at: self.joined_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxMysqlMembershipRepo {
    pool: MySqlPool,
}

impl SqlxMysqlMembershipRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxMysqlMembershipRepo {}

impl MembershipRepository for SqlxMysqlMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let id_str = id.to_string();
            let row = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, invited_at, joined_at, \
                        created_at, updated_at \
                 FROM yauth_memberships WHERE id = ?",
                id_str
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
            let org_id_str = organization_id.to_string();
            let user_id_str = user_id.to_string();
            let row = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, invited_at, joined_at, \
                        created_at, updated_at \
                 FROM yauth_memberships WHERE organization_id = ? AND user_id = ?",
                org_id_str,
                user_id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            row.map(MembershipRow::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let org_id_str = input.organization_id.to_string();
            let user_id_str = input.user_id.to_string();
            let status_str = input.status.as_str().to_string();

            // Preflight uniqueness check: the migration today does not enforce
            // a composite UNIQUE on (organization_id, user_id). Look up first
            // and surface a typed Conflict if a row already exists. Mirrors
            // the memory + diesel-pg backends.
            let existing = sqlx::query!(
                "SELECT id FROM yauth_memberships WHERE organization_id = ? AND user_id = ? LIMIT 1",
                org_id_str,
                user_id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            // MySQL: no RETURNING — INSERT then SELECT.
            sqlx::query!(
                "INSERT INTO yauth_memberships \
                 (id, organization_id, user_id, role, status, invited_at, joined_at, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                id_str,
                org_id_str,
                user_id_str,
                input.role,
                status_str,
                input.invited_at,
                input.joined_at,
                input.created_at,
                input.updated_at,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_conflict)?;

            let row = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, invited_at, joined_at, \
                        created_at, updated_at \
                 FROM yauth_memberships WHERE id = ?",
                id_str
            )
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_err)?;
            row.into_domain()
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut sets: Vec<&str> = Vec::new();

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
                // No-op update: return current state if the row exists, else NotFound.
                return self.find_by_id(id).await?.ok_or(RepoError::NotFound);
            }

            let sql = format!(
                "UPDATE yauth_memberships SET {} WHERE id = ?",
                sets.join(", ")
            );

            let mut query = sqlx::query(&sql);

            if let Some(ref role) = changes.role {
                query = query.bind(role.clone());
            }
            if let Some(status) = changes.status {
                query = query.bind(status.as_str().to_string());
            }
            if let Some(joined_at) = changes.joined_at {
                query = query.bind(joined_at);
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(updated_at);
            }

            let result = query
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;

            if result.rows_affected() == 0 {
                return Err(RepoError::NotFound);
            }

            self.find_by_id(id).await?.ok_or(RepoError::NotFound)
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            // Idempotent — deleting a missing membership returns Ok(()), per
            // trait contract.
            sqlx::query!("DELETE FROM yauth_memberships WHERE id = ?", id_str)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let org_id_str = organization_id.to_string();
            let rows = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, invited_at, joined_at, \
                        created_at, updated_at \
                 FROM yauth_memberships WHERE organization_id = ? ORDER BY created_at ASC",
                org_id_str
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            rows.into_iter().map(MembershipRow::into_domain).collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let rows = sqlx::query_as!(
                MembershipRow,
                "SELECT id, organization_id, user_id, role, status, invited_at, joined_at, \
                        created_at, updated_at \
                 FROM yauth_memberships WHERE user_id = ? ORDER BY created_at ASC",
                user_id_str
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            rows.into_iter().map(MembershipRow::into_domain).collect()
        })
    }
}
