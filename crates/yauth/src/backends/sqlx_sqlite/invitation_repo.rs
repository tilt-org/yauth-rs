//! sqlx-SQLite implementation of `InvitationRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`) and the
//! sqlx-pg idiom, with SQLite-specific divergences:
//!
//! - **UUIDs** stored as `TEXT`; converted at the repo boundary via
//!   `str_to_uuid` / `uuid_to_str`.
//! - **Timestamps** stored as ISO-8601 `TEXT` via `dt_to_str`. The
//!   fixed-width `%Y-%m-%dT%H:%M:%S%.f` format means lexicographic `>`
//!   comparisons match chronological order, so the expired/live filter
//!   works correctly with a parameter-bound `now` string.
//! - **`find_by_token_hash`** filters out expired AND already-accepted
//!   invitations at the query level — callers rely on the contract that
//!   a `Some(_)` result is ready to consume.
//! - **`mark_accepted`** is single-shot: re-marking an already-accepted
//!   row returns `RepoError::NotFound`. We implement that with a
//!   `WHERE accepted_at IS NULL` clause on the UPDATE so the second call
//!   touches zero rows.
//! - **`token_hash`** has a `UNIQUE` constraint in the migration, so a
//!   duplicate insert surfaces as `RepoError::Conflict` via
//!   `sqlx_conflict`.
//! - **Cascade delete** of invitations when the parent org is removed
//!   relies on `ON DELETE CASCADE` plus `PRAGMA foreign_keys = ON` on
//!   the connection.
//! - **Runtime queries** (`sqlx::query`, `sqlx::query_as::<_, Row>`) are
//!   used here instead of the `query!()` / `query_as!()` macros so this
//!   file does not require an offline sqlx cache entry.

use chrono::NaiveDateTime;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{
    dt_to_str, opt_dt_to_str, opt_str_to_dt, sqlx_conflict, sqlx_err, str_to_dt, str_to_uuid,
    uuid_to_str,
};
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Row type
// ──────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: String,
    organization_id: Option<String>,
    email: String,
    role: String,
    token_hash: String,
    invited_by_user_id: Option<String>,
    expires_at: String,
    accepted_at: Option<String>,
    created_at: String,
}

impl InvitationRow {
    fn into_domain(self) -> Result<domain::Invitation, RepoError> {
        let organization_id = self.organization_id.ok_or_else(|| {
            RepoError::Internal("invitation row has NULL organization_id (data corruption)".into())
        })?;
        let invited_by_user_id = self.invited_by_user_id.ok_or_else(|| {
            RepoError::Internal(
                "invitation row has NULL invited_by_user_id (data corruption)".into(),
            )
        })?;
        Ok(domain::Invitation {
            id: str_to_uuid(&self.id),
            organization_id: str_to_uuid(&organization_id),
            email: self.email,
            role: self.role,
            token_hash: self.token_hash,
            invited_by_user_id: str_to_uuid(&invited_by_user_id),
            expires_at: str_to_dt(&self.expires_at),
            accepted_at: opt_str_to_dt(self.accepted_at),
            created_at: str_to_dt(&self.created_at),
        })
    }
}

const SELECT_COLS: &str = "id, organization_id, email, role, token_hash, \
     invited_by_user_id, expires_at, accepted_at, created_at";

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxSqliteInvitationRepo {
    pool: SqlitePool,
}

impl SqlxSqliteInvitationRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxSqliteInvitationRepo {}

impl InvitationRepository for SqlxSqliteInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let id_str = uuid_to_str(id);
            let sql = format!("SELECT {SELECT_COLS} FROM yauth_invitations WHERE id = ?");
            let row = sqlx::query_as::<_, InvitationRow>(&sql)
                .bind(id_str)
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?;
            row.map(InvitationRow::into_domain).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            // Trait contract: only resolves to Some(_) for live tokens.
            // Filter expired + already-accepted at the query level.
            // ISO-8601 fixed-width datetimes compare lexicographically.
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let sql = format!(
                "SELECT {SELECT_COLS} FROM yauth_invitations \
                 WHERE token_hash = ? AND accepted_at IS NULL AND expires_at > ?"
            );
            let row = sqlx::query_as::<_, InvitationRow>(&sql)
                .bind(token_hash)
                .bind(now)
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?;
            row.map(InvitationRow::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let id_str = uuid_to_str(input.id);
            let org_id_str = uuid_to_str(input.organization_id);
            let inviter_id_str = uuid_to_str(input.invited_by_user_id);
            let expires_str = dt_to_str(input.expires_at);
            let accepted_str = opt_dt_to_str(input.accepted_at);
            let created_str = dt_to_str(input.created_at);
            let sql = format!(
                "INSERT INTO yauth_invitations \
                 (id, organization_id, email, role, token_hash, invited_by_user_id, \
                  expires_at, accepted_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 RETURNING {SELECT_COLS}"
            );
            let row = sqlx::query_as::<_, InvitationRow>(&sql)
                .bind(id_str)
                .bind(org_id_str)
                .bind(input.email)
                .bind(input.role)
                .bind(input.token_hash)
                .bind(inviter_id_str)
                .bind(expires_str)
                .bind(accepted_str)
                .bind(created_str)
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_conflict)?;
            row.into_domain()
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            // Single-shot: only flip `accepted_at` when it's still NULL.
            // Re-marking an already-accepted row touches zero rows and
            // surfaces as `NotFound`, matching memory + diesel-pg + sqlx-pg.
            let id_str = uuid_to_str(id);
            let accepted_str = dt_to_str(accepted_at);
            let sql = format!(
                "UPDATE yauth_invitations SET accepted_at = ? \
                 WHERE id = ? AND accepted_at IS NULL \
                 RETURNING {SELECT_COLS}"
            );
            let row = sqlx::query_as::<_, InvitationRow>(&sql)
                .bind(accepted_str)
                .bind(id_str)
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?;
            match row {
                Some(r) => r.into_domain(),
                None => Err(RepoError::NotFound),
            }
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Idempotent — deleting a missing invitation returns Ok(()).
            let id_str = uuid_to_str(id);
            sqlx::query("DELETE FROM yauth_invitations WHERE id = ?")
                .bind(id_str)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn list_pending_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::Invitation>> {
        Box::pin(async move {
            let org_id_str = uuid_to_str(organization_id);
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let sql = format!(
                "SELECT {SELECT_COLS} FROM yauth_invitations \
                 WHERE organization_id = ? \
                   AND accepted_at IS NULL \
                   AND expires_at > ? \
                 ORDER BY created_at ASC"
            );
            let rows = sqlx::query_as::<_, InvitationRow>(&sql)
                .bind(org_id_str)
                .bind(now)
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;
            rows.into_iter().map(InvitationRow::into_domain).collect()
        })
    }
}
