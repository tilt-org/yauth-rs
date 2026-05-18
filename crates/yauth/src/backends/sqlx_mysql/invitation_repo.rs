//! sqlx-MySQL implementation of `InvitationRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`) with MySQL
//! dialect adaptations:
//!
//! - **`find_by_token_hash`** filters out expired AND already-accepted
//!   invitations at the query level so callers can trust a `Some(_)` result
//!   is live.
//! - **`mark_accepted`** is single-shot: `UPDATE … WHERE accepted_at IS NULL`,
//!   so the second call touches zero rows and surfaces as `NotFound`.
//! - **CHAR(36) UUIDs** stored as `String`; conversions via `str_to_uuid`.
//! - **Token uniqueness** enforced at the DB layer (`UNIQUE` on
//!   `token_hash`) — duplicate inserts surface as `RepoError::Conflict` via
//!   `sqlx_conflict`.

use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{sqlx_conflict, sqlx_err, str_to_uuid};
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
    expires_at: NaiveDateTime,
    accepted_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
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
            expires_at: self.expires_at,
            accepted_at: self.accepted_at,
            created_at: self.created_at,
        })
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxMysqlInvitationRepo {
    pool: MySqlPool,
}

impl SqlxMysqlInvitationRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxMysqlInvitationRepo {}

impl InvitationRepository for SqlxMysqlInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let id_str = id.to_string();
            let row = sqlx::query_as!(
                InvitationRow,
                "SELECT id, organization_id, email, role, token_hash, invited_by_user_id, \
                        expires_at, accepted_at, created_at \
                 FROM yauth_invitations WHERE id = ?",
                id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            row.map(InvitationRow::into_domain).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            // Trait contract: only resolves to Some(_) for live tokens. Filter
            // out expired + already-accepted at the query level so callers
            // don't have to recheck.
            let now = chrono::Utc::now().naive_utc();
            let row = sqlx::query_as!(
                InvitationRow,
                "SELECT id, organization_id, email, role, token_hash, invited_by_user_id, \
                        expires_at, accepted_at, created_at \
                 FROM yauth_invitations \
                 WHERE token_hash = ? AND accepted_at IS NULL AND expires_at > ?",
                token_hash,
                now
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            row.map(InvitationRow::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let org_id_str = input.organization_id.to_string();
            let invited_by_str = input.invited_by_user_id.to_string();

            // MySQL: no RETURNING — INSERT then SELECT.
            sqlx::query!(
                "INSERT INTO yauth_invitations \
                 (id, organization_id, email, role, token_hash, invited_by_user_id, \
                  expires_at, accepted_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                id_str,
                org_id_str,
                input.email,
                input.role,
                input.token_hash,
                invited_by_str,
                input.expires_at,
                input.accepted_at,
                input.created_at,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_conflict)?;

            let row = sqlx::query_as!(
                InvitationRow,
                "SELECT id, organization_id, email, role, token_hash, invited_by_user_id, \
                        expires_at, accepted_at, created_at \
                 FROM yauth_invitations WHERE id = ?",
                id_str
            )
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_err)?;
            row.into_domain()
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let id_str = id.to_string();
            // Single-shot semantics: only flip `accepted_at` when it's still
            // NULL. Re-marking an already-accepted row touches zero rows and
            // surfaces as `NotFound`, matching the memory + diesel-pg backends.
            let result = sqlx::query!(
                "UPDATE yauth_invitations SET accepted_at = ? \
                 WHERE id = ? AND accepted_at IS NULL",
                accepted_at,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;

            if result.rows_affected() == 0 {
                return Err(RepoError::NotFound);
            }

            let row = sqlx::query_as!(
                InvitationRow,
                "SELECT id, organization_id, email, role, token_hash, invited_by_user_id, \
                        expires_at, accepted_at, created_at \
                 FROM yauth_invitations WHERE id = ?",
                id_str
            )
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_err)?;
            row.into_domain()
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!("DELETE FROM yauth_invitations WHERE id = ?", id_str)
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
            let org_id_str = organization_id.to_string();
            let now = chrono::Utc::now().naive_utc();
            let rows = sqlx::query_as!(
                InvitationRow,
                "SELECT id, organization_id, email, role, token_hash, invited_by_user_id, \
                        expires_at, accepted_at, created_at \
                 FROM yauth_invitations \
                 WHERE organization_id = ? AND accepted_at IS NULL AND expires_at > ? \
                 ORDER BY created_at ASC",
                org_id_str,
                now
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            rows.into_iter().map(InvitationRow::into_domain).collect()
        })
    }
}
