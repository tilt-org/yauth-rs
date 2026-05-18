//! sqlx-PG implementation of `InvitationRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`).
//!
//! Notes:
//! - `find_by_token_hash` filters out expired AND already-accepted
//!   invitations at the query level — callers rely on the contract that a
//!   `Some(_)` result is ready to consume.
//! - `mark_accepted` is single-shot: re-marking an already-accepted row
//!   returns `RepoError::NotFound`. We implement that with a
//!   `WHERE accepted_at IS NULL` clause on the UPDATE so the second call
//!   touches zero rows.
//! - `token_hash` has a `UNIQUE` constraint in the migration, so a duplicate
//!   insert surfaces as `RepoError::Conflict` via `sqlx_conflict`.

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{naive_to_utc, opt_naive_to_utc, sqlx_conflict, sqlx_err};
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Row type
// ──────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: Uuid,
    organization_id: Option<Uuid>,
    email: String,
    role: String,
    token_hash: String,
    invited_by_user_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
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
            id: self.id,
            organization_id,
            email: self.email,
            role: self.role,
            token_hash: self.token_hash,
            invited_by_user_id,
            expires_at: self.expires_at.naive_utc(),
            accepted_at: self.accepted_at.map(|dt| dt.naive_utc()),
            created_at: self.created_at.naive_utc(),
        })
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxPgInvitationRepo {
    pool: PgPool,
}

impl SqlxPgInvitationRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxPgInvitationRepo {}

impl InvitationRepository for SqlxPgInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let row = sqlx::query_as!(
                InvitationRow,
                "SELECT id, organization_id, email, role, token_hash, \
                        invited_by_user_id, expires_at, accepted_at, created_at \
                 FROM yauth_invitations WHERE id = $1",
                id
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
            // Trait contract: only resolves to Some(_) for live tokens.
            // Filter out expired + already-accepted at the query level so
            // callers don't have to recheck.
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                InvitationRow,
                "SELECT id, organization_id, email, role, token_hash, \
                        invited_by_user_id, expires_at, accepted_at, created_at \
                 FROM yauth_invitations \
                 WHERE token_hash = $1 \
                   AND accepted_at IS NULL \
                   AND expires_at > $2",
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
            let row = sqlx::query_as!(
                InvitationRow,
                "INSERT INTO yauth_invitations \
                 (id, organization_id, email, role, token_hash, invited_by_user_id, \
                  expires_at, accepted_at, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 RETURNING id, organization_id, email, role, token_hash, \
                           invited_by_user_id, expires_at, accepted_at, created_at",
                input.id,
                input.organization_id,
                input.email,
                input.role,
                input.token_hash,
                input.invited_by_user_id,
                naive_to_utc(input.expires_at),
                opt_naive_to_utc(input.accepted_at) as Option<DateTime<Utc>>,
                naive_to_utc(input.created_at),
            )
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
            // surfaces as `NotFound`, matching memory + diesel-pg.
            let row = sqlx::query_as!(
                InvitationRow,
                "UPDATE yauth_invitations \
                 SET accepted_at = $2 \
                 WHERE id = $1 AND accepted_at IS NULL \
                 RETURNING id, organization_id, email, role, token_hash, \
                           invited_by_user_id, expires_at, accepted_at, created_at",
                id,
                naive_to_utc(accepted_at)
            )
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
            sqlx::query!("DELETE FROM yauth_invitations WHERE id = $1", id)
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
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            let rows = sqlx::query_as!(
                InvitationRow,
                "SELECT id, organization_id, email, role, token_hash, \
                        invited_by_user_id, expires_at, accepted_at, created_at \
                 FROM yauth_invitations \
                 WHERE organization_id = $1 \
                   AND accepted_at IS NULL \
                   AND expires_at > $2 \
                 ORDER BY created_at ASC",
                organization_id,
                now
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            rows.into_iter().map(InvitationRow::into_domain).collect()
        })
    }
}
