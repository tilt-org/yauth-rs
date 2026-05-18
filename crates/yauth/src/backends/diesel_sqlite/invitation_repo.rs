//! Diesel native-SQLite implementation of `InvitationRepository`.
//!
//! Mirrors `diesel_pg::invitation_repo` with the SQLite divergences from
//! `mod.rs`:
//!
//! - TEXT-encoded UUIDs / ISO-8601 timestamps. The fixed-width
//!   `%Y-%m-%dT%H:%M:%S%.f` format means lexicographic `<` / `>` matches
//!   chronological order, so `expires_at.gt(&now)` works without parsing.
//! - No `RETURNING` — `INSERT/UPDATE → SELECT`.
//! - `token_hash UNIQUE` enforced by the migration; duplicate inserts surface
//!   via `diesel_conflict_sqlite` (matches `UNIQUE constraint failed`).
//! - `mark_accepted` is single-shot: the UPDATE filters
//!   `WHERE accepted_at IS NULL` so re-marking touches zero rows and returns
//!   `RepoError::NotFound`.

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::SqlitePool;
use super::models::{dt_to_str, opt_dt_to_str, opt_str_to_dt, str_to_dt, str_to_uuid, uuid_to_str};
use super::schema::yauth_invitations;
use crate::backends::diesel_common::{diesel_conflict_sqlite, diesel_err, get_conn};
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row + insert models
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_invitations)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct SqliteInvitation {
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

impl SqliteInvitation {
    fn into_domain(self) -> Result<domain::Invitation, RepoError> {
        let organization_id = self
            .organization_id
            .as_deref()
            .map(str_to_uuid)
            .ok_or_else(|| {
                RepoError::Internal(
                    "invitation row has NULL organization_id (data corruption)".into(),
                )
            })?;
        let invited_by_user_id = self
            .invited_by_user_id
            .as_deref()
            .map(str_to_uuid)
            .ok_or_else(|| {
                RepoError::Internal(
                    "invitation row has NULL invited_by_user_id (data corruption)".into(),
                )
            })?;
        Ok(domain::Invitation {
            id: str_to_uuid(&self.id),
            organization_id,
            email: self.email,
            role: self.role,
            token_hash: self.token_hash,
            invited_by_user_id,
            expires_at: str_to_dt(&self.expires_at),
            accepted_at: opt_str_to_dt(self.accepted_at),
            created_at: str_to_dt(&self.created_at),
        })
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = yauth_invitations)]
struct SqliteNewInvitation {
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

impl SqliteNewInvitation {
    fn from_domain(input: domain::NewInvitation) -> Self {
        Self {
            id: uuid_to_str(input.id),
            organization_id: Some(uuid_to_str(input.organization_id)),
            email: input.email,
            role: input.role,
            token_hash: input.token_hash,
            invited_by_user_id: Some(uuid_to_str(input.invited_by_user_id)),
            expires_at: dt_to_str(input.expires_at),
            accepted_at: opt_dt_to_str(input.accepted_at),
            created_at: dt_to_str(input.created_at),
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqliteInvitationRepo {
    pool: SqlitePool,
}

impl SqliteInvitationRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqliteInvitationRepo {}

impl InvitationRepository for SqliteInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<SqliteInvitation> = yauth_invitations::table
                .find(&id_str)
                .select(SqliteInvitation::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(SqliteInvitation::into_domain).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Filter expired + already-accepted at the query level so callers
            // can trust `Some(_)` is live. ISO-8601 fixed-width strings sort
            // chronologically under lexicographic `>`.
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let row: Option<SqliteInvitation> = yauth_invitations::table
                .filter(yauth_invitations::token_hash.eq(&token_hash))
                .filter(yauth_invitations::accepted_at.is_null())
                .filter(yauth_invitations::expires_at.gt(&now))
                .select(SqliteInvitation::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(SqliteInvitation::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let row = SqliteNewInvitation::from_domain(input);
            let id = row.id.clone();
            diesel::insert_into(yauth_invitations::table)
                .values(&row)
                .execute(&mut *conn)
                .await
                .map_err(diesel_conflict_sqlite)?;

            let inserted: SqliteInvitation = yauth_invitations::table
                .find(&id)
                .select(SqliteInvitation::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            inserted.into_domain()
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: chrono::NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let accepted_str = dt_to_str(accepted_at);
            // Single-shot: only flip `accepted_at` when it's still NULL.
            // Re-marking touches zero rows and returns `NotFound`.
            let affected = diesel::update(yauth_invitations::table)
                .filter(yauth_invitations::id.eq(&id_str))
                .filter(yauth_invitations::accepted_at.is_null())
                .set(yauth_invitations::accepted_at.eq(Some(&accepted_str)))
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;
            if affected == 0 {
                return Err(RepoError::NotFound);
            }
            let inserted: SqliteInvitation = yauth_invitations::table
                .find(&id_str)
                .select(SqliteInvitation::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            inserted.into_domain()
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            diesel::delete(yauth_invitations::table.find(&id_str))
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn list_pending_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::Invitation>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let org_str = uuid_to_str(organization_id);
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let rows: Vec<SqliteInvitation> = yauth_invitations::table
                .filter(yauth_invitations::organization_id.eq(Some(&org_str)))
                .filter(yauth_invitations::accepted_at.is_null())
                .filter(yauth_invitations::expires_at.gt(&now))
                .order(yauth_invitations::created_at.asc())
                .select(SqliteInvitation::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(SqliteInvitation::into_domain)
                .collect()
        })
    }
}
