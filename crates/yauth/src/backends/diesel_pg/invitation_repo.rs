//! Diesel-PG implementation of `InvitationRepository`.
//!
//! Notes for follow-up backend agents:
//!
//! - `find_by_token_hash` MUST filter out expired AND already-accepted
//!   invitations at the query level — callers rely on the contract that a
//!   `Some(_)` result is ready to consume.
//! - `mark_accepted` is single-shot: re-marking an already-accepted row
//!   returns `RepoError::NotFound`. We implement that with a `WHERE
//!   accepted_at IS NULL` clause on the UPDATE so the second call simply
//!   touches zero rows.
//! - `token_hash` has a `UNIQUE` constraint in the migration, so a duplicate
//!   insert surfaces as `RepoError::Conflict` via `diesel_conflict`.

use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::schema::yauth_invitations;
use crate::backends::diesel_common::{diesel_conflict, diesel_err, get_conn};
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

// ──────────────────────────────────────────────
// Diesel-annotated row + insert models
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_invitations)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct DieselInvitation {
    id: Uuid,
    organization_id: Option<Uuid>,
    email: String,
    role: String,
    token_hash: String,
    invited_by_user_id: Option<Uuid>,
    expires_at: NaiveDateTime,
    accepted_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
}

impl DieselInvitation {
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
            expires_at: self.expires_at,
            accepted_at: self.accepted_at,
            created_at: self.created_at,
        })
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = yauth_invitations)]
struct DieselNewInvitation {
    id: Uuid,
    organization_id: Option<Uuid>,
    email: String,
    role: String,
    token_hash: String,
    invited_by_user_id: Option<Uuid>,
    expires_at: NaiveDateTime,
    accepted_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
}

impl DieselNewInvitation {
    fn from_domain(input: domain::NewInvitation) -> Self {
        Self {
            id: input.id,
            organization_id: Some(input.organization_id),
            email: input.email,
            role: input.role,
            token_hash: input.token_hash,
            invited_by_user_id: Some(input.invited_by_user_id),
            expires_at: input.expires_at,
            accepted_at: input.accepted_at,
            created_at: input.created_at,
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct DieselInvitationRepo {
    pool: DbPool,
}

impl DieselInvitationRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselInvitationRepo {}

impl InvitationRepository for DieselInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let row: Option<DieselInvitation> = yauth_invitations::table
                .find(id)
                .select(DieselInvitation::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(DieselInvitation::into_domain).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Trait contract: only resolves to Some(_) for live tokens. Filter
            // out expired + already-accepted at the query level so callers
            // don't have to recheck.
            let now = chrono::Utc::now().naive_utc();
            let row: Option<DieselInvitation> = yauth_invitations::table
                .filter(yauth_invitations::token_hash.eq(&token_hash))
                .filter(yauth_invitations::accepted_at.is_null())
                .filter(yauth_invitations::expires_at.gt(now))
                .select(DieselInvitation::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(DieselInvitation::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let row: DieselInvitation = diesel::insert_into(yauth_invitations::table)
                .values(&DieselNewInvitation::from_domain(input))
                .returning(DieselInvitation::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(diesel_conflict)?;
            row.into_domain()
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Single-shot semantics: only flip `accepted_at` when it's still
            // NULL. Re-marking an already-accepted row touches zero rows and
            // surfaces as `NotFound`, matching the memory backend.
            let row: Option<DieselInvitation> = diesel::update(yauth_invitations::table)
                .filter(yauth_invitations::id.eq(id))
                .filter(yauth_invitations::accepted_at.is_null())
                .set(yauth_invitations::accepted_at.eq(Some(accepted_at)))
                .returning(DieselInvitation::as_returning())
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            match row {
                Some(r) => r.into_domain(),
                None => Err(RepoError::NotFound),
            }
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(yauth_invitations::table.find(id))
                .execute(&mut conn)
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
            let now = chrono::Utc::now().naive_utc();
            let rows: Vec<DieselInvitation> = yauth_invitations::table
                .filter(yauth_invitations::organization_id.eq(Some(organization_id)))
                .filter(yauth_invitations::accepted_at.is_null())
                .filter(yauth_invitations::expires_at.gt(now))
                .order(yauth_invitations::created_at.asc())
                .select(DieselInvitation::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(DieselInvitation::into_domain)
                .collect()
        })
    }
}
