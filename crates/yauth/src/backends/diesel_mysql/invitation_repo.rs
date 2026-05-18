//! Diesel-MySQL implementation of `InvitationRepository`.
//!
//! Mirrors `diesel_pg::invitation_repo` (commit 3221c25). MySQL specifics:
//!
//! - `INSERT` then `SELECT` (no `RETURNING`).
//! - `mark_accepted` is implemented as a guarded `UPDATE … WHERE id = ? AND
//!   accepted_at IS NULL`, then a fresh `SELECT`. Single-shot semantics:
//!   re-marking an already-accepted row touches zero rows and surfaces as
//!   `RepoError::NotFound`.
//! - `find_by_token_hash` and `list_pending_for_org` filter expired AND
//!   already-accepted rows at the query layer — callers can trust a
//!   `Some(_)` is live.

use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::MysqlPool;
use super::schema::yauth_invitations;
use crate::backends::diesel_common::{
    diesel_conflict_mysql, diesel_err, get_conn, opt_str_to_uuid, str_to_uuid, uuid_to_str,
};
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row model
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_invitations)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct MysqlInvitation {
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

impl MysqlInvitation {
    fn into_domain(self) -> Result<domain::Invitation, RepoError> {
        let organization_id = opt_str_to_uuid(self.organization_id).ok_or_else(|| {
            RepoError::Internal("invitation row has NULL organization_id (data corruption)".into())
        })?;
        let invited_by_user_id = opt_str_to_uuid(self.invited_by_user_id).ok_or_else(|| {
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
            expires_at: self.expires_at,
            accepted_at: self.accepted_at,
            created_at: self.created_at,
        })
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct MysqlInvitationRepo {
    pool: MysqlPool,
}

impl MysqlInvitationRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for MysqlInvitationRepo {}

impl InvitationRepository for MysqlInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<MysqlInvitation> = yauth_invitations::table
                .find(&id_str)
                .select(MysqlInvitation::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(MysqlInvitation::into_domain).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Trait contract: `Some(_)` must be a live invitation. Filter
            // expired and already-accepted rows out at the query level so
            // callers don't have to recheck.
            let now = chrono::Utc::now().naive_utc();
            let row: Option<MysqlInvitation> = yauth_invitations::table
                .filter(yauth_invitations::token_hash.eq(&token_hash))
                .filter(yauth_invitations::accepted_at.is_null())
                .filter(yauth_invitations::expires_at.gt(now))
                .select(MysqlInvitation::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(MysqlInvitation::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(input.id);
            let org_str = uuid_to_str(input.organization_id);
            let inv_str = uuid_to_str(input.invited_by_user_id);

            // MySQL has no RETURNING — INSERT then SELECT by known PK.
            // `token_hash` carries a UNIQUE constraint in the migration, so a
            // duplicate insert surfaces as `Conflict` via `diesel_conflict_mysql`.
            diesel::sql_query(
                "INSERT INTO yauth_invitations \
                 (id, organization_id, email, role, token_hash, invited_by_user_id, expires_at, accepted_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id_str)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(&org_str))
            .bind::<diesel::sql_types::Text, _>(&input.email)
            .bind::<diesel::sql_types::Text, _>(&input.role)
            .bind::<diesel::sql_types::Text, _>(&input.token_hash)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(&inv_str))
            .bind::<diesel::sql_types::Datetime, _>(&input.expires_at)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Datetime>, _>(&input.accepted_at)
            .bind::<diesel::sql_types::Datetime, _>(&input.created_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_mysql)?;

            let row: MysqlInvitation = yauth_invitations::table
                .find(&id_str)
                .select(MysqlInvitation::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
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
            let id_str = uuid_to_str(id);
            // Single-shot: only flip `accepted_at` when it's still NULL.
            // MySQL has no RETURNING so we UPDATE-then-SELECT, but we still
            // need to know whether the UPDATE matched a row (it won't if the
            // invitation was already accepted, mirroring the memory backend's
            // `NotFound` semantics).
            let affected = diesel::update(yauth_invitations::table)
                .filter(yauth_invitations::id.eq(&id_str))
                .filter(yauth_invitations::accepted_at.is_null())
                .set(yauth_invitations::accepted_at.eq(Some(accepted_at)))
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;
            if affected == 0 {
                return Err(RepoError::NotFound);
            }
            let row: MysqlInvitation = yauth_invitations::table
                .find(&id_str)
                .select(MysqlInvitation::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            row.into_domain()
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
            let now = chrono::Utc::now().naive_utc();
            let rows: Vec<MysqlInvitation> = yauth_invitations::table
                .filter(yauth_invitations::organization_id.eq(Some(&org_str)))
                .filter(yauth_invitations::accepted_at.is_null())
                .filter(yauth_invitations::expires_at.gt(now))
                .order(yauth_invitations::created_at.asc())
                .select(MysqlInvitation::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter().map(MysqlInvitation::into_domain).collect()
        })
    }
}
