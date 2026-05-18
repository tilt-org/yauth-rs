//! Diesel-libsql implementation of `InvitationRepository`.
//!
//! Mirrors the diesel-pg canonical impl:
//!
//! - `find_by_token_hash` filters out expired AND already-accepted rows so
//!   callers get a ready-to-consume `Some(_)`.
//! - `mark_accepted` is single-shot — the `accepted_at IS NULL` predicate on
//!   the UPDATE makes re-acceptance surface as `RepoError::NotFound`.
//! - `token_hash` has a `UNIQUE` constraint in the migration; libSQL surfaces
//!   the duplicate via `diesel_conflict_sqlite`.

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::LibsqlPool;
use super::models::{dt_to_str, opt_dt_to_str, opt_str_to_dt, str_to_dt, str_to_uuid, uuid_to_str};
use super::schema::yauth_invitations;
use crate::backends::diesel_common::{diesel_conflict_sqlite, diesel_err, get_conn};
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_invitations)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
struct LibsqlInvitation {
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

impl LibsqlInvitation {
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

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct LibsqlInvitationRepo {
    pool: LibsqlPool,
}

impl LibsqlInvitationRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for LibsqlInvitationRepo {}

impl InvitationRepository for LibsqlInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<LibsqlInvitation> = yauth_invitations::table
                .find(&id_str)
                .select(LibsqlInvitation::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(LibsqlInvitation::into_domain).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Filter at the query layer so callers don't have to recheck.
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let row: Option<LibsqlInvitation> = yauth_invitations::table
                .filter(yauth_invitations::token_hash.eq(&token_hash))
                .filter(yauth_invitations::accepted_at.is_null())
                .filter(yauth_invitations::expires_at.gt(&now))
                .select(LibsqlInvitation::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(LibsqlInvitation::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id = uuid_to_str(input.id);
            let oid = uuid_to_str(input.organization_id);
            let invited_by = uuid_to_str(input.invited_by_user_id);
            let expires_at = dt_to_str(input.expires_at);
            let accepted_at = opt_dt_to_str(input.accepted_at);
            let created_at = dt_to_str(input.created_at);
            diesel::sql_query(
                "INSERT INTO yauth_invitations \
                 (id, organization_id, email, role, token_hash, invited_by_user_id, expires_at, accepted_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&oid)
            .bind::<diesel::sql_types::Text, _>(&input.email)
            .bind::<diesel::sql_types::Text, _>(&input.role)
            .bind::<diesel::sql_types::Text, _>(&input.token_hash)
            .bind::<diesel::sql_types::Text, _>(&invited_by)
            .bind::<diesel::sql_types::Text, _>(&expires_at)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&accepted_at)
            .bind::<diesel::sql_types::Text, _>(&created_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_sqlite)?;

            let row: LibsqlInvitation = yauth_invitations::table
                .find(&id)
                .select(LibsqlInvitation::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            row.into_domain()
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
            // Re-marking an already-accepted row affects zero rows.
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
            let row: LibsqlInvitation = yauth_invitations::table
                .find(&id_str)
                .select(LibsqlInvitation::as_select())
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
            let oid = uuid_to_str(organization_id);
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let rows: Vec<LibsqlInvitation> = yauth_invitations::table
                .filter(yauth_invitations::organization_id.eq(Some(&oid)))
                .filter(yauth_invitations::accepted_at.is_null())
                .filter(yauth_invitations::expires_at.gt(&now))
                .order(yauth_invitations::created_at.asc())
                .select(LibsqlInvitation::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(LibsqlInvitation::into_domain)
                .collect()
        })
    }
}
