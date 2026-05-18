//! Diesel-MySQL implementation of `MembershipRepository`.
//!
//! Mirrors `diesel_pg::membership_repo` (commit 3221c25) with MySQL twists:
//!
//! - UUID columns are CHAR(36) → `String` in the diesel model.
//! - `INSERT` then `SELECT` (no `RETURNING`).
//! - `Option<Option<NaiveDateTime>>` in the update changeset to disambiguate
//!   "leave column alone" from "explicit NULL", same as the PG impl.
//!
//! `(organization_id, user_id)` uniqueness is enforced by a preflight `SELECT`
//! since the migration does not (yet) carry a composite UNIQUE — see the
//! diesel-pg doc comment for the rationale.

use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::MysqlPool;
use super::schema::yauth_memberships;
use crate::backends::diesel_common::{
    diesel_conflict_mysql, diesel_err, get_conn, opt_str_to_uuid, str_to_uuid, uuid_to_str,
};
use crate::domain;
use crate::repo::{MembershipRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row + update model
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_memberships)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct MysqlMembership {
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

impl MysqlMembership {
    fn into_domain(self) -> Result<domain::Membership, RepoError> {
        // Migration declares FKs nullable for cross-dialect cascade support;
        // logically every membership row has both keys. NULL == data corruption.
        let organization_id = opt_str_to_uuid(self.organization_id).ok_or_else(|| {
            RepoError::Internal("membership row has NULL organization_id (data corruption)".into())
        })?;
        let user_id = opt_str_to_uuid(self.user_id).ok_or_else(|| {
            RepoError::Internal("membership row has NULL user_id (data corruption)".into())
        })?;
        let status = domain::MembershipStatus::parse(&self.status).ok_or_else(|| {
            RepoError::Internal(format!("unknown membership status: {:?}", self.status).into())
        })?;
        Ok(domain::Membership {
            id: str_to_uuid(&self.id),
            organization_id,
            user_id,
            role: self.role,
            status,
            invited_at: self.invited_at,
            joined_at: self.joined_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Clone, AsChangeset, Default)]
#[diesel(table_name = yauth_memberships)]
struct MysqlUpdateMembership {
    role: Option<String>,
    status: Option<String>,
    joined_at: Option<Option<NaiveDateTime>>,
    updated_at: Option<NaiveDateTime>,
}

impl MysqlUpdateMembership {
    fn from_domain(input: domain::UpdateMembership) -> Self {
        Self {
            role: input.role,
            status: input.status.map(|s| s.as_str().to_string()),
            joined_at: input.joined_at,
            updated_at: input.updated_at,
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct MysqlMembershipRepo {
    pool: MysqlPool,
}

impl MysqlMembershipRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for MysqlMembershipRepo {}

impl MembershipRepository for MysqlMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<MysqlMembership> = yauth_memberships::table
                .find(&id_str)
                .select(MysqlMembership::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(MysqlMembership::into_domain).transpose()
        })
    }

    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let org_str = uuid_to_str(organization_id);
            let usr_str = uuid_to_str(user_id);
            let row: Option<MysqlMembership> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&org_str)))
                .filter(yauth_memberships::user_id.eq(Some(&usr_str)))
                .select(MysqlMembership::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(MysqlMembership::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(input.id);
            let org_str = uuid_to_str(input.organization_id);
            let usr_str = uuid_to_str(input.user_id);
            let status_str = input.status.as_str().to_string();

            // Preflight uniqueness check — the migration does not yet carry
            // a composite UNIQUE on (organization_id, user_id), so we look
            // up first and surface a typed `Conflict` matching the memory
            // backend.
            let existing: Option<String> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&org_str)))
                .filter(yauth_memberships::user_id.eq(Some(&usr_str)))
                .select(yauth_memberships::id)
                .first::<String>(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            // MySQL has no RETURNING — INSERT then SELECT by known PK.
            diesel::sql_query(
                "INSERT INTO yauth_memberships \
                 (id, organization_id, user_id, role, status, invited_at, joined_at, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id_str)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(&org_str))
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(&usr_str))
            .bind::<diesel::sql_types::Text, _>(&input.role)
            .bind::<diesel::sql_types::Text, _>(&status_str)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Datetime>, _>(&input.invited_at)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Datetime>, _>(&input.joined_at)
            .bind::<diesel::sql_types::Datetime, _>(&input.created_at)
            .bind::<diesel::sql_types::Datetime, _>(&input.updated_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_mysql)?;

            let row: MysqlMembership = yauth_memberships::table
                .find(&id_str)
                .select(MysqlMembership::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            row.into_domain()
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let mysql_changes = MysqlUpdateMembership::from_domain(changes);

            let affected = diesel::update(yauth_memberships::table.find(&id_str))
                .set(&mysql_changes)
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;
            if affected == 0 {
                let exists: Option<String> = yauth_memberships::table
                    .find(&id_str)
                    .select(yauth_memberships::id)
                    .first::<String>(&mut *conn)
                    .await
                    .optional()
                    .map_err(diesel_err)?;
                if exists.is_none() {
                    return Err(RepoError::NotFound);
                }
            }

            let row: MysqlMembership = yauth_memberships::table
                .find(&id_str)
                .select(MysqlMembership::as_select())
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
            // Idempotent — deleting a missing membership returns Ok(()).
            diesel::delete(yauth_memberships::table.find(&id_str))
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let org_str = uuid_to_str(organization_id);
            let rows: Vec<MysqlMembership> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&org_str)))
                .order(yauth_memberships::created_at.asc())
                .select(MysqlMembership::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter().map(MysqlMembership::into_domain).collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let usr_str = uuid_to_str(user_id);
            let rows: Vec<MysqlMembership> = yauth_memberships::table
                .filter(yauth_memberships::user_id.eq(Some(&usr_str)))
                .order(yauth_memberships::created_at.asc())
                .select(MysqlMembership::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter().map(MysqlMembership::into_domain).collect()
        })
    }
}
