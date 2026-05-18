//! Diesel-libsql implementation of `MembershipRepository`.
//!
//! Mirrors the diesel-pg canonical impl with the same nullable-FK caveat:
//! `organization_id` / `user_id` are `Nullable<Text>` in the schema because the
//! cross-dialect plugin generator emits nullable FKs with `ON DELETE CASCADE`.
//! The domain types are non-nullable; a NULL value here is data corruption and
//! surfaces as `RepoError::Internal`.
//!
//! `(organization_id, user_id)` uniqueness is not enforced by the migration —
//! the repo does a preflight `SELECT` matching the memory + diesel-pg behaviour.

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::LibsqlPool;
use super::models::{dt_to_str, opt_dt_to_str, opt_str_to_dt, str_to_dt, str_to_uuid, uuid_to_str};
use super::schema::yauth_memberships;
use crate::backends::diesel_common::{diesel_conflict_sqlite, diesel_err, get_conn};
use crate::domain;
use crate::repo::{MembershipRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_memberships)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
struct LibsqlMembership {
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

impl LibsqlMembership {
    fn into_domain(self) -> Result<domain::Membership, RepoError> {
        let organization_id = self
            .organization_id
            .as_deref()
            .map(str_to_uuid)
            .ok_or_else(|| {
                RepoError::Internal(
                    "membership row has NULL organization_id (data corruption)".into(),
                )
            })?;
        let user_id = self.user_id.as_deref().map(str_to_uuid).ok_or_else(|| {
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
            invited_at: opt_str_to_dt(self.invited_at),
            joined_at: opt_str_to_dt(self.joined_at),
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        })
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct LibsqlMembershipRepo {
    pool: LibsqlPool,
}

impl LibsqlMembershipRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for LibsqlMembershipRepo {}

impl MembershipRepository for LibsqlMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<LibsqlMembership> = yauth_memberships::table
                .find(&id_str)
                .select(LibsqlMembership::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(LibsqlMembership::into_domain).transpose()
        })
    }

    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let oid = uuid_to_str(organization_id);
            let uid = uuid_to_str(user_id);
            let row: Option<LibsqlMembership> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&oid)))
                .filter(yauth_memberships::user_id.eq(Some(&uid)))
                .select(LibsqlMembership::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(LibsqlMembership::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let oid = uuid_to_str(input.organization_id);
            let uid = uuid_to_str(input.user_id);

            // Preflight uniqueness check — composite UNIQUE on
            // (organization_id, user_id) is not in the migration; this matches
            // the diesel-pg + memory contract.
            let existing: Option<String> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&oid)))
                .filter(yauth_memberships::user_id.eq(Some(&uid)))
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

            let id = uuid_to_str(input.id);
            let status = input.status.as_str().to_string();
            let invited_at = opt_dt_to_str(input.invited_at);
            let joined_at = opt_dt_to_str(input.joined_at);
            let created_at = dt_to_str(input.created_at);
            let updated_at = dt_to_str(input.updated_at);
            diesel::sql_query(
                "INSERT INTO yauth_memberships \
                 (id, organization_id, user_id, role, status, invited_at, joined_at, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&oid)
            .bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Text, _>(&input.role)
            .bind::<diesel::sql_types::Text, _>(&status)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&invited_at)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&joined_at)
            .bind::<diesel::sql_types::Text, _>(&created_at)
            .bind::<diesel::sql_types::Text, _>(&updated_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_sqlite)?;

            let row: LibsqlMembership = yauth_memberships::table
                .find(&id)
                .select(LibsqlMembership::as_select())
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

            if let Some(role) = changes.role {
                diesel::update(yauth_memberships::table.find(&id_str))
                    .set(yauth_memberships::role.eq(role))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
            }
            if let Some(status) = changes.status {
                diesel::update(yauth_memberships::table.find(&id_str))
                    .set(yauth_memberships::status.eq(status.as_str().to_string()))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
            }
            if let Some(joined_at) = changes.joined_at {
                diesel::update(yauth_memberships::table.find(&id_str))
                    .set(yauth_memberships::joined_at.eq(opt_dt_to_str(joined_at)))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
            }
            if let Some(updated_at) = changes.updated_at {
                diesel::update(yauth_memberships::table.find(&id_str))
                    .set(yauth_memberships::updated_at.eq(dt_to_str(updated_at)))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
            }

            let row: Option<LibsqlMembership> = yauth_memberships::table
                .find(&id_str)
                .select(LibsqlMembership::as_select())
                .first(&mut *conn)
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
            let id_str = uuid_to_str(id);
            // Idempotent — missing row returns Ok(()), per trait contract.
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
            let oid = uuid_to_str(organization_id);
            let rows: Vec<LibsqlMembership> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&oid)))
                .order(yauth_memberships::created_at.asc())
                .select(LibsqlMembership::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(LibsqlMembership::into_domain)
                .collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let rows: Vec<LibsqlMembership> = yauth_memberships::table
                .filter(yauth_memberships::user_id.eq(Some(&uid)))
                .order(yauth_memberships::created_at.asc())
                .select(LibsqlMembership::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(LibsqlMembership::into_domain)
                .collect()
        })
    }
}
