//! Diesel native-SQLite implementation of `MembershipRepository`.
//!
//! Mirrors `diesel_pg::membership_repo` with the SQLite divergences from
//! `mod.rs`: TEXT-encoded UUIDs/timestamps, no `RETURNING` (insert/update
//! then SELECT), and the same preflight uniqueness check for
//! `(organization_id, user_id)` since the migration carries no composite
//! UNIQUE today.
//!
//! The schema declares `organization_id` and `user_id` as nullable to match
//! the cross-dialect FK generator's `ON DELETE CASCADE` shape. Every row
//! logically carries both keys; a NULL on read means data corruption and
//! surfaces as `RepoError::Internal`.

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::SqlitePool;
use super::models::{dt_to_str, opt_dt_to_str, opt_str_to_dt, str_to_dt, str_to_uuid, uuid_to_str};
use super::schema::yauth_memberships;
use crate::backends::diesel_common::{diesel_conflict_sqlite, diesel_err, get_conn};
use crate::domain;
use crate::repo::{MembershipRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row + insert/update models
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_memberships)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct SqliteMembership {
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

impl SqliteMembership {
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

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = yauth_memberships)]
struct SqliteNewMembership {
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

impl SqliteNewMembership {
    fn from_domain(input: domain::NewMembership) -> Self {
        Self {
            id: uuid_to_str(input.id),
            organization_id: Some(uuid_to_str(input.organization_id)),
            user_id: Some(uuid_to_str(input.user_id)),
            role: input.role,
            status: input.status.as_str().to_string(),
            invited_at: opt_dt_to_str(input.invited_at),
            joined_at: opt_dt_to_str(input.joined_at),
            created_at: dt_to_str(input.created_at),
            updated_at: dt_to_str(input.updated_at),
        }
    }
}

#[derive(Debug, Clone, AsChangeset, Default)]
#[diesel(table_name = yauth_memberships)]
struct SqliteUpdateMembership {
    role: Option<String>,
    status: Option<String>,
    joined_at: Option<Option<String>>,
    updated_at: Option<String>,
}

impl SqliteUpdateMembership {
    fn from_domain(input: domain::UpdateMembership) -> Self {
        Self {
            role: input.role,
            status: input.status.map(|s| s.as_str().to_string()),
            joined_at: input.joined_at.map(|opt| opt.map(dt_to_str)),
            updated_at: input.updated_at.map(dt_to_str),
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqliteMembershipRepo {
    pool: SqlitePool,
}

impl SqliteMembershipRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqliteMembershipRepo {}

impl MembershipRepository for SqliteMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<SqliteMembership> = yauth_memberships::table
                .find(&id_str)
                .select(SqliteMembership::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(SqliteMembership::into_domain).transpose()
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
            let user_str = uuid_to_str(user_id);
            let row: Option<SqliteMembership> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&org_str)))
                .filter(yauth_memberships::user_id.eq(Some(&user_str)))
                .select(SqliteMembership::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(SqliteMembership::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Preflight: the migration does not (yet) carry a composite UNIQUE
            // on (organization_id, user_id), so we look up first and surface
            // a typed `Conflict` matching the memory backend's behaviour.
            let org_str = uuid_to_str(input.organization_id);
            let user_str = uuid_to_str(input.user_id);
            let existing: Option<String> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&org_str)))
                .filter(yauth_memberships::user_id.eq(Some(&user_str)))
                .select(yauth_memberships::id)
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            let row = SqliteNewMembership::from_domain(input);
            let id = row.id.clone();
            diesel::insert_into(yauth_memberships::table)
                .values(&row)
                .execute(&mut *conn)
                .await
                .map_err(diesel_conflict_sqlite)?;

            let inserted: SqliteMembership = yauth_memberships::table
                .find(&id)
                .select(SqliteMembership::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            inserted.into_domain()
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
            let sqlite_changes = SqliteUpdateMembership::from_domain(changes);
            let affected = diesel::update(yauth_memberships::table.find(&id_str))
                .set(&sqlite_changes)
                .execute(&mut *conn)
                .await
                .map_err(diesel_err)?;
            if affected == 0 {
                return Err(RepoError::NotFound);
            }
            let inserted: SqliteMembership = yauth_memberships::table
                .find(&id_str)
                .select(SqliteMembership::as_select())
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
            // Idempotent — deleting a missing membership returns Ok(()), per
            // trait contract.
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
            let rows: Vec<SqliteMembership> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(&org_str)))
                .order(yauth_memberships::created_at.asc())
                .select(SqliteMembership::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(SqliteMembership::into_domain)
                .collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let user_str = uuid_to_str(user_id);
            let rows: Vec<SqliteMembership> = yauth_memberships::table
                .filter(yauth_memberships::user_id.eq(Some(&user_str)))
                .order(yauth_memberships::created_at.asc())
                .select(SqliteMembership::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(SqliteMembership::into_domain)
                .collect()
        })
    }
}
