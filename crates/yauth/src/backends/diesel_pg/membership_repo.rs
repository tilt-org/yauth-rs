//! Diesel-PG implementation of `MembershipRepository`.
//!
//! Notes for follow-up backend agents:
//!
//! - The schema has `organization_id` and `user_id` as `Nullable<Uuid>` because
//!   the cross-dialect plugin schema generator currently emits nullable FKs
//!   with `ON DELETE CASCADE`. That is a quirk of how the cascade was
//!   declared, not a real semantic — the domain types are non-nullable and
//!   this repo treats `NULL` from a query as a corrupted row.
//! - `(organization_id, user_id)` uniqueness is **not** enforced by the
//!   migration today (no composite UNIQUE). The repo enforces it with a
//!   preflight `SELECT` inside `create`, mirroring the memory backend. This
//!   is the canonical pattern — when a UNIQUE index lands the preflight can
//!   stay (it costs one extra round-trip but never lies).

use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::schema::yauth_memberships;
use crate::backends::diesel_common::{diesel_conflict, diesel_err, get_conn};
use crate::domain;
use crate::repo::{MembershipRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

// ──────────────────────────────────────────────
// Diesel-annotated row + insert/update models
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_memberships)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct DieselMembership {
    id: Uuid,
    organization_id: Option<Uuid>,
    user_id: Option<Uuid>,
    role: String,
    status: String,
    invited_at: Option<NaiveDateTime>,
    joined_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl DieselMembership {
    fn into_domain(self) -> Result<domain::Membership, RepoError> {
        // Migration declares the FKs as nullable for cross-dialect cascade
        // support, but logically every membership row carries both keys.
        // A NULL here means data corruption — surface it as an Internal
        // error rather than silently dropping the row.
        let organization_id = self.organization_id.ok_or_else(|| {
            RepoError::Internal("membership row has NULL organization_id (data corruption)".into())
        })?;
        let user_id = self.user_id.ok_or_else(|| {
            RepoError::Internal("membership row has NULL user_id (data corruption)".into())
        })?;
        let status = domain::MembershipStatus::parse(&self.status).ok_or_else(|| {
            RepoError::Internal(format!("unknown membership status: {:?}", self.status).into())
        })?;
        Ok(domain::Membership {
            id: self.id,
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

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = yauth_memberships)]
struct DieselNewMembership {
    id: Uuid,
    organization_id: Option<Uuid>,
    user_id: Option<Uuid>,
    role: String,
    status: String,
    invited_at: Option<NaiveDateTime>,
    joined_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl DieselNewMembership {
    fn from_domain(input: domain::NewMembership) -> Self {
        Self {
            id: input.id,
            organization_id: Some(input.organization_id),
            user_id: Some(input.user_id),
            role: input.role,
            status: input.status.as_str().to_string(),
            invited_at: input.invited_at,
            joined_at: input.joined_at,
            created_at: input.created_at,
            updated_at: input.updated_at,
        }
    }
}

#[derive(Debug, Clone, AsChangeset, Default)]
#[diesel(table_name = yauth_memberships)]
struct DieselUpdateMembership {
    role: Option<String>,
    status: Option<String>,
    joined_at: Option<Option<NaiveDateTime>>,
    updated_at: Option<NaiveDateTime>,
}

impl DieselUpdateMembership {
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

pub(crate) struct DieselMembershipRepo {
    pool: DbPool,
}

impl DieselMembershipRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselMembershipRepo {}

impl MembershipRepository for DieselMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let row: Option<DieselMembership> = yauth_memberships::table
                .find(id)
                .select(DieselMembership::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(DieselMembership::into_domain).transpose()
        })
    }

    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let row: Option<DieselMembership> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(organization_id)))
                .filter(yauth_memberships::user_id.eq(Some(user_id)))
                .select(DieselMembership::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            row.map(DieselMembership::into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Preflight uniqueness check: the migration today does not enforce
            // a composite UNIQUE on (organization_id, user_id), so we look up
            // first and surface a typed Conflict if a row already exists.
            // The trait contract guarantees this; the SQL backend behaviour
            // must match the memory backend.
            let existing: Option<Uuid> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(input.organization_id)))
                .filter(yauth_memberships::user_id.eq(Some(input.user_id)))
                .select(yauth_memberships::id)
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            let row: DieselMembership = diesel::insert_into(yauth_memberships::table)
                .values(&DieselNewMembership::from_domain(input))
                .returning(DieselMembership::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(diesel_conflict)?;
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
            let row: DieselMembership = diesel::update(yauth_memberships::table.find(id))
                .set(&DieselUpdateMembership::from_domain(changes))
                .returning(DieselMembership::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(|e| match e {
                    diesel::result::Error::NotFound => RepoError::NotFound,
                    other => diesel_err(other),
                })?;
            row.into_domain()
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Idempotent — deleting a missing membership returns Ok(()), per
            // trait contract.
            diesel::delete(yauth_memberships::table.find(id))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let rows: Vec<DieselMembership> = yauth_memberships::table
                .filter(yauth_memberships::organization_id.eq(Some(organization_id)))
                .order(yauth_memberships::created_at.asc())
                .select(DieselMembership::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(DieselMembership::into_domain)
                .collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let rows: Vec<DieselMembership> = yauth_memberships::table
                .filter(yauth_memberships::user_id.eq(Some(user_id)))
                .order(yauth_memberships::created_at.asc())
                .select(DieselMembership::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            rows.into_iter()
                .map(DieselMembership::into_domain)
                .collect()
        })
    }
}
