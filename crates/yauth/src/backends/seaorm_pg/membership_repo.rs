//! SeaORM-PG implementation of `MembershipRepository`.
//!
//! Mirrors the canonical diesel-pg semantics (see
//! `crates/yauth/src/backends/diesel_pg/membership_repo.rs`):
//!
//! - The schema has `organization_id` and `user_id` as nullable FKs because
//!   the cross-dialect plugin schema generator emits nullable FKs with
//!   `ON DELETE CASCADE`. Domain types are non-nullable; `NULL` from a query
//!   is treated as data corruption.
//! - `(organization_id, user_id)` uniqueness is enforced at the repo layer
//!   via a preflight `SELECT` in `create`. The migration does not (yet) carry
//!   a composite UNIQUE; the preflight matches memory + diesel-pg behaviour
//!   and yields a typed `Conflict` instead of a 500.

use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, QueryOrder, Set};
use uuid::Uuid;

use super::entities::memberships;
use super::{opt_to_tz, sea_conflict, sea_err, to_tz};
use crate::domain;
use crate::repo::{MembershipRepository, RepoError, RepoFuture, sealed};

fn into_domain(m: memberships::Model) -> Result<domain::Membership, RepoError> {
    let organization_id = m.organization_id.ok_or_else(|| {
        RepoError::Internal("membership row has NULL organization_id (data corruption)".into())
    })?;
    let user_id = m.user_id.ok_or_else(|| {
        RepoError::Internal("membership row has NULL user_id (data corruption)".into())
    })?;
    let status = domain::MembershipStatus::parse(&m.status).ok_or_else(|| {
        RepoError::Internal(format!("unknown membership status: {:?}", m.status).into())
    })?;
    Ok(domain::Membership {
        id: m.id,
        organization_id,
        user_id,
        role: m.role,
        status,
        invited_at: m.invited_at.map(|dt| dt.naive_utc()),
        joined_at: m.joined_at.map(|dt| dt.naive_utc()),
        created_at: m.created_at.naive_utc(),
        updated_at: m.updated_at.naive_utc(),
    })
}

pub(crate) struct SeaOrmMembershipRepo {
    db: DatabaseConnection,
}

impl SeaOrmMembershipRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmMembershipRepo {}

impl MembershipRepository for SeaOrmMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let row = memberships::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(into_domain).transpose()
        })
    }

    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let row = memberships::Entity::find()
                .filter(memberships::Column::OrganizationId.eq(organization_id))
                .filter(memberships::Column::UserId.eq(user_id))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            // Preflight uniqueness: the migration does not enforce a composite
            // UNIQUE on (organization_id, user_id), so look up first and
            // surface a typed Conflict if a row already exists. Matches the
            // memory + diesel-pg behaviour.
            let dup = memberships::Entity::find()
                .filter(memberships::Column::OrganizationId.eq(input.organization_id))
                .filter(memberships::Column::UserId.eq(input.user_id))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            if dup.is_some() {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            let model = memberships::ActiveModel {
                id: Set(input.id),
                organization_id: Set(Some(input.organization_id)),
                user_id: Set(Some(input.user_id)),
                role: Set(input.role),
                status: Set(input.status.as_str().to_string()),
                invited_at: Set(opt_to_tz(input.invited_at)),
                joined_at: Set(opt_to_tz(input.joined_at)),
                created_at: Set(to_tz(input.created_at)),
                updated_at: Set(to_tz(input.updated_at)),
            };
            let result = model.insert(&self.db).await.map_err(sea_conflict)?;
            into_domain(result)
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let existing = memberships::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .map_err(sea_err)?
                .ok_or(RepoError::NotFound)?;

            let mut model: memberships::ActiveModel = existing.into();

            if let Some(role) = changes.role {
                model.role = Set(role);
            }
            if let Some(status) = changes.status {
                model.status = Set(status.as_str().to_string());
            }
            if let Some(joined_at) = changes.joined_at {
                model.joined_at = Set(opt_to_tz(joined_at));
            }
            if let Some(updated_at) = changes.updated_at {
                model.updated_at = Set(to_tz(updated_at));
            }

            let result = model.update(&self.db).await.map_err(sea_err)?;
            into_domain(result)
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Idempotent — deleting a missing membership returns Ok(()), per
            // trait contract.
            let _ = memberships::Entity::delete_by_id(id)
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let rows = memberships::Entity::find()
                .filter(memberships::Column::OrganizationId.eq(organization_id))
                .order_by_asc(memberships::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            rows.into_iter().map(into_domain).collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let rows = memberships::Entity::find()
                .filter(memberships::Column::UserId.eq(user_id))
                .order_by_asc(memberships::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            rows.into_iter().map(into_domain).collect()
        })
    }
}
