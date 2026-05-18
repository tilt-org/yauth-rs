//! SeaORM-SQLite implementation of `MembershipRepository`.
//!
//! Notes (mirrors diesel-pg semantics):
//!
//! - `(organization_id, user_id)` uniqueness is not enforced by the migration,
//!   so `create` does a preflight `SELECT` to match the trait contract. When
//!   a UNIQUE index lands the preflight can stay (1 extra round-trip but
//!   never lies).
//! - FK columns are nullable in the migration; we treat NULL on read as data
//!   corruption (see `entities::memberships`).

use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, QueryOrder, Set};
use uuid::Uuid;

use super::entities::memberships;
use super::{sea_conflict, sea_err};
use crate::domain;
use crate::repo::{MembershipRepository, RepoError, RepoFuture, sealed};

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
            let row = memberships::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(|m| m.into_domain()).transpose()
        })
    }

    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let row = memberships::Entity::find()
                .filter(memberships::Column::OrganizationId.eq(Some(organization_id.to_string())))
                .filter(memberships::Column::UserId.eq(Some(user_id.to_string())))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(|m| m.into_domain()).transpose()
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            // Preflight uniqueness check on (organization_id, user_id) -- the
            // migration does not declare a composite UNIQUE yet, so we
            // enforce the contract here.
            let existing = memberships::Entity::find()
                .filter(
                    memberships::Column::OrganizationId.eq(Some(input.organization_id.to_string())),
                )
                .filter(memberships::Column::UserId.eq(Some(input.user_id.to_string())))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            let model = memberships::ActiveModel {
                id: Set(input.id.to_string()),
                organization_id: Set(Some(input.organization_id.to_string())),
                user_id: Set(Some(input.user_id.to_string())),
                role: Set(input.role),
                status: Set(input.status.as_str().to_string()),
                invited_at: Set(super::opt_to_tz(input.invited_at)),
                joined_at: Set(super::opt_to_tz(input.joined_at)),
                created_at: Set(super::to_tz(input.created_at)),
                updated_at: Set(super::to_tz(input.updated_at)),
            };
            let result = model.insert(&self.db).await.map_err(sea_conflict)?;
            result.into_domain()
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let existing = memberships::Entity::find_by_id(id.to_string())
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
                model.joined_at = Set(super::opt_to_tz(joined_at));
            }
            if let Some(updated_at) = changes.updated_at {
                model.updated_at = Set(super::to_tz(updated_at));
            }

            let result = model.update(&self.db).await.map_err(sea_err)?;
            result.into_domain()
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Idempotent -- removing a missing membership returns Ok(()).
            memberships::Entity::delete_by_id(id.to_string())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let rows = memberships::Entity::find()
                .filter(memberships::Column::OrganizationId.eq(Some(organization_id.to_string())))
                .order_by_asc(memberships::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            rows.into_iter().map(|m| m.into_domain()).collect()
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let rows = memberships::Entity::find()
                .filter(memberships::Column::UserId.eq(Some(user_id.to_string())))
                .order_by_asc(memberships::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            rows.into_iter().map(|m| m.into_domain()).collect()
        })
    }
}
