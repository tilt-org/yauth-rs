//! SeaORM-SQLite implementation of `InvitationRepository`.
//!
//! - `find_by_token_hash` filters out expired AND already-accepted rows at
//!   the query level. Callers rely on a `Some(_)` result being live.
//! - `mark_accepted` is single-shot: an UPDATE with a `WHERE accepted_at IS
//!   NULL` clause. The second call touches zero rows and returns
//!   `RepoError::NotFound`, matching diesel-pg + memory.
//! - `token_hash` has a UNIQUE index in the SQLite DDL, so duplicate inserts
//!   surface as `RepoError::Conflict` via `sea_conflict`.

use chrono::NaiveDateTime;
use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, ColumnTrait, QueryOrder, Set};
use uuid::Uuid;

use super::entities::invitations;
use super::{sea_conflict, sea_err};
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};

pub(crate) struct SeaOrmInvitationRepo {
    db: DatabaseConnection,
}

impl SeaOrmInvitationRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmInvitationRepo {}

impl InvitationRepository for SeaOrmInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let row = invitations::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(|m| m.into_domain()).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = chrono::Utc::now().naive_utc();
            let row = invitations::Entity::find()
                .filter(invitations::Column::TokenHash.eq(token_hash))
                .filter(invitations::Column::AcceptedAt.is_null())
                .filter(invitations::Column::ExpiresAt.gt(super::to_tz(now)))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(|m| m.into_domain()).transpose()
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let model = invitations::ActiveModel {
                id: Set(input.id.to_string()),
                organization_id: Set(Some(input.organization_id.to_string())),
                email: Set(input.email),
                role: Set(input.role),
                token_hash: Set(input.token_hash),
                invited_by_user_id: Set(Some(input.invited_by_user_id.to_string())),
                expires_at: Set(super::to_tz(input.expires_at)),
                accepted_at: Set(super::opt_to_tz(input.accepted_at)),
                created_at: Set(super::to_tz(input.created_at)),
            };
            let result = model.insert(&self.db).await.map_err(sea_conflict)?;
            result.into_domain()
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            // Single-shot: only flip accepted_at while it's NULL.
            let update_result = invitations::Entity::update_many()
                .col_expr(
                    invitations::Column::AcceptedAt,
                    sea_orm::sea_query::Expr::value(super::to_tz(accepted_at)),
                )
                .filter(invitations::Column::Id.eq(id.to_string()))
                .filter(invitations::Column::AcceptedAt.is_null())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            if update_result.rows_affected == 0 {
                return Err(RepoError::NotFound);
            }
            // Re-read the row to return the fresh state.
            let row = invitations::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?
                .ok_or(RepoError::NotFound)?;
            row.into_domain()
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            invitations::Entity::delete_by_id(id.to_string())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn list_pending_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::Invitation>> {
        Box::pin(async move {
            let now = chrono::Utc::now().naive_utc();
            let rows = invitations::Entity::find()
                .filter(invitations::Column::OrganizationId.eq(Some(organization_id.to_string())))
                .filter(invitations::Column::AcceptedAt.is_null())
                .filter(invitations::Column::ExpiresAt.gt(super::to_tz(now)))
                .order_by_asc(invitations::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            rows.into_iter().map(|m| m.into_domain()).collect()
        })
    }
}
