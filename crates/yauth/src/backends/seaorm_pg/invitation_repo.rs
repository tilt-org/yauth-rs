//! SeaORM-PG implementation of `InvitationRepository`.
//!
//! Mirrors the canonical diesel-pg semantics (see
//! `crates/yauth/src/backends/diesel_pg/invitation_repo.rs`):
//!
//! - `find_by_token_hash` filters out expired AND already-accepted invitations
//!   at the query level — callers rely on the contract that a `Some(_)` result
//!   is ready to consume.
//! - `mark_accepted` is single-shot: re-marking an already-accepted row
//!   returns `RepoError::NotFound`. Implemented with `update_many` filtered on
//!   `accepted_at IS NULL`; zero rows affected ⇒ NotFound.
//! - `token_hash` has a `UNIQUE` constraint in the migration, so a duplicate
//!   insert surfaces as `RepoError::Conflict` via `sea_conflict`.

use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, QueryOrder, Set};
use uuid::Uuid;

use super::entities::invitations;
use super::{sea_conflict, sea_err, to_tz};
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};

fn into_domain(m: invitations::Model) -> Result<domain::Invitation, RepoError> {
    let organization_id = m.organization_id.ok_or_else(|| {
        RepoError::Internal("invitation row has NULL organization_id (data corruption)".into())
    })?;
    let invited_by_user_id = m.invited_by_user_id.ok_or_else(|| {
        RepoError::Internal("invitation row has NULL invited_by_user_id (data corruption)".into())
    })?;
    Ok(domain::Invitation {
        id: m.id,
        organization_id,
        email: m.email,
        role: m.role,
        token_hash: m.token_hash,
        invited_by_user_id,
        expires_at: m.expires_at.naive_utc(),
        accepted_at: m.accepted_at.map(|dt| dt.naive_utc()),
        created_at: m.created_at.naive_utc(),
    })
}

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
            let row = invitations::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(into_domain).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            // Trait contract: only resolves to Some(_) for live tokens. Filter
            // expired + already-accepted at the query level.
            let now = chrono::Utc::now().fixed_offset();
            let row = invitations::Entity::find()
                .filter(invitations::Column::TokenHash.eq(token_hash))
                .filter(invitations::Column::AcceptedAt.is_null())
                .filter(invitations::Column::ExpiresAt.gt(now))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(into_domain).transpose()
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let model = invitations::ActiveModel {
                id: Set(input.id),
                organization_id: Set(Some(input.organization_id)),
                email: Set(input.email),
                role: Set(input.role),
                token_hash: Set(input.token_hash),
                invited_by_user_id: Set(Some(input.invited_by_user_id)),
                expires_at: Set(to_tz(input.expires_at)),
                accepted_at: Set(input.accepted_at.map(to_tz)),
                created_at: Set(to_tz(input.created_at)),
            };
            let result = model.insert(&self.db).await.map_err(sea_conflict)?;
            into_domain(result)
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: chrono::NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            // Single-shot semantics: UPDATE ... WHERE id = $1 AND accepted_at
            // IS NULL. Zero rows affected => NotFound (re-marking an already
            // accepted invitation), matching memory + diesel-pg.
            let accepted_tz = to_tz(accepted_at);
            let result = invitations::Entity::update_many()
                .col_expr(
                    invitations::Column::AcceptedAt,
                    Expr::value(Some(accepted_tz)),
                )
                .filter(invitations::Column::Id.eq(id))
                .filter(invitations::Column::AcceptedAt.is_null())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            if result.rows_affected == 0 {
                return Err(RepoError::NotFound);
            }
            // Reload so the caller sees the post-update state.
            let row = invitations::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .map_err(sea_err)?
                .ok_or(RepoError::NotFound)?;
            into_domain(row)
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let _ = invitations::Entity::delete_by_id(id)
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
            let now = chrono::Utc::now().fixed_offset();
            let rows = invitations::Entity::find()
                .filter(invitations::Column::OrganizationId.eq(organization_id))
                .filter(invitations::Column::AcceptedAt.is_null())
                .filter(invitations::Column::ExpiresAt.gt(now))
                .order_by_asc(invitations::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            rows.into_iter().map(into_domain).collect()
        })
    }
}
