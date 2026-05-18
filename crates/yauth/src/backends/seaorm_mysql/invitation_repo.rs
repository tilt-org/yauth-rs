//! SeaORM-MySQL implementation of `InvitationRepository`.
//!
//! Mirrors the canonical diesel-pg semantics:
//!
//! - `find_by_token_hash` filters out expired AND already-accepted invitations
//!   at the query level so callers can trust a `Some(_)` is live.
//! - `mark_accepted` is single-shot: an UPDATE with `WHERE accepted_at IS NULL`
//!   touches zero rows on a second call and surfaces as `RepoError::NotFound`.
//! - `token_hash` has a UNIQUE constraint in the migration, so a duplicate
//!   insert surfaces as `RepoError::Conflict` via `sea_conflict`.
//! - `delete` is idempotent — removing a missing invitation returns `Ok(())`.

use chrono::NaiveDateTime;
use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, QueryOrder, Set};
use uuid::Uuid;

use super::entities::invitations;
use super::{sea_conflict, sea_err, to_tz};
use crate::backends::seaorm_common::str_to_uuid;
use crate::domain;
use crate::repo::{InvitationRepository, RepoError, RepoFuture, sealed};

fn invitation_into_domain(m: invitations::Model) -> Result<domain::Invitation, RepoError> {
    let organization_id = m
        .organization_id
        .as_deref()
        .map(str_to_uuid)
        .ok_or_else(|| {
            RepoError::Internal("invitation row has NULL organization_id (data corruption)".into())
        })?;
    let invited_by_user_id = m
        .invited_by_user_id
        .as_deref()
        .map(str_to_uuid)
        .ok_or_else(|| {
            RepoError::Internal(
                "invitation row has NULL invited_by_user_id (data corruption)".into(),
            )
        })?;
    Ok(domain::Invitation {
        id: str_to_uuid(&m.id),
        organization_id,
        email: m.email,
        role: m.role,
        token_hash: m.token_hash,
        invited_by_user_id,
        expires_at: m.expires_at.naive_utc(),
        accepted_at: m.accepted_at.map(|d| d.naive_utc()),
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
            let row = invitations::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(invitation_into_domain).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            // Trait contract: only Some(_) for live tokens. Filter out
            // already-accepted + expired at the query level.
            let now = to_tz(chrono::Utc::now().naive_utc());
            let row = invitations::Entity::find()
                .filter(invitations::Column::TokenHash.eq(token_hash))
                .filter(invitations::Column::AcceptedAt.is_null())
                .filter(invitations::Column::ExpiresAt.gt(now))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            row.map(invitation_into_domain).transpose()
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
                expires_at: Set(to_tz(input.expires_at)),
                accepted_at: Set(input.accepted_at.map(to_tz)),
                created_at: Set(to_tz(input.created_at)),
            };
            let result = model.insert(&self.db).await.map_err(sea_conflict)?;
            invitation_into_domain(result)
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            // Single-shot semantics: only flip `accepted_at` when it's still
            // NULL. Use UPDATE ... WHERE id = ? AND accepted_at IS NULL so a
            // second call touches zero rows. MySQL has no RETURNING, so we
            // re-read after the update on success.
            let res = invitations::Entity::update_many()
                .col_expr(
                    invitations::Column::AcceptedAt,
                    Expr::value(Some(to_tz(accepted_at))),
                )
                .filter(invitations::Column::Id.eq(id.to_string()))
                .filter(invitations::Column::AcceptedAt.is_null())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            if res.rows_affected == 0 {
                return Err(RepoError::NotFound);
            }
            let row = invitations::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?
                .ok_or(RepoError::NotFound)?;
            invitation_into_domain(row)
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
            let now = to_tz(chrono::Utc::now().naive_utc());
            let rows = invitations::Entity::find()
                .filter(invitations::Column::OrganizationId.eq(organization_id.to_string()))
                .filter(invitations::Column::AcceptedAt.is_null())
                .filter(invitations::Column::ExpiresAt.gt(now))
                .order_by_asc(invitations::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            rows.into_iter().map(invitation_into_domain).collect()
        })
    }
}
