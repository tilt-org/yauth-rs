//! SeaORM-PG implementation of `OrganizationRepository`.
//!
//! Mirrors the canonical diesel-pg semantics (see
//! `crates/yauth/src/backends/diesel_pg/organization_repo.rs`):
//!
//! - **Case-insensitive slug uniqueness.** Enforced at the DB level (`UNIQUE`
//!   on `slug`) and via `LOWER(slug) = LOWER($1)` in lookups so `"Acme"` and
//!   `"acme"` resolve to the same row.
//! - **Cascade delete.** FKs on `yauth_memberships.organization_id` and
//!   `yauth_invitations.organization_id` are `ON DELETE CASCADE`, so a single
//!   `DELETE FROM yauth_organizations` tears down the whole tenant graph.
//! - **Conflict mapping.** Unique-violations surface as `RepoError::Conflict`.

use sea_orm::prelude::*;
use sea_orm::sea_query::{Expr, Func};
use sea_orm::{ActiveModelTrait, ExprTrait, QueryOrder, QuerySelect, Set};
use uuid::Uuid;

use super::entities::{memberships, organizations};
use super::{sea_conflict, sea_err};
use crate::domain;
use crate::repo::{OrganizationRepository, RepoError, RepoFuture, sealed};

pub(crate) struct SeaOrmOrganizationRepo {
    db: DatabaseConnection,
}

impl SeaOrmOrganizationRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmOrganizationRepo {}

impl OrganizationRepository for SeaOrmOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let row = organizations::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug = slug.to_lowercase();
        Box::pin(async move {
            // Case-insensitive slug lookup per trait contract — compare
            // LOWER(slug) = LOWER($1). DB UNIQUE on slug is case-sensitive,
            // but the repo contract is case-insensitive on the lookup.
            let row = organizations::Entity::find()
                .filter(Expr::expr(Func::lower(Expr::col(organizations::Column::Slug))).eq(slug))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let model = organizations::ActiveModel {
                id: Set(input.id),
                name: Set(input.name),
                slug: Set(input.slug),
                display_name: Set(input.display_name),
                avatar_url: Set(input.avatar_url),
                metadata: Set(input.metadata),
                created_at: Set(super::to_tz(input.created_at)),
                updated_at: Set(super::to_tz(input.updated_at)),
            };
            let result = model.insert(&self.db).await.map_err(sea_conflict)?;
            Ok(result.into_domain())
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganization,
    ) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let existing = organizations::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .map_err(sea_err)?
                .ok_or(RepoError::NotFound)?;

            let mut model: organizations::ActiveModel = existing.into();

            if let Some(name) = changes.name {
                model.name = Set(name);
            }
            if let Some(slug) = changes.slug {
                model.slug = Set(slug);
            }
            if let Some(display_name) = changes.display_name {
                model.display_name = Set(display_name);
            }
            if let Some(avatar_url) = changes.avatar_url {
                model.avatar_url = Set(avatar_url);
            }
            if let Some(metadata) = changes.metadata {
                model.metadata = Set(metadata);
            }
            if let Some(updated_at) = changes.updated_at {
                model.updated_at = Set(super::to_tz(updated_at));
            }

            let result = model.update(&self.db).await.map_err(sea_conflict)?;
            Ok(result.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Cascade to memberships + invitations is handled by FK
            // ON DELETE CASCADE in the migration. A missing row is reported
            // as NotFound to mirror the memory + diesel-pg semantics.
            //
            // Use `delete_many().filter(id=$1)` rather than `delete_by_id`:
            // some sea-orm/sqlx revisions don't populate `rows_affected` for
            // `delete_by_id`, which makes the NotFound branch unreachable.
            let result = organizations::Entity::delete_many()
                .filter(organizations::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            if result.rows_affected == 0 {
                return Err(RepoError::NotFound);
            }
            Ok(())
        })
    }

    fn list_for_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Organization>> {
        Box::pin(async move {
            // Two-step lookup: collect the org-ids this user belongs to, then
            // load the orgs. Matches the diesel-pg pattern and keeps the
            // nullable membership FKs out of the join.
            let org_ids: Vec<Option<Uuid>> = memberships::Entity::find()
                .filter(memberships::Column::UserId.eq(user_id))
                .select_only()
                .column(memberships::Column::OrganizationId)
                .into_tuple()
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            let org_ids: Vec<Uuid> = org_ids.into_iter().flatten().collect();
            if org_ids.is_empty() {
                return Ok(Vec::new());
            }
            let rows = organizations::Entity::find()
                .filter(organizations::Column::Id.is_in(org_ids))
                .order_by_asc(organizations::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows.into_iter().map(|m| m.into_domain()).collect())
        })
    }

    fn list(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::Organization>, i64)> {
        let search = search.map(|s| s.to_string());
        Box::pin(async move {
            let mut query = organizations::Entity::find();

            if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                query = query.filter(
                    Expr::expr(Func::lower(Expr::col(organizations::Column::Name)))
                        .like(pattern.clone())
                        .or(
                            Expr::expr(Func::lower(Expr::col(organizations::Column::Slug)))
                                .like(pattern),
                        ),
                );
            }

            let total = query.clone().count(&self.db).await.map_err(sea_err)? as i64;

            let rows = query
                .order_by_asc(organizations::Column::CreatedAt)
                .limit(Some(limit as u64))
                .offset(Some(offset as u64))
                .all(&self.db)
                .await
                .map_err(sea_err)?;

            Ok((rows.into_iter().map(|m| m.into_domain()).collect(), total))
        })
    }
}
