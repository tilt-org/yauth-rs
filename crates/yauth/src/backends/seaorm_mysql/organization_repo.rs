//! SeaORM-MySQL implementation of `OrganizationRepository`.
//!
//! Mirrors the semantics of the canonical diesel-pg implementation
//! (commit 3221c25):
//!
//! - **Case-insensitive slug uniqueness.** Lookups via `LOWER(slug) = LOWER($1)`.
//!   MySQL's default `utf8mb4_0900_ai_ci` collation already compares case-
//!   insensitively, but spelling the lower() out keeps the contract explicit
//!   and survives collation drift.
//! - **Cascade delete.** FKs on `yauth_memberships.organization_id` and
//!   `yauth_invitations.organization_id` are declared `ON DELETE CASCADE` in the
//!   migration, so a single delete tears down the tenant graph.
//! - **Conflict mapping.** A unique-violation surfaces as
//!   `RepoError::Conflict(...)` via `sea_conflict`.
//! - **Cross-table list_for_user.** Two-step query (membership ids, then orgs)
//!   to avoid joining across feature-gated entities.

use sea_orm::prelude::*;
use sea_orm::sea_query::{Expr, Func};
use sea_orm::{ActiveModelTrait, ExprTrait, QueryOrder, QuerySelect, Set};
use uuid::Uuid;

use super::entities::{memberships, organizations};
use super::{sea_conflict, sea_err, to_tz};
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
            let row = organizations::Entity::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug = slug.to_lowercase();
        Box::pin(async move {
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
            // Preflight: enforce case-insensitive slug uniqueness even if the
            // column's collation is case-sensitive. The DB UNIQUE index on
            // `slug` will still catch exact-case dupes; this catches mixed-case.
            let slug_lc = input.slug.to_lowercase();
            let existing = organizations::Entity::find()
                .filter(
                    Expr::expr(Func::lower(Expr::col(organizations::Column::Slug)))
                        .eq(slug_lc.clone()),
                )
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(format!(
                    "organization slug already exists: {}",
                    input.slug
                )));
            }

            let model = organizations::ActiveModel {
                id: Set(input.id.to_string()),
                name: Set(input.name),
                slug: Set(input.slug),
                display_name: Set(input.display_name),
                avatar_url: Set(input.avatar_url),
                metadata: Set(input.metadata),
                created_at: Set(to_tz(input.created_at)),
                updated_at: Set(to_tz(input.updated_at)),
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
            let existing = organizations::Entity::find_by_id(id.to_string())
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
                model.updated_at = Set(to_tz(updated_at));
            }

            let result = model.update(&self.db).await.map_err(sea_conflict)?;
            Ok(result.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Cascade to memberships + invitations via FK ON DELETE CASCADE.
            // Missing row reported as NotFound to mirror diesel-pg.
            let result = organizations::Entity::delete_by_id(id.to_string())
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
            // Two-step: collect org-ids the user belongs to, then fetch orgs.
            // Avoids joining across entities and keeps the membership FK
            // nullability irrelevant here.
            let org_ids: Vec<Option<String>> = memberships::Entity::find()
                .filter(memberships::Column::UserId.eq(user_id.to_string()))
                .select_only()
                .column(memberships::Column::OrganizationId)
                .into_tuple()
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            let org_ids: Vec<String> = org_ids.into_iter().flatten().collect();
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
