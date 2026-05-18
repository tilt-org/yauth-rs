//! SeaORM-SQLite implementation of `OrganizationRepository`.
//!
//! Mirrors the diesel-pg canonical impl, adapted for SQLite quirks:
//!
//! - UUIDs are stored as TEXT (per `generate_sqlite_ddl`); we hold them as
//!   `String` on the model and parse at the domain boundary.
//! - JSON `metadata` is stored as a TEXT blob -- serialized on insert,
//!   parsed back on read.
//! - Case-insensitive slug lookup uses `LOWER(slug) = LOWER($1)`. SQLite's
//!   built-in `LOWER()` is ASCII-only, which matches our slug character set
//!   (URL-safe ASCII). Matches the pattern used by `user_repo.rs` for emails.
//! - Cascade delete is enforced by FK `ON DELETE CASCADE` in the schema,
//!   which requires `PRAGMA foreign_keys = ON`. The test harness and the
//!   generated DDL both set that; production callers should mirror it on
//!   connection setup.

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
            // Preflight case-insensitive uniqueness check. SQLite's UNIQUE on
            // `slug` is case-sensitive, but the trait contract requires the
            // primitive to be case-insensitive. Mirrors the memory backend.
            let slug_lower = input.slug.to_lowercase();
            let existing = organizations::Entity::find()
                .filter(
                    Expr::expr(Func::lower(Expr::col(organizations::Column::Slug)))
                        .eq(slug_lower.clone()),
                )
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(format!(
                    "organization slug '{}' already exists",
                    input.slug
                )));
            }

            let metadata_text = match input.metadata {
                Some(v) => Some(serde_json::to_string(&v).map_err(|e| {
                    RepoError::Internal(
                        format!("failed to serialize organization metadata: {e}").into(),
                    )
                })?),
                None => None,
            };

            let model = organizations::ActiveModel {
                id: Set(input.id.to_string()),
                name: Set(input.name),
                slug: Set(input.slug),
                display_name: Set(input.display_name),
                avatar_url: Set(input.avatar_url),
                metadata: Set(metadata_text),
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
            // Preflight: when renaming the slug, ensure no other org owns it
            // (case-insensitive). Memory backend has the same guard.
            if let Some(new_slug) = &changes.slug {
                let new_lower = new_slug.to_lowercase();
                let conflict = organizations::Entity::find()
                    .filter(
                        Expr::expr(Func::lower(Expr::col(organizations::Column::Slug)))
                            .eq(new_lower),
                    )
                    .filter(organizations::Column::Id.ne(id.to_string()))
                    .one(&self.db)
                    .await
                    .map_err(sea_err)?;
                if conflict.is_some() {
                    return Err(RepoError::Conflict(format!(
                        "organization slug '{new_slug}' already exists"
                    )));
                }
            }

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
                let text = match metadata {
                    Some(v) => Some(serde_json::to_string(&v).map_err(|e| {
                        RepoError::Internal(
                            format!("failed to serialize organization metadata: {e}").into(),
                        )
                    })?),
                    None => None,
                };
                model.metadata = Set(text);
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
            // Cascade to memberships + invitations is enforced by FK
            // ON DELETE CASCADE in the SQLite schema. Requires
            // `PRAGMA foreign_keys = ON` on the connection.
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
            // Two-step: collect org ids from memberships, then load orgs.
            // Mirrors diesel_pg; avoids needing a Related<> for memberships.
            let membership_rows = memberships::Entity::find()
                .filter(memberships::Column::UserId.eq(Some(user_id.to_string())))
                .all(&self.db)
                .await
                .map_err(sea_err)?;

            let mut org_ids: Vec<String> = membership_rows
                .into_iter()
                .filter_map(|m| m.organization_id)
                .collect();
            org_ids.sort();
            org_ids.dedup();
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
                .limit(Some(std::cmp::Ord::max(limit, 0) as u64))
                .offset(Some(std::cmp::Ord::max(offset, 0) as u64))
                .all(&self.db)
                .await
                .map_err(sea_err)?;

            Ok((rows.into_iter().map(|m| m.into_domain()).collect(), total))
        })
    }
}
