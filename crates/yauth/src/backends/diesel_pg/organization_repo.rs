//! Diesel-PG implementation of `OrganizationRepository`.
//!
//! Canonical reference impl for the SQL backends — every other ORM/dialect
//! repo should mirror these semantics:
//!
//! - **Case-insensitive slug uniqueness.** Enforced both at the DB level
//!   (`UNIQUE` on `slug`) and via `LOWER(slug) = LOWER($1)` in lookups so a
//!   slug like `"Acme"` is the same identifier as `"acme"`.
//! - **Cascade delete.** FKs on `yauth_memberships.organization_id` and
//!   `yauth_invitations.organization_id` are `ON DELETE CASCADE`, so a single
//!   `DELETE FROM yauth_organizations WHERE id = $1` tears down the whole
//!   tenant graph.
//! - **Conflict mapping.** A unique-violation from PG surfaces as
//!   `RepoError::Conflict(...)`, not a 500.

use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::schema::yauth_organizations;
use crate::backends::diesel_common::{diesel_conflict, diesel_err, get_conn};
use crate::domain;
use crate::repo::{OrganizationRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

// ──────────────────────────────────────────────
// Diesel-annotated row + insert/update models
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_organizations)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct DieselOrganization {
    id: Uuid,
    name: String,
    slug: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl DieselOrganization {
    fn into_domain(self) -> domain::Organization {
        domain::Organization {
            id: self.id,
            name: self.name,
            slug: self.slug,
            display_name: self.display_name,
            avatar_url: self.avatar_url,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = yauth_organizations)]
struct DieselNewOrganization {
    id: Uuid,
    name: String,
    slug: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl DieselNewOrganization {
    fn from_domain(input: domain::NewOrganization) -> Self {
        Self {
            id: input.id,
            name: input.name,
            slug: input.slug,
            display_name: input.display_name,
            avatar_url: input.avatar_url,
            metadata: input.metadata,
            created_at: input.created_at,
            updated_at: input.updated_at,
        }
    }
}

#[derive(Debug, Clone, AsChangeset, Default)]
#[diesel(table_name = yauth_organizations)]
struct DieselUpdateOrganization {
    name: Option<String>,
    slug: Option<String>,
    // `Option<Option<T>>` is diesel's idiom for "explicitly set to NULL"
    // vs "leave column alone": Some(None) writes NULL, None leaves it.
    display_name: Option<Option<String>>,
    avatar_url: Option<Option<String>>,
    metadata: Option<Option<serde_json::Value>>,
    updated_at: Option<NaiveDateTime>,
}

impl DieselUpdateOrganization {
    fn from_domain(input: domain::UpdateOrganization) -> Self {
        Self {
            name: input.name,
            slug: input.slug,
            display_name: input.display_name,
            avatar_url: input.avatar_url,
            metadata: input.metadata,
            updated_at: input.updated_at,
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct DieselOrganizationRepo {
    pool: DbPool,
}

impl DieselOrganizationRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselOrganizationRepo {}

impl OrganizationRepository for DieselOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let row: Option<DieselOrganization> = yauth_organizations::table
                .find(id)
                .select(DieselOrganization::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(row.map(DieselOrganization::into_domain))
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug = slug.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Case-insensitive slug lookup per trait contract. `ILIKE` is
            // exact (no wildcard) here — the slug is escaped by the parameter
            // binder, not interpolated.
            let row: Option<DieselOrganization> = yauth_organizations::table
                .filter(yauth_organizations::slug.ilike(&slug))
                .select(DieselOrganization::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(row.map(DieselOrganization::into_domain))
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let row: DieselOrganization = diesel::insert_into(yauth_organizations::table)
                .values(&DieselNewOrganization::from_domain(input))
                .returning(DieselOrganization::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(diesel_conflict)?;
            Ok(row.into_domain())
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganization,
    ) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let row: DieselOrganization = diesel::update(yauth_organizations::table.find(id))
                .set(&DieselUpdateOrganization::from_domain(changes))
                .returning(DieselOrganization::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(|e| match e {
                    diesel::result::Error::NotFound => RepoError::NotFound,
                    other => diesel_conflict(other),
                })?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Cascade to memberships + invitations is handled by the FK
            // ON DELETE CASCADE in the migration. A missing row is reported
            // as `NotFound` to mirror the memory backend's semantics.
            let affected = diesel::delete(yauth_organizations::table.find(id))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            if affected == 0 {
                return Err(RepoError::NotFound);
            }
            Ok(())
        })
    }

    fn list_for_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Organization>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Two-step instead of inner-join: collect the org-ids this user
            // belongs to, then `WHERE id IN (...)`. Avoids needing
            // `allow_tables_to_appear_in_same_query!` for memberships×orgs
            // and keeps the membership FK nullability irrelevant here.
            use super::schema::yauth_memberships;
            let org_ids: Vec<Option<Uuid>> = yauth_memberships::table
                .filter(yauth_memberships::user_id.eq(Some(user_id)))
                .select(yauth_memberships::organization_id)
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            let org_ids: Vec<Uuid> = org_ids.into_iter().flatten().collect();
            if org_ids.is_empty() {
                return Ok(Vec::new());
            }
            let rows: Vec<DieselOrganization> = yauth_organizations::table
                .filter(yauth_organizations::id.eq_any(&org_ids))
                .order(yauth_organizations::created_at.asc())
                .select(DieselOrganization::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(rows
                .into_iter()
                .map(DieselOrganization::into_domain)
                .collect())
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
            let mut conn = get_conn(&self.pool).await?;
            let total: i64 = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                yauth_organizations::table
                    .filter(
                        yauth_organizations::name
                            .ilike(pattern.clone())
                            .or(yauth_organizations::slug.ilike(pattern)),
                    )
                    .count()
                    .get_result(&mut conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_organizations::table
                    .count()
                    .get_result(&mut conn)
                    .await
                    .map_err(diesel_err)?
            };

            let rows: Vec<DieselOrganization> = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                yauth_organizations::table
                    .filter(
                        yauth_organizations::name
                            .ilike(pattern.clone())
                            .or(yauth_organizations::slug.ilike(pattern)),
                    )
                    .order(yauth_organizations::created_at.asc())
                    .limit(limit)
                    .offset(offset)
                    .select(DieselOrganization::as_select())
                    .load(&mut conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_organizations::table
                    .order(yauth_organizations::created_at.asc())
                    .limit(limit)
                    .offset(offset)
                    .select(DieselOrganization::as_select())
                    .load(&mut conn)
                    .await
                    .map_err(diesel_err)?
            };

            Ok((
                rows.into_iter()
                    .map(DieselOrganization::into_domain)
                    .collect(),
                total,
            ))
        })
    }
}
