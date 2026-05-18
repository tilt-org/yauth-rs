//! Diesel-libsql implementation of `OrganizationRepository`.
//!
//! Mirrors the diesel-pg canonical impl with the SQLite/libSQL-specific
//! adjustments documented in the backend module:
//!
//! - UUID / DateTime / JSON columns stored as TEXT, converted at the edges.
//! - `INSERT ... RETURNING` is supported by libSQL but diesel-libsql does not
//!   support the `Insertable` derive — we use `diesel::sql_query` for inserts
//!   (matching the rest of this backend) and re-select on updates.
//! - Case-insensitive slug lookup uses `LOWER(slug) = LOWER(?)`. SQLite's `LIKE`
//!   is case-insensitive for ASCII but `=` is case-sensitive, so we hit `LOWER`
//!   explicitly — matches the docs note in the canonical impl.
//! - FK cascade on delete is provided by the migration plus
//!   `PRAGMA foreign_keys = ON`. Without that pragma, libSQL silently ignores
//!   FK constraints; the integration test sets the pragma on the pool.

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::LibsqlPool;
use super::models::{dt_to_str, json_to_str, opt_str_to_json, str_to_dt, str_to_uuid, uuid_to_str};
use super::schema::yauth_organizations;
use crate::backends::diesel_common::{diesel_conflict_sqlite, diesel_err, get_conn};
use crate::domain;
use crate::repo::{OrganizationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, QueryableByName)]
#[diesel(table_name = yauth_organizations)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
struct LibsqlOrganization {
    id: String,
    name: String,
    slug: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<String>,
    created_at: String,
    updated_at: String,
}

impl LibsqlOrganization {
    fn into_domain(self) -> domain::Organization {
        domain::Organization {
            id: str_to_uuid(&self.id),
            name: self.name,
            slug: self.slug,
            display_name: self.display_name,
            avatar_url: self.avatar_url,
            metadata: opt_str_to_json(self.metadata),
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct LibsqlOrganizationRepo {
    pool: LibsqlPool,
}

impl LibsqlOrganizationRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for LibsqlOrganizationRepo {}

impl OrganizationRepository for LibsqlOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<LibsqlOrganization> = yauth_organizations::table
                .find(&id_str)
                .select(LibsqlOrganization::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(row.map(LibsqlOrganization::into_domain))
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug = slug.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Case-insensitive slug lookup per trait contract. SQLite `=` is
            // case-sensitive on TEXT columns, so wrap both sides in LOWER().
            let row: Option<LibsqlOrganization> = diesel::sql_query(
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE LOWER(slug) = LOWER(?)",
            )
            .bind::<diesel::sql_types::Text, _>(&slug)
            .get_result::<LibsqlOrganization>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_err)?;
            Ok(row.map(LibsqlOrganization::into_domain))
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Pre-flight case-insensitive slug check. SQLite's UNIQUE on `slug`
            // is case-sensitive, but the trait contract demands case-insensitive
            // conflict semantics — mirroring the memory backend.
            let existing: Option<String> = diesel::sql_query(
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE LOWER(slug) = LOWER(?) LIMIT 1",
            )
            .bind::<diesel::sql_types::Text, _>(&input.slug)
            .get_result::<LibsqlOrganization>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_err)?
            .map(|r| r.id);
            if existing.is_some() {
                return Err(RepoError::Conflict(format!(
                    "organization slug already exists: {}",
                    input.slug
                )));
            }

            let id = uuid_to_str(input.id);
            let metadata = input.metadata.clone().map(json_to_str);
            let created_at = dt_to_str(input.created_at);
            let updated_at = dt_to_str(input.updated_at);
            diesel::sql_query(
                "INSERT INTO yauth_organizations \
                 (id, name, slug, display_name, avatar_url, metadata, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&input.name)
            .bind::<diesel::sql_types::Text, _>(&input.slug)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&input.display_name)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&input.avatar_url)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&metadata)
            .bind::<diesel::sql_types::Text, _>(&created_at)
            .bind::<diesel::sql_types::Text, _>(&updated_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_sqlite)?;

            let row: LibsqlOrganization = yauth_organizations::table
                .find(&id)
                .select(LibsqlOrganization::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
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
            let id_str = uuid_to_str(id);

            // diesel-libsql does not have great AsChangeset support across all
            // nullable columns. Hand-rolled column-by-column updates keep the
            // explicit-NULL semantics (`Some(None)` clears) from
            // `UpdateOrganization`.
            if let Some(name) = changes.name {
                diesel::update(yauth_organizations::table.find(&id_str))
                    .set(yauth_organizations::name.eq(name))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_conflict_sqlite)?;
            }
            if let Some(slug) = changes.slug {
                diesel::update(yauth_organizations::table.find(&id_str))
                    .set(yauth_organizations::slug.eq(slug))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_conflict_sqlite)?;
            }
            if let Some(display_name) = changes.display_name {
                diesel::update(yauth_organizations::table.find(&id_str))
                    .set(yauth_organizations::display_name.eq(display_name))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
            }
            if let Some(avatar_url) = changes.avatar_url {
                diesel::update(yauth_organizations::table.find(&id_str))
                    .set(yauth_organizations::avatar_url.eq(avatar_url))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
            }
            if let Some(metadata) = changes.metadata {
                let m = metadata.map(json_to_str);
                diesel::update(yauth_organizations::table.find(&id_str))
                    .set(yauth_organizations::metadata.eq(m))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
            }
            if let Some(updated_at) = changes.updated_at {
                diesel::update(yauth_organizations::table.find(&id_str))
                    .set(yauth_organizations::updated_at.eq(dt_to_str(updated_at)))
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
            }

            // Re-select to return the fresh row. A missing row at this point
            // means the caller targeted a non-existent id.
            let row: Option<LibsqlOrganization> = yauth_organizations::table
                .find(&id_str)
                .select(LibsqlOrganization::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            match row {
                Some(r) => Ok(r.into_domain()),
                None => Err(RepoError::NotFound),
            }
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            // FK ON DELETE CASCADE handles memberships + invitations provided
            // `PRAGMA foreign_keys = ON` is set on the connection. Missing row
            // surfaces as `NotFound` to mirror the memory backend.
            let affected = diesel::delete(yauth_organizations::table.find(&id_str))
                .execute(&mut *conn)
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
            // Two-step (no JOIN) to keep `allow_tables_to_appear_in_same_query`
            // unchanged and side-step nullable-FK quirks.
            use super::schema::yauth_memberships;
            let uid = uuid_to_str(user_id);
            let org_ids: Vec<Option<String>> = yauth_memberships::table
                .filter(yauth_memberships::user_id.eq(Some(&uid)))
                .select(yauth_memberships::organization_id)
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            let org_ids: Vec<String> = org_ids.into_iter().flatten().collect();
            if org_ids.is_empty() {
                return Ok(Vec::new());
            }
            let rows: Vec<LibsqlOrganization> = yauth_organizations::table
                .filter(yauth_organizations::id.eq_any(&org_ids))
                .order(yauth_organizations::created_at.asc())
                .select(LibsqlOrganization::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(rows
                .into_iter()
                .map(LibsqlOrganization::into_domain)
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
                            .like(pattern.clone())
                            .or(yauth_organizations::slug.like(pattern)),
                    )
                    .count()
                    .get_result(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_organizations::table
                    .count()
                    .get_result(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            };

            let rows: Vec<LibsqlOrganization> = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                yauth_organizations::table
                    .filter(
                        yauth_organizations::name
                            .like(pattern.clone())
                            .or(yauth_organizations::slug.like(pattern)),
                    )
                    .order(yauth_organizations::created_at.asc())
                    .limit(limit)
                    .offset(offset)
                    .select(LibsqlOrganization::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_organizations::table
                    .order(yauth_organizations::created_at.asc())
                    .limit(limit)
                    .offset(offset)
                    .select(LibsqlOrganization::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            };

            Ok((
                rows.into_iter()
                    .map(LibsqlOrganization::into_domain)
                    .collect(),
                total,
            ))
        })
    }
}
