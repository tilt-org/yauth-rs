//! Diesel native-SQLite implementation of `OrganizationRepository`.
//!
//! Mirrors the diesel-pg canonical impl with the SQLite-specific divergences
//! documented in `mod.rs`:
//!
//! - **UUIDs** stored as `TEXT` (`uuid::Uuid::to_string()`), converted at the
//!   repo boundary via `str_to_uuid` / `uuid_to_str`.
//! - **Timestamps** stored as ISO-8601 `TEXT` via `dt_to_str`. `expires_at`
//!   comparisons therefore compare lexicographic strings — fine because
//!   `dt_to_str` emits a fixed-width `%Y-%m-%dT%H:%M:%S%.f` format.
//! - **JSON** (`metadata`) stored as `TEXT` via `json_to_str`.
//! - **No `RETURNING`** — every mutating call follows the
//!   `INSERT/UPDATE → SELECT` pattern used elsewhere in this backend.
//! - **Case-insensitive slug uniqueness** is enforced with a preflight
//!   `LOWER(slug) = LOWER(?)` `SELECT` inside `create`. The migration declares
//!   `slug UNIQUE`, but SQLite's `TEXT` defaults to `BINARY` collation, so
//!   exact-case duplicates fall back to a `UNIQUE constraint failed` which
//!   `diesel_conflict_sqlite` maps to `RepoError::Conflict`.
//! - **Cascade delete** relies on the FK `ON DELETE CASCADE` declarations,
//!   which require `PRAGMA foreign_keys = ON` on the connection. The pool
//!   bootstrap (`setup_sqlite_schema_diesel`) sets it; downstream embedders
//!   must do the same or cascade tests will fail.

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::SqlitePool;
use super::models::{
    dt_to_str, opt_json_to_str, opt_str_to_json, str_to_dt, str_to_uuid, uuid_to_str,
};
use super::schema::yauth_organizations;
use crate::backends::diesel_common::{diesel_conflict_sqlite, diesel_err, get_conn};
use crate::domain;
use crate::repo::{OrganizationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row + insert/update models
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_organizations)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct SqliteOrganization {
    id: String,
    name: String,
    slug: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<String>,
    created_at: String,
    updated_at: String,
}

impl SqliteOrganization {
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

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = yauth_organizations)]
struct SqliteNewOrganization {
    id: String,
    name: String,
    slug: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<String>,
    created_at: String,
    updated_at: String,
}

impl SqliteNewOrganization {
    fn from_domain(input: domain::NewOrganization) -> Self {
        Self {
            id: uuid_to_str(input.id),
            name: input.name,
            slug: input.slug,
            display_name: input.display_name,
            avatar_url: input.avatar_url,
            metadata: opt_json_to_str(input.metadata),
            created_at: dt_to_str(input.created_at),
            updated_at: dt_to_str(input.updated_at),
        }
    }
}

#[derive(Debug, Clone, AsChangeset, Default)]
#[diesel(table_name = yauth_organizations)]
struct SqliteUpdateOrganization {
    name: Option<String>,
    slug: Option<String>,
    // `Option<Option<T>>` is diesel's idiom for "explicitly set to NULL"
    // vs "leave column alone": Some(None) writes NULL, None leaves it.
    display_name: Option<Option<String>>,
    avatar_url: Option<Option<String>>,
    metadata: Option<Option<String>>,
    updated_at: Option<String>,
}

impl SqliteUpdateOrganization {
    fn from_domain(input: domain::UpdateOrganization) -> Self {
        Self {
            name: input.name,
            slug: input.slug,
            display_name: input.display_name,
            avatar_url: input.avatar_url,
            metadata: input.metadata.map(|opt| {
                opt.map(|v| serde_json::to_string(&v).unwrap_or_else(|_| "null".into()))
            }),
            updated_at: input.updated_at.map(dt_to_str),
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqliteOrganizationRepo {
    pool: SqlitePool,
}

impl SqliteOrganizationRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqliteOrganizationRepo {}

impl OrganizationRepository for SqliteOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<SqliteOrganization> = yauth_organizations::table
                .find(&id_str)
                .select(SqliteOrganization::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(row.map(SqliteOrganization::into_domain))
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug_lower = slug.to_lowercase();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // SQLite `LIKE` is case-insensitive for ASCII by default, but
            // `=` and `UNIQUE` use BINARY collation. Lower both sides for a
            // robust case-insensitive comparison.
            let row: Option<SqliteOrganization> = yauth_organizations::table
                .filter(
                    diesel::dsl::sql::<diesel::sql_types::Bool>("LOWER(slug) = ")
                        .bind::<diesel::sql_types::Text, _>(&slug_lower),
                )
                .select(SqliteOrganization::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(row.map(SqliteOrganization::into_domain))
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // Preflight case-insensitive uniqueness check. The migration's
            // `slug UNIQUE` is BINARY-collated in SQLite, so a `"Acme"` vs
            // `"acme"` collision would otherwise slip through and only
            // surface on the *next* exact-case insert. Match the memory
            // backend / diesel-pg `ILIKE` semantics by lowering both sides
            // here.
            let slug_lower = input.slug.to_lowercase();
            let existing: Option<String> = yauth_organizations::table
                .filter(
                    diesel::dsl::sql::<diesel::sql_types::Bool>("LOWER(slug) = ")
                        .bind::<diesel::sql_types::Text, _>(&slug_lower),
                )
                .select(yauth_organizations::id)
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(format!(
                    "organization slug '{}' already exists",
                    input.slug
                )));
            }

            let row = SqliteNewOrganization::from_domain(input);
            let id = row.id.clone();
            diesel::insert_into(yauth_organizations::table)
                .values(&row)
                .execute(&mut *conn)
                .await
                .map_err(diesel_conflict_sqlite)?;

            let inserted: SqliteOrganization = yauth_organizations::table
                .find(&id)
                .select(SqliteOrganization::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(inserted.into_domain())
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
            let sqlite_changes = SqliteUpdateOrganization::from_domain(changes);

            let affected = diesel::update(yauth_organizations::table.find(&id_str))
                .set(&sqlite_changes)
                .execute(&mut *conn)
                .await
                .map_err(diesel_conflict_sqlite)?;
            if affected == 0 {
                return Err(RepoError::NotFound);
            }

            let inserted: SqliteOrganization = yauth_organizations::table
                .find(&id_str)
                .select(SqliteOrganization::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(inserted.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            // Cascade to memberships + invitations relies on the FK
            // `ON DELETE CASCADE` declarations AND `PRAGMA foreign_keys = ON`
            // being set on this connection (it's a SQLite per-connection
            // pragma). Embedders must set it; the test harness does.
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
            let user_id_str = uuid_to_str(user_id);
            // Two-step: collect membership org-ids for the user, then
            // hydrate the org rows. Avoids needing
            // `allow_tables_to_appear_in_same_query!` for memberships×orgs.
            use super::schema::yauth_memberships;
            let org_ids: Vec<Option<String>> = yauth_memberships::table
                .filter(yauth_memberships::user_id.eq(Some(&user_id_str)))
                .select(yauth_memberships::organization_id)
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            let org_ids: Vec<String> = org_ids.into_iter().flatten().collect();
            if org_ids.is_empty() {
                return Ok(Vec::new());
            }
            let rows: Vec<SqliteOrganization> = yauth_organizations::table
                .filter(yauth_organizations::id.eq_any(&org_ids))
                .order(yauth_organizations::created_at.asc())
                .select(SqliteOrganization::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(rows
                .into_iter()
                .map(SqliteOrganization::into_domain)
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
            // SQLite `LIKE` is case-insensitive for ASCII by default — good
            // enough for the slug/name needle search. We still lower-case
            // the pattern for explicit symmetry with diesel-pg's `ILIKE`.
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

            let rows: Vec<SqliteOrganization> = if let Some(ref s) = search {
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
                    .select(SqliteOrganization::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            } else {
                yauth_organizations::table
                    .order(yauth_organizations::created_at.asc())
                    .limit(limit)
                    .offset(offset)
                    .select(SqliteOrganization::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?
            };

            Ok((
                rows.into_iter()
                    .map(SqliteOrganization::into_domain)
                    .collect(),
                total,
            ))
        })
    }
}
