//! sqlx-SQLite implementation of `OrganizationRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`) and the
//! sqlx-pg idiom, with SQLite-specific divergences:
//!
//! - **UUIDs** stored as `TEXT` (`uuid::Uuid::to_string()`), converted at
//!   the repo boundary via `str_to_uuid` / `uuid_to_str`.
//! - **Timestamps** stored as ISO-8601 `TEXT` via `dt_to_str` so
//!   lexicographic comparison matches chronological order.
//! - **JSON** (`metadata`) stored as `TEXT` via `json_to_str`.
//! - **Case-insensitive slug uniqueness** is enforced with a preflight
//!   `LOWER(slug) = LOWER(?)` `SELECT` inside `create`. The migration
//!   declares `slug UNIQUE`, but SQLite's `TEXT` defaults to `BINARY`
//!   collation so exact-case duplicates still fall back to the DB
//!   `UNIQUE constraint failed`, which `sqlx_conflict` maps to
//!   `RepoError::Conflict`.
//! - **`find_by_slug`** also uses `LOWER(slug) = LOWER(?)` rather than
//!   relying on `LIKE`'s ASCII-only case-insensitivity, for parity with
//!   the diesel-sqlite impl.
//! - **Cascade delete** relies on the FK `ON DELETE CASCADE` declarations
//!   AND `PRAGMA foreign_keys = ON` being set on the connection (a per-
//!   connection SQLite pragma). The test harness sets it via
//!   `setup_sqlite_schema_sqlx`; downstream embedders must do the same.
//! - **RETURNING** is supported on SQLite 3.35+ (sqlx pulls in a recent
//!   bundled sqlite), so we mirror sqlx-pg's RETURNING-based pattern
//!   instead of the diesel-sqlite INSERT-then-SELECT shape.
//! - **Runtime queries** (`sqlx::query`, `sqlx::query_as::<_, Row>`) are
//!   used here instead of the `query!()` / `query_as!()` macros so this
//!   file does not require an offline sqlx cache entry. The sibling
//!   sqlx-pg repo uses the compile-time macros; both shapes coexist in
//!   the codebase.

use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::backends::sqlx_common::{
    dt_to_str, json_to_str, opt_str_to_json, sqlx_conflict, sqlx_err, str_to_dt, str_to_uuid,
    uuid_to_str,
};
use crate::domain;
use crate::repo::{OrganizationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Row type
// ──────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct OrganizationRow {
    id: String,
    name: String,
    slug: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<String>,
    created_at: String,
    updated_at: String,
}

impl OrganizationRow {
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

const SELECT_COLS: &str =
    "id, name, slug, display_name, avatar_url, metadata, created_at, updated_at";

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxSqliteOrganizationRepo {
    pool: SqlitePool,
}

impl SqlxSqliteOrganizationRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxSqliteOrganizationRepo {}

impl OrganizationRepository for SqlxSqliteOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let id_str = uuid_to_str(id);
            let sql = format!("SELECT {SELECT_COLS} FROM yauth_organizations WHERE id = ?");
            let row = sqlx::query_as::<_, OrganizationRow>(&sql)
                .bind(id_str)
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(row.map(OrganizationRow::into_domain))
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug_lower = slug.to_lowercase();
        Box::pin(async move {
            // SQLite `=` and `UNIQUE` use BINARY collation. Match diesel-pg
            // `ILIKE` semantics by lowering both sides explicitly.
            let sql =
                format!("SELECT {SELECT_COLS} FROM yauth_organizations WHERE LOWER(slug) = ?");
            let row = sqlx::query_as::<_, OrganizationRow>(&sql)
                .bind(slug_lower)
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(row.map(OrganizationRow::into_domain))
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            // Preflight case-insensitive uniqueness check. The migration's
            // `slug UNIQUE` is BINARY-collated in SQLite, so a `"Acme"` vs
            // `"acme"` collision would otherwise slip through. Match the
            // memory backend / diesel-pg `ILIKE` semantics by lowering
            // both sides here. Exact-case duplicates still hit the DB
            // `UNIQUE` and surface via `sqlx_conflict`.
            let slug_lower = input.slug.to_lowercase();
            let existing =
                sqlx::query("SELECT id FROM yauth_organizations WHERE LOWER(slug) = ? LIMIT 1")
                    .bind(&slug_lower)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
            if existing.is_some() {
                return Err(RepoError::Conflict(format!(
                    "organization slug '{}' already exists",
                    input.slug
                )));
            }

            let id_str = uuid_to_str(input.id);
            let created_str = dt_to_str(input.created_at);
            let updated_str = dt_to_str(input.updated_at);
            let metadata_str = input.metadata.map(json_to_str);
            let sql = format!(
                "INSERT INTO yauth_organizations \
                 (id, name, slug, display_name, avatar_url, metadata, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                 RETURNING {SELECT_COLS}"
            );
            let row = sqlx::query_as::<_, OrganizationRow>(&sql)
                .bind(id_str)
                .bind(input.name)
                .bind(input.slug)
                .bind(input.display_name)
                .bind(input.avatar_url)
                .bind(metadata_str)
                .bind(created_str)
                .bind(updated_str)
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_conflict)?;
            Ok(row.into_domain())
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganization,
    ) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            // Dynamic SET — column set is conditional. Mirrors the sqlx-pg
            // pattern. Nested `Option<Option<T>>` lets callers explicitly
            // clear nullable columns by passing `Some(None)`.
            let mut sets: Vec<&'static str> = Vec::new();
            if changes.name.is_some() {
                sets.push("name = ?");
            }
            if changes.slug.is_some() {
                sets.push("slug = ?");
            }
            if changes.display_name.is_some() {
                sets.push("display_name = ?");
            }
            if changes.avatar_url.is_some() {
                sets.push("avatar_url = ?");
            }
            if changes.metadata.is_some() {
                sets.push("metadata = ?");
            }
            if changes.updated_at.is_some() {
                sets.push("updated_at = ?");
            }

            if sets.is_empty() {
                return self.find_by_id(id).await?.ok_or(RepoError::NotFound);
            }

            let sql = format!(
                "UPDATE yauth_organizations SET {} WHERE id = ? RETURNING {SELECT_COLS}",
                sets.join(", ")
            );

            let mut query = sqlx::query_as::<_, OrganizationRow>(&sql);

            if let Some(ref name) = changes.name {
                query = query.bind(name.clone());
            }
            if let Some(ref slug) = changes.slug {
                query = query.bind(slug.clone());
            }
            if let Some(ref display_name) = changes.display_name {
                query = query.bind(display_name.clone());
            }
            if let Some(ref avatar_url) = changes.avatar_url {
                query = query.bind(avatar_url.clone());
            }
            if let Some(ref metadata) = changes.metadata {
                query = query.bind(metadata.clone().map(json_to_str));
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(dt_to_str(updated_at));
            }

            let row = query
                .bind(uuid_to_str(id))
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_conflict)?
                .ok_or(RepoError::NotFound)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Cascade to memberships + invitations relies on the FK
            // `ON DELETE CASCADE` declarations AND `PRAGMA foreign_keys = ON`
            // on this connection. A missing row is reported as `NotFound` to
            // mirror the memory + diesel-pg backends.
            let id_str = uuid_to_str(id);
            let result = sqlx::query("DELETE FROM yauth_organizations WHERE id = ?")
                .bind(id_str)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            if result.rows_affected() == 0 {
                return Err(RepoError::NotFound);
            }
            Ok(())
        })
    }

    fn list_for_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Organization>> {
        Box::pin(async move {
            // Two-step: collect membership org-ids for the user, then
            // hydrate the org rows. Avoids cross-table joins and keeps the
            // membership FK nullability irrelevant here.
            let user_id_str = uuid_to_str(user_id);
            let org_id_rows = sqlx::query(
                "SELECT organization_id FROM yauth_memberships \
                 WHERE user_id = ? AND organization_id IS NOT NULL",
            )
            .bind(user_id_str)
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;

            let org_ids: Vec<String> = org_id_rows
                .into_iter()
                .filter_map(|r| {
                    r.try_get::<Option<String>, _>("organization_id")
                        .ok()
                        .flatten()
                })
                .collect();

            if org_ids.is_empty() {
                return Ok(Vec::new());
            }

            // SQLite has no array binding — render an IN clause with
            // placeholders. Org-ids are TEXT, bound individually.
            let placeholders = std::iter::repeat_n("?", org_ids.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT {SELECT_COLS} FROM yauth_organizations \
                 WHERE id IN ({placeholders}) ORDER BY created_at ASC"
            );
            let mut query = sqlx::query_as::<_, OrganizationRow>(&sql);
            for oid in &org_ids {
                query = query.bind(oid);
            }

            let rows = query.fetch_all(&self.pool).await.map_err(sqlx_err)?;
            Ok(rows.into_iter().map(OrganizationRow::into_domain).collect())
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
            // SQLite `LIKE` is case-insensitive for ASCII by default —
            // good enough for the slug/name needle search. We still
            // lower-case the pattern for explicit symmetry with the
            // sqlx-pg `ILIKE` shape.
            let (rows, total) = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                let total: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM yauth_organizations \
                     WHERE name LIKE ? OR slug LIKE ?",
                )
                .bind(&pattern)
                .bind(&pattern)
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;

                let sql = format!(
                    "SELECT {SELECT_COLS} FROM yauth_organizations \
                     WHERE name LIKE ? OR slug LIKE ? \
                     ORDER BY created_at ASC LIMIT ? OFFSET ?"
                );
                let rows = sqlx::query_as::<_, OrganizationRow>(&sql)
                    .bind(&pattern)
                    .bind(&pattern)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
                (rows, total)
            } else {
                let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM yauth_organizations")
                    .fetch_one(&self.pool)
                    .await
                    .map_err(sqlx_err)?;

                let sql = format!(
                    "SELECT {SELECT_COLS} FROM yauth_organizations \
                     ORDER BY created_at ASC LIMIT ? OFFSET ?"
                );
                let rows = sqlx::query_as::<_, OrganizationRow>(&sql)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
                (rows, total)
            };

            Ok((
                rows.into_iter().map(OrganizationRow::into_domain).collect(),
                total,
            ))
        })
    }
}
