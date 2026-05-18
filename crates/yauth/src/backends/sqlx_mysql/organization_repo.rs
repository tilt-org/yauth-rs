//! sqlx-MySQL implementation of `OrganizationRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`) with MySQL
//! dialect adaptations:
//!
//! - **No `RETURNING`.** Inserts/updates are followed by a `SELECT WHERE id = ?`.
//! - **No `ILIKE`.** Case-insensitive slug lookup uses `LOWER(slug) = LOWER(?)`;
//!   substring search uses `LOWER(col) LIKE LOWER(?)`.
//! - **CHAR(36) UUIDs.** Bound as `String`; rehydrated via `str_to_uuid`.
//! - **DATETIME columns** map cleanly to `chrono::NaiveDateTime` with sqlx.
//! - **Conflict mapping.** MySQL `1062` duplicate-entry surfaces as
//!   `RepoError::Conflict(...)` via `sqlx_conflict`.

use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{sqlx_conflict, sqlx_err, str_to_uuid};
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
    metadata: Option<serde_json::Value>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl OrganizationRow {
    fn into_domain(self) -> domain::Organization {
        domain::Organization {
            id: str_to_uuid(&self.id),
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

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxMysqlOrganizationRepo {
    pool: MySqlPool,
}

impl SqlxMysqlOrganizationRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxMysqlOrganizationRepo {}

impl OrganizationRepository for SqlxMysqlOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let id_str = id.to_string();
            let row = sqlx::query_as!(
                OrganizationRow,
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE id = ?",
                id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(OrganizationRow::into_domain))
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug = slug.to_string();
        Box::pin(async move {
            // MySQL has no ILIKE — fold both sides to LOWER for case-insensitive
            // equality. The slug is parameter-bound, not interpolated.
            let row = sqlx::query_as!(
                OrganizationRow,
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE LOWER(slug) = LOWER(?)",
                slug
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(OrganizationRow::into_domain))
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            // MySQL: no RETURNING — INSERT then SELECT by id.
            sqlx::query!(
                "INSERT INTO yauth_organizations \
                 (id, name, slug, display_name, avatar_url, metadata, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                id_str,
                input.name,
                input.slug,
                input.display_name,
                input.avatar_url,
                input.metadata,
                input.created_at,
                input.updated_at,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_conflict)?;

            let row = sqlx::query_as!(
                OrganizationRow,
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE id = ?",
                id_str
            )
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganization,
    ) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            // Dynamic SET clause — must stay as runtime query() since the
            // column set is conditional. Each `Some(_)` field writes; the
            // nested `Option<Option<T>>` lets callers explicitly clear
            // nullable columns by passing `Some(None)`.
            let mut sets: Vec<&str> = Vec::new();

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
                "UPDATE yauth_organizations SET {} WHERE id = ?",
                sets.join(", ")
            );

            let mut query = sqlx::query(&sql);

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
                query = query.bind(metadata.clone());
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(updated_at);
            }

            let result = query
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_conflict)?;

            if result.rows_affected() == 0 {
                return Err(RepoError::NotFound);
            }

            self.find_by_id(id).await?.ok_or(RepoError::NotFound)
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            // Cascade to memberships + invitations is handled by FK
            // ON DELETE CASCADE in the migration. A missing row surfaces as
            // `NotFound`, matching the memory + diesel-pg backends.
            let result = sqlx::query!("DELETE FROM yauth_organizations WHERE id = ?", id_str)
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
            let user_id_str = user_id.to_string();
            // Two-step: collect this user's org-ids, then fetch the orgs.
            // Mirrors the diesel-pg semantics and avoids cross-table JOINs.
            let rows = sqlx::query!(
                "SELECT organization_id FROM yauth_memberships \
                 WHERE user_id = ? AND organization_id IS NOT NULL",
                user_id_str
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;

            let org_ids: Vec<String> = rows.into_iter().filter_map(|r| r.organization_id).collect();
            if org_ids.is_empty() {
                return Ok(Vec::new());
            }

            // Build a parameterised `IN (?, ?, …)` list — MySQL has no array
            // binding so we expand placeholders to match the id count.
            let placeholders = std::iter::repeat_n("?", org_ids.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE id IN ({}) ORDER BY created_at ASC",
                placeholders
            );

            let mut query = sqlx::query_as::<_, OrganizationRow>(&sql);
            for id in &org_ids {
                query = query.bind(id);
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
            let (rows, total) = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                let total_row = sqlx::query!(
                    "SELECT COUNT(*) as count FROM yauth_organizations \
                     WHERE LOWER(name) LIKE ? OR LOWER(slug) LIKE ?",
                    pattern,
                    pattern
                )
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;
                let total = total_row.count;

                let rows = sqlx::query_as!(
                    OrganizationRow,
                    "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                     FROM yauth_organizations \
                     WHERE LOWER(name) LIKE ? OR LOWER(slug) LIKE ? \
                     ORDER BY created_at ASC LIMIT ? OFFSET ?",
                    pattern,
                    pattern,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;
                (rows, total)
            } else {
                let total_row =
                    sqlx::query!("SELECT COUNT(*) as count FROM yauth_organizations /* mysql */")
                        .fetch_one(&self.pool)
                        .await
                        .map_err(sqlx_err)?;
                let total = total_row.count;

                let rows = sqlx::query_as!(
                    OrganizationRow,
                    "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                     FROM yauth_organizations ORDER BY created_at ASC LIMIT ? OFFSET ?",
                    limit,
                    offset
                )
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
