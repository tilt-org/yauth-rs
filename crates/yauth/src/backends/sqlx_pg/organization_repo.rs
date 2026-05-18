//! sqlx-PG implementation of `OrganizationRepository`.
//!
//! Mirrors the diesel-pg canonical pattern (commit `3221c25`) using sqlx
//! compile-time `query!()` / `query_as!()` macros. Semantics:
//!
//! - **Case-insensitive slug uniqueness.** Enforced both at the DB level
//!   (`UNIQUE` on `slug`) and via `slug ILIKE $1` in lookups so a slug like
//!   `"Acme"` matches `"acme"`.
//! - **Cascade delete.** FKs on `yauth_memberships.organization_id` and
//!   `yauth_invitations.organization_id` are `ON DELETE CASCADE`, so a single
//!   `DELETE FROM yauth_organizations` tears down the whole tenant graph.
//! - **Conflict mapping.** A PG `23505` unique-violation surfaces as
//!   `RepoError::Conflict(...)`, not a 500.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{naive_to_utc, sqlx_conflict, sqlx_err};
use crate::domain;
use crate::repo::{OrganizationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Row type
// ──────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct OrganizationRow {
    id: Uuid,
    name: String,
    slug: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl OrganizationRow {
    fn into_domain(self) -> domain::Organization {
        domain::Organization {
            id: self.id,
            name: self.name,
            slug: self.slug,
            display_name: self.display_name,
            avatar_url: self.avatar_url,
            metadata: self.metadata,
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct SqlxPgOrganizationRepo {
    pool: PgPool,
}

impl SqlxPgOrganizationRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxPgOrganizationRepo {}

impl OrganizationRepository for SqlxPgOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let row = sqlx::query_as!(
                OrganizationRow,
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE id = $1",
                id
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
            // Case-insensitive slug lookup per trait contract. ILIKE is exact
            // (no wildcards) here — the slug is parameter-bound, not
            // interpolated.
            let row = sqlx::query_as!(
                OrganizationRow,
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE slug ILIKE $1",
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
            let row = sqlx::query_as!(
                OrganizationRow,
                "INSERT INTO yauth_organizations \
                 (id, name, slug, display_name, avatar_url, metadata, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 RETURNING id, name, slug, display_name, avatar_url, metadata, created_at, updated_at",
                input.id,
                input.name,
                input.slug,
                input.display_name as Option<String>,
                input.avatar_url as Option<String>,
                input.metadata as Option<serde_json::Value>,
                naive_to_utc(input.created_at),
                naive_to_utc(input.updated_at),
            )
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
            // Dynamic SET — runtime sqlx::query_as because column set is
            // conditional. Mirrors the diesel-pg AsChangeset behaviour: each
            // field that is `Some(_)` is written, the rest are untouched.
            // Nested `Option<Option<T>>` lets callers explicitly clear
            // nullable columns by passing `Some(None)`.
            let mut sets: Vec<String> = Vec::new();
            let mut param_idx = 1u32; // $1 is reserved for `id`

            macro_rules! push_set {
                ($field:expr, $col:expr) => {
                    if $field.is_some() {
                        param_idx += 1;
                        sets.push(format!("{} = ${}", $col, param_idx));
                    }
                };
            }

            push_set!(changes.name, "name");
            push_set!(changes.slug, "slug");
            push_set!(changes.display_name, "display_name");
            push_set!(changes.avatar_url, "avatar_url");
            push_set!(changes.metadata, "metadata");
            push_set!(changes.updated_at, "updated_at");

            if sets.is_empty() {
                return self.find_by_id(id).await?.ok_or(RepoError::NotFound);
            }

            let sql = format!(
                "UPDATE yauth_organizations SET {} WHERE id = $1 \
                 RETURNING id, name, slug, display_name, avatar_url, metadata, created_at, updated_at",
                sets.join(", ")
            );

            let mut query = sqlx::query_as::<_, OrganizationRow>(&sql).bind(id);

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
                query = query.bind(naive_to_utc(updated_at));
            }

            let row = query
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_conflict)?
                .ok_or(RepoError::NotFound)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Cascade to memberships + invitations is handled by FK
            // ON DELETE CASCADE in the migration. A missing row is reported
            // as `NotFound` to mirror the memory + diesel-pg backends.
            let result = sqlx::query!("DELETE FROM yauth_organizations WHERE id = $1", id)
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
            // Two-step: collect the org-ids this user belongs to, then fetch
            // the orgs. Matches the diesel-pg semantics, avoids cross-table
            // joins, and keeps the membership FK nullability irrelevant here.
            let org_ids: Vec<Uuid> = sqlx::query!(
                "SELECT organization_id FROM yauth_memberships \
                 WHERE user_id = $1 AND organization_id IS NOT NULL",
                user_id
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?
            .into_iter()
            .filter_map(|r| r.organization_id)
            .collect();

            if org_ids.is_empty() {
                return Ok(Vec::new());
            }

            let rows = sqlx::query_as!(
                OrganizationRow,
                "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                 FROM yauth_organizations WHERE id = ANY($1) ORDER BY created_at ASC",
                &org_ids
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;

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
                let total = sqlx::query!(
                    "SELECT COUNT(*) as count FROM yauth_organizations \
                     WHERE name ILIKE $1 OR slug ILIKE $1",
                    pattern
                )
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?
                .count
                .unwrap_or(0);

                let rows = sqlx::query_as!(
                    OrganizationRow,
                    "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                     FROM yauth_organizations \
                     WHERE name ILIKE $1 OR slug ILIKE $1 \
                     ORDER BY created_at ASC LIMIT $2 OFFSET $3",
                    pattern,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;
                (rows, total)
            } else {
                let total = sqlx::query!("SELECT COUNT(*) as count FROM yauth_organizations")
                    .fetch_one(&self.pool)
                    .await
                    .map_err(sqlx_err)?
                    .count
                    .unwrap_or(0);

                let rows = sqlx::query_as!(
                    OrganizationRow,
                    "SELECT id, name, slug, display_name, avatar_url, metadata, created_at, updated_at \
                     FROM yauth_organizations ORDER BY created_at ASC LIMIT $1 OFFSET $2",
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
