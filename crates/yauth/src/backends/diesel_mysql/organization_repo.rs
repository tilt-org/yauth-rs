//! Diesel-MySQL implementation of `OrganizationRepository`.
//!
//! Mirrors the diesel-pg canonical impl (commit 3221c25) with MySQL-specific
//! divergences:
//!
//! - **No `ILIKE`.** Case-insensitive slug lookup uses `LOWER(slug) = LOWER(?)`
//!   for exact equality and `LOWER(col) LIKE LOWER(?)` for `list` search.
//!   This is portable across the case-collation knobs (`utf8mb4_bin`,
//!   `utf8mb4_general_ci`, …) that MySQL/MariaDB ship with.
//! - **No `RETURNING`.** `INSERT` then `SELECT` by primary key. The PK is
//!   client-generated (Uuid::now_v7), so we know it ahead of time.
//! - **UUIDs as CHAR(36).** Stored as `String` in diesel models — converted
//!   to/from `Uuid` via the shared `uuid_to_str` / `str_to_uuid` helpers.
//! - **JSON as `JSON` column, surfaced as `Text`.** Diesel-async maps both to
//!   `Text`; the model layer does the (de)serialization.
//!
//! Cascade-delete on `yauth_memberships` / `yauth_invitations` is handled by
//! the FK declarations the migration emits.

use chrono::NaiveDateTime;
use diesel::dsl::sql;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel::sql_types::Bool;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::MysqlPool;
use super::schema::yauth_organizations;
use crate::backends::diesel_common::{
    diesel_conflict_mysql, diesel_err, get_conn, json_to_str, opt_json_to_str, opt_str_to_json,
    str_to_uuid, uuid_to_str,
};
use crate::domain;
use crate::repo::{OrganizationRepository, RepoError, RepoFuture, sealed};

// ──────────────────────────────────────────────
// Diesel-annotated row + insert/update models
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_organizations)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct MysqlOrganization {
    id: String,
    name: String,
    slug: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<String>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl MysqlOrganization {
    fn into_domain(self) -> domain::Organization {
        domain::Organization {
            id: str_to_uuid(&self.id),
            name: self.name,
            slug: self.slug,
            display_name: self.display_name,
            avatar_url: self.avatar_url,
            metadata: opt_str_to_json(self.metadata),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone, AsChangeset, Default)]
#[diesel(table_name = yauth_organizations)]
struct MysqlUpdateOrganization {
    name: Option<String>,
    slug: Option<String>,
    // `Option<Option<T>>` is diesel's idiom for "explicitly set NULL" vs
    // "leave column alone": Some(None) writes NULL, None leaves it.
    display_name: Option<Option<String>>,
    avatar_url: Option<Option<String>>,
    metadata: Option<Option<String>>,
    updated_at: Option<NaiveDateTime>,
}

impl MysqlUpdateOrganization {
    fn from_domain(input: domain::UpdateOrganization) -> Self {
        Self {
            name: input.name,
            slug: input.slug,
            display_name: input.display_name,
            avatar_url: input.avatar_url,
            metadata: input.metadata.map(|outer| outer.map(json_to_str)),
            updated_at: input.updated_at,
        }
    }
}

// ──────────────────────────────────────────────
// Repository
// ──────────────────────────────────────────────

pub(crate) struct MysqlOrganizationRepo {
    pool: MysqlPool,
}

impl MysqlOrganizationRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for MysqlOrganizationRepo {}

impl OrganizationRepository for MysqlOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            let row: Option<MysqlOrganization> = yauth_organizations::table
                .find(&id_str)
                .select(MysqlOrganization::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(row.map(MysqlOrganization::into_domain))
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug_lower = slug.to_lowercase();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            // MySQL has no `ILIKE`. Use `LOWER(slug) = ?` (we pre-lowercase
            // the input) so behaviour is independent of the table collation —
            // a column on `utf8mb4_bin` would otherwise reject case-folded
            // matches that the trait contract requires.
            let row: Option<MysqlOrganization> = yauth_organizations::table
                .filter(
                    sql::<Bool>("LOWER(slug) = ").bind::<diesel::sql_types::Text, _>(slug_lower),
                )
                .select(MysqlOrganization::as_select())
                .first(&mut *conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(row.map(MysqlOrganization::into_domain))
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(input.id);
            let metadata_str = opt_json_to_str(input.metadata);

            // MySQL has no RETURNING — INSERT then SELECT by known PK.
            diesel::sql_query(
                "INSERT INTO yauth_organizations \
                 (id, name, slug, display_name, avatar_url, metadata, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id_str)
            .bind::<diesel::sql_types::Text, _>(&input.name)
            .bind::<diesel::sql_types::Text, _>(&input.slug)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&input.display_name)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&input.avatar_url)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&metadata_str)
            .bind::<diesel::sql_types::Datetime, _>(&input.created_at)
            .bind::<diesel::sql_types::Datetime, _>(&input.updated_at)
            .execute(&mut *conn)
            .await
            .map_err(diesel_conflict_mysql)?;

            let row: MysqlOrganization = yauth_organizations::table
                .find(&id_str)
                .select(MysqlOrganization::as_select())
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
            let mysql_changes = MysqlUpdateOrganization::from_domain(changes);

            // MySQL has no RETURNING — UPDATE then SELECT. Map zero-row
            // updates to `NotFound`, conflict-class errors (duplicate slug)
            // to `Conflict`.
            let affected = diesel::update(yauth_organizations::table.find(&id_str))
                .set(&mysql_changes)
                .execute(&mut *conn)
                .await
                .map_err(diesel_conflict_mysql)?;
            if affected == 0 {
                // Could be "row doesn't exist" or "AsChangeset was all-None"
                // — confirm the row exists. Memory backend's semantics:
                // updating a missing row is NotFound, updating with empty
                // changeset returns the existing row unchanged.
                let exists: Option<String> = yauth_organizations::table
                    .find(&id_str)
                    .select(yauth_organizations::id)
                    .first::<String>(&mut *conn)
                    .await
                    .optional()
                    .map_err(diesel_err)?;
                if exists.is_none() {
                    return Err(RepoError::NotFound);
                }
            }

            let row: MysqlOrganization = yauth_organizations::table
                .find(&id_str)
                .select(MysqlOrganization::as_select())
                .first(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let id_str = uuid_to_str(id);
            // Cascade to memberships + invitations via FK ON DELETE CASCADE.
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
            let uid_str = uuid_to_str(user_id);
            // Two-step instead of inner-join: collect org ids the user
            // belongs to, then `WHERE id IN (...)`. Avoids fiddling with
            // `allow_tables_to_appear_in_same_query!` for memberships×orgs
            // and keeps the membership FK nullability quirk irrelevant.
            use super::schema::yauth_memberships;
            let org_ids: Vec<Option<String>> = yauth_memberships::table
                .filter(yauth_memberships::user_id.eq(Some(&uid_str)))
                .select(yauth_memberships::organization_id)
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            let org_ids: Vec<String> = org_ids.into_iter().flatten().collect();
            if org_ids.is_empty() {
                return Ok(Vec::new());
            }
            let rows: Vec<MysqlOrganization> = yauth_organizations::table
                .filter(yauth_organizations::id.eq_any(&org_ids))
                .order(yauth_organizations::created_at.asc())
                .select(MysqlOrganization::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(rows
                .into_iter()
                .map(MysqlOrganization::into_domain)
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

            // MySQL has no `ILIKE`. Build the case-insensitive LIKE predicate
            // with `LOWER(col) LIKE ?` (input pre-lowercased) so behaviour
            // doesn't depend on column collation.
            let (total, rows): (i64, Vec<MysqlOrganization>) = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                let total: i64 = yauth_organizations::table
                    .filter(
                        sql::<Bool>("LOWER(name) LIKE ")
                            .bind::<diesel::sql_types::Text, _>(pattern.clone())
                            .sql(" OR LOWER(slug) LIKE ")
                            .bind::<diesel::sql_types::Text, _>(pattern.clone()),
                    )
                    .count()
                    .get_result(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
                let rows: Vec<MysqlOrganization> = yauth_organizations::table
                    .filter(
                        sql::<Bool>("LOWER(name) LIKE ")
                            .bind::<diesel::sql_types::Text, _>(pattern.clone())
                            .sql(" OR LOWER(slug) LIKE ")
                            .bind::<diesel::sql_types::Text, _>(pattern),
                    )
                    .order(yauth_organizations::created_at.asc())
                    .limit(limit)
                    .offset(offset)
                    .select(MysqlOrganization::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
                (total, rows)
            } else {
                let total: i64 = yauth_organizations::table
                    .count()
                    .get_result(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
                let rows: Vec<MysqlOrganization> = yauth_organizations::table
                    .order(yauth_organizations::created_at.asc())
                    .limit(limit)
                    .offset(offset)
                    .select(MysqlOrganization::as_select())
                    .load(&mut *conn)
                    .await
                    .map_err(diesel_err)?;
                (total, rows)
            };

            Ok((
                rows.into_iter()
                    .map(MysqlOrganization::into_domain)
                    .collect(),
                total,
            ))
        })
    }
}
