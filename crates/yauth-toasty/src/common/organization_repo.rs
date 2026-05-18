//! Toasty implementations of the organizations primitive repos (issue #87).
//!
//! Mirrors the semantics of the canonical diesel-pg backend (see
//! `crates/yauth/src/backends/diesel_pg/organization_repo.rs` and siblings):
//!
//! - **Case-insensitive slug lookup / uniqueness.** Toasty 0.4 has no
//!   `ILIKE`-equivalent. We normalize the slug to lower-case on every write
//!   (`create` / `update`) and on every read (`find_by_slug`) so the column
//!   carries the canonical form and a plain `filter_by_slug` exact match
//!   suffices. The DB-level `#[unique]` on `slug` catches duplicates and is
//!   surfaced as `RepoError::Conflict`.
//! - **Cascade delete.** Toasty does NOT auto-cascade across `has_many`
//!   relationships in the entity API today, so the org repo's `delete`
//!   explicitly tears down `memberships` and `invitations` for the org
//!   before removing the org row. This matches the diesel-pg behaviour
//!   declared via FK `ON DELETE CASCADE`.
//! - **`(organization_id, user_id)` uniqueness on memberships** is enforced
//!   by a preflight SELECT inside `create` — there is no composite UNIQUE
//!   in the migration yet, so the repo layer is the source of truth.
//! - **`find_by_token_hash` and `list_pending_for_org`** filter expired AND
//!   already-accepted invitations at the query level so callers can trust
//!   that a `Some(_)` result is live.
//! - **`mark_accepted` is single-shot:** a re-mark on an already-accepted
//!   row returns `RepoError::NotFound`.

use chrono::NaiveDateTime;
use toasty::Db;
use uuid::Uuid;

use crate::entities::{YauthInvitation, YauthMembership, YauthOrganization};
use crate::helpers::{
    chrono_to_jiff, jiff_to_chrono, json_from_domain, json_to_domain, opt_chrono_to_jiff,
    opt_jiff_to_chrono, toasty_conflict, toasty_err,
};
use yauth::repo::{
    InvitationRepository, MembershipRepository, OrganizationRepository, RepoError, RepoFuture,
    sealed,
};
use yauth_entity as domain;

// ──────────────────────────────────────────────
// Organization
// ──────────────────────────────────────────────

pub(crate) struct ToastyOrganizationRepo {
    db: Db,
}

impl ToastyOrganizationRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyOrganizationRepo {}

impl OrganizationRepository for ToastyOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthOrganization::get_by_id(&mut db, &id).await {
                Ok(row) => Ok(Some(org_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let needle = slug.to_lowercase();
        Box::pin(async move {
            let mut db = self.db.clone();
            // Slugs are always stored lower-case (see `create` / `update`), so
            // an exact-match lookup is equivalent to a case-insensitive one.
            match YauthOrganization::filter_by_slug(&needle)
                .get(&mut db)
                .await
            {
                Ok(row) => Ok(Some(org_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let row = toasty::create!(YauthOrganization {
                id: input.id,
                name: input.name,
                slug: input.slug.to_lowercase(),
                display_name: input.display_name,
                avatar_url: input.avatar_url,
                metadata: input.metadata.map(json_from_domain),
                created_at: chrono_to_jiff(input.created_at),
                updated_at: chrono_to_jiff(input.updated_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_conflict)?;
            Ok(org_to_domain(row))
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganization,
    ) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // Preflight slug uniqueness check: if the caller is renaming, look
            // for a different org already using the new slug. Mirrors the
            // memory backend's behaviour and gives a typed Conflict instead
            // of an "unique constraint" Internal.
            if let Some(new_slug) = &changes.slug {
                let new_lower = new_slug.to_lowercase();
                let existing = YauthOrganization::filter_by_slug(&new_lower)
                    .get(&mut db)
                    .await
                    .ok();
                if let Some(other) = existing
                    && other.id != id
                {
                    return Err(RepoError::Conflict(format!(
                        "organization slug '{new_slug}' already exists"
                    )));
                }
            }

            let mut org = YauthOrganization::get_by_id(&mut db, &id)
                .await
                .map_err(|_| RepoError::NotFound)?;

            let mut update = org.update();

            if let Some(name) = changes.name {
                update = update.name(name);
            }
            if let Some(slug) = changes.slug {
                update = update.slug(slug.to_lowercase());
            }
            if let Some(display_name) = changes.display_name {
                update = update.display_name(display_name);
            }
            if let Some(avatar_url) = changes.avatar_url {
                update = update.avatar_url(avatar_url);
            }
            if let Some(metadata) = changes.metadata {
                update = update.metadata(metadata.map(json_from_domain));
            }
            if let Some(updated_at) = changes.updated_at {
                update = update.updated_at(chrono_to_jiff(updated_at));
            }

            update.exec(&mut db).await.map_err(toasty_conflict)?;

            // Re-fetch to get the post-update row (mirrors user_repo pattern).
            let updated = YauthOrganization::get_by_id(&mut db, &id)
                .await
                .map_err(toasty_err)?;
            Ok(org_to_domain(updated))
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // Confirm the org exists so a missing id surfaces as NotFound
            // (matching the diesel-pg / memory backends).
            let org = YauthOrganization::get_by_id(&mut db, &id)
                .await
                .map_err(|_| RepoError::NotFound)?;

            // Toasty 0.4 does not auto-cascade across `has_many` relations
            // at the entity API level — explicit cleanup. Both children FK
            // back to this org; no further chains to chase.
            let memberships: Vec<YauthMembership> = YauthMembership::filter_by_organization_id(id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            for m in memberships {
                m.delete().exec(&mut db).await.map_err(toasty_err)?;
            }

            let invitations: Vec<YauthInvitation> = YauthInvitation::filter_by_organization_id(id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            for i in invitations {
                i.delete().exec(&mut db).await.map_err(toasty_err)?;
            }

            org.delete().exec(&mut db).await.map_err(toasty_err)?;
            Ok(())
        })
    }

    fn list_for_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Organization>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let memberships: Vec<YauthMembership> = YauthMembership::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;

            let mut org_ids: Vec<Uuid> = memberships.iter().map(|m| m.organization_id).collect();
            org_ids.sort();
            org_ids.dedup();

            let mut out = Vec::with_capacity(org_ids.len());
            for oid in org_ids {
                if let Ok(org) = YauthOrganization::get_by_id(&mut db, &oid).await {
                    out.push(org_to_domain(org));
                }
            }
            // Stable ordering by created_at to match the other backends.
            out.sort_by_key(|a| a.created_at);
            Ok(out)
        })
    }

    fn list(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::Organization>, i64)> {
        let needle = search.map(|s| s.to_lowercase());
        Box::pin(async move {
            let mut db = self.db.clone();
            // GAP: Toasty has no `ILIKE` — load everything and filter in
            // application memory. Same compromise as `UserRepository::list`
            // in `user_repo.rs`. Acceptable while the admin org list is
            // bounded; revisit if it grows past a few thousand rows.
            let all: Vec<YauthOrganization> = YauthOrganization::all()
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;

            let mut filtered: Vec<domain::Organization> = all
                .into_iter()
                .map(org_to_domain)
                .filter(|o| match &needle {
                    None => true,
                    Some(n) => {
                        o.name.to_lowercase().contains(n) || o.slug.to_lowercase().contains(n)
                    }
                })
                .collect();
            filtered.sort_by_key(|a| a.created_at);

            let total = filtered.len() as i64;
            let start = offset.max(0) as usize;
            let take = limit.max(0) as usize;
            let page = filtered.into_iter().skip(start).take(take).collect();
            Ok((page, total))
        })
    }
}

// ──────────────────────────────────────────────
// Membership
// ──────────────────────────────────────────────

pub(crate) struct ToastyMembershipRepo {
    db: Db,
}

impl ToastyMembershipRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyMembershipRepo {}

impl MembershipRepository for ToastyMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthMembership::get_by_id(&mut db, &id).await {
                Ok(row) => Ok(Some(membership_to_domain(row)?)),
                Err(_) => Ok(None),
            }
        })
    }

    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // Toasty 0.4 lacks compound filters — use the indexed
            // `organization_id` lookup and filter the second column in
            // application memory (membership rows per org are bounded).
            let rows: Vec<YauthMembership> =
                YauthMembership::filter_by_organization_id(organization_id)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            match rows.into_iter().find(|m| m.user_id == user_id) {
                Some(row) => Ok(Some(membership_to_domain(row)?)),
                None => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // Preflight uniqueness check on (organization_id, user_id). The
            // migration does not carry a composite UNIQUE today; the repo
            // layer is the source of truth — matches the diesel-pg backend.
            // Filter by indexed org_id, then narrow on user_id in the app
            // layer (Toasty 0.4 lacks compound filters).
            let existing: Vec<YauthMembership> =
                YauthMembership::filter_by_organization_id(input.organization_id)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            if existing.iter().any(|m| m.user_id == input.user_id) {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }

            let row = toasty::create!(YauthMembership {
                id: input.id,
                organization_id: input.organization_id,
                user_id: input.user_id,
                role: input.role,
                status: input.status.as_str().to_string(),
                invited_at: opt_chrono_to_jiff(input.invited_at),
                joined_at: opt_chrono_to_jiff(input.joined_at),
                created_at: chrono_to_jiff(input.created_at),
                updated_at: chrono_to_jiff(input.updated_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_conflict)?;

            membership_to_domain(row)
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let mut m = YauthMembership::get_by_id(&mut db, &id)
                .await
                .map_err(|_| RepoError::NotFound)?;

            let mut update = m.update();
            if let Some(role) = changes.role {
                update = update.role(role);
            }
            if let Some(status) = changes.status {
                update = update.status(status.as_str().to_string());
            }
            if let Some(joined_at) = changes.joined_at {
                update = update.joined_at(opt_chrono_to_jiff(joined_at));
            }
            if let Some(updated_at) = changes.updated_at {
                update = update.updated_at(chrono_to_jiff(updated_at));
            }
            update.exec(&mut db).await.map_err(toasty_err)?;

            let updated = YauthMembership::get_by_id(&mut db, &id)
                .await
                .map_err(toasty_err)?;
            membership_to_domain(updated)
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // Idempotent — deleting a missing row is Ok(()), per trait
            // contract.
            if let Ok(m) = YauthMembership::get_by_id(&mut db, &id).await {
                m.delete().exec(&mut db).await.map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthMembership> =
                YauthMembership::filter_by_organization_id(organization_id)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            let mut out: Vec<domain::Membership> = rows
                .into_iter()
                .map(membership_to_domain)
                .collect::<Result<_, _>>()?;
            out.sort_by_key(|a| a.created_at);
            Ok(out)
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthMembership> = YauthMembership::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            let mut out: Vec<domain::Membership> = rows
                .into_iter()
                .map(membership_to_domain)
                .collect::<Result<_, _>>()?;
            out.sort_by_key(|a| a.created_at);
            Ok(out)
        })
    }
}

// ──────────────────────────────────────────────
// Invitation
// ──────────────────────────────────────────────

pub(crate) struct ToastyInvitationRepo {
    db: Db,
}

impl ToastyInvitationRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyInvitationRepo {}

impl InvitationRepository for ToastyInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthInvitation::get_by_id(&mut db, &id).await {
                Ok(row) => Ok(Some(invitation_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let needle = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            // Trait contract: only resolves to Some(_) for *live* tokens —
            // not expired AND not yet accepted. Filter both in-application
            // because Toasty 0.4 makes timestamp predicates verbose.
            let now_jiff = chrono_to_jiff(chrono::Utc::now().naive_utc());
            let row = YauthInvitation::filter_by_token_hash(&needle)
                .get(&mut db)
                .await
                .ok();
            match row {
                Some(r) if r.accepted_at.is_none() && r.expires_at > now_jiff => {
                    Ok(Some(invitation_to_domain(r)))
                }
                _ => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let row = toasty::create!(YauthInvitation {
                id: input.id,
                organization_id: input.organization_id,
                email: input.email,
                role: input.role,
                token_hash: input.token_hash,
                invited_by_user_id: input.invited_by_user_id,
                expires_at: chrono_to_jiff(input.expires_at),
                accepted_at: opt_chrono_to_jiff(input.accepted_at),
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_conflict)?;
            Ok(invitation_to_domain(row))
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let mut inv = YauthInvitation::get_by_id(&mut db, &id)
                .await
                .map_err(|_| RepoError::NotFound)?;
            // Single-shot semantics: a second `mark_accepted` returns
            // `NotFound`, matching the diesel-pg `WHERE accepted_at IS NULL`
            // UPDATE.
            if inv.accepted_at.is_some() {
                return Err(RepoError::NotFound);
            }
            inv.update()
                .accepted_at(Some(chrono_to_jiff(accepted_at)))
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            let updated = YauthInvitation::get_by_id(&mut db, &id)
                .await
                .map_err(toasty_err)?;
            Ok(invitation_to_domain(updated))
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // Idempotent — matches the memory and diesel-pg backends.
            if let Ok(inv) = YauthInvitation::get_by_id(&mut db, &id).await {
                inv.delete().exec(&mut db).await.map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn list_pending_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::Invitation>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthInvitation> =
                YauthInvitation::filter_by_organization_id(organization_id)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            let now_jiff = chrono_to_jiff(chrono::Utc::now().naive_utc());
            // Filter expired + already-accepted at the application layer.
            let mut out: Vec<domain::Invitation> = rows
                .into_iter()
                .filter(|i| i.accepted_at.is_none() && i.expires_at > now_jiff)
                .map(invitation_to_domain)
                .collect();
            out.sort_by_key(|a| a.created_at);
            Ok(out)
        })
    }
}

// ──────────────────────────────────────────────
// Conversion helpers
// ──────────────────────────────────────────────

fn org_to_domain(m: YauthOrganization) -> domain::Organization {
    domain::Organization {
        id: m.id,
        name: m.name,
        slug: m.slug,
        display_name: m.display_name,
        avatar_url: m.avatar_url,
        metadata: m.metadata.map(json_to_domain),
        created_at: jiff_to_chrono(m.created_at),
        updated_at: jiff_to_chrono(m.updated_at),
    }
}

fn membership_to_domain(m: YauthMembership) -> Result<domain::Membership, RepoError> {
    let status = domain::MembershipStatus::parse(&m.status).ok_or_else(|| {
        RepoError::Internal(format!("unknown membership status: {:?}", m.status).into())
    })?;
    Ok(domain::Membership {
        id: m.id,
        organization_id: m.organization_id,
        user_id: m.user_id,
        role: m.role,
        status,
        invited_at: opt_jiff_to_chrono(m.invited_at),
        joined_at: opt_jiff_to_chrono(m.joined_at),
        created_at: jiff_to_chrono(m.created_at),
        updated_at: jiff_to_chrono(m.updated_at),
    })
}

fn invitation_to_domain(m: YauthInvitation) -> domain::Invitation {
    domain::Invitation {
        id: m.id,
        organization_id: m.organization_id,
        email: m.email,
        role: m.role,
        token_hash: m.token_hash,
        invited_by_user_id: m.invited_by_user_id,
        expires_at: jiff_to_chrono(m.expires_at),
        accepted_at: opt_jiff_to_chrono(m.accepted_at),
        created_at: jiff_to_chrono(m.created_at),
    }
}
