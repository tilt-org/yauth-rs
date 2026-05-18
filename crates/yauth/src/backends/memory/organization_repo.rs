//! In-memory implementations of the org primitive repos (issue #87).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::NaiveDateTime;
use uuid::Uuid;

use crate::domain;
use crate::repo::{
    InvitationRepository, MembershipRepository, OrganizationRepository, RepoError, RepoFuture,
    sealed,
};

// ──────────────────────────────────────────────
// Organization
// ──────────────────────────────────────────────

pub(crate) struct InMemoryOrganizationRepo {
    pub(crate) orgs: Arc<RwLock<HashMap<Uuid, domain::Organization>>>,
    pub(crate) memberships: Arc<RwLock<HashMap<Uuid, domain::Membership>>>,
    pub(crate) invitations: Arc<RwLock<HashMap<Uuid, domain::Invitation>>>,
}

impl InMemoryOrganizationRepo {
    pub(crate) fn new(
        orgs: Arc<RwLock<HashMap<Uuid, domain::Organization>>>,
        memberships: Arc<RwLock<HashMap<Uuid, domain::Membership>>>,
        invitations: Arc<RwLock<HashMap<Uuid, domain::Invitation>>>,
    ) -> Self {
        Self {
            orgs,
            memberships,
            invitations,
        }
    }
}

impl sealed::Sealed for InMemoryOrganizationRepo {}

impl OrganizationRepository for InMemoryOrganizationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            let map = self.orgs.read().unwrap();
            Ok(map.get(&id).cloned())
        })
    }

    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        let slug_lower = slug.to_lowercase();
        Box::pin(async move {
            let map = self.orgs.read().unwrap();
            Ok(map
                .values()
                .find(|o| o.slug.to_lowercase() == slug_lower)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut map = self.orgs.write().unwrap();
            let slug_lower = input.slug.to_lowercase();
            if map.values().any(|o| o.slug.to_lowercase() == slug_lower) {
                return Err(RepoError::Conflict(format!(
                    "organization slug '{}' already exists",
                    input.slug
                )));
            }
            let org = domain::Organization {
                id: input.id,
                name: input.name,
                slug: input.slug,
                display_name: input.display_name,
                avatar_url: input.avatar_url,
                metadata: input.metadata,
                created_at: input.created_at,
                updated_at: input.updated_at,
            };
            map.insert(org.id, org.clone());
            Ok(org)
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganization,
    ) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move {
            let mut map = self.orgs.write().unwrap();
            // If renaming the slug, ensure it's not in use by another org.
            if let Some(new_slug) = &changes.slug {
                let new_lower = new_slug.to_lowercase();
                if map
                    .iter()
                    .any(|(k, o)| *k != id && o.slug.to_lowercase() == new_lower)
                {
                    return Err(RepoError::Conflict(format!(
                        "organization slug '{new_slug}' already exists"
                    )));
                }
            }
            let org = map.get_mut(&id).ok_or(RepoError::NotFound)?;
            if let Some(v) = changes.name {
                org.name = v;
            }
            if let Some(v) = changes.slug {
                org.slug = v;
            }
            if let Some(v) = changes.display_name {
                org.display_name = v;
            }
            if let Some(v) = changes.avatar_url {
                org.avatar_url = v;
            }
            if let Some(v) = changes.metadata {
                org.metadata = v;
            }
            if let Some(v) = changes.updated_at {
                org.updated_at = v;
            }
            Ok(org.clone())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut orgs = self.orgs.write().unwrap();
            if orgs.remove(&id).is_none() {
                return Err(RepoError::NotFound);
            }
            // Cascade.
            let mut memberships = self.memberships.write().unwrap();
            memberships.retain(|_, m| m.organization_id != id);
            let mut invitations = self.invitations.write().unwrap();
            invitations.retain(|_, i| i.organization_id != id);
            Ok(())
        })
    }

    fn list_for_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Organization>> {
        Box::pin(async move {
            let memberships = self.memberships.read().unwrap();
            let orgs = self.orgs.read().unwrap();
            let mut ids: Vec<Uuid> = memberships
                .values()
                .filter(|m| m.user_id == user_id)
                .map(|m| m.organization_id)
                .collect();
            ids.sort();
            ids.dedup();
            Ok(ids
                .into_iter()
                .filter_map(|id| orgs.get(&id).cloned())
                .collect())
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
            let map = self.orgs.read().unwrap();
            let mut filtered: Vec<domain::Organization> = map
                .values()
                .filter(|o| match &needle {
                    None => true,
                    Some(n) => {
                        o.name.to_lowercase().contains(n) || o.slug.to_lowercase().contains(n)
                    }
                })
                .cloned()
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

pub(crate) struct InMemoryMembershipRepo {
    pub(crate) memberships: Arc<RwLock<HashMap<Uuid, domain::Membership>>>,
}

impl InMemoryMembershipRepo {
    pub(crate) fn new(memberships: Arc<RwLock<HashMap<Uuid, domain::Membership>>>) -> Self {
        Self { memberships }
    }
}

impl sealed::Sealed for InMemoryMembershipRepo {}

impl MembershipRepository for InMemoryMembershipRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let map = self.memberships.read().unwrap();
            Ok(map.get(&id).cloned())
        })
    }

    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            let map = self.memberships.read().unwrap();
            Ok(map
                .values()
                .find(|m| m.organization_id == organization_id && m.user_id == user_id)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut map = self.memberships.write().unwrap();
            if map
                .values()
                .any(|m| m.organization_id == input.organization_id && m.user_id == input.user_id)
            {
                return Err(RepoError::Conflict(
                    "user already a member of this organization".to_string(),
                ));
            }
            let m = domain::Membership {
                id: input.id,
                organization_id: input.organization_id,
                user_id: input.user_id,
                role: input.role,
                status: input.status,
                invited_at: input.invited_at,
                joined_at: input.joined_at,
                created_at: input.created_at,
                updated_at: input.updated_at,
            };
            map.insert(m.id, m.clone());
            Ok(m)
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move {
            let mut map = self.memberships.write().unwrap();
            let m = map.get_mut(&id).ok_or(RepoError::NotFound)?;
            if let Some(v) = changes.role {
                m.role = v;
            }
            if let Some(v) = changes.status {
                m.status = v;
            }
            if let Some(v) = changes.joined_at {
                m.joined_at = v;
            }
            if let Some(v) = changes.updated_at {
                m.updated_at = v;
            }
            Ok(m.clone())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.memberships.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let map = self.memberships.read().unwrap();
            let mut v: Vec<_> = map
                .values()
                .filter(|m| m.organization_id == organization_id)
                .cloned()
                .collect();
            v.sort_by_key(|a| a.created_at);
            Ok(v)
        })
    }

    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            let map = self.memberships.read().unwrap();
            let mut v: Vec<_> = map
                .values()
                .filter(|m| m.user_id == user_id)
                .cloned()
                .collect();
            v.sort_by_key(|a| a.created_at);
            Ok(v)
        })
    }
}

// ──────────────────────────────────────────────
// Invitation
// ──────────────────────────────────────────────

pub(crate) struct InMemoryInvitationRepo {
    pub(crate) invitations: Arc<RwLock<HashMap<Uuid, domain::Invitation>>>,
}

impl InMemoryInvitationRepo {
    pub(crate) fn new(invitations: Arc<RwLock<HashMap<Uuid, domain::Invitation>>>) -> Self {
        Self { invitations }
    }
}

impl sealed::Sealed for InMemoryInvitationRepo {}

impl InvitationRepository for InMemoryInvitationRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            let map = self.invitations.read().unwrap();
            Ok(map.get(&id).cloned())
        })
    }

    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        let needle = token_hash.to_string();
        Box::pin(async move {
            let map = self.invitations.read().unwrap();
            let now = chrono::Utc::now().naive_utc();
            Ok(map
                .values()
                .find(|i| i.token_hash == needle && i.accepted_at.is_none() && i.expires_at > now)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut map = self.invitations.write().unwrap();
            if map.values().any(|i| i.token_hash == input.token_hash) {
                return Err(RepoError::Conflict(
                    "invitation token hash collision".to_string(),
                ));
            }
            let inv = domain::Invitation {
                id: input.id,
                organization_id: input.organization_id,
                email: input.email,
                role: input.role,
                token_hash: input.token_hash,
                invited_by_user_id: input.invited_by_user_id,
                expires_at: input.expires_at,
                accepted_at: input.accepted_at,
                created_at: input.created_at,
            };
            map.insert(inv.id, inv.clone());
            Ok(inv)
        })
    }

    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            let mut map = self.invitations.write().unwrap();
            let inv = map.get_mut(&id).ok_or(RepoError::NotFound)?;
            if inv.accepted_at.is_some() {
                return Err(RepoError::NotFound);
            }
            inv.accepted_at = Some(accepted_at);
            Ok(inv.clone())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.invitations.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn list_pending_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::Invitation>> {
        Box::pin(async move {
            let map = self.invitations.read().unwrap();
            let now = chrono::Utc::now().naive_utc();
            let mut v: Vec<_> = map
                .values()
                .filter(|i| {
                    i.organization_id == organization_id
                        && i.accepted_at.is_none()
                        && i.expires_at > now
                })
                .cloned()
                .collect();
            v.sort_by_key(|a| a.created_at);
            Ok(v)
        })
    }
}
