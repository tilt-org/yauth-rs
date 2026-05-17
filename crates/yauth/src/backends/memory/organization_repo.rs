//! In-memory implementations of the org primitive repos (issue #87).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::NaiveDateTime;
use uuid::Uuid;

use crate::domain;
use crate::repo::{
    InvitationRepository, MembershipRepository, OrganizationDomainRepository,
    OrganizationPolicyRepository, OrganizationRepository, RepoError, RepoFuture, sealed,
};

// ──────────────────────────────────────────────
// Organization
// ──────────────────────────────────────────────

pub(crate) struct InMemoryOrganizationRepo {
    pub(crate) orgs: Arc<RwLock<HashMap<Uuid, domain::Organization>>>,
    pub(crate) memberships: Arc<RwLock<HashMap<Uuid, domain::Membership>>>,
    pub(crate) invitations: Arc<RwLock<HashMap<Uuid, domain::Invitation>>>,
    pub(crate) organization_domains: Arc<RwLock<HashMap<Uuid, domain::OrganizationDomain>>>,
    pub(crate) organization_policies: Arc<RwLock<HashMap<Uuid, domain::OrganizationPolicy>>>,
}

impl InMemoryOrganizationRepo {
    pub(crate) fn new(
        orgs: Arc<RwLock<HashMap<Uuid, domain::Organization>>>,
        memberships: Arc<RwLock<HashMap<Uuid, domain::Membership>>>,
        invitations: Arc<RwLock<HashMap<Uuid, domain::Invitation>>>,
        organization_domains: Arc<RwLock<HashMap<Uuid, domain::OrganizationDomain>>>,
        organization_policies: Arc<RwLock<HashMap<Uuid, domain::OrganizationPolicy>>>,
    ) -> Self {
        Self {
            orgs,
            memberships,
            invitations,
            organization_domains,
            organization_policies,
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
            let mut domains = self.organization_domains.write().unwrap();
            domains.retain(|_, d| d.organization_id != id);
            // Issue #92: policy is 1:1 keyed by org id — cascade.
            let mut policies = self.organization_policies.write().unwrap();
            policies.remove(&id);
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
            // Owner-protection invariant (#88): a role change that demotes
            // the *last* owner of an organization is rejected at the repo
            // layer. The handler-side `rbac::guard_role_change` is the
            // primary gate; this is defense-in-depth so any caller that
            // bypasses the helper still gets the safety. Promotions to
            // `owner` are constrained — at most one owner per org outside
            // the short window where `transfer_ownership` holds two
            // owners simultaneously.
            const OWNER: &str = "owner";
            if let Some(new_role) = &changes.role {
                let current = map.get(&id).ok_or(RepoError::NotFound)?.clone();
                let org_id = current.organization_id;
                let owners_in_org = map
                    .values()
                    .filter(|m| m.organization_id == org_id && m.role == OWNER)
                    .count();
                let demoting_owner = current.role == OWNER && new_role != OWNER;
                // Promotion-to-owner is allowed when there are 0 or 1
                // existing owners — the second slot is reserved for the
                // brief two-owner window during `transfer_ownership`. If
                // the org already has two owners, an unrelated caller is
                // doing something invalid.
                let promoting_to_owner = new_role == OWNER && current.role != OWNER;
                if promoting_to_owner && owners_in_org >= 2 {
                    return Err(RepoError::Conflict(
                        "organization already has the maximum number of owners".to_string(),
                    ));
                }
                if demoting_owner && owners_in_org <= 1 {
                    return Err(RepoError::Conflict(
                        "cannot demote the last owner; transfer ownership first".to_string(),
                    ));
                }
            }
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
            // Owner-protection invariant (#88): if the target is the last
            // owner of its org, delete is rejected. Handler-side
            // `rbac::guard_delete` is primary; this is defense-in-depth.
            const OWNER: &str = "owner";
            if let Some(target) = map.get(&id)
                && target.role == OWNER
            {
                let org_id = target.organization_id;
                let owners_in_org = map
                    .values()
                    .filter(|m| m.organization_id == org_id && m.role == OWNER)
                    .count();
                if owners_in_org <= 1 {
                    return Err(RepoError::Conflict(
                        "cannot remove the last owner; transfer ownership first".to_string(),
                    ));
                }
            }
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

// ──────────────────────────────────────────────
// OrganizationDomain (issue #90)
// ──────────────────────────────────────────────

pub(crate) struct InMemoryOrganizationDomainRepo {
    pub(crate) domains: Arc<RwLock<HashMap<Uuid, domain::OrganizationDomain>>>,
}

impl InMemoryOrganizationDomainRepo {
    pub(crate) fn new(domains: Arc<RwLock<HashMap<Uuid, domain::OrganizationDomain>>>) -> Self {
        Self { domains }
    }
}

impl sealed::Sealed for InMemoryOrganizationDomainRepo {}

impl OrganizationDomainRepository for InMemoryOrganizationDomainRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::OrganizationDomain>> {
        Box::pin(async move {
            let map = self.domains.read().unwrap();
            Ok(map.get(&id).cloned())
        })
    }

    fn find_by_domain(&self, d: &str) -> RepoFuture<'_, Option<domain::OrganizationDomain>> {
        let needle = d.trim().to_lowercase();
        Box::pin(async move {
            let map = self.domains.read().unwrap();
            Ok(map.values().find(|x| x.domain == needle).cloned())
        })
    }

    fn create(
        &self,
        input: domain::NewOrganizationDomain,
    ) -> RepoFuture<'_, domain::OrganizationDomain> {
        Box::pin(async move {
            let canonical = input.domain.trim().to_lowercase();
            if canonical.is_empty() {
                return Err(RepoError::Conflict("domain must not be empty".to_string()));
            }
            let mut map = self.domains.write().unwrap();
            // Deployment-wide uniqueness on `domain` (case-insensitive).
            if map.values().any(|x| x.domain == canonical) {
                return Err(RepoError::Conflict(format!(
                    "domain '{canonical}' is already claimed"
                )));
            }
            let row = domain::OrganizationDomain {
                id: input.id,
                organization_id: input.organization_id,
                domain: canonical,
                status: input.status,
                verification_token: input.verification_token,
                verified_at: input.verified_at,
                last_checked_at: input.last_checked_at,
                auto_join_on_signup: input.auto_join_on_signup,
                default_role_on_auto_join: input.default_role_on_auto_join,
                require_email_verified: input.require_email_verified,
                created_at: input.created_at,
                updated_at: input.updated_at,
            };
            map.insert(row.id, row.clone());
            Ok(row)
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganizationDomain,
    ) -> RepoFuture<'_, domain::OrganizationDomain> {
        Box::pin(async move {
            let mut map = self.domains.write().unwrap();
            let row = map.get_mut(&id).ok_or(RepoError::NotFound)?;
            if let Some(v) = changes.status {
                row.status = v;
            }
            if let Some(v) = changes.verified_at {
                row.verified_at = v;
            }
            if let Some(v) = changes.last_checked_at {
                row.last_checked_at = v;
            }
            if let Some(v) = changes.auto_join_on_signup {
                row.auto_join_on_signup = v;
            }
            if let Some(v) = changes.default_role_on_auto_join {
                row.default_role_on_auto_join = v;
            }
            if let Some(v) = changes.require_email_verified {
                row.require_email_verified = v;
            }
            if let Some(v) = changes.updated_at {
                row.updated_at = v;
            }
            Ok(row.clone())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.domains.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn list_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::OrganizationDomain>> {
        Box::pin(async move {
            let map = self.domains.read().unwrap();
            let mut v: Vec<_> = map
                .values()
                .filter(|x| x.organization_id == organization_id)
                .cloned()
                .collect();
            v.sort_by_key(|a| a.created_at);
            Ok(v)
        })
    }
}

// ──────────────────────────────────────────────
// OrganizationPolicy (issue #92)
// ──────────────────────────────────────────────

pub(crate) struct InMemoryOrganizationPolicyRepo {
    pub(crate) policies: Arc<RwLock<HashMap<Uuid, domain::OrganizationPolicy>>>,
}

impl InMemoryOrganizationPolicyRepo {
    pub(crate) fn new(policies: Arc<RwLock<HashMap<Uuid, domain::OrganizationPolicy>>>) -> Self {
        Self { policies }
    }
}

impl sealed::Sealed for InMemoryOrganizationPolicyRepo {}

impl OrganizationPolicyRepository for InMemoryOrganizationPolicyRepo {
    fn find_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::OrganizationPolicy>> {
        Box::pin(async move {
            let map = self.policies.read().unwrap();
            Ok(map.get(&organization_id).cloned())
        })
    }

    fn create(
        &self,
        input: domain::NewOrganizationPolicy,
    ) -> RepoFuture<'_, domain::OrganizationPolicy> {
        Box::pin(async move {
            let mut map = self.policies.write().unwrap();
            if map.contains_key(&input.organization_id) {
                return Err(RepoError::Conflict(format!(
                    "policy already exists for org {}",
                    input.organization_id
                )));
            }
            let row = domain::OrganizationPolicy {
                organization_id: input.organization_id,
                max_session_duration_secs: input.max_session_duration_secs,
                idle_timeout_secs: input.idle_timeout_secs,
                mfa_required: input.mfa_required,
                mfa_grace_period_days: input.mfa_grace_period_days,
                ip_allowlist: input.ip_allowlist,
                max_concurrent_sessions: input.max_concurrent_sessions,
                allowed_auth_methods: input.allowed_auth_methods,
                session_binding: input.session_binding,
                created_at: input.created_at,
                updated_at: input.updated_at,
            };
            map.insert(row.organization_id, row.clone());
            Ok(row)
        })
    }

    fn update(
        &self,
        organization_id: Uuid,
        changes: domain::UpdateOrganizationPolicy,
    ) -> RepoFuture<'_, domain::OrganizationPolicy> {
        Box::pin(async move {
            let mut map = self.policies.write().unwrap();
            let row = map.get_mut(&organization_id).ok_or(RepoError::NotFound)?;
            if let Some(v) = changes.max_session_duration_secs {
                row.max_session_duration_secs = v;
            }
            if let Some(v) = changes.idle_timeout_secs {
                row.idle_timeout_secs = v;
            }
            if let Some(v) = changes.mfa_required {
                row.mfa_required = v;
            }
            if let Some(v) = changes.mfa_grace_period_days {
                row.mfa_grace_period_days = v;
            }
            if let Some(v) = changes.ip_allowlist {
                row.ip_allowlist = v;
            }
            if let Some(v) = changes.max_concurrent_sessions {
                row.max_concurrent_sessions = v;
            }
            if let Some(v) = changes.allowed_auth_methods {
                row.allowed_auth_methods = v;
            }
            if let Some(v) = changes.session_binding {
                row.session_binding = v;
            }
            if let Some(v) = changes.updated_at {
                row.updated_at = v;
            }
            Ok(row.clone())
        })
    }

    fn delete(&self, organization_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.policies.write().unwrap();
            map.remove(&organization_id);
            Ok(())
        })
    }
}
