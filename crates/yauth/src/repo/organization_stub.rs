//! Backend-agnostic stub implementations of the org primitive repos.
//!
//! Used by SQL backends as a temporary placeholder until each ORM gets a real
//! implementation (tracked in follow-up issues). With the `organizations`
//! feature OFF (the default), none of this is compiled, so the stub never
//! shows up in default builds. With the feature ON against a stubbed backend,
//! every method returns `RepoError::NotImplemented` (HTTP 501) with a
//! descriptive `"<backend>::<trait>::<method>"` payload.
//!
//! Memory backend ships a complete real implementation. See
//! `backends/memory/organization_repo.rs`. Diesel-PG ships a complete real
//! implementation. See
//! `backends/diesel_pg/{organization,membership,invitation}_repo.rs`.

use super::{
    InvitationRepository, MembershipRepository, OrganizationDomainRepository,
    OrganizationRepository, RepoError, RepoFuture, sealed,
};
use crate::domain;
use uuid::Uuid;

fn pending(backend: &'static str, trait_name: &'static str, op: &'static str) -> RepoError {
    RepoError::NotImplemented(format!("{backend}::{trait_name}::{op}"))
}

/// Stub `OrganizationRepository` used by SQL backends until their concrete
/// implementations land. Each method returns `RepoError::NotImplemented`.
pub struct StubOrganizationRepo {
    backend: &'static str,
}

impl StubOrganizationRepo {
    pub fn new(backend: &'static str) -> Self {
        Self { backend }
    }
}

impl sealed::Sealed for StubOrganizationRepo {}

impl OrganizationRepository for StubOrganizationRepo {
    fn find_by_id(&self, _id: Uuid) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationRepository",
                "find_by_id",
            ))
        })
    }
    fn find_by_slug(&self, _slug: &str) -> RepoFuture<'_, Option<domain::Organization>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationRepository",
                "find_by_slug",
            ))
        })
    }
    fn create(&self, _input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move { Err(pending(self.backend, "OrganizationRepository", "create")) })
    }
    fn update(
        &self,
        _id: Uuid,
        _changes: domain::UpdateOrganization,
    ) -> RepoFuture<'_, domain::Organization> {
        Box::pin(async move { Err(pending(self.backend, "OrganizationRepository", "update")) })
    }
    fn delete(&self, _id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move { Err(pending(self.backend, "OrganizationRepository", "delete")) })
    }
    fn list_for_user(&self, _user_id: Uuid) -> RepoFuture<'_, Vec<domain::Organization>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationRepository",
                "list_for_user",
            ))
        })
    }
    fn list(
        &self,
        _search: Option<&str>,
        _limit: i64,
        _offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::Organization>, i64)> {
        Box::pin(async move { Err(pending(self.backend, "OrganizationRepository", "list")) })
    }
}

/// Stub `MembershipRepository`.
pub struct StubMembershipRepo {
    backend: &'static str,
}

impl StubMembershipRepo {
    pub fn new(backend: &'static str) -> Self {
        Self { backend }
    }
}

impl sealed::Sealed for StubMembershipRepo {}

impl MembershipRepository for StubMembershipRepo {
    fn find_by_id(&self, _id: Uuid) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move { Err(pending(self.backend, "MembershipRepository", "find_by_id")) })
    }
    fn find_by_org_user(
        &self,
        _organization_id: Uuid,
        _user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "MembershipRepository",
                "find_by_org_user",
            ))
        })
    }
    fn create(&self, _input: domain::NewMembership) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move { Err(pending(self.backend, "MembershipRepository", "create")) })
    }
    fn update(
        &self,
        _id: Uuid,
        _changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership> {
        Box::pin(async move { Err(pending(self.backend, "MembershipRepository", "update")) })
    }
    fn delete(&self, _id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move { Err(pending(self.backend, "MembershipRepository", "delete")) })
    }
    fn list_by_org(&self, _organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move { Err(pending(self.backend, "MembershipRepository", "list_by_org")) })
    }
    fn list_by_user(&self, _user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "MembershipRepository",
                "list_by_user",
            ))
        })
    }
}

/// Stub `InvitationRepository`.
pub struct StubInvitationRepo {
    backend: &'static str,
}

impl StubInvitationRepo {
    pub fn new(backend: &'static str) -> Self {
        Self { backend }
    }
}

impl sealed::Sealed for StubInvitationRepo {}

impl InvitationRepository for StubInvitationRepo {
    fn find_by_id(&self, _id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move { Err(pending(self.backend, "InvitationRepository", "find_by_id")) })
    }
    fn find_by_token_hash(&self, _token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "InvitationRepository",
                "find_by_token_hash",
            ))
        })
    }
    fn create(&self, _input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move { Err(pending(self.backend, "InvitationRepository", "create")) })
    }
    fn mark_accepted(
        &self,
        _id: Uuid,
        _accepted_at: chrono::NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "InvitationRepository",
                "mark_accepted",
            ))
        })
    }
    fn delete(&self, _id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move { Err(pending(self.backend, "InvitationRepository", "delete")) })
    }
    fn list_pending_for_org(
        &self,
        _organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::Invitation>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "InvitationRepository",
                "list_pending_for_org",
            ))
        })
    }
}

/// Stub `OrganizationDomainRepository` (issue #90).
pub struct StubOrganizationDomainRepo {
    backend: &'static str,
}

impl StubOrganizationDomainRepo {
    pub fn new(backend: &'static str) -> Self {
        Self { backend }
    }
}

impl sealed::Sealed for StubOrganizationDomainRepo {}

impl OrganizationDomainRepository for StubOrganizationDomainRepo {
    fn find_by_id(&self, _id: Uuid) -> RepoFuture<'_, Option<domain::OrganizationDomain>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationDomainRepository",
                "find_by_id",
            ))
        })
    }
    fn find_by_domain(&self, _domain: &str) -> RepoFuture<'_, Option<domain::OrganizationDomain>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationDomainRepository",
                "find_by_domain",
            ))
        })
    }
    fn create(
        &self,
        _input: domain::NewOrganizationDomain,
    ) -> RepoFuture<'_, domain::OrganizationDomain> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationDomainRepository",
                "create",
            ))
        })
    }
    fn update(
        &self,
        _id: Uuid,
        _changes: domain::UpdateOrganizationDomain,
    ) -> RepoFuture<'_, domain::OrganizationDomain> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationDomainRepository",
                "update",
            ))
        })
    }
    fn delete(&self, _id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationDomainRepository",
                "delete",
            ))
        })
    }
    fn list_for_org(
        &self,
        _organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::OrganizationDomain>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "OrganizationDomainRepository",
                "list_for_org",
            ))
        })
    }
}
