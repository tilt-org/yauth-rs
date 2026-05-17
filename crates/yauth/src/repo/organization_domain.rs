//! Repository trait for verified email domain claims (issue #90).
//!
//! Sealed; compiled only with the `organizations` feature. Memory backend
//! ships a full implementation. SQL backends ship the stub in
//! [`super::organization_stub`] until a per-backend impl lands as
//! follow-up work.
//!
//! # Invariants
//!
//! - `domain` is deployment-wide unique (case-insensitive). Two orgs may
//!   not own the same domain at the same time. The repo enforces this
//!   with [`RepoError::Conflict`] on `create`.
//! - `find_by_domain` is case-insensitive on the domain argument.
//! - `delete` is idempotent — deleting a non-existent row returns
//!   `Ok(())`. Org cascade deletion is the org-repo's responsibility.

use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

pub trait OrganizationDomainRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::OrganizationDomain>>;

    /// Case-insensitive domain lookup. Returns the single owning org's
    /// claim (deployment-wide uniqueness invariant).
    fn find_by_domain(&self, domain: &str) -> RepoFuture<'_, Option<domain::OrganizationDomain>>;

    /// Insert a new domain claim. Returns `RepoError::Conflict` if the
    /// domain (case-insensitive) is already claimed by any org.
    fn create(
        &self,
        input: domain::NewOrganizationDomain,
    ) -> RepoFuture<'_, domain::OrganizationDomain>;

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganizationDomain,
    ) -> RepoFuture<'_, domain::OrganizationDomain>;

    /// Idempotent delete.
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// List all domain claims for an org, ordered by `created_at` ASC.
    fn list_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::OrganizationDomain>>;
}
