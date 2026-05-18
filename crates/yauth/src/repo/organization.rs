//! Repository traits for the organizations primitive (issue #87).
//!
//! All three traits — `OrganizationRepository`, `MembershipRepository`,
//! `InvitationRepository` — are sealed and only compiled when the
//! `organizations` Cargo feature is enabled. Backends opt in by implementing
//! these in addition to the always-on repos.

use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for `Organization` entities.
///
/// # Invariants
///
/// - **`create`**: MUST reject duplicate slugs (case-insensitive).
/// - **`find_by_slug`**: MUST be case-insensitive.
/// - **`delete`**: MUST cascade to memberships and invitations (FK ON DELETE
///   CASCADE in SQL backends; explicit in memory backend).
pub trait OrganizationRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Organization>>;

    /// Case-insensitive slug lookup.
    fn find_by_slug(&self, slug: &str) -> RepoFuture<'_, Option<domain::Organization>>;

    /// Returns `RepoError::Conflict` if slug already exists (case-insensitive).
    fn create(&self, input: domain::NewOrganization) -> RepoFuture<'_, domain::Organization>;

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateOrganization,
    ) -> RepoFuture<'_, domain::Organization>;

    /// Delete org and cascade to memberships + invitations.
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// List all orgs a user is a member of.
    fn list_for_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Organization>>;

    /// Paginated admin listing with optional search on name/slug.
    fn list(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::Organization>, i64)>;
}

/// Repository for `Membership` rows.
///
/// # Invariants
///
/// - **`create`**: MUST reject duplicate (org_id, user_id) pairs.
/// - **`delete_by_org_user`**: idempotent — removing a non-existent membership
///   returns `Ok(())`.
pub trait MembershipRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Membership>>;

    /// Lookup the membership row tying a user to an org, if any.
    fn find_by_org_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::Membership>>;

    /// Returns `RepoError::Conflict` if (organization_id, user_id) already exists.
    fn create(&self, input: domain::NewMembership) -> RepoFuture<'_, domain::Membership>;

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateMembership,
    ) -> RepoFuture<'_, domain::Membership>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// All memberships in an organization.
    fn list_by_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>>;

    /// All memberships for a user (one per org).
    fn list_by_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Membership>>;
}

/// Repository for outstanding `Invitation` rows.
///
/// # Invariants
///
/// - **`find_by_token_hash`**: returns `None` for expired or already-accepted
///   invitations (caller does not need to filter).
/// - **`mark_accepted`**: idempotent on a single invitation; once accepted,
///   subsequent calls return `RepoError::NotFound`.
pub trait InvitationRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Invitation>>;

    /// Lookup by hashed token. Returns `None` for expired/accepted entries.
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::Invitation>>;

    fn create(&self, input: domain::NewInvitation) -> RepoFuture<'_, domain::Invitation>;

    /// Mark an invitation as accepted at the given timestamp.
    fn mark_accepted(
        &self,
        id: Uuid,
        accepted_at: chrono::NaiveDateTime,
    ) -> RepoFuture<'_, domain::Invitation>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// All pending (not yet accepted) invitations for an org.
    fn list_pending_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::Invitation>>;
}
