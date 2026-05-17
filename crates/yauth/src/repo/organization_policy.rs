//! Repository trait for per-organization auth policy (issue #92).
//!
//! Sealed; compiled only with the `organizations` feature. Memory backend
//! ships a full implementation. SQL backends ship the stub in
//! [`super::organization_stub`] until per-backend impls land.
//!
//! # Invariants
//!
//! - Exactly one row per organization. `upsert` is the canonical write —
//!   PATCH semantics on top of a "default unrestricted" baseline. The
//!   caller is responsible for materializing the default row when the
//!   org is created.
//! - `find_for_org` returning `None` is **not** an error — it means "no
//!   custom policy set, inherit global". Callers must treat `None` as
//!   "use [`OrganizationPolicy::unrestricted`]" semantically.
//! - Deletion of the org cascades to the policy row (see the memory
//!   backend's `OrganizationRepository::delete`).

use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

pub trait OrganizationPolicyRepository: sealed::Sealed + Send + Sync {
    /// Fetch the policy for an org. `Ok(None)` means no row exists —
    /// callers should treat this as "inherit global".
    fn find_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::OrganizationPolicy>>;

    /// Insert a fresh policy row. Returns `RepoError::Conflict` if a
    /// row already exists for this org (use `update` instead).
    fn create(
        &self,
        input: domain::NewOrganizationPolicy,
    ) -> RepoFuture<'_, domain::OrganizationPolicy>;

    /// Apply a partial update to the existing row. Returns
    /// `RepoError::NotFound` if no row exists for this org — callers
    /// who want "create if missing" semantics should call `create` on
    /// `NotFound`.
    fn update(
        &self,
        organization_id: Uuid,
        changes: domain::UpdateOrganizationPolicy,
    ) -> RepoFuture<'_, domain::OrganizationPolicy>;

    /// Idempotent delete. Useful when an org wants to fall back to
    /// global defaults — equivalent to "policy = unrestricted".
    fn delete(&self, organization_id: Uuid) -> RepoFuture<'_, ()>;
}
