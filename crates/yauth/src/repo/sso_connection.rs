//! Repository trait for SSO connections (issue #93).
//!
//! Sealed; compiled only with the `organizations` feature. Memory backend
//! ships a full implementation. SQL backends ship the stub in
//! [`super::organization_stub`] until per-backend impls land.
//!
//! # Invariants
//!
//! - One row per `id` (UUIDv7). The `(organization_id, name)` pair is
//!   advisory-unique for the admin UI; the repo does NOT enforce it so
//!   admins can rename freely and back-end constraints don't fight the
//!   audit trail.
//! - `delete` is destructive — disabling a connection without losing
//!   audit history is the `status = "disabled"` update path. Callers
//!   that want soft-delete semantics MUST use `update(status =
//!   Disabled)` instead.
//! - `list_for_org` returns rows ordered by `created_at` ASC.

use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

pub trait SsoConnectionRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::SsoConnection>>;

    /// Insert a fresh connection row. Returns `RepoError::Conflict` on
    /// `id` collision (caller bug).
    fn create(&self, input: domain::NewSsoConnection) -> RepoFuture<'_, domain::SsoConnection>;

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateSsoConnection,
    ) -> RepoFuture<'_, domain::SsoConnection>;

    /// Idempotent delete. Returns `Ok(())` whether or not a row existed.
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// List all connections for an org, ordered by `created_at` ASC.
    fn list_for_org(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::SsoConnection>>;

    /// Find the **first active** OIDC connection for an org, used by
    /// the HRD path (`/sso/login?org=...`). Returns `None` if the org
    /// has no active OIDC connection.
    fn find_active_oidc_for_org(
        &self,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::SsoConnection>>;
}
