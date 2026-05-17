//! Repository trait for external identity links (issue #93).
//!
//! Sealed; compiled only with the `organizations` feature. Memory backend
//! ships a full implementation. SQL backends ship the stub in
//! [`super::organization_stub`] until per-backend impls land.
//!
//! # Invariants
//!
//! - `(provider, external_id)` is deployment-wide unique. `create`
//!   returns [`super::RepoError::Conflict`] on collision — callers
//!   handle re-link as "delete old, create new", not implicit upsert.
//! - `find_by_provider_external_id` is the hot-path lookup on every
//!   SSO callback. It MUST be O(1) or O(log N) on storage.
//! - Deleting a user cascades to their external identities (memory
//!   backend implements this via the user repo's existing cascade).

use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

pub trait ExternalIdentityRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::ExternalIdentity>>;

    /// Hot-path lookup: given an IdP-side `(provider, external_id)`,
    /// resolve to the linked yauth user.
    fn find_by_provider_external_id(
        &self,
        provider: &str,
        external_id: &str,
    ) -> RepoFuture<'_, Option<domain::ExternalIdentity>>;

    fn create(
        &self,
        input: domain::NewExternalIdentity,
    ) -> RepoFuture<'_, domain::ExternalIdentity>;

    /// Stamp `last_login_at` after a successful federated sign-in.
    fn touch_last_login(
        &self,
        id: Uuid,
        last_login_at: chrono::NaiveDateTime,
    ) -> RepoFuture<'_, domain::ExternalIdentity>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// List all external identities a user has linked. Ordered by
    /// `linked_at` ASC.
    fn list_for_user(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ExternalIdentity>>;
}
