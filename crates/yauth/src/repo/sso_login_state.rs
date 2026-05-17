//! Repository trait for [`SsoLoginState`](crate::domain::SsoLoginState).
//!
//! Sealed; compiled only with the `organizations` feature. Memory backend
//! ships a full implementation. SQL backends ship the stub in
//! [`super::organization_stub`].
//!
//! # Invariants
//!
//! - `state` is the primary lookup key — one row per state token.
//! - `find_and_delete` is **one-shot**: a successful lookup MUST also
//!   remove the row, so state-replay attempts hit `None` on the second
//!   call. Expired rows ALSO return `None` and SHOULD be reaped in the
//!   same operation.
//! - `create` returns `RepoError::Conflict` on duplicate `state` (vanishingly
//!   rare — 32 bytes of entropy — but the type must reflect the
//!   storage-layer constraint).

use super::{RepoFuture, sealed};
use crate::domain;

pub trait SsoLoginStateRepository: sealed::Sealed + Send + Sync {
    fn create(&self, input: domain::NewSsoLoginState) -> RepoFuture<'_, ()>;

    /// Consume-once lookup. If the row exists AND is not expired,
    /// return it and remove it from storage. Otherwise return `None`.
    /// Expiry-on-read prevents replay against an old state row.
    fn find_and_delete(&self, state: &str) -> RepoFuture<'_, Option<domain::SsoLoginState>>;

    /// Best-effort GC of expired rows. Returns the number deleted.
    /// Memory backend implements this for tests; SQL backends are
    /// expected to wire a periodic prune.
    fn delete_expired(&self) -> RepoFuture<'_, usize>;
}
