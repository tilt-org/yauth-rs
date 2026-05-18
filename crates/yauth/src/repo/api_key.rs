use super::{RepoError, RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for API keys (user-scoped *and* org-scoped — issue #91).
///
/// # Invariants
///
/// - **Uniqueness**: key name must be unique per owner (per user for
///   user-scoped keys, per organization for org-scoped keys).
/// - **Exactly-one-owner**: every key has exactly one of `user_id` /
///   `organization_id` set. Create returns [`RepoError::Conflict`] when
///   both or neither are present.
/// - **Expiration on read**: `find_by_prefix` MUST return `None` if the
///   key is expired.
///
/// # Backwards compatibility
///
/// The org-scoped methods carry default impls returning
/// [`RepoError::NotImplemented`] so SQL backends compile without an
/// upgrade. The memory backend ships a complete implementation; SQL
/// backends will gain real impls in follow-up PRs (mirroring the #87
/// stubs pattern).
pub trait ApiKeyRepository: sealed::Sealed + Send + Sync {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>>;

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>>;

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>>;

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()>;

    // ── Issue #91: org-scoped (service account) operations ────────────

    /// Fetch a key by id, scoped to an organization. Used for the
    /// org-admin routes — returns `None` when the key exists but belongs
    /// to a different org.
    fn find_by_id_and_org(
        &self,
        _id: Uuid,
        _organization_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async {
            Err(RepoError::NotImplemented(
                "ApiKeyRepository::find_by_id_and_org".to_string(),
            ))
        })
    }

    /// List all keys (active + within-grace) owned by an org, newest first.
    fn list_by_org_id(&self, _organization_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async {
            Err(RepoError::NotImplemented(
                "ApiKeyRepository::list_by_org_id".to_string(),
            ))
        })
    }

    /// Set `expires_at` on a single key. Used by the rotate handler to
    /// stamp a grace-period expiry on the old key when minting a new
    /// one.
    fn set_expires_at(&self, _id: Uuid, _expires_at: chrono::NaiveDateTime) -> RepoFuture<'_, ()> {
        Box::pin(async {
            Err(RepoError::NotImplemented(
                "ApiKeyRepository::set_expires_at".to_string(),
            ))
        })
    }
}
