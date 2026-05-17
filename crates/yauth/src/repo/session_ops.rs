use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for ephemeral session operations (create, validate, delete).
///
/// Replaces the old `SessionStore` trait from the stores module. Every
/// `DatabaseBackend` must implement this — no more falling back to memory stores.
pub trait SessionOpsRepository: sealed::Sealed + Send + Sync {
    /// Store a new session. Returns the session UUID.
    fn create_session(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: std::time::Duration,
    ) -> RepoFuture<'_, Uuid>;

    /// Look up a session by token hash. Returns None if not found or expired.
    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>>;

    /// Delete a session by token hash. Returns true if a session was deleted.
    fn delete_session(&self, token_hash: &str) -> RepoFuture<'_, bool>;

    /// Delete all sessions for a user. Returns count deleted.
    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64>;

    /// Delete all sessions for a user except the one matching `keep_hash`.
    fn delete_other_sessions_for_user(&self, user_id: Uuid, keep_hash: &str)
    -> RepoFuture<'_, u64>;

    /// Set or clear the active organization on the session row (issue #89).
    ///
    /// Pass `Some(org_id)` to switch into an organization, or `None` to
    /// clear. Returns the updated [`domain::StoredSession`].
    ///
    /// Backends that have not yet shipped the `active_org_id` column return
    /// `RepoError::NotImplemented` so a 501 surfaces at the route boundary.
    fn set_active_org(
        &self,
        session_id: Uuid,
        active_org_id: Option<Uuid>,
    ) -> RepoFuture<'_, domain::StoredSession> {
        let _ = (session_id, active_org_id);
        Box::pin(async move {
            Err(crate::repo::RepoError::NotImplemented(
                "SessionOpsRepository::set_active_org".to_string(),
            ))
        })
    }
}
