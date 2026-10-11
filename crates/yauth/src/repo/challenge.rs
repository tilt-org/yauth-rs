use super::{RepoError, RepoFuture, sealed};

/// Repository for ephemeral challenge storage (CSRF, WebAuthn, MFA pending sessions).
///
/// Replaces the old `ChallengeStore` trait from the stores module.
/// Key-value store with TTL-based expiration.
pub trait ChallengeRepository: sealed::Sealed + Send + Sync {
    /// Set a challenge value with a TTL in seconds.
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()>;

    /// Get a challenge value. Returns None if not found or expired.
    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>>;

    /// Delete a challenge by key.
    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()>;

    /// Replace the value only if the challenge still exists and has not expired.
    /// The original expiry must remain unchanged. Returns `false` for a missing
    /// or expired challenge, including one another request already consumed.
    ///
    /// The existence/expiry check and update must be atomic with deletion. A
    /// get-then-set fallback would recreate a consumed challenge. Backends
    /// without this primitive fail closed: MFA deletes the challenge on error,
    /// requiring a fresh login after a failed factor instead of reviving it.
    fn update_challenge_if_live(
        &self,
        _key: &str,
        _value: serde_json::Value,
    ) -> RepoFuture<'_, bool> {
        Box::pin(async {
            Err(RepoError::NotImplemented(
                "ChallengeRepository::update_challenge_if_live".into(),
            ))
        })
    }

    /// Set-if-absent: take `key` for `value` only when no *live* entry holds
    /// it. Returns `true` when this call took the key, `false` when a
    /// still-unexpired entry was already there. An expired entry is claimable.
    ///
    /// This is the primitive a single-use marker needs. `get_challenge` then
    /// `set_challenge` cannot express it: two callers racing on the same key
    /// both read "absent" and both write, so both believe they own it (yauth
    /// #263 finding S2a, review finding 4).
    ///
    /// The default implementation *is* that read-then-write, so every backend
    /// keeps compiling and keeps the same observable behaviour under no
    /// contention. It is **not atomic** — backends that can express the claim
    /// in one operation override it, and callers that need the guarantee must
    /// run on one of those. The in-memory, SeaORM-Postgres and Redis-cached
    /// backends do.
    fn try_claim_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, bool> {
        let key = key.to_string();
        Box::pin(async move {
            if self.get_challenge(&key).await?.is_some() {
                return Ok(false);
            }
            self.set_challenge(&key, value, ttl_secs).await?;
            Ok(true)
        })
    }
}
