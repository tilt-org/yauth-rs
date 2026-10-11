use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_KEYS: usize = 10_000;

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Returns true if the request is allowed, false if rate limited.
    pub async fn check(&self, key: &str) -> bool {
        let mut map = self.requests.lock().await;
        let now = Instant::now();

        // Evict stale keys periodically to bound memory usage
        if map.len() > MAX_KEYS {
            map.retain(|_, entries| {
                entries.retain(|t| now.duration_since(*t) < self.window);
                !entries.is_empty()
            });
        }

        let entry = map.entry(key.to_string()).or_default();
        // Remove entries outside the window
        entry.retain(|t| now.duration_since(*t) < self.window);
        let allowed = entry.len() < self.max_requests;
        if allowed {
            entry.push(now);
        } else {
            // Record rate limiting on the parent SERVER span
            crate::otel::set_attribute("yauth.rate_limited", true);
        }
        allowed
    }
}

/// Admission for operations that may send mail to an unauthenticated caller's
/// chosen address. Unlike general auth throttling, storage failure must not
/// turn an email endpoint into an unmetered sender. Never log the key/error:
/// either can contain a recipient address from the database or provider.
pub(crate) async fn check_mail_rate_limit(
    state: &crate::state::YAuthState,
    key: &str,
    limit: u32,
    window_secs: u64,
) -> Result<(), crate::error::ApiError> {
    let result = state
        .repos
        .rate_limits
        .check_rate_limit(key, limit, window_secs)
        .await
        .map_err(|_| {
            tracing::warn!(target: "yauth.email", "email admission budget unavailable");
            crate::error::api_err(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Email requests are temporarily unavailable",
            )
        })?;
    if !result.allowed {
        return Err(crate::error::api_err(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
        ));
    }
    Ok(())
}

/// The rate-limit key of a per-recipient mail budget: `<scope>:` plus the
/// SHA-256 (hex) of the canonical address (null bytes stripped, trimmed,
/// Unicode-lowercased). Admission insert errors propagate as a 503, and a host
/// may store keys in a bounded column (the casino schema's is VARCHAR(255)), so
/// a key that embedded the address turned long input into an apparent storage
/// outage. The digest keeps every key 64 hex characters past its scope and
/// keeps addresses out of the table. It is unkeyed: it bounds and obscures the
/// key, but whoever already knows an address can still find its row.
pub(crate) fn mail_budget_key(scope: &str, email: &str) -> String {
    let normalized = crate::auth::input::sanitize(email).to_lowercase();
    format!("{scope}:{}", crate::auth::crypto::hash_token(&normalized))
}

/// One destination budget shared by registration (including duplicates),
/// verification resends, resets and magic links. Operation hopping cannot
/// multiply the mailbox's quota. Match the auth plane's canonical address
/// normalization; no new external service or deployment setting is required.
pub(crate) async fn check_recipient_mail_budget(
    state: &crate::state::YAuthState,
    email: &str,
) -> Result<(), crate::error::ApiError> {
    check_mail_rate_limit(state, &mail_budget_key("auth-email", email), 10, 60).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_under_limit() {
        let rl = RateLimiter::new(3, 60);
        assert!(rl.check("user1").await);
        assert!(rl.check("user1").await);
        assert!(rl.check("user1").await);
    }

    #[tokio::test]
    async fn blocks_at_limit() {
        let rl = RateLimiter::new(2, 60);
        assert!(rl.check("user1").await);
        assert!(rl.check("user1").await);
        assert!(!rl.check("user1").await);
    }

    #[tokio::test]
    async fn different_keys_independent() {
        let rl = RateLimiter::new(1, 60);
        assert!(rl.check("user1").await);
        assert!(rl.check("user2").await);
        assert!(!rl.check("user1").await);
        assert!(!rl.check("user2").await);
    }

    #[test]
    fn mail_budget_keys_are_fixed_width_digests_of_the_canonical_address() {
        let key = mail_budget_key("auth-email", "player@example.com");
        assert_eq!(key.len(), "auth-email:".len() + 64);
        assert!(key.starts_with("auth-email:"));
        assert!(!key.contains('@'), "{key}");
        // Normalized before hashing: case, padding and null bytes share a budget.
        assert_eq!(key, mail_budget_key("auth-email", " PLAYER@Example.com\0 "));
        // Scopes stay distinct, and length no longer depends on the input.
        assert_ne!(key, mail_budget_key("forgot", "player@example.com"));
        let long = format!("{}@example.com", "a".repeat(1_000));
        assert_eq!(
            mail_budget_key("magic-link", &long).len(),
            "magic-link:".len() + 64
        );
    }

    #[tokio::test]
    async fn window_resets_after_expiry() {
        let rl = RateLimiter::new(1, 1); // 1 req / 1 sec
        assert!(rl.check("user1").await);
        assert!(!rl.check("user1").await);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(rl.check("user1").await);
    }
}
