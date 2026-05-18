//! Verifier for organization domain claims (issue #90).
//!
//! Two-channel verification:
//!
//! 1. **DNS TXT** — query `_yauth-domain-verify.<domain>` and look for a
//!    TXT record whose value equals the per-claim `verification_token`.
//!    This is the primary channel.
//! 2. **HTTP `.well-known` fallback** — optional. Fetch
//!    `https://<domain>/.well-known/yauth-domain-verify`. If the body
//!    contains the token (whitespace-trimmed line match), accept.
//!
//! Both channels are best-effort. If neither responds before
//! [`VerifyConfig::timeout`], we return [`VerifyOutcome::NotFound`]
//! rather than bubbling the I/O error up the API surface — operators
//! retry by hitting the verify endpoint again, and admins can see the
//! `last_checked_at` timestamp move.

use std::time::Duration;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

/// Subdomain prefix queried for the DNS TXT challenge.
pub const TXT_PREFIX: &str = "_yauth-domain-verify";

/// HTTP path queried for the optional `.well-known` fallback.
pub const WELL_KNOWN_PATH: &str = "/.well-known/yauth-domain-verify";

/// Result of a verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// TXT record (or `.well-known`) found and matched the expected token.
    Verified,
    /// We were able to query but didn't find a matching record.
    NotFound,
}

/// Knobs for the verifier. The defaults are conservative — short timeouts,
/// `.well-known` enabled.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Hard timeout for the entire verification operation
    /// (DNS + optional HTTP fallback).
    pub timeout: Duration,
    /// Try the HTTP `.well-known/yauth-domain-verify` channel if DNS fails.
    pub enable_well_known_fallback: bool,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            enable_well_known_fallback: true,
        }
    }
}

/// Build the FQDN used for the TXT challenge — `_yauth-domain-verify.<domain>`.
pub fn challenge_fqdn(domain: &str) -> String {
    format!("{TXT_PREFIX}.{}", domain.trim().trim_end_matches('.'))
}

/// Run a verification attempt against `domain` using `expected_token`.
///
/// Tries DNS first, then `.well-known` if enabled and DNS came up empty.
/// Errors during lookup are treated as `NotFound` — verification is a
/// pull operation and we don't want flaky DNS to advertise a false-Failed
/// status that operators have to firefight.
pub async fn verify_domain(
    domain: &str,
    expected_token: &str,
    cfg: &VerifyConfig,
) -> VerifyOutcome {
    let fqdn = challenge_fqdn(domain);
    let txt_check = txt_lookup_matches(&fqdn, expected_token);
    let outcome = tokio::time::timeout(cfg.timeout, txt_check)
        .await
        .unwrap_or(VerifyOutcome::NotFound);

    if matches!(outcome, VerifyOutcome::Verified) {
        return VerifyOutcome::Verified;
    }

    if cfg.enable_well_known_fallback {
        let well_known = well_known_matches(domain, expected_token);
        if let Ok(VerifyOutcome::Verified) = tokio::time::timeout(cfg.timeout, well_known).await {
            return VerifyOutcome::Verified;
        }
    }

    VerifyOutcome::NotFound
}

async fn txt_lookup_matches(fqdn: &str, expected_token: &str) -> VerifyOutcome {
    // `from_system_conf` may fail (e.g. unreadable /etc/resolv.conf or
    // unusual sandboxes); fall back to the Cloudflare-style default
    // config so verification still works in containers.
    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(_) => TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
    };

    let response = match resolver.txt_lookup(fqdn).await {
        Ok(r) => r,
        Err(_) => return VerifyOutcome::NotFound,
    };

    for txt in response.iter() {
        for raw in txt.iter() {
            if let Ok(s) = std::str::from_utf8(raw)
                && s.trim() == expected_token
            {
                return VerifyOutcome::Verified;
            }
        }
    }
    VerifyOutcome::NotFound
}

async fn well_known_matches(domain: &str, expected_token: &str) -> VerifyOutcome {
    let url = format!(
        "https://{}{}",
        domain.trim().trim_end_matches('.'),
        WELL_KNOWN_PATH
    );
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return VerifyOutcome::NotFound,
    };
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return VerifyOutcome::NotFound,
    };
    if !resp.status().is_success() {
        return VerifyOutcome::NotFound;
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return VerifyOutcome::NotFound,
    };
    if body.lines().any(|line| line.trim() == expected_token) {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::NotFound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_fqdn_strips_trailing_dot() {
        assert_eq!(challenge_fqdn("acme.com"), "_yauth-domain-verify.acme.com");
        assert_eq!(challenge_fqdn("acme.com."), "_yauth-domain-verify.acme.com");
        assert_eq!(
            challenge_fqdn(" acme.com "),
            "_yauth-domain-verify.acme.com"
        );
    }
}
