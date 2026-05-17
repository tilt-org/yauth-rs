//! Verified email domains + JIT membership (issue #90).
//!
//! Organizations may claim email domains (e.g. `acme.com`). Once verified
//! via DNS TXT record (or the optional `.well-known` HTTP fallback), users
//! who sign up — or whose email becomes verified — with an address in that
//! domain are automatically added to the organization with a default role.
//!
//! ## Anti-abuse
//!
//! - `domain` is **deployment-wide unique** — at most one org may claim a
//!   given domain. This is enforced at the storage layer.
//! - Only org admins/owners may claim or remove a domain.
//! - Verification is challenge-response: the org publishes a DNS TXT
//!   record at `_yauth-domain-verify.<domain>` containing the
//!   per-domain `verification_token` issued at claim time.
//! - Auto-join is gated by `require_email_verified` (default `true`) so
//!   typosquatting accounts cannot piggy-back into a claimed org.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Lifecycle state for an [`OrganizationDomain`] claim.
///
/// Stored as `VARCHAR` (mirrors `MembershipStatus`) so backend DDL stays
/// uniform across dialects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainStatus {
    /// Claim recorded, not yet verified.
    Pending,
    /// Verification passed at least once. Auto-join eligible.
    Verified,
    /// Last verification attempt failed (DNS missing token, etc.).
    Failed,
}

impl DomainStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DomainStatus::Pending => "pending",
            DomainStatus::Verified => "verified",
            DomainStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "verified" => Some(Self::Verified),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// A domain claim attached to an [`Organization`](super::Organization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationDomain {
    pub id: Uuid,
    pub organization_id: Uuid,
    /// Canonical, lowercase domain (e.g. `"acme.com"`).
    pub domain: String,
    pub status: DomainStatus,
    /// Random opaque value the verifier looks for in the DNS TXT record.
    /// Returned ONCE at claim time — clients show this to the operator so
    /// they can publish the record.
    pub verification_token: String,
    pub verified_at: Option<NaiveDateTime>,
    pub last_checked_at: Option<NaiveDateTime>,
    /// Whether matching new users should be auto-joined to the org.
    pub auto_join_on_signup: bool,
    /// Role granted on auto-join (defaults to `"member"`).
    pub default_role_on_auto_join: String,
    /// Auto-join only after the user has verified their email address.
    /// Defaults to `true` — see anti-abuse note on the module.
    pub require_email_verified: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Input payload for `OrganizationDomainRepository::create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrganizationDomain {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub domain: String,
    pub status: DomainStatus,
    pub verification_token: String,
    pub verified_at: Option<NaiveDateTime>,
    pub last_checked_at: Option<NaiveDateTime>,
    pub auto_join_on_signup: bool,
    pub default_role_on_auto_join: String,
    pub require_email_verified: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Partial update for an [`OrganizationDomain`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateOrganizationDomain {
    pub status: Option<DomainStatus>,
    pub verified_at: Option<Option<NaiveDateTime>>,
    pub last_checked_at: Option<Option<NaiveDateTime>>,
    pub auto_join_on_signup: Option<bool>,
    pub default_role_on_auto_join: Option<String>,
    pub require_email_verified: Option<bool>,
    pub updated_at: Option<NaiveDateTime>,
}

/// Extract the domain part of an email address and lowercase it.
///
/// Returns `None` if there is no `@` or the domain part is empty.
pub fn domain_from_email(email: &str) -> Option<String> {
    let (_local, domain) = email.split_once('@')?;
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trip() {
        for s in [
            DomainStatus::Pending,
            DomainStatus::Verified,
            DomainStatus::Failed,
        ] {
            assert_eq!(DomainStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(DomainStatus::parse("nope"), None);
    }

    #[test]
    fn domain_from_email_lowercases() {
        assert_eq!(
            domain_from_email("Alice@Acme.COM"),
            Some("acme.com".to_string())
        );
    }

    #[test]
    fn domain_from_email_rejects_missing_at() {
        assert_eq!(domain_from_email("no-at-sign"), None);
    }

    #[test]
    fn domain_from_email_rejects_empty_domain() {
        assert_eq!(domain_from_email("user@"), None);
    }
}
