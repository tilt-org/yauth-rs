//! External identity links — federation-linked users (issue #93).
//!
//! Each row maps a yauth [`crate::User`] to a `(provider, external_id)`
//! pair coming from an external IdP. `provider` is a free-form string;
//! the convention is `"oidc:<issuer_url>"` so two IdPs that happen to
//! mint the same `sub` (e.g. `sub: "1"`) can never collide.
//!
//! # Invariants
//!
//! - `(provider, external_id)` is **deployment-wide unique** — exactly
//!   one yauth user can be linked to a given IdP-side identity at a
//!   time. Re-linking requires the old row to be deleted first
//!   (handler concern; the repo enforces uniqueness on the column
//!   pair).
//! - A single user may have **many** external identities (one per IdP
//!   they sign in via). The pair `(user_id, provider)` is NOT unique —
//!   a user may have two Okta tenants linked, etc.
//!
//! # Anti-takeover
//!
//! When the IdP rotates a user's `email` claim, yauth must NOT silently
//! merge two yauth accounts. The login flow looks up by
//! `(provider, external_id)` first; only if that lookup fails AND
//! JIT-provisioning is enabled do we provision (or, with explicit
//! admin opt-in, re-link an existing yauth account by email).

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An external-IdP-issued identity, linked to a yauth user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Provider string. Convention: `"oidc:<issuer_url_no_trailing_slash>"`
    /// (e.g. `"oidc:https://login.acme.com"`). For SAML (#94) the
    /// convention will be `"saml:<entity_id>"`.
    pub provider: String,
    /// Stable IdP-side identifier — the value of the configured
    /// `external_id` claim (default `sub`).
    pub external_id: String,
    pub linked_at: NaiveDateTime,
    pub last_login_at: NaiveDateTime,
}

/// Insert payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewExternalIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub external_id: String,
    pub linked_at: NaiveDateTime,
    pub last_login_at: NaiveDateTime,
}

/// Build a canonical provider string for an OIDC issuer.
///
/// The trailing slash is normalised away so `https://idp/` and
/// `https://idp` map to the same provider — OIDC issuers are
/// frequently misspelled in admin UIs by one trailing slash.
pub fn oidc_provider(issuer: &str) -> String {
    let trimmed = issuer.trim();
    let no_slash = trimmed.trim_end_matches('/');
    format!("oidc:{no_slash}")
}

/// Build a canonical provider string for a SAML IdP.
///
/// Distinct namespace from [`oidc_provider`] so a SAML IdP and an
/// OIDC IdP that happen to share an issuer URI never collide on the
/// `(provider, external_id)` unique constraint.
pub fn saml_provider(idp_entity_id: &str) -> String {
    let trimmed = idp_entity_id.trim();
    let no_slash = trimmed.trim_end_matches('/');
    format!("saml:{no_slash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saml_provider_namespaces_separately_from_oidc() {
        let s = saml_provider("urn:idp:acme:saml");
        let o = oidc_provider("urn:idp:acme:saml");
        assert_ne!(s, o);
        assert!(s.starts_with("saml:"));
        assert!(o.starts_with("oidc:"));
    }

    #[test]
    fn saml_provider_strips_trailing_slash_and_whitespace() {
        assert_eq!(saml_provider("  urn:idp:acme/  "), "saml:urn:idp:acme");
    }

    #[test]
    fn oidc_provider_strips_trailing_slash() {
        assert_eq!(
            oidc_provider("https://login.acme.com/"),
            "oidc:https://login.acme.com"
        );
    }

    #[test]
    fn oidc_provider_preserves_no_slash() {
        assert_eq!(
            oidc_provider("https://login.acme.com"),
            "oidc:https://login.acme.com"
        );
    }

    #[test]
    fn oidc_provider_trims_whitespace() {
        assert_eq!(
            oidc_provider("  https://idp.example  "),
            "oidc:https://idp.example"
        );
    }
}
