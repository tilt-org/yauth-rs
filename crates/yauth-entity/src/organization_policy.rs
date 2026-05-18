//! Per-organization auth policy (issue #92).
//!
//! Lets app admins opt in to stricter posture than the deployment-wide
//! `YAuthConfig` — for one org or for many — without affecting every other
//! tenant. The policy attaches one-to-one to an [`Organization`] and is
//! resolved per request when the caller has an active org.
//!
//! # Resolution order
//!
//! When a user is acting in an active org, the **effective policy** is the
//! merge of the org policy with the global `YAuthConfig`:
//!
//! - **Numeric fields** (`max_session_duration_secs`, `idle_timeout_secs`,
//!   `max_concurrent_sessions`) — the **stricter** value wins. `Some(60)`
//!   beats both `Some(3600)` and `None`. The org policy can only
//!   *tighten* the global default; it cannot loosen it.
//! - **Booleans / explicit toggles** (`mfa_required`, `session_binding`)
//!   — the org policy's explicit setting wins. `mfa_required = true` on
//!   the org forces MFA even if the global default is `false`.
//! - **List fields** (`ip_allowlist`, `allowed_auth_methods`) — when the
//!   org policy is empty, no restriction (inherit global). When the org
//!   policy is non-empty, only entries in the org list are permitted.
//!
//! See `docs/configuration.md` for a worked example.
//!
//! # Cross-org users
//!
//! A user logged into org A and switching to org B has their session
//! re-evaluated against B's policy on the very next request — there is
//! no caching. The middleware reads the active-org column on the session
//! row (or the `org` claim on the JWT) and resolves the effective policy
//! fresh on each call.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How sessions are bound to the originating client (issue #92).
///
/// Maps to a stored VARCHAR so the column survives across all SQL dialects
/// (mirrors `MembershipStatus` / `DomainStatus`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionBinding {
    /// No binding — sessions roam freely across IPs and User-Agents.
    #[default]
    None,
    /// Bind to client IP. A request with a mismatched IP is rejected.
    Ip,
    /// Bind to the User-Agent string.
    UserAgent,
    /// Bind to both IP **and** User-Agent — strictest.
    Both,
}

impl SessionBinding {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionBinding::None => "none",
            SessionBinding::Ip => "ip",
            SessionBinding::UserAgent => "user_agent",
            SessionBinding::Both => "both",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "ip" => Some(Self::Ip),
            "user_agent" => Some(Self::UserAgent),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    /// True if this binding requires an IP match on every request.
    pub fn requires_ip(self) -> bool {
        matches!(self, Self::Ip | Self::Both)
    }

    /// True if this binding requires a User-Agent match on every request.
    pub fn requires_user_agent(self) -> bool {
        matches!(self, Self::UserAgent | Self::Both)
    }
}

/// Identifier for an authentication method an org may enable or disable
/// (issue #92, `allowed_auth_methods`).
///
/// Stored as a string in the per-org policy's JSON column so adding a new
/// method (e.g. `sso_oidc`) requires no DDL migration. Unknown variants
/// round-trip through [`AuthMethod::Other`] to keep the policy parseable
/// after a yauth downgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Passkey,
    MagicLink,
    Oauth,
    SsoSaml,
    SsoOidc,
    Bearer,
    ApiKey,
    /// Forward-compat variant for methods added after this binary was
    /// built. Carries the raw string so the wire format round-trips.
    #[serde(untagged)]
    Other(String),
}

impl AuthMethod {
    pub fn as_str(&self) -> &str {
        match self {
            AuthMethod::Password => "password",
            AuthMethod::Passkey => "passkey",
            AuthMethod::MagicLink => "magic_link",
            AuthMethod::Oauth => "oauth",
            AuthMethod::SsoSaml => "sso_saml",
            AuthMethod::SsoOidc => "sso_oidc",
            AuthMethod::Bearer => "bearer",
            AuthMethod::ApiKey => "api_key",
            AuthMethod::Other(s) => s.as_str(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "password" => Self::Password,
            "passkey" => Self::Passkey,
            "magic_link" => Self::MagicLink,
            "oauth" => Self::Oauth,
            "sso_saml" => Self::SsoSaml,
            "sso_oidc" => Self::SsoOidc,
            "bearer" => Self::Bearer,
            "api_key" => Self::ApiKey,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Per-organization auth policy (issue #92).
///
/// Every field is `Option` / `Vec` so that the **default** policy carries
/// "no restriction" and inherits from the deployment-wide `YAuthConfig`.
/// Each field's resolution semantics are documented on the module — read
/// that **before** modifying behavior, lest you accidentally loosen
/// posture for orgs that opted into a stricter setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationPolicy {
    /// One row per organization. The org's UUID is also the policy's
    /// primary key (1:1).
    pub organization_id: Uuid,
    /// Max session lifetime in seconds. `None` = inherit
    /// `YAuthConfig::session_ttl`. When `Some(n)`, the org's session
    /// `expires_at` is clamped to `min(global_ttl, n)`.
    pub max_session_duration_secs: Option<i64>,
    /// Idle timeout in seconds. After this much inactivity (no
    /// authenticated request), the next request 401s and the session is
    /// purged. `None` = no idle timeout.
    pub idle_timeout_secs: Option<i64>,
    /// Require MFA enrollment for all members. After `mfa_grace_period_days`
    /// from the user's first session, unenrolled members are blocked from
    /// every route except MFA enrollment.
    pub mfa_required: bool,
    /// Grace period in days for new members to enroll an MFA factor. After
    /// this, requests are blocked until enrollment completes.
    pub mfa_grace_period_days: i32,
    /// CIDR allowlist for the org. Empty = no restriction. Stored as
    /// `Vec<String>` (e.g. `"10.0.0.0/8"`) so the wire format is dialect
    /// independent; parsed lazily at enforcement time.
    pub ip_allowlist: Vec<String>,
    /// Cap on simultaneous active sessions per member. When at-cap, the
    /// oldest session is revoked on the next create.
    pub max_concurrent_sessions: Option<i32>,
    /// Allowed authentication methods. Empty = all methods inherited from
    /// global. Non-empty = ONLY these methods are accepted for new
    /// logins. Existing sessions established via a disallowed method
    /// are NOT retroactively revoked — re-keying is an admin action.
    pub allowed_auth_methods: Vec<AuthMethod>,
    /// Session binding mode — see [`SessionBinding`].
    pub session_binding: SessionBinding,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl OrganizationPolicy {
    /// Construct a "no restriction" policy for a fresh org. All fields
    /// inherit from global config; identical posture to having no row at
    /// all.
    pub fn unrestricted(organization_id: Uuid, now: NaiveDateTime) -> Self {
        Self {
            organization_id,
            max_session_duration_secs: None,
            idle_timeout_secs: None,
            mfa_required: false,
            mfa_grace_period_days: 14,
            ip_allowlist: Vec::new(),
            max_concurrent_sessions: None,
            allowed_auth_methods: Vec::new(),
            session_binding: SessionBinding::None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Insert payload for the policy repository. Same shape as the entity —
/// the repo derives no fields server-side, callers stamp `created_at` /
/// `updated_at` themselves so wall-clock skew is the caller's problem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrganizationPolicy {
    pub organization_id: Uuid,
    pub max_session_duration_secs: Option<i64>,
    pub idle_timeout_secs: Option<i64>,
    pub mfa_required: bool,
    pub mfa_grace_period_days: i32,
    pub ip_allowlist: Vec<String>,
    pub max_concurrent_sessions: Option<i32>,
    pub allowed_auth_methods: Vec<AuthMethod>,
    pub session_binding: SessionBinding,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Partial update for an [`OrganizationPolicy`]. Each `Option` distinguishes
/// "don't touch" (`None`) from "set to this value" (`Some(_)`). For list
/// fields the inner type is the whole list, replacing the existing rows
/// atomically — there is no add/remove API to avoid TOCTOU during the
/// admin form's PATCH cycle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateOrganizationPolicy {
    pub max_session_duration_secs: Option<Option<i64>>,
    pub idle_timeout_secs: Option<Option<i64>>,
    pub mfa_required: Option<bool>,
    pub mfa_grace_period_days: Option<i32>,
    pub ip_allowlist: Option<Vec<String>>,
    pub max_concurrent_sessions: Option<Option<i32>>,
    pub allowed_auth_methods: Option<Vec<AuthMethod>>,
    pub session_binding: Option<SessionBinding>,
    pub updated_at: Option<NaiveDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_binding_round_trip() {
        for b in [
            SessionBinding::None,
            SessionBinding::Ip,
            SessionBinding::UserAgent,
            SessionBinding::Both,
        ] {
            assert_eq!(SessionBinding::parse(b.as_str()), Some(b));
        }
        assert_eq!(SessionBinding::parse("nope"), None);
    }

    #[test]
    fn session_binding_requires() {
        assert!(!SessionBinding::None.requires_ip());
        assert!(!SessionBinding::None.requires_user_agent());
        assert!(SessionBinding::Ip.requires_ip());
        assert!(!SessionBinding::Ip.requires_user_agent());
        assert!(!SessionBinding::UserAgent.requires_ip());
        assert!(SessionBinding::UserAgent.requires_user_agent());
        assert!(SessionBinding::Both.requires_ip());
        assert!(SessionBinding::Both.requires_user_agent());
    }

    #[test]
    fn auth_method_round_trip() {
        for m in [
            AuthMethod::Password,
            AuthMethod::Passkey,
            AuthMethod::MagicLink,
            AuthMethod::Oauth,
            AuthMethod::SsoSaml,
            AuthMethod::SsoOidc,
            AuthMethod::Bearer,
            AuthMethod::ApiKey,
        ] {
            let s = m.as_str().to_string();
            assert_eq!(AuthMethod::parse(&s), m);
        }
        // Forward-compat: unknown variant survives the round trip.
        match AuthMethod::parse("future_method") {
            AuthMethod::Other(s) => assert_eq!(s, "future_method"),
            _ => panic!("expected Other"),
        }
    }

    #[test]
    fn unrestricted_default_is_no_restriction() {
        let now = chrono::Utc::now().naive_utc();
        let p = OrganizationPolicy::unrestricted(Uuid::nil(), now);
        assert!(p.max_session_duration_secs.is_none());
        assert!(p.idle_timeout_secs.is_none());
        assert!(!p.mfa_required);
        assert!(p.ip_allowlist.is_empty());
        assert!(p.max_concurrent_sessions.is_none());
        assert!(p.allowed_auth_methods.is_empty());
        assert_eq!(p.session_binding, SessionBinding::None);
    }
}
