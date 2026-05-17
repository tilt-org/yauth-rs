//! Per-org auth policy resolution + enforcement helpers (issue #92).
//!
//! Lives in `auth` because it sits next to the other gates (session,
//! rbac, rate_limit, password_policy) and is invoked from middleware and
//! login handlers alike.
//!
//! # Resolution order
//!
//! Each "effective" field is the merge of `org_policy` over global
//! `YAuthConfig`. The org policy can only *tighten* the global default
//! for numeric fields; explicit booleans / enums on the org win unconditionally.
//! See [`yauth_entity::organization_policy`] for the human-readable contract.
//!
//! # Failure mode
//!
//! Repository errors during policy lookup are logged via `otel::record_error`
//! and the call **fails open** to the unrestricted policy. A flaky DB
//! should not lock every user out of every org. Enforcement points that
//! 401/403 do so on **explicit policy violations only**, not on lookup
//! errors. This is deliberate — see the comment on
//! [`load_effective_policy`].

use std::net::IpAddr;
use std::str::FromStr;

use axum::http::StatusCode;
use uuid::Uuid;
use yauth_entity::{AuthMethod, OrganizationPolicy, SessionBinding};

use crate::config::YAuthConfig;
use crate::error::{ApiError, api_err};
use crate::state::YAuthState;

/// The materialized policy that actually gates a request. Built by
/// merging an [`OrganizationPolicy`] over the deployment-wide
/// [`YAuthConfig`].
///
/// All fields are absolute (never `Option`) — callers don't need to
/// re-implement the merge logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    /// Max lifetime for a newly created session. `None` = global default
    /// (driven by `YAuthConfig::session_ttl`).
    pub max_session_duration_secs: Option<i64>,
    /// Idle timeout for the session. `None` = no idle timeout.
    pub idle_timeout_secs: Option<i64>,
    pub mfa_required: bool,
    pub mfa_grace_period_days: i32,
    /// Parsed CIDR list. Empty = no restriction. Entries that failed to
    /// parse are silently dropped — the route-level admin validation
    /// catches bad input before storage.
    pub ip_allowlist: Vec<IpAllowEntry>,
    pub max_concurrent_sessions: Option<i32>,
    /// Allowed auth methods. Empty = all methods allowed.
    pub allowed_auth_methods: Vec<AuthMethod>,
    pub session_binding: SessionBinding,
}

/// A single allowlist entry. We support **exact IP match** (no
/// dependency on a CIDR crate) — a CIDR range can be expressed as
/// multiple exact rows in the admin UI when needed. This keeps the
/// runtime feature-flag-clean: no new optional dep for issue #92.
///
/// Future expansion to subnet matching is a non-breaking change since
/// the [`OrganizationPolicy::ip_allowlist`] wire type is `Vec<String>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAllowEntry {
    pub raw: String,
    pub addr: IpAddr,
}

impl IpAllowEntry {
    /// Parse one allowlist entry. Returns `None` for input we cannot
    /// usefully match against — those rows are silently dropped at
    /// resolve time so a single typo doesn't lock the org out.
    pub fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return None;
        }
        // Future: handle CIDR notation. For now, strip an optional `/32`
        // or `/128` suffix that is functionally equivalent to an exact
        // match — admins commonly paste CIDR even for single hosts.
        let host_part = trimmed.split_once('/').map_or(trimmed, |(h, _)| h);
        IpAddr::from_str(host_part).ok().map(|addr| Self {
            raw: trimmed.to_string(),
            addr,
        })
    }
}

impl EffectivePolicy {
    /// "No restriction" policy. Used when no org context exists or when
    /// the policy repo failed to load (see [`load_effective_policy`]).
    pub fn unrestricted() -> Self {
        Self {
            max_session_duration_secs: None,
            idle_timeout_secs: None,
            mfa_required: false,
            mfa_grace_period_days: 14,
            ip_allowlist: Vec::new(),
            max_concurrent_sessions: None,
            allowed_auth_methods: Vec::new(),
            session_binding: SessionBinding::None,
        }
    }

    /// Merge a stored [`OrganizationPolicy`] over the global config.
    ///
    /// Numeric fields use **stricter-wins** semantics — a smaller
    /// session lifetime / smaller idle timeout / smaller max-concurrent
    /// always beats a larger one. Booleans take the org's explicit
    /// setting. List fields take the org's contents verbatim (empty =
    /// no restriction).
    pub fn from_merge(global: &YAuthConfig, org_policy: Option<&OrganizationPolicy>) -> Self {
        let global_session_secs = i64::try_from(global.session_ttl.as_secs()).ok();
        let bind_ip = global.session_binding.bind_ip;
        let bind_ua = global.session_binding.bind_user_agent;
        let global_binding = match (bind_ip, bind_ua) {
            (true, true) => SessionBinding::Both,
            (true, false) => SessionBinding::Ip,
            (false, true) => SessionBinding::UserAgent,
            (false, false) => SessionBinding::None,
        };

        let Some(p) = org_policy else {
            return Self {
                max_session_duration_secs: global_session_secs,
                idle_timeout_secs: None,
                mfa_required: false,
                mfa_grace_period_days: 14,
                ip_allowlist: Vec::new(),
                max_concurrent_sessions: None,
                allowed_auth_methods: Vec::new(),
                session_binding: global_binding,
            };
        };

        let max_session = match (global_session_secs, p.max_session_duration_secs) {
            (Some(g), Some(o)) => Some(g.min(o)),
            (Some(g), None) => Some(g),
            (None, o) => o,
        };

        let ip_allowlist = p
            .ip_allowlist
            .iter()
            .filter_map(|s| IpAllowEntry::parse(s))
            .collect();

        Self {
            max_session_duration_secs: max_session,
            idle_timeout_secs: p.idle_timeout_secs,
            mfa_required: p.mfa_required,
            mfa_grace_period_days: p.mfa_grace_period_days,
            ip_allowlist,
            max_concurrent_sessions: p.max_concurrent_sessions,
            allowed_auth_methods: p.allowed_auth_methods.clone(),
            // Org binding overrides global only when set to non-None.
            // Treating "policy::None" as "inherit" matches the rest of
            // the resolution rules — admins who want to *force* "no
            // binding" should change the global config, not the org.
            session_binding: if p.session_binding == SessionBinding::None {
                global_binding
            } else {
                p.session_binding
            },
        }
    }
}

/// Load and merge the org policy for `org_id`. Returns the unrestricted
/// policy with global defaults when:
///
/// - `org_id` is `None` (single-tenant request)
/// - the repo returns `Ok(None)` (org never set a custom policy)
/// - the repo errors (failure is logged via OTel; we fail open so a
///   flaky DB doesn't lock every member out — operators see the OTel
///   alert and act)
pub async fn load_effective_policy(state: &YAuthState, org_id: Option<Uuid>) -> EffectivePolicy {
    let Some(org_id) = org_id else {
        return EffectivePolicy::from_merge(&state.config, None);
    };
    match state.repos.organization_policies.find_for_org(org_id).await {
        Ok(p) => EffectivePolicy::from_merge(&state.config, p.as_ref()),
        Err(e) => {
            crate::otel::record_error("org_policy_load_failed", &e);
            EffectivePolicy::from_merge(&state.config, None)
        }
    }
}

// ──────────────────────────────────────────────
// Enforcement helpers
// ──────────────────────────────────────────────

/// Clamp a proposed session duration (seconds) to the effective max.
///
/// The shorter of the two wins. `proposed_secs = 0` is interpreted as
/// "use the policy max" — handy for callers that want to "issue a
/// session whose lifetime follows the org policy".
pub fn clamp_session_duration(policy: &EffectivePolicy, proposed_secs: u64) -> u64 {
    let Some(cap) = policy.max_session_duration_secs.filter(|c| *c > 0) else {
        return proposed_secs;
    };
    let cap = cap as u64;
    if proposed_secs == 0 {
        return cap;
    }
    proposed_secs.min(cap)
}

/// Reject a request whose client IP is not in the policy's allowlist.
///
/// `client_ip` is the resolved request IP (post-proxy parsing). When
/// `policy.ip_allowlist` is empty this is a no-op. When non-empty:
/// - parsable `client_ip` matched exactly against the list,
/// - missing or unparsable `client_ip` is rejected (defense-in-depth:
///   if the proxy headers were stripped we cannot prove the source).
pub fn enforce_ip_allowlist(
    policy: &EffectivePolicy,
    client_ip: Option<&str>,
) -> Result<(), ApiError> {
    if policy.ip_allowlist.is_empty() {
        return Ok(());
    }
    let Some(ip_str) = client_ip else {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "IP allowlist enforced but client IP is unknown",
        ));
    };
    let Ok(addr) = IpAddr::from_str(ip_str.trim()) else {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "IP allowlist enforced but client IP is unparseable",
        ));
    };
    if policy.ip_allowlist.iter().any(|e| e.addr == addr) {
        Ok(())
    } else {
        Err(api_err(
            StatusCode::FORBIDDEN,
            "client IP not in organization allowlist",
        ))
    }
}

/// Reject a login attempt that uses a disabled auth method.
///
/// Returns `405 Method Not Allowed` so the client can render a helpful
/// message ("this org disallows password sign-in, use SSO"). When the
/// allowlist is empty, every method passes (inherit global behavior).
pub fn enforce_auth_method(policy: &EffectivePolicy, method: &AuthMethod) -> Result<(), ApiError> {
    if policy.allowed_auth_methods.is_empty() {
        return Ok(());
    }
    if policy.allowed_auth_methods.contains(method) {
        Ok(())
    } else {
        Err(api_err(
            StatusCode::METHOD_NOT_ALLOWED,
            "Authentication method disabled for this organization",
        ))
    }
}

/// Reject a request whose session is older than the idle timeout.
///
/// `last_seen_at_secs_ago` is "wall-clock seconds since the session's
/// `last_seen_at` (or `created_at`, whichever is later)". The caller
/// owns the clock — this helper only does the math.
pub fn enforce_idle_timeout(
    policy: &EffectivePolicy,
    last_seen_at_secs_ago: i64,
) -> Result<(), ApiError> {
    let Some(idle) = policy.idle_timeout_secs.filter(|n| *n > 0) else {
        return Ok(());
    };
    if last_seen_at_secs_ago > idle {
        Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Session idle timeout exceeded; please sign in again",
        ))
    } else {
        Ok(())
    }
}

/// Check session binding constraints — refuse if IP or User-Agent
/// changed mid-session beyond what the policy allows.
///
/// Returns `Err` on mismatch when the bound dimension is mandatory. For
/// "no binding" or "unbound dimension" the result is always `Ok`. The
/// 401 is the documented pentest case from issue #92 (cannot bypass
/// allowlist by mid-session IP change).
pub fn enforce_session_binding(
    policy: &EffectivePolicy,
    stored_ip: Option<&str>,
    request_ip: Option<&str>,
    stored_ua: Option<&str>,
    request_ua: Option<&str>,
) -> Result<(), ApiError> {
    if policy.session_binding.requires_ip()
        && let Some(stored) = stored_ip
        && stored != request_ip.unwrap_or("")
    {
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Session bound to different client IP",
        ));
    }
    if policy.session_binding.requires_user_agent()
        && let Some(stored) = stored_ua
        && stored != request_ua.unwrap_or("")
    {
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Session bound to different User-Agent",
        ));
    }
    Ok(())
}

/// Decide whether MFA enrollment must be enforced for this user RIGHT
/// NOW. Returns `true` when:
///   * the policy requires MFA, AND
///   * the user has no enrolled factor, AND
///   * the grace period from `account_created_at` has expired.
///
/// `now_secs_since_account_creation` is "how many seconds since the
/// user's account was created" — past the grace period the gate flips
/// on. Callers should let unenrolled users hit the MFA enrollment
/// routes only.
pub fn must_force_mfa_enrollment(
    policy: &EffectivePolicy,
    is_mfa_enrolled: bool,
    now_secs_since_account_creation: i64,
) -> bool {
    if !policy.mfa_required {
        return false;
    }
    if is_mfa_enrolled {
        return false;
    }
    let grace_secs = i64::from(policy.mfa_grace_period_days).max(0) * 86_400;
    now_secs_since_account_creation > grace_secs
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_policy(modify: impl FnOnce(&mut OrganizationPolicy)) -> OrganizationPolicy {
        let now = Utc::now().naive_utc();
        let mut p = OrganizationPolicy {
            organization_id: Uuid::nil(),
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
        };
        modify(&mut p);
        p
    }

    #[test]
    fn merge_uses_stricter_session_duration() {
        let mut global = YAuthConfig::default();
        // Global = 7 days. Org caps to 1h.
        global.session_ttl = std::time::Duration::from_secs(604_800);
        let p = make_policy(|p| p.max_session_duration_secs = Some(3600));
        let eff = EffectivePolicy::from_merge(&global, Some(&p));
        assert_eq!(eff.max_session_duration_secs, Some(3600));
    }

    #[test]
    fn merge_keeps_global_when_org_unset() {
        let mut global = YAuthConfig::default();
        global.session_ttl = std::time::Duration::from_secs(3600);
        let eff = EffectivePolicy::from_merge(&global, None);
        assert_eq!(eff.max_session_duration_secs, Some(3600));
    }

    #[test]
    fn merge_promotes_org_mfa_to_true() {
        let global = YAuthConfig::default();
        let p = make_policy(|p| p.mfa_required = true);
        let eff = EffectivePolicy::from_merge(&global, Some(&p));
        assert!(eff.mfa_required);
    }

    #[test]
    fn clamp_session_duration_respects_cap() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.max_session_duration_secs = Some(60);
        assert_eq!(clamp_session_duration(&eff, 3600), 60);
        // proposed_secs = 0 → use cap.
        assert_eq!(clamp_session_duration(&eff, 0), 60);
    }

    #[test]
    fn clamp_session_duration_no_cap_passes_through() {
        let eff = EffectivePolicy::unrestricted();
        assert_eq!(clamp_session_duration(&eff, 60), 60);
        assert_eq!(clamp_session_duration(&eff, 0), 0);
    }

    #[test]
    fn enforce_ip_allowlist_blocks_unlisted() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.ip_allowlist = vec![IpAllowEntry::parse("10.0.0.1").unwrap()];
        assert!(enforce_ip_allowlist(&eff, Some("10.0.0.1")).is_ok());
        assert!(enforce_ip_allowlist(&eff, Some("10.0.0.2")).is_err());
        assert!(enforce_ip_allowlist(&eff, None).is_err());
        assert!(enforce_ip_allowlist(&eff, Some("garbage")).is_err());
    }

    #[test]
    fn enforce_ip_allowlist_empty_is_noop() {
        let eff = EffectivePolicy::unrestricted();
        assert!(enforce_ip_allowlist(&eff, None).is_ok());
        assert!(enforce_ip_allowlist(&eff, Some("anything")).is_ok());
    }

    #[test]
    fn enforce_auth_method_gate() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.allowed_auth_methods = vec![AuthMethod::SsoSaml];
        assert!(enforce_auth_method(&eff, &AuthMethod::SsoSaml).is_ok());
        assert!(enforce_auth_method(&eff, &AuthMethod::Password).is_err());
        // Empty list = no restriction.
        eff.allowed_auth_methods.clear();
        assert!(enforce_auth_method(&eff, &AuthMethod::Password).is_ok());
    }

    #[test]
    fn enforce_idle_timeout_triggers_past_cap() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.idle_timeout_secs = Some(60);
        assert!(enforce_idle_timeout(&eff, 30).is_ok());
        assert!(enforce_idle_timeout(&eff, 61).is_err());
        // No idle cap = no-op.
        eff.idle_timeout_secs = None;
        assert!(enforce_idle_timeout(&eff, 999_999).is_ok());
    }

    #[test]
    fn enforce_session_binding_ip_change_blocks() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.session_binding = SessionBinding::Ip;
        assert!(
            enforce_session_binding(&eff, Some("1.1.1.1"), Some("1.1.1.1"), None, None).is_ok()
        );
        assert!(
            enforce_session_binding(&eff, Some("1.1.1.1"), Some("9.9.9.9"), None, None).is_err()
        );
    }

    #[test]
    fn enforce_session_binding_ua_change_blocks() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.session_binding = SessionBinding::UserAgent;
        assert!(enforce_session_binding(&eff, None, None, Some("foo"), Some("foo")).is_ok());
        assert!(enforce_session_binding(&eff, None, None, Some("foo"), Some("bar")).is_err());
    }

    #[test]
    fn must_force_mfa_enrollment_respects_grace() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.mfa_required = true;
        eff.mfa_grace_period_days = 1; // 86_400s
        assert!(!must_force_mfa_enrollment(&eff, false, 1)); // inside grace
        assert!(must_force_mfa_enrollment(&eff, false, 86_500)); // past grace
        assert!(!must_force_mfa_enrollment(&eff, true, 86_500)); // already enrolled
        eff.mfa_required = false;
        assert!(!must_force_mfa_enrollment(&eff, false, 999_999));
    }

    #[test]
    fn ip_entry_strips_cidr_suffix() {
        assert_eq!(
            IpAllowEntry::parse("10.0.0.1/32").map(|e| e.addr.to_string()),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn ip_entry_rejects_garbage() {
        assert!(IpAllowEntry::parse("not-an-ip").is_none());
        assert!(IpAllowEntry::parse("").is_none());
    }
}
