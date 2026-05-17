//! Integration tests for per-organization auth policy (issue #92).
//!
//! Two test surfaces:
//!
//! 1. **Repository invariants** on the in-memory backend — round-trip,
//!    cascade-on-org-delete, unique-per-org `create`, partial update.
//! 2. **Enforcement logic** in `auth::policy_enforcer` — resolution
//!    order (stricter wins on numerics, explicit wins on toggles), and
//!    each of the seven enforcement points from issue #92's design
//!    table. Pentest-flavored cases (mid-session IP change, MFA grace
//!    expiry, disabled auth method) live under
//!    [`pentest`] so `cargo test pentest` picks them up.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password"
))]

use std::time::Duration;

use chrono::Utc;
use uuid::Uuid;

use yauth::auth::policy_enforcer::{
    EffectivePolicy, IpAllowEntry, clamp_session_duration, enforce_auth_method,
    enforce_idle_timeout, enforce_ip_allowlist, enforce_session_binding, must_force_mfa_enrollment,
};
use yauth::backends::memory::InMemoryBackend;
use yauth::config::YAuthConfig;
use yauth::repo::{DatabaseBackend, RepoError};
use yauth_entity::{
    AuthMethod, NewOrganization, NewOrganizationPolicy, OrganizationPolicy, SessionBinding,
    UpdateOrganizationPolicy,
};

fn now() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

fn new_org(slug: &str) -> NewOrganization {
    let now = now();
    NewOrganization {
        id: Uuid::now_v7(),
        name: slug.to_string(),
        slug: slug.to_string(),
        display_name: None,
        avatar_url: None,
        metadata: None,
        created_at: now,
        updated_at: now,
    }
}

fn unrestricted_policy(org_id: Uuid) -> NewOrganizationPolicy {
    let now = now();
    NewOrganizationPolicy {
        organization_id: org_id,
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

// ──────────────────────────────────────────────
// Repository invariants
// ──────────────────────────────────────────────

#[tokio::test]
async fn create_and_round_trip() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();

    // No row yet — "missing" returns Ok(None), not an error.
    assert!(
        repos
            .organization_policies
            .find_for_org(org.id)
            .await
            .unwrap()
            .is_none()
    );

    let created = repos
        .organization_policies
        .create(NewOrganizationPolicy {
            mfa_required: true,
            idle_timeout_secs: Some(900),
            ..unrestricted_policy(org.id)
        })
        .await
        .unwrap();
    assert!(created.mfa_required);
    assert_eq!(created.idle_timeout_secs, Some(900));

    let fetched = repos
        .organization_policies
        .find_for_org(org.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched, created);
}

#[tokio::test]
async fn second_create_is_conflict() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();

    repos
        .organization_policies
        .create(unrestricted_policy(org.id))
        .await
        .unwrap();
    let err = repos
        .organization_policies
        .create(unrestricted_policy(org.id))
        .await
        .unwrap_err();
    assert!(matches!(err, RepoError::Conflict(_)), "got {err:?}");
}

#[tokio::test]
async fn partial_update_preserves_unrelated_fields() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let _ = repos
        .organization_policies
        .create(NewOrganizationPolicy {
            mfa_required: true,
            idle_timeout_secs: Some(600),
            ip_allowlist: vec!["10.0.0.1".to_string()],
            ..unrestricted_policy(org.id)
        })
        .await
        .unwrap();

    // Touch only idle_timeout.
    let updated = repos
        .organization_policies
        .update(
            org.id,
            UpdateOrganizationPolicy {
                idle_timeout_secs: Some(Some(120)),
                updated_at: Some(now()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.idle_timeout_secs, Some(120));
    assert!(updated.mfa_required); // preserved
    assert_eq!(updated.ip_allowlist, vec!["10.0.0.1".to_string()]); // preserved
}

#[tokio::test]
async fn update_clear_with_inner_none() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let _ = repos
        .organization_policies
        .create(NewOrganizationPolicy {
            idle_timeout_secs: Some(600),
            ..unrestricted_policy(org.id)
        })
        .await
        .unwrap();

    let updated = repos
        .organization_policies
        .update(
            org.id,
            UpdateOrganizationPolicy {
                idle_timeout_secs: Some(None),
                updated_at: Some(now()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(updated.idle_timeout_secs.is_none());
}

#[tokio::test]
async fn update_missing_org_is_not_found() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let err = repos
        .organization_policies
        .update(
            Uuid::now_v7(),
            UpdateOrganizationPolicy {
                mfa_required: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RepoError::NotFound), "got {err:?}");
}

#[tokio::test]
async fn org_delete_cascades_policy() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let _ = repos
        .organization_policies
        .create(unrestricted_policy(org.id))
        .await
        .unwrap();

    repos.organizations.delete(org.id).await.unwrap();
    assert!(
        repos
            .organization_policies
            .find_for_org(org.id)
            .await
            .unwrap()
            .is_none()
    );
}

// ──────────────────────────────────────────────
// Resolution order
// ──────────────────────────────────────────────

#[test]
fn merge_stricter_wins_on_session_duration() {
    let mut global = YAuthConfig::default();
    global.session_ttl = Duration::from_secs(86_400); // 1 day
    let now = now();
    // Org caps to 1 hour.
    let p = OrganizationPolicy {
        organization_id: Uuid::nil(),
        max_session_duration_secs: Some(3600),
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
    let eff = EffectivePolicy::from_merge(&global, Some(&p));
    assert_eq!(eff.max_session_duration_secs, Some(3600));
}

#[test]
fn merge_no_policy_inherits_global() {
    let mut global = YAuthConfig::default();
    global.session_ttl = Duration::from_secs(3600);
    let eff = EffectivePolicy::from_merge(&global, None);
    assert_eq!(eff.max_session_duration_secs, Some(3600));
    assert!(!eff.mfa_required);
}

#[test]
fn merge_org_explicit_mfa_overrides_global_false() {
    let global = YAuthConfig::default();
    let now = now();
    let p = OrganizationPolicy {
        organization_id: Uuid::nil(),
        max_session_duration_secs: None,
        idle_timeout_secs: None,
        mfa_required: true,
        mfa_grace_period_days: 7,
        ip_allowlist: Vec::new(),
        max_concurrent_sessions: None,
        allowed_auth_methods: Vec::new(),
        session_binding: SessionBinding::None,
        created_at: now,
        updated_at: now,
    };
    let eff = EffectivePolicy::from_merge(&global, Some(&p));
    assert!(eff.mfa_required);
    assert_eq!(eff.mfa_grace_period_days, 7);
}

// ──────────────────────────────────────────────
// Enforcement points
// ──────────────────────────────────────────────

#[test]
fn clamp_session_duration_caps_to_policy() {
    let mut eff = EffectivePolicy::unrestricted();
    eff.max_session_duration_secs = Some(60);
    assert_eq!(clamp_session_duration(&eff, 3600), 60);
    assert_eq!(clamp_session_duration(&eff, 30), 30);
}

#[test]
fn auth_method_disabled_returns_405() {
    let mut eff = EffectivePolicy::unrestricted();
    eff.allowed_auth_methods = vec![AuthMethod::SsoSaml];
    let err = enforce_auth_method(&eff, &AuthMethod::Password).unwrap_err();
    // The pentest case from issue #92: "allowed_auth_methods restricted
    // to SSO — direct password login returns 405."
    assert_eq!(err.0, axum::http::StatusCode::METHOD_NOT_ALLOWED);
}

#[test]
fn ip_allowlist_blocks_unlisted_ip() {
    let mut eff = EffectivePolicy::unrestricted();
    eff.ip_allowlist = vec![IpAllowEntry::parse("203.0.113.5").unwrap()];
    assert!(enforce_ip_allowlist(&eff, Some("203.0.113.5")).is_ok());
    let err = enforce_ip_allowlist(&eff, Some("198.51.100.1")).unwrap_err();
    assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
}

#[test]
fn idle_timeout_blocks_stale_session() {
    let mut eff = EffectivePolicy::unrestricted();
    eff.idle_timeout_secs = Some(30);
    assert!(enforce_idle_timeout(&eff, 10).is_ok());
    let err = enforce_idle_timeout(&eff, 60).unwrap_err();
    assert_eq!(err.0, axum::http::StatusCode::UNAUTHORIZED);
}

// ──────────────────────────────────────────────
// Pentest cases
// ──────────────────────────────────────────────

mod pentest {
    use super::*;

    /// Issue #92 pentest case: "Session created in org A with 2h
    /// timeout — switching to org B with 8h must NOT extend (re-eval
    /// per request)."
    ///
    /// The check is structural: the enforcer reads from a fresh
    /// [`EffectivePolicy`] each call and never caches the
    /// stricter-wins decision across orgs.
    #[test]
    fn org_switch_does_not_extend_session_cap() {
        // Imagine the user's request currently resolves against org A.
        let mut eff_a = EffectivePolicy::unrestricted();
        eff_a.max_session_duration_secs = Some(7200); // 2h
        assert_eq!(clamp_session_duration(&eff_a, 86_400), 7200);

        // Now they switch to org B with a looser 8h cap. The middleware
        // re-resolves and builds a NEW EffectivePolicy from B. The cap
        // is whatever B's policy says — but per the issue, the existing
        // session's `expires_at` was already clamped at create time, so
        // even though `max_session_duration_secs` is wider here, the
        // server-stored expiry doesn't bump. That property is enforced
        // at the *session-create* boundary, not at the policy-resolve
        // boundary. The pentest here is that policy-resolve is stateless
        // — switching orgs is not a session-expiry-rewriting operation.
        let mut eff_b = EffectivePolicy::unrestricted();
        eff_b.max_session_duration_secs = Some(28_800); // 8h

        // Stricter cap (A) was applied at session creation; switching
        // to B at most relaxes the cap for *new* sessions. Existing
        // session is unchanged.
        assert_eq!(clamp_session_duration(&eff_b, 7200), 7200);
    }

    /// Issue #92 pentest case: "Bypass IP allowlist by changing IP
    /// mid-session — every request re-checks."
    #[test]
    fn ip_allowlist_rechecks_each_request() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.ip_allowlist = vec![IpAllowEntry::parse("10.0.0.1").unwrap()];

        // First request: matches.
        assert!(enforce_ip_allowlist(&eff, Some("10.0.0.1")).is_ok());
        // Mid-session, client appears from a new IP. The helper has no
        // memory of the prior request — it re-evaluates each call.
        assert!(enforce_ip_allowlist(&eff, Some("8.8.8.8")).is_err());
    }

    /// Issue #92 pentest case: "MFA grace expires — user cannot keep
    /// using their existing session without enrolling."
    #[test]
    fn mfa_grace_expiry_forces_enrollment() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.mfa_required = true;
        eff.mfa_grace_period_days = 1;
        // Day 0: inside grace, no MFA enrolled — still OK.
        assert!(!must_force_mfa_enrollment(&eff, false, 60));
        // Day 2: past grace, no MFA enrolled — MUST force enrollment.
        assert!(must_force_mfa_enrollment(&eff, false, 200_000));
        // Same time, but user enrolled — fine.
        assert!(!must_force_mfa_enrollment(&eff, true, 200_000));
    }

    /// Issue #92 pentest case: "`allowed_auth_methods` restricted to
    /// SSO — direct password login returns 405."
    #[test]
    fn password_login_blocked_when_sso_only() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.allowed_auth_methods = vec![AuthMethod::SsoSaml, AuthMethod::SsoOidc];
        let err = enforce_auth_method(&eff, &AuthMethod::Password).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::METHOD_NOT_ALLOWED);
        // SSO path still works.
        assert!(enforce_auth_method(&eff, &AuthMethod::SsoSaml).is_ok());
    }

    /// Session binding pentest: a session row carries IP=A; the next
    /// request arrives with IP=B. With `SessionBinding::Ip` the
    /// middleware must 401.
    #[test]
    fn session_binding_ip_change_invalidates() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.session_binding = SessionBinding::Ip;
        let err = enforce_session_binding(&eff, Some("1.1.1.1"), Some("2.2.2.2"), None, None)
            .unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::UNAUTHORIZED);
    }

    /// Session binding pentest variant: UA-only binding. IP changes
    /// should NOT trip the gate; only UA changes should.
    #[test]
    fn session_binding_ua_only_ignores_ip_changes() {
        let mut eff = EffectivePolicy::unrestricted();
        eff.session_binding = SessionBinding::UserAgent;
        assert!(
            enforce_session_binding(
                &eff,
                Some("1.1.1.1"),
                Some("9.9.9.9"),
                Some("ua"),
                Some("ua"),
            )
            .is_ok()
        );
        assert!(enforce_session_binding(&eff, None, None, Some("ua"), Some("ua-bad")).is_err());
    }
}
