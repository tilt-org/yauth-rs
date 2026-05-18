//! Integration tests for the SSO OIDC client (issue #93).
//!
//! Phase A scope:
//!
//! - Repository invariants (round-trip, deployment-wide
//!   `(provider, external_id)` uniqueness, cascade-on-org-delete).
//! - `auth::oidc_client` pure-logic helpers exercised through their
//!   handler-facing contracts.
//!
//! Phase B (follow-up commit, same PR) will add:
//!
//! - End-to-end `/sso/login` → fixture-IdP redirect → `/sso/callback`
//!   → JIT provisioning round-trip with a deterministic local IdP.
//! - Pentest cases: state replay, nonce replay, audience mismatch,
//!   JWKS kid rollover, claim injection (group → role escalation).

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password"
))]

use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use yauth::auth::oidc_client::{
    ClaimExtractError, ExtractedIdentity, PassthroughCipher, SecretCipher, SecretDecryptError,
    build_authorize_url, compute_pkce_challenge, extract_identity_from_claims, generate_nonce,
    generate_state_token, mask_secret, pkce_generate, validate_discovery_url,
    validate_group_to_role, validate_scopes,
};
use yauth::backends::memory::InMemoryBackend;
use yauth::repo::{DatabaseBackend, RepoError};
use yauth_entity::{
    ClaimMappings, ConnectionKind, ConnectionStatus, NewExternalIdentity, NewOrganization,
    NewSsoConnection, NewUser, OidcConnectionConfig, UpdateSsoConnection,
};

fn now() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

fn new_user(email: &str) -> NewUser {
    let now = now();
    NewUser {
        id: Uuid::now_v7(),
        email: email.to_string(),
        display_name: None,
        email_verified: true,
        role: "user".to_string(),
        banned: false,
        banned_reason: None,
        banned_until: None,
        created_at: now,
        updated_at: now,
    }
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

fn sample_oidc_config() -> OidcConnectionConfig {
    OidcConnectionConfig {
        discovery_url: "https://idp.example/.well-known/openid-configuration".to_string(),
        client_id: "client-1".to_string(),
        client_secret: "yauth-pt-v1:c2VjcmV0".to_string(),
        scopes: OidcConnectionConfig::default_scopes(),
        claim_mappings: ClaimMappings::default(),
    }
}

fn new_oidc_conn(org_id: Uuid, status: ConnectionStatus) -> NewSsoConnection {
    let now = now();
    NewSsoConnection {
        id: Uuid::now_v7(),
        organization_id: org_id,
        kind: ConnectionKind::OidcClient,
        name: "Acme IdP".to_string(),
        status,
        config: serde_json::to_value(sample_oidc_config()).unwrap(),
        jit_provisioning_enabled: true,
        default_role_on_jit: "member".to_string(),
        created_at: now,
        updated_at: now,
    }
}

// ─────────────────────────────────────────────────────────────
// SsoConnection repository invariants
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn sso_create_and_round_trip() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();

    let input = new_oidc_conn(org.id, ConnectionStatus::Draft);
    let id = input.id;
    let created = repos.sso_connections.create(input).await.unwrap();
    assert_eq!(created.id, id);
    assert_eq!(created.status, ConnectionStatus::Draft);

    let fetched = repos.sso_connections.find_by_id(id).await.unwrap().unwrap();
    assert_eq!(fetched, created);

    let cfg = fetched.oidc_config().unwrap();
    assert_eq!(cfg.client_id, "client-1");
}

#[tokio::test]
async fn sso_duplicate_id_is_conflict() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let row = new_oidc_conn(org.id, ConnectionStatus::Draft);
    let id = row.id;
    repos.sso_connections.create(row).await.unwrap();
    let mut dup = new_oidc_conn(org.id, ConnectionStatus::Draft);
    dup.id = id; // collide
    let err = repos.sso_connections.create(dup).await.unwrap_err();
    assert!(matches!(err, RepoError::Conflict(_)), "got {err:?}");
}

#[tokio::test]
async fn sso_update_partial_preserves_unrelated() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let row = new_oidc_conn(org.id, ConnectionStatus::Draft);
    let id = row.id;
    let created = repos.sso_connections.create(row).await.unwrap();

    let updated = repos
        .sso_connections
        .update(
            id,
            UpdateSsoConnection {
                status: Some(ConnectionStatus::Active),
                updated_at: Some(now()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.status, ConnectionStatus::Active);
    assert_eq!(updated.name, created.name); // preserved
    assert_eq!(updated.config, created.config); // preserved
}

#[tokio::test]
async fn sso_list_for_org_filters_and_orders() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org_a = repos.organizations.create(new_org("aaa")).await.unwrap();
    let org_b = repos.organizations.create(new_org("bbb")).await.unwrap();

    repos
        .sso_connections
        .create(new_oidc_conn(org_a.id, ConnectionStatus::Active))
        .await
        .unwrap();
    repos
        .sso_connections
        .create(new_oidc_conn(org_a.id, ConnectionStatus::Draft))
        .await
        .unwrap();
    repos
        .sso_connections
        .create(new_oidc_conn(org_b.id, ConnectionStatus::Active))
        .await
        .unwrap();

    let a = repos.sso_connections.list_for_org(org_a.id).await.unwrap();
    let b = repos.sso_connections.list_for_org(org_b.id).await.unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(b.len(), 1);
    // Ordering: created_at ASC.
    assert!(a[0].created_at <= a[1].created_at);
}

#[tokio::test]
async fn sso_find_active_oidc_skips_drafts_and_disabled() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();

    repos
        .sso_connections
        .create(new_oidc_conn(org.id, ConnectionStatus::Draft))
        .await
        .unwrap();
    let active = repos
        .sso_connections
        .create(new_oidc_conn(org.id, ConnectionStatus::Active))
        .await
        .unwrap();
    repos
        .sso_connections
        .create(new_oidc_conn(org.id, ConnectionStatus::Disabled))
        .await
        .unwrap();

    let resolved = repos
        .sso_connections
        .find_active_oidc_for_org(org.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolved.id, active.id);
}

#[tokio::test]
async fn sso_find_active_oidc_returns_none_when_no_active() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    repos
        .sso_connections
        .create(new_oidc_conn(org.id, ConnectionStatus::Draft))
        .await
        .unwrap();
    assert!(
        repos
            .sso_connections
            .find_active_oidc_for_org(org.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sso_cascade_on_org_delete() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let row = new_oidc_conn(org.id, ConnectionStatus::Active);
    let id = row.id;
    repos.sso_connections.create(row).await.unwrap();
    repos.organizations.delete(org.id).await.unwrap();
    assert!(
        repos
            .sso_connections
            .find_by_id(id)
            .await
            .unwrap()
            .is_none()
    );
}

// ─────────────────────────────────────────────────────────────
// ExternalIdentity invariants
// ─────────────────────────────────────────────────────────────

fn new_ext(user_id: Uuid, provider: &str, external_id: &str) -> NewExternalIdentity {
    let now = now();
    NewExternalIdentity {
        id: Uuid::now_v7(),
        user_id,
        provider: provider.to_string(),
        external_id: external_id.to_string(),
        linked_at: now,
        last_login_at: now,
    }
}

#[tokio::test]
async fn external_identity_round_trip() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let user = repos
        .users
        .create(new_user("alice@acme.com"))
        .await
        .unwrap();

    let row = repos
        .external_identities
        .create(new_ext(user.id, "oidc:https://idp", "sub-1"))
        .await
        .unwrap();

    let fetched = repos
        .external_identities
        .find_by_provider_external_id("oidc:https://idp", "sub-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.id, row.id);
    assert_eq!(fetched.user_id, user.id);
}

#[tokio::test]
async fn external_identity_provider_external_id_is_unique() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let alice = repos.users.create(new_user("a@acme")).await.unwrap();
    let bob = repos.users.create(new_user("b@acme")).await.unwrap();
    repos
        .external_identities
        .create(new_ext(alice.id, "oidc:https://idp", "sub-1"))
        .await
        .unwrap();
    let err = repos
        .external_identities
        .create(new_ext(bob.id, "oidc:https://idp", "sub-1"))
        .await
        .unwrap_err();
    assert!(matches!(err, RepoError::Conflict(_)), "got {err:?}");
}

#[tokio::test]
async fn external_identity_touch_last_login() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let alice = repos.users.create(new_user("a@acme")).await.unwrap();
    let row = repos
        .external_identities
        .create(new_ext(alice.id, "oidc:https://idp", "sub-1"))
        .await
        .unwrap();
    let bumped_at = row.last_login_at + chrono::Duration::days(1);
    let updated = repos
        .external_identities
        .touch_last_login(row.id, bumped_at)
        .await
        .unwrap();
    assert_eq!(updated.last_login_at, bumped_at);
}

#[tokio::test]
async fn external_identity_cascade_on_user_delete() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let alice = repos.users.create(new_user("a@acme")).await.unwrap();
    let row = repos
        .external_identities
        .create(new_ext(alice.id, "oidc:https://idp", "sub-1"))
        .await
        .unwrap();
    repos.users.delete(alice.id).await.unwrap();
    assert!(
        repos
            .external_identities
            .find_by_id(row.id)
            .await
            .unwrap()
            .is_none()
    );
}

// ─────────────────────────────────────────────────────────────
// PKCE + state + authorize URL — the security-critical primitives
// ─────────────────────────────────────────────────────────────

#[test]
fn pkce_pair_round_trips_through_challenge() {
    let p = pkce_generate();
    assert_eq!(compute_pkce_challenge(&p.verifier), p.challenge);
}

#[test]
fn pkce_known_rfc_vector() {
    // RFC 7636 Appendix B test vector — guards against accidental
    // base64-vs-base64url drift.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert_eq!(compute_pkce_challenge(verifier), expected);
}

#[test]
fn state_and_nonce_are_unique() {
    assert_ne!(generate_state_token(), generate_state_token());
    assert_ne!(generate_nonce(), generate_nonce());
}

#[test]
fn authorize_url_includes_security_params() {
    let cfg = sample_oidc_config();
    let url = build_authorize_url(
        "https://idp/authorize",
        &cfg,
        "https://app/cb",
        "state-token",
        "nonce-1",
        "challenge-1",
    );
    for k in [
        "response_type=code",
        "client_id=client-1",
        "state=state-token",
        "nonce=nonce-1",
        "code_challenge=challenge-1",
        "code_challenge_method=S256",
    ] {
        assert!(url.contains(k), "url missing {k}: {url}");
    }
}

// ─────────────────────────────────────────────────────────────
// Claim extraction — group→role mapping correctness
// ─────────────────────────────────────────────────────────────

#[test]
fn group_to_role_first_match_wins() {
    let mut m = ClaimMappings::default();
    m.group_to_role
        .insert("prism-admins".to_string(), "admin".to_string());
    let claims = serde_json::json!({
        "sub": "user-1",
        "email": "a@b",
        "groups": ["prism-admins"]
    });
    let id = extract_identity_from_claims(&m, &claims).unwrap();
    assert_eq!(id.mapped_roles, vec!["admin"]);
}

#[test]
fn group_to_role_no_match_yields_empty_roles() {
    let mut m = ClaimMappings::default();
    m.group_to_role
        .insert("prism-admins".to_string(), "admin".to_string());
    let claims = serde_json::json!({
        "sub": "user-1",
        "email": "a@b",
        "groups": ["random-other-group"]
    });
    let id = extract_identity_from_claims(&m, &claims).unwrap();
    assert!(id.mapped_roles.is_empty());
}

// ─────────────────────────────────────────────────────────────
// Pentest cases (Phase A subset — pure-logic boundary).
// Full IdP-in-the-loop pentests follow in Phase B.
// ─────────────────────────────────────────────────────────────

#[test]
fn pentest_external_id_must_be_string_not_object() {
    let claims = serde_json::json!({
        "sub": {"oh": "no"},
        "email": "alice@acme.com"
    });
    let err = extract_identity_from_claims(&ClaimMappings::default(), &claims).unwrap_err();
    assert_eq!(err, ClaimExtractError::NotAString("sub".to_string()));
}

#[test]
fn pentest_group_claim_must_be_array() {
    // Claim injection: an IdP misconfiguration delivers `groups` as a
    // string. The handler must NOT silently treat it as a single
    // group named after the JSON value — it must reject the response
    // outright.
    let claims = serde_json::json!({
        "sub": "u",
        "email": "a@b",
        "groups": "admin"
    });
    let err = extract_identity_from_claims(&ClaimMappings::default(), &claims).unwrap_err();
    assert!(matches!(err, ClaimExtractError::NotAnArray(_)));
}

#[test]
fn pentest_secret_cipher_round_trip_does_not_leak_plaintext() {
    let cipher = PassthroughCipher;
    let plain = "ultra-secret-token-12345";
    let ct = cipher.encrypt(plain);
    assert!(!ct.contains(plain));
    assert_eq!(cipher.decrypt(&ct).unwrap(), plain);
}

#[test]
fn pentest_secret_cipher_tampered_marker_rejected() {
    let cipher = PassthroughCipher;
    // Drop the marker — should fail closed.
    let err = cipher.decrypt("c2VjcmV0").unwrap_err();
    assert_eq!(err, SecretDecryptError::MissingMarker);
}

#[test]
fn pentest_mask_secret_is_constant_length() {
    // Defend against length-side-channel leaks.
    assert_eq!(mask_secret(""), mask_secret("very long secret"));
}

#[test]
fn pentest_default_scopes_force_openid() {
    let s = OidcConnectionConfig::normalise_scopes(&["email".to_string()]);
    assert_eq!(s[0], "openid");
}

#[test]
fn pentest_discovery_url_rejects_http() {
    assert!(validate_discovery_url("http://idp/.well-known/openid-configuration").is_err());
}

#[test]
fn pentest_scopes_must_include_openid() {
    assert!(validate_scopes(&["email".to_string()]).is_err());
}

#[test]
fn pentest_group_to_role_rejects_unknown_role_names() {
    let mut map = HashMap::new();
    map.insert("g".to_string(), "superduper".to_string());
    assert!(validate_group_to_role(&map).is_err());
}

#[test]
fn pentest_extracted_identity_flags_missing_email() {
    let claims = serde_json::json!({"sub": "u"});
    let id = extract_identity_from_claims(&ClaimMappings::default(), &claims).unwrap();
    assert!(id.missing_email());
    // Smoke: drop unused warnings.
    let _ = ExtractedIdentity {
        external_id: "u".to_string(),
        email: None,
        display_name: None,
        mapped_roles: Vec::new(),
    };
}
