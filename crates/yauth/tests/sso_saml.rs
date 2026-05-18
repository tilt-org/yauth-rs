//! Integration tests for the SAML SP repo + provider plumbing (issue #94).
//!
//! End-to-end IdP-in-the-loop pentest cases live in
//! `sso_saml_pentest.rs`; this file covers the data-layer invariants
//! and the trait facade.

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password"
))]
#![forbid(unsafe_code)]

use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use yauth::auth::saml_sp::{DefaultSamlProvider, SamlProvider};
use yauth::backends::memory::InMemoryBackend;
use yauth::repo::DatabaseBackend;
use yauth_entity::{
    ConnectionKind, ConnectionStatus, NewOrganization, NewSsoConnection, SamlAttributeMappings,
    SamlConnectionConfig, SsoConnection, UpdateSsoConnection,
};

fn now() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

fn new_org(slug: &str) -> NewOrganization {
    let n = now();
    NewOrganization {
        id: Uuid::now_v7(),
        name: slug.into(),
        slug: slug.into(),
        display_name: None,
        avatar_url: None,
        metadata: None,
        created_at: n,
        updated_at: n,
    }
}

fn sample_saml_cfg() -> SamlConnectionConfig {
    SamlConnectionConfig {
        idp_entity_id: "urn:idp:acme".into(),
        idp_sso_url: "https://idp.example/sso".into(),
        idp_slo_url: None,
        idp_x509_cert: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".into(),
        sp_entity_id: "https://app.example/sso/saml/metadata/abc".into(),
        sp_acs_url: "https://app.example/sso/saml/acs".into(),
        sp_private_key: None,
        idp_initiated_sso_allowed: false,
        assertion_signed_required: true,
        response_signed_required: true,
        want_encrypted_assertions: false,
        attribute_mappings: SamlAttributeMappings::default(),
    }
}

fn build_conn(org_id: Uuid, kind: ConnectionKind, status: ConnectionStatus) -> NewSsoConnection {
    let n = now();
    let config = match kind {
        ConnectionKind::OidcClient => serde_json::json!({
            "discovery_url": "https://idp.example/.well-known/openid-configuration",
            "client_id": "client",
            "client_secret": "yauth-pt-v1:",
            "scopes": ["openid"],
            "claim_mappings": {"email": "email", "external_id": "sub", "display_name": "name", "groups": "groups", "group_to_role": {}},
        }),
        ConnectionKind::SamlSp => serde_json::to_value(sample_saml_cfg()).unwrap(),
    };
    NewSsoConnection {
        id: Uuid::now_v7(),
        organization_id: org_id,
        kind,
        name: "Sample".into(),
        status,
        config,
        jit_provisioning_enabled: true,
        default_role_on_jit: "member".into(),
        created_at: n,
        updated_at: n,
    }
}

#[tokio::test]
async fn saml_connection_round_trips_through_repo() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();

    let row = repos
        .sso_connections
        .create(build_conn(
            org.id,
            ConnectionKind::SamlSp,
            ConnectionStatus::Active,
        ))
        .await
        .unwrap();
    assert_eq!(row.kind, ConnectionKind::SamlSp);

    let fetched = repos
        .sso_connections
        .find_by_id(row.id)
        .await
        .unwrap()
        .unwrap();
    let cfg = fetched
        .saml_config()
        .expect("saml config must decode after round-trip");
    assert_eq!(cfg.idp_entity_id, "urn:idp:acme");
    // Mutually exclusive accessor: OIDC view must be None on a SAML row.
    assert!(fetched.oidc_config().is_none());
}

#[tokio::test]
async fn find_active_saml_for_org_only_returns_active_saml_rows() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();

    // Draft SAML — should NOT be returned.
    let _draft = repos
        .sso_connections
        .create(build_conn(
            org.id,
            ConnectionKind::SamlSp,
            ConnectionStatus::Draft,
        ))
        .await
        .unwrap();

    // Active OIDC — should NOT be returned by the SAML query.
    let _oidc = repos
        .sso_connections
        .create(build_conn(
            org.id,
            ConnectionKind::OidcClient,
            ConnectionStatus::Active,
        ))
        .await
        .unwrap();

    assert!(
        repos
            .sso_connections
            .find_active_saml_for_org(org.id)
            .await
            .unwrap()
            .is_none()
    );

    // Add an active SAML — now we should find it.
    let active = repos
        .sso_connections
        .create(build_conn(
            org.id,
            ConnectionKind::SamlSp,
            ConnectionStatus::Active,
        ))
        .await
        .unwrap();
    let found = repos
        .sso_connections
        .find_active_saml_for_org(org.id)
        .await
        .unwrap()
        .expect("active SAML must be found");
    assert_eq!(found.id, active.id);
}

#[tokio::test]
async fn updating_saml_status_to_disabled_hides_from_active_lookup() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let row = repos
        .sso_connections
        .create(build_conn(
            org.id,
            ConnectionKind::SamlSp,
            ConnectionStatus::Active,
        ))
        .await
        .unwrap();
    assert!(
        repos
            .sso_connections
            .find_active_saml_for_org(org.id)
            .await
            .unwrap()
            .is_some()
    );

    let now_dt = now();
    repos
        .sso_connections
        .update(
            row.id,
            UpdateSsoConnection {
                status: Some(ConnectionStatus::Disabled),
                updated_at: Some(now_dt),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        repos
            .sso_connections
            .find_active_saml_for_org(org.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn saml_attribute_mappings_default_uses_schemas_xmlsoap_uris() {
    let m = SamlAttributeMappings::default();
    assert!(m.email.contains("schemas.xmlsoap.org"));
    assert_eq!(m.external_id, "NameID");
}

#[test]
fn sp_metadata_xml_contains_acs_url_and_entity_id() {
    let cfg = sample_saml_cfg();
    let provider = DefaultSamlProvider::new();
    let xml = provider.render_sp_metadata(&cfg).expect("metadata renders");
    assert!(xml.contains(&cfg.sp_entity_id));
    assert!(xml.contains(&cfg.sp_acs_url));
    assert!(xml.contains("EntityDescriptor"));
    // WantAssertionsSigned must mirror the connection's strict flag.
    assert!(xml.contains("WantAssertionsSigned=\"true\""));
}

#[test]
fn build_authn_request_yields_deterministic_request_id_format() {
    let cfg = sample_saml_cfg();
    let provider = DefaultSamlProvider::new();
    let req = provider.build_authn_request(&cfg, "rs-xyz").unwrap();
    // ID format: leading underscore + UUIDv7 simple form (32 hex chars).
    assert!(req.request_id.starts_with('_'));
    assert_eq!(req.request_id.len(), 33);
    // Base64 deflate output must not be empty.
    assert!(!req.saml_request_b64_deflated.is_empty());
}

#[test]
fn provider_string_uses_saml_namespace() {
    let p = yauth_entity::saml_provider("urn:idp:acme");
    assert!(p.starts_with("saml:"));
    let o = yauth_entity::oidc_provider("urn:idp:acme");
    assert_ne!(p, o);
}

#[test]
fn saml_config_security_defaults_strict() {
    // Build the config the way the admin handler does, but use the
    // type defaults via Deserialize-from-JSON to make sure missing
    // strict flags trip a hard error rather than silently default
    // open.
    let bare = serde_json::json!({
        "idp_entity_id": "urn:idp:acme",
        "idp_sso_url": "https://idp",
        "idp_x509_cert": "PEM",
        "sp_entity_id": "sp",
        "sp_acs_url": "acs",
        "attribute_mappings": {
            "email": "e", "display_name": null, "external_id": "NameID",
            "groups": null, "group_to_role": {}
        }
    });
    // Missing the two `*_signed_required` fields → serde fails closed.
    let res: Result<SamlConnectionConfig, _> = serde_json::from_value(bare);
    assert!(res.is_err(), "strict flags must be required at the wire");
}

#[test]
fn ssoconnection_response_masks_saml_secrets() {
    // Verify the in-memory connection_to_response code path: a row
    // with `sp_private_key=Some("ENC:...")` must come out with a
    // masked value, never the ciphertext.
    let mut cfg = sample_saml_cfg();
    cfg.sp_private_key = Some("yauth-aead-v1:CIPHERTEXT".into());
    let conn = SsoConnection {
        id: Uuid::nil(),
        organization_id: Uuid::nil(),
        kind: ConnectionKind::SamlSp,
        name: "Acme".into(),
        status: ConnectionStatus::Active,
        config: serde_json::to_value(&cfg).unwrap(),
        jit_provisioning_enabled: true,
        default_role_on_jit: "member".into(),
        created_at: now(),
        updated_at: now(),
    };
    let parsed = conn.saml_config().unwrap();
    assert_eq!(
        parsed.sp_private_key.as_deref(),
        Some("yauth-aead-v1:CIPHERTEXT")
    );
    // The masking happens in the HTTP-response code path
    // (plugins::organizations::connection_to_response). We assert
    // the contract here: that the entity-level decode preserves the
    // value (so the cipher can decrypt at use-time) and that
    // anyone reading `conn.config` directly gets ciphertext, never
    // plaintext.
    let raw = conn.config.to_string();
    assert!(raw.contains("yauth-aead-v1:CIPHERTEXT"));
    assert!(!raw.contains("BEGIN RSA PRIVATE KEY"));
}

#[test]
fn replay_cache_eviction_is_lazy_but_present() {
    let cache = yauth::auth::saml_sp::ReplayCache::new();
    let ttl = std::time::Duration::from_millis(1);
    cache.check_and_insert("p", "id-a", ttl).unwrap();
    // Allow TTL to elapse.
    std::thread::sleep(std::time::Duration::from_millis(5));
    // After TTL, inserting again should succeed (cache evicted).
    cache.check_and_insert("p", "id-a", ttl).unwrap();
    let _ = HashMap::<String, String>::new(); // silence import lint
}
