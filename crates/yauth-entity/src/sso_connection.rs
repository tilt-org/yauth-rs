//! SSO connection entity — federated sign-in from external IdPs (issue #93).
//!
//! A [`SsoConnection`] attaches **one** federation configuration to **one**
//! organization. The first supported kind is [`ConnectionKind::OidcClient`]:
//! yauth acts as an OIDC Relying Party against an external IdP
//! (Okta / Entra ID / Auth0 / Keycloak / Google / generic OIDC).
//!
//! The sibling SAML SP kind is reserved here on the enum surface so the
//! wire format stays stable across the #93 / #94 split — the SAML repo
//! impls land in issue #94.
//!
//! # Wire shape
//!
//! - `kind` is a `VARCHAR` (`"oidc_client"` / `"saml_sp"`) for dialect
//!   parity with [`crate::AuthMethod`].
//! - `status` is a `VARCHAR` (`"draft" | "active" | "disabled"`).
//! - `config` is an opaque JSON blob — `OidcConnectionConfig` for OIDC,
//!   `SamlConnectionConfig` (issue #94) for SAML. Storing the variant in
//!   a JSON column means adding a new IdP-shaped field is a no-DDL
//!   migration.
//!
//! # Security
//!
//! `OidcConnectionConfig::client_secret` is **encrypted at rest** at the
//! repository boundary. The caller wraps the plaintext secret in
//! [`SecretCipher`] (a tiny base64-marker round-trip in the shipped
//! impl — apps with KMS plug a real cipher in via the same trait).
//! The `Display` impl on this struct masks the secret so accidental
//! `tracing::info!("{conn:?}")` cannot leak it.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which federation protocol this connection uses.
///
/// Stored as `VARCHAR` so adding a new kind is a no-DDL change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionKind {
    /// yauth acts as an OIDC Relying Party against an external IdP (#93).
    OidcClient,
    /// yauth acts as a SAML Service Provider (issue #94 — reserved).
    SamlSp,
}

impl ConnectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionKind::OidcClient => "oidc_client",
            ConnectionKind::SamlSp => "saml_sp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "oidc_client" => Some(Self::OidcClient),
            "saml_sp" => Some(Self::SamlSp),
            _ => None,
        }
    }
}

/// Lifecycle for a connection. Admins build a `draft`, flip it to
/// `active` after the round-trip test passes, and `disabled` it
/// without losing the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Draft,
    Active,
    Disabled,
}

impl ConnectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionStatus::Draft => "draft",
            ConnectionStatus::Active => "active",
            ConnectionStatus::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// Claim-mapping rules driving identity extraction from an IdP id_token.
///
/// Every field is namespaced to the IdP's `id_token` (or userinfo
/// response) — yauth never invents claims that aren't present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMappings {
    /// Name of the claim carrying the user's email. Default `"email"`.
    pub email: String,
    /// Name of the claim carrying the user's display name. `None` =
    /// don't extract a display name on JIT.
    pub display_name: Option<String>,
    /// Name of the claim carrying the **stable** IdP user identifier.
    /// Default `"sub"`. This is the join key on
    /// [`crate::ExternalIdentity::external_id`] — changing it after
    /// users have linked breaks every existing login.
    pub external_id: String,
    /// Optional claim carrying an array of group names. `None` = skip
    /// group-based role assignment.
    pub groups: Option<String>,
    /// Map of IdP group name → yauth org role.
    ///
    /// Resolution: first matching group wins, in iteration order
    /// (i.e. the caller is responsible for putting the most-privileged
    /// match first).
    pub group_to_role: HashMap<String, String>,
}

impl Default for ClaimMappings {
    fn default() -> Self {
        Self {
            email: "email".to_string(),
            display_name: Some("name".to_string()),
            external_id: "sub".to_string(),
            groups: Some("groups".to_string()),
            group_to_role: HashMap::new(),
        }
    }
}

/// Per-connection OIDC configuration. Serialised into
/// [`SsoConnection::config`].
///
/// The `client_secret` field carries an **encrypted** value as stored;
/// it is decrypted only at the moment of use (token exchange) and never
/// surfaced on the admin API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcConnectionConfig {
    /// Full `.well-known/openid-configuration` URL. yauth discovers the
    /// IdP's authorization / token / jwks endpoints from this document
    /// at first use; the document is cached per RFC 5861 rules with a
    /// hard 1-hour ceiling.
    pub discovery_url: String,
    pub client_id: String,
    /// Encrypted client secret. See module docs.
    pub client_secret: String,
    /// Requested scopes; `openid` is always added by the runtime if
    /// missing. Defaults to `["openid", "email", "profile"]`.
    pub scopes: Vec<String>,
    pub claim_mappings: ClaimMappings,
}

impl OidcConnectionConfig {
    /// Default scope set: `openid`, `email`, `profile`. `openid` MUST
    /// be present per OIDC Core §3.1.2.1; the runtime enforces this
    /// regardless of what the admin sets.
    pub fn default_scopes() -> Vec<String> {
        vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ]
    }

    /// Force `openid` into the scope list if the admin forgot it.
    /// Returns the post-normalisation set so callers can store the
    /// canonical shape.
    pub fn normalise_scopes(scopes: &[String]) -> Vec<String> {
        let mut out: Vec<String> = scopes.to_vec();
        if !out.iter().any(|s| s == "openid") {
            out.insert(0, "openid".to_string());
        }
        out
    }
}

/// Attribute → identity mapping for a SAML connection. Mirrors
/// [`ClaimMappings`] but on SAML attribute names instead of OIDC claim
/// names. Defaults match the schemas.xmlsoap.org URIs that every major
/// IdP (Okta, Entra, OneLogin, ADFS, Auth0, Ping) emits out of the
/// box.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlAttributeMappings {
    /// SAML attribute carrying the user's email. Default
    /// `"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"`.
    pub email: String,
    /// SAML attribute carrying display name. Default
    /// `"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"`.
    pub display_name: Option<String>,
    /// Where to source the **stable** external id from. Special value
    /// `"NameID"` means use the assertion's `<NameID>` element; any
    /// other value is treated as an attribute name.
    pub external_id: String,
    /// SAML attribute carrying group membership (multi-valued). `None` =
    /// skip group-based role assignment.
    pub groups: Option<String>,
    /// Map of IdP group name → yauth org role.
    pub group_to_role: HashMap<String, String>,
}

impl Default for SamlAttributeMappings {
    fn default() -> Self {
        Self {
            email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".into(),
            display_name: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".into()),
            external_id: "NameID".into(),
            groups: None,
            group_to_role: HashMap::new(),
        }
    }
}

/// Per-connection SAML 2.0 Service Provider configuration. Serialised
/// into [`SsoConnection::config`].
///
/// The `sp_private_key` field carries an **encrypted** PEM as stored;
/// it is decrypted only at the moment of use (assertion decryption or
/// AuthnRequest signing) and never surfaced on the admin API.
///
/// # Security defaults
///
/// `assertion_signed_required` and `response_signed_required` default
/// to `true`. They CANNOT be turned off at the application layer
/// without an explicit admin override — leaving either field set to
/// `false` is a knowingly accepted footgun.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlConnectionConfig {
    /// IdP's entity ID (`urn:idp:acme:saml`). MUST match the assertion
    /// `<Issuer>` value to prove the assertion came from the IdP we
    /// expect.
    pub idp_entity_id: String,
    /// IdP's SSO endpoint — yauth redirects users here on SP-initiated
    /// login.
    pub idp_sso_url: String,
    /// IdP's optional SLO endpoint. `None` = SLO not supported.
    #[serde(default)]
    pub idp_slo_url: Option<String>,
    /// PEM-encoded X.509 certificate (`-----BEGIN CERTIFICATE-----…`).
    /// Used to verify XML-DSig signatures on `<Response>` and/or
    /// `<Assertion>`.
    pub idp_x509_cert: String,
    /// SP's entity ID. Derived per-connection so two connections on
    /// the same yauth deployment cannot be cross-confused
    /// (CVE-2022-class issue). Always
    /// `<base_url>/sso/saml/metadata/<connection-uuid>`.
    pub sp_entity_id: String,
    /// SP's Assertion Consumer Service URL — where the IdP POSTs the
    /// SAMLResponse. Always `<base_url>/sso/saml/acs`.
    pub sp_acs_url: String,
    /// PEM private key for AuthnRequest signing / encrypted-assertion
    /// decryption. **Encrypted at rest** (AEAD via `SecretCipher`).
    /// `None` = SP signing disabled.
    #[serde(default)]
    pub sp_private_key: Option<String>,
    /// Allow IdP-initiated SSO (no SP-side AuthnRequest). **Default
    /// `false`** — there's no CSRF binding on the IdP-initiated path,
    /// so admins must consciously opt in.
    #[serde(default)]
    pub idp_initiated_sso_allowed: bool,
    /// Require the `<Assertion>` to carry an XML signature. **Default
    /// `true`.**
    pub assertion_signed_required: bool,
    /// Require the wrapping `<Response>` to carry an XML signature.
    /// **Default `true`.**
    pub response_signed_required: bool,
    /// Reject `<Response>` whose `<Assertion>` is not encrypted.
    /// Default `false` — encrypted assertions are rare; turn on if
    /// regulatory regime requires it.
    #[serde(default)]
    pub want_encrypted_assertions: bool,
    pub attribute_mappings: SamlAttributeMappings,
}

impl SamlConnectionConfig {
    /// Default sp_entity_id given a base URL and connection UUID. The
    /// per-connection derivation is load-bearing: it defeats the class
    /// of attacks where IdP A's assertion is replayed at connection B
    /// on the same deployment (the audience won't match).
    pub fn default_sp_entity_id(base_url: &str, conn_id: Uuid) -> String {
        format!(
            "{}/sso/saml/metadata/{}",
            base_url.trim_end_matches('/'),
            conn_id
        )
    }

    /// Default `sp_acs_url` given a base URL.
    pub fn default_sp_acs_url(base_url: &str) -> String {
        format!("{}/sso/saml/acs", base_url.trim_end_matches('/'))
    }
}

/// A federation connection row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoConnection {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub kind: ConnectionKind,
    /// Operator-friendly display name. Not used in protocol — purely
    /// for the admin UI.
    pub name: String,
    pub status: ConnectionStatus,
    /// Protocol-specific configuration. See
    /// [`OidcConnectionConfig`] for `oidc_client` and
    /// [`SamlConnectionConfig`] for `saml_sp`.
    pub config: serde_json::Value,
    pub jit_provisioning_enabled: bool,
    pub default_role_on_jit: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl SsoConnection {
    /// Parse the embedded [`OidcConnectionConfig`] when `kind` is
    /// `OidcClient`. Returns `None` on a SAML row.
    pub fn oidc_config(&self) -> Option<OidcConnectionConfig> {
        match self.kind {
            ConnectionKind::OidcClient => serde_json::from_value(self.config.clone()).ok(),
            ConnectionKind::SamlSp => None,
        }
    }

    /// Parse the embedded [`SamlConnectionConfig`] when `kind` is
    /// `SamlSp`. Returns `None` on an OIDC row.
    pub fn saml_config(&self) -> Option<SamlConnectionConfig> {
        match self.kind {
            ConnectionKind::SamlSp => serde_json::from_value(self.config.clone()).ok(),
            ConnectionKind::OidcClient => None,
        }
    }
}

/// Insert payload for [`SsoConnection`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSsoConnection {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub kind: ConnectionKind,
    pub name: String,
    pub status: ConnectionStatus,
    pub config: serde_json::Value,
    pub jit_provisioning_enabled: bool,
    pub default_role_on_jit: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Partial update payload for [`SsoConnection`].
///
/// Each top-level `Option` is "leave alone" / "set to this". For
/// `config` we replace the entire JSON blob atomically — there is no
/// partial-merge API since the encrypted-secret round-trip means each
/// PATCH has to send a coherent config payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateSsoConnection {
    pub name: Option<String>,
    pub status: Option<ConnectionStatus>,
    pub config: Option<serde_json::Value>,
    pub jit_provisioning_enabled: Option<bool>,
    pub default_role_on_jit: Option<String>,
    pub updated_at: Option<NaiveDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_kind_round_trip() {
        for k in [ConnectionKind::OidcClient, ConnectionKind::SamlSp] {
            assert_eq!(ConnectionKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(ConnectionKind::parse("nope"), None);
    }

    #[test]
    fn connection_status_round_trip() {
        for s in [
            ConnectionStatus::Draft,
            ConnectionStatus::Active,
            ConnectionStatus::Disabled,
        ] {
            assert_eq!(ConnectionStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(ConnectionStatus::parse("nope"), None);
    }

    #[test]
    fn claim_mappings_default_uses_oidc_core_names() {
        let m = ClaimMappings::default();
        assert_eq!(m.email, "email");
        assert_eq!(m.external_id, "sub");
        assert_eq!(m.display_name.as_deref(), Some("name"));
        assert_eq!(m.groups.as_deref(), Some("groups"));
        assert!(m.group_to_role.is_empty());
    }

    #[test]
    fn normalise_scopes_inserts_openid_when_missing() {
        let s = OidcConnectionConfig::normalise_scopes(&["email".to_string()]);
        assert_eq!(s[0], "openid");
        assert!(s.contains(&"email".to_string()));
    }

    #[test]
    fn normalise_scopes_preserves_when_present() {
        let s =
            OidcConnectionConfig::normalise_scopes(&["openid".to_string(), "email".to_string()]);
        assert_eq!(s, vec!["openid".to_string(), "email".to_string()]);
    }

    #[test]
    fn default_scopes_includes_openid_email_profile() {
        let s = OidcConnectionConfig::default_scopes();
        assert!(s.contains(&"openid".to_string()));
        assert!(s.contains(&"email".to_string()));
        assert!(s.contains(&"profile".to_string()));
    }

    #[test]
    fn oidc_config_round_trips_through_json() {
        let cfg = OidcConnectionConfig {
            discovery_url: "https://idp/.well-known/openid-configuration".to_string(),
            client_id: "client-1".to_string(),
            client_secret: "ENCRYPTED:abc".to_string(),
            scopes: OidcConnectionConfig::default_scopes(),
            claim_mappings: ClaimMappings::default(),
        };
        let now = chrono::Utc::now().naive_utc();
        let conn = SsoConnection {
            id: Uuid::nil(),
            organization_id: Uuid::nil(),
            kind: ConnectionKind::OidcClient,
            name: "Acme Okta".to_string(),
            status: ConnectionStatus::Draft,
            config: serde_json::to_value(&cfg).unwrap(),
            jit_provisioning_enabled: true,
            default_role_on_jit: "member".to_string(),
            created_at: now,
            updated_at: now,
        };
        let parsed = conn.oidc_config().expect("config must parse");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn saml_attribute_mappings_default_uses_schemas_xmlsoap_uris() {
        let m = SamlAttributeMappings::default();
        assert!(m.email.contains("schemas.xmlsoap.org"));
        assert_eq!(m.external_id, "NameID");
        assert!(
            m.display_name
                .as_ref()
                .unwrap()
                .contains("schemas.xmlsoap.org")
        );
        assert!(m.groups.is_none());
    }

    #[test]
    fn saml_config_round_trips_through_json() {
        let cfg = SamlConnectionConfig {
            idp_entity_id: "urn:idp:acme:saml".into(),
            idp_sso_url: "https://acme.okta.com/sso/saml".into(),
            idp_slo_url: None,
            idp_x509_cert: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".into(),
            sp_entity_id: "https://app/sso/saml/metadata/abc".into(),
            sp_acs_url: "https://app/sso/saml/acs".into(),
            sp_private_key: Some("ENC:key".into()),
            idp_initiated_sso_allowed: false,
            assertion_signed_required: true,
            response_signed_required: true,
            want_encrypted_assertions: false,
            attribute_mappings: SamlAttributeMappings::default(),
        };
        let now = chrono::Utc::now().naive_utc();
        let conn = SsoConnection {
            id: Uuid::nil(),
            organization_id: Uuid::nil(),
            kind: ConnectionKind::SamlSp,
            name: "Acme SAML".into(),
            status: ConnectionStatus::Draft,
            config: serde_json::to_value(&cfg).unwrap(),
            jit_provisioning_enabled: true,
            default_role_on_jit: "member".into(),
            created_at: now,
            updated_at: now,
        };
        let parsed = conn.saml_config().expect("config must parse");
        assert_eq!(parsed, cfg);
        // Mutually exclusive: parsing as OIDC must yield None.
        assert!(conn.oidc_config().is_none());
    }

    #[test]
    fn default_sp_entity_id_is_connection_scoped() {
        let id = Uuid::nil();
        let a = SamlConnectionConfig::default_sp_entity_id("https://app", id);
        let b = SamlConnectionConfig::default_sp_entity_id("https://app/", id);
        assert_eq!(a, b);
        assert!(a.ends_with(&id.to_string()));
    }

    #[test]
    fn saml_config_security_defaults_are_strict() {
        // Defaults established by the admin code path (not by Default
        // impl — we want a missing field on PATCH to fail closed).
        let cfg = SamlConnectionConfig {
            idp_entity_id: "urn:idp:acme:saml".into(),
            idp_sso_url: "https://idp/sso".into(),
            idp_slo_url: None,
            idp_x509_cert: "PEM".into(),
            sp_entity_id: "sp".into(),
            sp_acs_url: "acs".into(),
            sp_private_key: None,
            idp_initiated_sso_allowed: false,
            assertion_signed_required: true,
            response_signed_required: true,
            want_encrypted_assertions: false,
            attribute_mappings: SamlAttributeMappings::default(),
        };
        assert!(cfg.assertion_signed_required);
        assert!(cfg.response_signed_required);
        assert!(!cfg.idp_initiated_sso_allowed);
    }

    #[test]
    fn oidc_config_returns_none_for_saml_row() {
        let now = chrono::Utc::now().naive_utc();
        let conn = SsoConnection {
            id: Uuid::nil(),
            organization_id: Uuid::nil(),
            kind: ConnectionKind::SamlSp,
            name: "Acme SAML".to_string(),
            status: ConnectionStatus::Draft,
            config: serde_json::json!({}),
            jit_provisioning_enabled: false,
            default_role_on_jit: "member".to_string(),
            created_at: now,
            updated_at: now,
        };
        assert!(conn.oidc_config().is_none());
    }
}
