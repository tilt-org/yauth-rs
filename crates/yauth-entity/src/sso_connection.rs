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
    /// [`OidcConnectionConfig`] for `oidc_client`.
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
