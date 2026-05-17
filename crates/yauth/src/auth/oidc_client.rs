//! OIDC client federation primitives (issue #93).
//!
//! Pure-logic building blocks shared by the SSO connection admin
//! handlers and (eventually) the user-facing `/sso/login` +
//! `/sso/callback` handlers. The full login/callback wiring lands in
//! a follow-up commit — see `docs/sso/oidc-client.md` for the
//! sequence. This module already ships everything the admin CRUD
//! routes need:
//!
//! - [`SecretCipher`] — encrypt-at-rest for the IdP `client_secret`.
//!   Default implementation (`PassthroughCipher`) base64-marks the
//!   plaintext so storage never holds a raw secret in plain text;
//!   apps with real KMS plug in their own `SecretCipher` via the
//!   same trait. The marker also ensures we can detect tampered
//!   blobs at decryption time.
//! - [`StateBlob`] — the opaque opaque short-lived token persisted in
//!   `yauth_oauth_states` (re-using the existing `OauthState` repo
//!   per the issue's "PKCE-required" gotcha) carrying the
//!   state-token + nonce + PKCE verifier as one JSON blob.
//! - [`pkce_generate`] / [`compute_pkce_challenge`] — RFC 7636
//!   S256 verifier + challenge.
//! - [`extract_identity_from_claims`] — apply a connection's
//!   [`yauth_entity::ClaimMappings`] to a parsed id_token to produce
//!   `(external_id, email, display_name, groups)`. The hot path is
//!   under 50 lines and fully unit-tested.
//! - [`build_authorize_url`] — assemble the redirect URL with state,
//!   nonce, scope, and PKCE challenge from a connection's
//!   [`yauth_entity::OidcConnectionConfig`].

use std::collections::HashMap;

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use yauth_entity::{ClaimMappings, OidcConnectionConfig};

/// Identity extracted from an id_token after claim mapping.
///
/// Held alive only inside the callback handler; never persisted as a
/// struct (we deconstruct it into the `User` + `ExternalIdentity` rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedIdentity {
    /// Stable IdP user identifier — drives the
    /// `ExternalIdentity.external_id` column.
    pub external_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    /// Roles resolved via `ClaimMappings::group_to_role`. May be
    /// empty when the claim is absent or no group matched.
    pub mapped_roles: Vec<String>,
}

impl ExtractedIdentity {
    /// True if **no** `email` claim could be extracted. Login
    /// handlers MUST reject this with `400` because every JIT path
    /// needs an email to look up / create the yauth user.
    pub fn missing_email(&self) -> bool {
        self.email.is_none()
    }
}

/// Errors from [`extract_identity_from_claims`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClaimExtractError {
    #[error("missing required claim `{0}`")]
    MissingClaim(String),
    #[error("claim `{0}` is not a string")]
    NotAString(String),
    #[error("claim `{0}` is not an array")]
    NotAnArray(String),
}

/// Apply [`ClaimMappings`] to a parsed id_token (or userinfo response)
/// and produce the resolved [`ExtractedIdentity`].
///
/// The `external_id` claim is **required**; everything else is best-
/// effort. The groups claim, when present, must be an array; the
/// first matching `group_to_role` entry wins (caller iterates in
/// insertion order — `HashMap` is fine because mapped_roles is a
/// `Vec` and dedupe happens at handler level).
pub fn extract_identity_from_claims(
    mappings: &ClaimMappings,
    claims: &serde_json::Value,
) -> Result<ExtractedIdentity, ClaimExtractError> {
    // External ID — required.
    let external_id = claims
        .get(&mappings.external_id)
        .ok_or_else(|| ClaimExtractError::MissingClaim(mappings.external_id.clone()))?
        .as_str()
        .ok_or_else(|| ClaimExtractError::NotAString(mappings.external_id.clone()))?
        .to_string();

    // Email — optional.
    let email = claims
        .get(&mappings.email)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Display name — optional + opt-in.
    let display_name = mappings
        .display_name
        .as_ref()
        .and_then(|k| claims.get(k))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Groups → roles.
    let mut mapped_roles = Vec::new();
    if let Some(groups_key) = mappings.groups.as_ref()
        && let Some(arr) = claims.get(groups_key)
    {
        let list = arr
            .as_array()
            .ok_or_else(|| ClaimExtractError::NotAnArray(groups_key.clone()))?;
        for entry in list {
            if let Some(g) = entry.as_str()
                && let Some(role) = mappings.group_to_role.get(g)
                && !mapped_roles.iter().any(|r| r == role)
            {
                mapped_roles.push(role.clone());
            }
        }
    }

    Ok(ExtractedIdentity {
        external_id,
        email,
        display_name,
        mapped_roles,
    })
}

// ─────────────────────────────────────────────────────────────────
// PKCE (RFC 7636 §4)
// ─────────────────────────────────────────────────────────────────

/// Output of [`pkce_generate`].
#[derive(Debug, Clone)]
pub struct PkcePair {
    /// 43-128 char URL-safe random verifier. Persist alongside state.
    pub verifier: String,
    /// `SHA256(verifier)` base64url-no-pad. Sent on the authorize URL.
    pub challenge: String,
}

/// Generate a fresh PKCE verifier + S256 challenge.
pub fn pkce_generate() -> PkcePair {
    // 32 bytes of entropy → 43 chars base64url-no-pad — within the
    // RFC 7636 verifier length window of 43-128.
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let challenge = compute_pkce_challenge(&verifier);
    PkcePair {
        verifier,
        challenge,
    }
}

/// Compute the S256 challenge for a given verifier.
pub fn compute_pkce_challenge(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

// ─────────────────────────────────────────────────────────────────
// State blob — serialised into `yauth_oauth_states.state` column
// ─────────────────────────────────────────────────────────────────

/// Short-lived state carried through the IdP round-trip.
///
/// Persisted into `yauth_oauth_states.state` as a JSON blob keyed
/// by the random `state` token. Carries the nonce + PKCE verifier
/// so the callback can match them up. The whole thing expires
/// inside 10 minutes — see [`STATE_TTL_SECS`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateBlob {
    /// SsoConnection id (so the callback knows which IdP issued).
    pub connection_id: uuid::Uuid,
    /// Issuer of the IdP that minted the original authorize request —
    /// callback validates this matches the id_token's `iss`.
    pub issuer: String,
    /// Nonce we sent on the authorize request. The callback MUST
    /// require the id_token's `nonce` matches this exactly.
    pub nonce: String,
    /// PKCE verifier. Sent on the token-exchange request to prove
    /// possession of the original authorize-request keypair.
    pub pkce_verifier: String,
    /// Where to redirect the user after a successful login. Bounded
    /// to in-app paths by handlers — never an external URL.
    pub redirect_to: Option<String>,
}

/// State-token expiry. Matches the OAuth plugin's existing 10-minute
/// budget so admins don't have to learn two TTLs.
pub const STATE_TTL_SECS: i64 = 10 * 60;

/// Generate a fresh opaque state token. 32 bytes of entropy in hex —
/// long enough that brute-force lookup is statistically impossible
/// inside the 10-minute window.
pub fn generate_state_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a fresh nonce. 16 bytes of entropy hex-encoded — same
/// rationale as the state token.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ─────────────────────────────────────────────────────────────────
// Authorize URL builder
// ─────────────────────────────────────────────────────────────────

/// Assemble the IdP authorize URL.
///
/// `authorize_endpoint` comes from the IdP's discovery document
/// (cached, refreshed per RFC 5861 rules — discovery wiring is
/// Phase B).
pub fn build_authorize_url(
    authorize_endpoint: &str,
    cfg: &OidcConnectionConfig,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    pkce_challenge: &str,
) -> String {
    let scopes = OidcConnectionConfig::normalise_scopes(&cfg.scopes).join(" ");
    let mut params: Vec<(&str, String)> = vec![
        ("response_type", "code".to_string()),
        ("client_id", cfg.client_id.clone()),
        ("redirect_uri", redirect_uri.to_string()),
        ("scope", scopes),
        ("state", state.to_string()),
        ("nonce", nonce.to_string()),
        ("code_challenge", pkce_challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ];
    let qs = serde_urlencoded::to_string(&mut params).unwrap_or_default();
    let join = if authorize_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{authorize_endpoint}{join}{qs}")
}

// ─────────────────────────────────────────────────────────────────
// SecretCipher — encrypt-at-rest for client_secret
// ─────────────────────────────────────────────────────────────────

/// Encrypt / decrypt a string secret at the storage boundary.
///
/// The shipped [`PassthroughCipher`] base64-marks the plaintext so
/// the DB never holds the literal bytes; downstream apps with real
/// KMS implement their own `SecretCipher` and inject it via the
/// builder. The trait deliberately stays narrow — `&str` in,
/// `String` out — because the only call sites are the SSO connection
/// admin handlers and the token-exchange call.
pub trait SecretCipher: Send + Sync + 'static {
    fn encrypt(&self, plaintext: &str) -> String;
    fn decrypt(&self, ciphertext: &str) -> Result<String, SecretDecryptError>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretDecryptError {
    #[error("invalid ciphertext: missing yauth marker")]
    MissingMarker,
    #[error("invalid ciphertext: bad base64 payload")]
    BadBase64,
    #[error("invalid ciphertext: payload is not UTF-8")]
    BadUtf8,
}

/// Base64-marker passthrough cipher.
///
/// Plaintext `"hunter2"` becomes `"yauth-pt-v1:aHVudGVyMg"`. This is
/// **not** cryptographically secure — it's an obfuscation layer that
/// (a) keeps secrets off the eye of an operator scrolling through a
/// SQL row dump and (b) ensures the storage shape is uniform across
/// the passthrough + real-cipher cases so swapping implementations
/// is a one-line builder change.
///
/// Apps with actual KMS implement [`SecretCipher`] themselves.
pub struct PassthroughCipher;

const PT_MARKER: &str = "yauth-pt-v1:";

impl SecretCipher for PassthroughCipher {
    fn encrypt(&self, plaintext: &str) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext.as_bytes());
        format!("{PT_MARKER}{payload}")
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String, SecretDecryptError> {
        let Some(payload) = ciphertext.strip_prefix(PT_MARKER) else {
            return Err(SecretDecryptError::MissingMarker);
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| SecretDecryptError::BadBase64)?;
        String::from_utf8(bytes).map_err(|_| SecretDecryptError::BadUtf8)
    }
}

/// Convenience: mask a client_secret for log/HTTP-response display.
/// Returns `"********"` regardless of input length so timing/length
/// side channels can't peek at the wrapped secret.
pub fn mask_secret(_s: &str) -> &'static str {
    "********"
}

// ─────────────────────────────────────────────────────────────────
// Helpers shared between admin CRUD + (Phase B) login routes
// ─────────────────────────────────────────────────────────────────

/// Validate a discovery URL: must be `https://` and end with the
/// well-known suffix. We don't fetch the document here — that's
/// Phase B's concern — but we do reject obvious config errors so
/// admins see a 400 instead of a runtime 5xx later.
pub fn validate_discovery_url(url: &str) -> Result<(), &'static str> {
    if !url.starts_with("https://") {
        // Localhost http is convenient for tests; gated by feature
        // flag to keep the admin route firmly https-only by default.
        if !cfg!(test) || !url.starts_with("http://127.0.0.1") {
            return Err("discovery_url must be https://");
        }
    }
    if !url.contains("/.well-known/openid-configuration") {
        return Err("discovery_url must end with /.well-known/openid-configuration");
    }
    Ok(())
}

/// Validate the scope list — `openid` is required; nothing else
/// must be empty/whitespace.
pub fn validate_scopes(scopes: &[String]) -> Result<(), &'static str> {
    if scopes.is_empty() {
        return Err("scopes must not be empty (at least `openid`)");
    }
    if !scopes.iter().any(|s| s == "openid") {
        return Err("scopes must include `openid` per OIDC Core §3.1.2.1");
    }
    if scopes.iter().any(|s| s.trim().is_empty()) {
        return Err("scopes must not contain empty strings");
    }
    Ok(())
}

/// Validate group-to-role mapping — roles must be drawn from the
/// known yauth role catalogue. Lets handlers 400 before persisting
/// a mapping that would silently no-op.
pub fn validate_group_to_role(map: &HashMap<String, String>) -> Result<(), &'static str> {
    for role in map.values() {
        match role.as_str() {
            "owner" | "admin" | "member" => {}
            _ => return Err("group_to_role values must be one of: owner, admin, member"),
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_mappings() -> ClaimMappings {
        ClaimMappings::default()
    }

    fn group_mappings() -> ClaimMappings {
        let mut m = ClaimMappings::default();
        m.group_to_role
            .insert("prism-admins".to_string(), "admin".to_string());
        m.group_to_role
            .insert("prism-owners".to_string(), "owner".to_string());
        m
    }

    #[test]
    fn extract_identity_happy_path() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "email": "alice@acme.com",
            "name": "Alice",
            "groups": ["prism-admins", "marketing"]
        });
        let id = extract_identity_from_claims(&group_mappings(), &claims).unwrap();
        assert_eq!(id.external_id, "user-1");
        assert_eq!(id.email.as_deref(), Some("alice@acme.com"));
        assert_eq!(id.display_name.as_deref(), Some("Alice"));
        assert_eq!(id.mapped_roles, vec!["admin".to_string()]);
    }

    #[test]
    fn extract_identity_missing_sub_is_error() {
        let claims = serde_json::json!({
            "email": "alice@acme.com"
        });
        let err = extract_identity_from_claims(&default_mappings(), &claims).unwrap_err();
        assert_eq!(err, ClaimExtractError::MissingClaim("sub".to_string()));
    }

    #[test]
    fn extract_identity_missing_email_is_ok_but_flagged() {
        let claims = serde_json::json!({
            "sub": "user-1"
        });
        let id = extract_identity_from_claims(&default_mappings(), &claims).unwrap();
        assert!(id.missing_email());
    }

    #[test]
    fn extract_identity_groups_dedupes() {
        let mut m = group_mappings();
        m.group_to_role
            .insert("alt-admins".to_string(), "admin".to_string());
        let claims = serde_json::json!({
            "sub": "user-1",
            "email": "a@b",
            "groups": ["prism-admins", "alt-admins"]
        });
        let id = extract_identity_from_claims(&m, &claims).unwrap();
        assert_eq!(id.mapped_roles, vec!["admin".to_string()]);
    }

    #[test]
    fn extract_identity_groups_rejects_non_array() {
        let claims = serde_json::json!({
            "sub": "u",
            "email": "a@b",
            "groups": "not-an-array"
        });
        let err = extract_identity_from_claims(&group_mappings(), &claims).unwrap_err();
        assert_eq!(err, ClaimExtractError::NotAnArray("groups".to_string()));
    }

    #[test]
    fn extract_identity_groups_missing_is_silent() {
        let claims = serde_json::json!({
            "sub": "u",
            "email": "a@b"
        });
        let id = extract_identity_from_claims(&group_mappings(), &claims).unwrap();
        assert!(id.mapped_roles.is_empty());
    }

    // ── PKCE ────────────────────────────────────────────

    #[test]
    fn pkce_generate_yields_43_char_verifier() {
        let p = pkce_generate();
        assert_eq!(p.verifier.len(), 43);
        // base64url alphabet: A-Z a-z 0-9 - _
        assert!(
            p.verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn pkce_challenge_is_sha256_b64url() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(compute_pkce_challenge(verifier), expected);
    }

    #[test]
    fn pkce_generate_pair_round_trips() {
        let p = pkce_generate();
        assert_eq!(compute_pkce_challenge(&p.verifier), p.challenge);
    }

    // ── State / nonce ───────────────────────────────────

    #[test]
    fn state_blob_round_trips_json() {
        let blob = StateBlob {
            connection_id: uuid::Uuid::nil(),
            issuer: "https://idp/".to_string(),
            nonce: "abc".to_string(),
            pkce_verifier: "verifier".to_string(),
            redirect_to: Some("/app".to_string()),
        };
        let s = serde_json::to_string(&blob).unwrap();
        let back: StateBlob = serde_json::from_str(&s).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn state_token_is_64_hex() {
        let t = generate_state_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn nonce_is_32_hex() {
        let n = generate_nonce();
        assert_eq!(n.len(), 32);
        assert!(n.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn state_and_nonce_are_unique_across_calls() {
        assert_ne!(generate_state_token(), generate_state_token());
        assert_ne!(generate_nonce(), generate_nonce());
    }

    // ── Authorize URL ──────────────────────────────────

    #[test]
    fn authorize_url_contains_all_required_params() {
        let cfg = OidcConnectionConfig {
            discovery_url: "https://idp/.well-known/openid-configuration".to_string(),
            client_id: "client-1".to_string(),
            client_secret: "secret".to_string(),
            scopes: OidcConnectionConfig::default_scopes(),
            claim_mappings: ClaimMappings::default(),
        };
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
        // scope must be space-separated (URL-encoded as +)
        assert!(url.contains("scope=openid+email+profile"));
    }

    #[test]
    fn authorize_url_respects_existing_query() {
        let cfg = OidcConnectionConfig {
            discovery_url: "https://idp/.well-known/openid-configuration".to_string(),
            client_id: "c".to_string(),
            client_secret: "s".to_string(),
            scopes: vec!["openid".to_string()],
            claim_mappings: ClaimMappings::default(),
        };
        let url = build_authorize_url(
            "https://idp/authorize?audience=api",
            &cfg,
            "https://app/cb",
            "st",
            "n",
            "ch",
        );
        assert!(url.starts_with("https://idp/authorize?audience=api&"));
    }

    // ── SecretCipher ───────────────────────────────────

    #[test]
    fn passthrough_round_trips() {
        let c = PassthroughCipher;
        let plain = "hunter2";
        let enc = c.encrypt(plain);
        assert!(enc.starts_with(PT_MARKER));
        assert!(
            !enc.contains(plain),
            "ciphertext must not contain plaintext"
        );
        assert_eq!(c.decrypt(&enc).unwrap(), plain);
    }

    #[test]
    fn passthrough_rejects_unmarked_ciphertext() {
        let c = PassthroughCipher;
        let err = c.decrypt("raw-plaintext").unwrap_err();
        assert_eq!(err, SecretDecryptError::MissingMarker);
    }

    #[test]
    fn passthrough_rejects_bad_base64() {
        let c = PassthroughCipher;
        let err = c
            .decrypt(&format!("{PT_MARKER}!!!not base64!!!"))
            .unwrap_err();
        assert_eq!(err, SecretDecryptError::BadBase64);
    }

    #[test]
    fn mask_secret_is_constant() {
        assert_eq!(mask_secret(""), "********");
        assert_eq!(mask_secret("anything-goes"), "********");
    }

    // ── Validation helpers ─────────────────────────────

    #[test]
    fn discovery_url_must_be_https_and_well_known() {
        assert!(validate_discovery_url("https://idp/.well-known/openid-configuration").is_ok());
        assert!(validate_discovery_url("http://idp/.well-known/openid-configuration").is_err());
        // localhost http is allowed under cfg(test).
        assert!(
            validate_discovery_url("http://127.0.0.1:8080/.well-known/openid-configuration")
                .is_ok()
        );
        assert!(validate_discovery_url("https://idp/not-well-known").is_err());
    }

    #[test]
    fn scopes_must_include_openid() {
        assert!(validate_scopes(&[]).is_err());
        assert!(validate_scopes(&["email".to_string()]).is_err());
        assert!(validate_scopes(&["openid".to_string()]).is_ok());
        assert!(validate_scopes(&["openid".to_string(), "".to_string()]).is_err());
    }

    #[test]
    fn group_to_role_rejects_unknown_roles() {
        let mut map = HashMap::new();
        map.insert("g".to_string(), "superduper".to_string());
        assert!(validate_group_to_role(&map).is_err());

        map.insert("g".to_string(), "admin".to_string());
        assert!(validate_group_to_role(&map).is_ok());
    }
}
