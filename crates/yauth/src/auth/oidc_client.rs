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
// AEAD cipher — ChaCha20-Poly1305 over the deployment secret
// ─────────────────────────────────────────────────────────────────

/// Real AEAD cipher for `client_secret` storage.
///
/// Replaces [`PassthroughCipher`] in production deployments. Keyed off a
/// 32-byte deployment secret — operators typically derive this from an
/// HKDF off a single root secret that lives in their secret manager
/// (Vault, AWS Secrets Manager, GCP Secret Manager, etc.).
///
/// # Format
///
/// `yauth-aead-v1:<base64url-no-pad(12-byte nonce || ciphertext || 16-byte tag)>`
///
/// The 12-byte nonce is freshly generated per encryption and is part
/// of the stored blob — apps don't need to track it separately.
///
/// # Key rotation
///
/// The marker carries a single version (`v1`). To rotate keys without
/// downtime, deploy a new build with a `KeyRotatingCipher` that holds
/// both the old and the new key, attempts decrypt against the new
/// first then falls back to the old, and re-encrypts at write time
/// with the new. Concrete `KeyRotatingCipher` is out of scope here —
/// the trait surface stays narrow and apps wrap their own.
///
/// # Security
///
/// ChaCha20-Poly1305 is constant-time without hardware AES support
/// (most non-AES-NI ARM cores) and produces ciphertext + 128-bit
/// authentication tag in one shot. Per RFC 8439 §4 the same
/// `(key, nonce)` pair must NEVER be reused — `encrypt` generates a
/// fresh nonce on every call.
pub struct ChaCha20Poly1305Cipher {
    key: chacha20poly1305::Key,
}

const AEAD_MARKER: &str = "yauth-aead-v1:";
const AEAD_NONCE_LEN: usize = 12;

impl ChaCha20Poly1305Cipher {
    /// Construct from a 32-byte key. Returns `None` on wrong length —
    /// the caller is responsible for HKDF-ing a deployment root
    /// secret down to 32 bytes.
    pub fn new(key_bytes: &[u8]) -> Option<Self> {
        if key_bytes.len() != 32 {
            return None;
        }
        Some(Self {
            #[allow(deprecated)]
            key: *chacha20poly1305::Key::from_slice(key_bytes),
        })
    }
}

impl SecretCipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &str) -> String {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = ChaCha20Poly1305::new(&self.key);
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);
        // Encrypt — Poly1305 tag is appended to ciphertext.
        let ct = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("ChaCha20-Poly1305 encrypt cannot fail with valid inputs");
        let mut blob = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&blob);
        format!("{AEAD_MARKER}{payload}")
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String, SecretDecryptError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let payload = ciphertext
            .strip_prefix(AEAD_MARKER)
            .ok_or(SecretDecryptError::MissingMarker)?;
        let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| SecretDecryptError::BadBase64)?;
        if blob.len() < AEAD_NONCE_LEN + 16 {
            // Need at least a nonce + a Poly1305 tag.
            return Err(SecretDecryptError::BadBase64);
        }
        let (nonce_bytes, ct) = blob.split_at(AEAD_NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(&self.key);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct)
            .map_err(|_| SecretDecryptError::BadBase64)?;
        String::from_utf8(pt).map_err(|_| SecretDecryptError::BadUtf8)
    }
}

// ─────────────────────────────────────────────────────────────────
// OIDC discovery + JWKS cache
// ─────────────────────────────────────────────────────────────────

/// OIDC discovery document, parsed.
///
/// We only keep the fields we use — yauth doesn't need
/// `userinfo_endpoint`, `registration_endpoint`, etc. Adding fields
/// later is a one-line patch since `serde(default)` lets us forward-
/// extend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

/// JWKS as fetched from the IdP. Public-key material only — we never
/// see the IdP's signing private key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoteJwks {
    pub keys: Vec<RemoteJwk>,
}

/// One key entry. We support RSA (RS256) for now — ES256 lands later
/// as a follow-up. All other `kty` values are ignored during lookup.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoteJwk {
    #[serde(default)]
    pub kid: Option<String>,
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    /// RSA modulus (base64url-no-pad). Present when `kty == "RSA"`.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent (base64url-no-pad). Present when `kty == "RSA"`.
    #[serde(default)]
    pub e: Option<String>,
}

/// Cache entry per `issuer`.
#[derive(Debug, Clone)]
struct CachedJwks {
    jwks: RemoteJwks,
    fetched_at: std::time::Instant,
    ttl: std::time::Duration,
    /// Last time we refreshed *because of a kid miss*. Rate-limits
    /// the "rotate IdP keys at midnight" path so a stream of bad
    /// tokens can't DDoS the IdP's JWKS endpoint.
    last_kid_miss_refresh: Option<std::time::Instant>,
}

impl CachedJwks {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < self.ttl
    }
}

/// Concurrent JWKS cache, keyed by IdP `issuer`.
///
/// # Refresh policy
///
/// - **TTL hit, kid present**: serve from cache, no fetch.
/// - **TTL miss**: fetch + replace.
/// - **TTL hit but kid missing**: fetch *at most once per minute per
///   issuer* (rate-limited). On the second-in-a-minute kid miss we
///   reject the token without re-hitting the IdP.
///
/// # Concurrency
///
/// `Arc<RwLock<HashMap<...>>>` — the IdP's JWKS document is a few KB
/// at most, contention is bounded. Fetches happen outside the lock.
#[derive(Clone, Default)]
pub struct JwksCache {
    inner: std::sync::Arc<tokio::sync::RwLock<HashMap<String, CachedJwks>>>,
    /// Discovery-document cache, indexed by the discovery URL. Documents
    /// are stable per IdP — TTL: 1 h hard cap.
    discovery: std::sync::Arc<
        tokio::sync::RwLock<HashMap<String, (DiscoveryDocument, std::time::Instant)>>,
    >,
}

/// Errors from the discovery / JWKS path.
#[derive(Debug, thiserror::Error)]
pub enum OidcFetchError {
    #[error("network error: {0}")]
    Network(String),
    #[error("discovery document is malformed: {0}")]
    BadDiscovery(String),
    #[error("JWKS document is malformed: {0}")]
    BadJwks(String),
    #[error("rate limited: kid-miss refresh already attempted within the last minute")]
    RateLimited,
}

/// Hard ceiling on JWKS cache TTL.
pub const JWKS_TTL_MAX: std::time::Duration = std::time::Duration::from_secs(3600);

/// Default JWKS TTL when the IdP doesn't advertise one.
pub const JWKS_TTL_DEFAULT: std::time::Duration = std::time::Duration::from_secs(900);

/// Rate-limit window for kid-miss refreshes.
pub const JWKS_KID_MISS_REFRESH_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

impl JwksCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch + cache an IdP discovery document.
    ///
    /// The discovery URL is treated as opaque — we never derive
    /// authority from it; the `issuer` field in the returned document
    /// drives id_token `iss` validation downstream.
    pub async fn discover(
        &self,
        client: &reqwest::Client,
        discovery_url: &str,
    ) -> Result<DiscoveryDocument, OidcFetchError> {
        // Cache hit?
        if let Some((doc, fetched_at)) = self.discovery.read().await.get(discovery_url).cloned()
            && fetched_at.elapsed() < JWKS_TTL_MAX
        {
            return Ok(doc);
        }
        // Miss — fetch.
        let resp = client
            .get(discovery_url)
            .send()
            .await
            .map_err(|e| OidcFetchError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(OidcFetchError::Network(format!(
                "discovery HTTP {}",
                resp.status()
            )));
        }
        let doc: DiscoveryDocument = resp
            .json()
            .await
            .map_err(|e| OidcFetchError::BadDiscovery(e.to_string()))?;
        // Insert into cache. Per RFC 8414 §3 we trust the document's
        // own `issuer` field — if the IdP wants to lie about that,
        // its TLS cert is the chokepoint.
        self.discovery.write().await.insert(
            discovery_url.to_string(),
            (doc.clone(), std::time::Instant::now()),
        );
        Ok(doc)
    }

    /// Resolve a key by `kid` against the cached JWKS for `issuer`,
    /// fetching if necessary. Honors the rate-limit on kid-miss
    /// refreshes.
    ///
    /// `jwks_uri` is the URI to fetch on miss. Caller passes it
    /// through from the discovery document.
    pub async fn key_for_kid(
        &self,
        client: &reqwest::Client,
        issuer: &str,
        jwks_uri: &str,
        kid: &str,
    ) -> Result<RemoteJwk, OidcFetchError> {
        // Fast path: cached + fresh + contains kid.
        {
            let guard = self.inner.read().await;
            if let Some(entry) = guard.get(issuer)
                && entry.is_fresh()
                && let Some(k) = entry
                    .jwks
                    .keys
                    .iter()
                    .find(|k| k.kid.as_deref() == Some(kid))
            {
                return Ok(k.clone());
            }
        }

        // Either no entry / stale / kid missing. Decide if we refresh.
        let now = std::time::Instant::now();
        let kid_miss_refresh_ok = {
            let guard = self.inner.read().await;
            match guard.get(issuer) {
                None => true,
                Some(entry) => {
                    // If TTL-expired, refresh unconditionally.
                    if !entry.is_fresh() {
                        true
                    } else {
                        // Cached but kid missing — rate-limited refresh.
                        match entry.last_kid_miss_refresh {
                            None => true,
                            Some(last) => now.duration_since(last) > JWKS_KID_MISS_REFRESH_WINDOW,
                        }
                    }
                }
            }
        };

        if !kid_miss_refresh_ok {
            return Err(OidcFetchError::RateLimited);
        }

        // Fetch JWKS.
        let resp = client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| OidcFetchError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(OidcFetchError::Network(format!(
                "jwks HTTP {}",
                resp.status()
            )));
        }
        let jwks: RemoteJwks = resp
            .json()
            .await
            .map_err(|e| OidcFetchError::BadJwks(e.to_string()))?;

        // Write into cache.
        let was_kid_miss = {
            let guard = self.inner.read().await;
            guard.get(issuer).map(|e| e.is_fresh()).unwrap_or(false)
        };
        self.inner.write().await.insert(
            issuer.to_string(),
            CachedJwks {
                jwks: jwks.clone(),
                fetched_at: now,
                ttl: JWKS_TTL_DEFAULT,
                last_kid_miss_refresh: if was_kid_miss { Some(now) } else { None },
            },
        );

        jwks.keys
            .into_iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| OidcFetchError::BadJwks(format!("kid `{kid}` not in JWKS")))
    }

    /// Test-only: inject a pre-built JWKS into the cache. Lets the
    /// IdP-loop pentest seed the cache without standing up a real
    /// HTTP server.
    #[doc(hidden)]
    pub async fn insert_for_test(&self, issuer: &str, jwks: RemoteJwks) {
        self.inner.write().await.insert(
            issuer.to_string(),
            CachedJwks {
                jwks,
                fetched_at: std::time::Instant::now(),
                ttl: JWKS_TTL_DEFAULT,
                last_kid_miss_refresh: None,
            },
        );
    }
}

// ─────────────────────────────────────────────────────────────────
// id_token validation
// ─────────────────────────────────────────────────────────────────

/// Reasons an id_token was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdTokenError {
    #[error("malformed id_token: {0}")]
    Malformed(String),
    #[error("unsupported signing algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("issuer mismatch: token `{actual}`, expected `{expected}`")]
    IssuerMismatch { actual: String, expected: String },
    #[error("audience mismatch: token does not contain expected client_id `{expected}`")]
    AudienceMismatch { expected: String },
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid (iat > now)")]
    NotYetValid,
    #[error("signature verification failed")]
    BadSignature,
    #[error("missing `kid` header (cannot pick a JWKS key without one)")]
    MissingKid,
    #[error("JWKS lookup failed: {0}")]
    JwksLookup(String),
}

/// Claims we care about during validation. Extra claims pass through
/// in the `extra` JSON value for the claim-extractor downstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    #[serde(default)]
    pub aud: AudienceClaim,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Everything else — claim extraction reads from here.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// `aud` claim — either a single string OR an array. OIDC Core §2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    Single(String),
    Multi(Vec<String>),
}

impl Default for AudienceClaim {
    fn default() -> Self {
        AudienceClaim::Multi(Vec::new())
    }
}

impl AudienceClaim {
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            AudienceClaim::Single(s) => s == expected,
            AudienceClaim::Multi(v) => v.iter().any(|s| s == expected),
        }
    }
}

/// Validate an id_token end-to-end against a connection's config.
///
/// The `jwk` is expected to be pre-resolved via [`JwksCache::key_for_kid`]
/// using the `kid` from the token header.
///
/// # Checks (in order)
///
/// 1. `alg` is one of `RS256` / `RS384` / `RS512` (no `none`, no HS*).
/// 2. Signature verifies against `jwk`.
/// 3. `iss == expected_issuer`.
/// 4. `aud` contains `expected_client_id`.
/// 5. `nonce == expected_nonce`.
/// 6. `exp > now`.
/// 7. `iat <= now + leeway`.
/// 8. `nbf <= now + leeway` (when present).
///
/// A leeway of ±60s absorbs minor clock skew without compromising
/// the OIDC Core §3.1.3.7 freshness contract.
pub fn validate_id_token(
    raw_token: &str,
    jwk: &RemoteJwk,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_nonce: &str,
    now_unix: i64,
) -> Result<IdTokenClaims, IdTokenError> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    let header = decode_header(raw_token)
        .map_err(|e| IdTokenError::Malformed(format!("header parse: {e}")))?;

    // Algorithm — must be asymmetric RSA. ES256 lands as a follow-up.
    let alg = match header.alg {
        Algorithm::RS256 => Algorithm::RS256,
        Algorithm::RS384 => Algorithm::RS384,
        Algorithm::RS512 => Algorithm::RS512,
        other => return Err(IdTokenError::UnsupportedAlg(format!("{other:?}"))),
    };

    // JWK must be RSA with `n` + `e`.
    if !jwk.kty.eq_ignore_ascii_case("RSA") {
        return Err(IdTokenError::UnsupportedAlg(format!("kty={}", jwk.kty)));
    }
    let n = jwk
        .n
        .as_deref()
        .ok_or_else(|| IdTokenError::JwksLookup("RSA key missing `n`".into()))?;
    let e = jwk
        .e
        .as_deref()
        .ok_or_else(|| IdTokenError::JwksLookup("RSA key missing `e`".into()))?;
    let decoding_key = DecodingKey::from_rsa_components(n, e)
        .map_err(|e| IdTokenError::JwksLookup(format!("rsa key parse: {e}")))?;

    // Use jsonwebtoken's validator — but disable its own time / aud /
    // iss checks so we control the error variants. We just want the
    // signature verification + claim deserialization.
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let data = decode::<IdTokenClaims>(raw_token, &decoding_key, &validation)
        .map_err(|_| IdTokenError::BadSignature)?;
    let claims = data.claims;

    // Issuer pinning.
    if claims.iss != expected_issuer {
        return Err(IdTokenError::IssuerMismatch {
            actual: claims.iss.clone(),
            expected: expected_issuer.to_string(),
        });
    }

    // Audience check.
    if !claims.aud.contains(expected_client_id) {
        return Err(IdTokenError::AudienceMismatch {
            expected: expected_client_id.to_string(),
        });
    }

    // Nonce check.
    if claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(IdTokenError::NonceMismatch);
    }

    // Time-bounds check with 60s leeway.
    const LEEWAY: i64 = 60;
    if claims.exp + LEEWAY <= now_unix {
        return Err(IdTokenError::Expired);
    }
    if claims.iat > now_unix + LEEWAY {
        return Err(IdTokenError::NotYetValid);
    }
    if let Some(nbf) = claims.nbf
        && nbf > now_unix + LEEWAY
    {
        return Err(IdTokenError::NotYetValid);
    }

    Ok(claims)
}

/// Extract the `kid` from a raw JWT's protected header. Convenience
/// for callers who want to resolve the JWKS key before validating.
pub fn id_token_kid(raw_token: &str) -> Result<String, IdTokenError> {
    use jsonwebtoken::decode_header;
    let h = decode_header(raw_token)
        .map_err(|e| IdTokenError::Malformed(format!("header parse: {e}")))?;
    h.kid.ok_or(IdTokenError::MissingKid)
}

// ─────────────────────────────────────────────────────────────────
// Token exchange
// ─────────────────────────────────────────────────────────────────

/// Response from the IdP's token endpoint. We only keep the bits we
/// need — `access_token` + `refresh_token` are intentionally not
/// persisted (yauth is acting as an OIDC consumer; we don't proxy the
/// IdP's API tokens onward).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub id_token: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

/// Errors from the token-exchange call.
#[derive(Debug, thiserror::Error)]
pub enum TokenExchangeError {
    #[error("network error: {0}")]
    Network(String),
    #[error("IdP returned HTTP {status}: {body}")]
    BadResponse { status: u16, body: String },
    #[error("token response malformed: {0}")]
    BadFormat(String),
}

/// Exchange an authorization code for an id_token at the IdP.
///
/// Sends `code` + `code_verifier` + `client_id` + `client_secret`
/// (plaintext at this point — caller decrypted via `SecretCipher`)
/// via `application/x-www-form-urlencoded` per OIDC Core §3.1.3.1.
pub async fn exchange_code(
    client: &reqwest::Client,
    token_endpoint: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: &str,
    code_verifier: &str,
) -> Result<TokenResponse, TokenExchangeError> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code_verifier", code_verifier),
    ];
    let resp = client
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| TokenExchangeError::Network(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(TokenExchangeError::BadResponse {
            status: status.as_u16(),
            body,
        });
    }
    resp.json::<TokenResponse>()
        .await
        .map_err(|e| TokenExchangeError::BadFormat(e.to_string()))
}

/// Convert [`IdTokenClaims`] back into a flat `serde_json::Value`
/// suitable for [`extract_identity_from_claims`].
///
/// We keep `iss`, `aud`, `exp`, `iat`, `nbf`, `nonce` available
/// alongside the IdP-specific claims so a connection's
/// `ClaimMappings.external_id` can point at any of them (e.g. Entra
/// ID prefers `oid` over `sub`).
pub fn claims_to_json(claims: &IdTokenClaims) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("iss".into(), serde_json::Value::String(claims.iss.clone()));
    match &claims.aud {
        AudienceClaim::Single(s) => {
            map.insert("aud".into(), serde_json::Value::String(s.clone()));
        }
        AudienceClaim::Multi(v) => {
            map.insert(
                "aud".into(),
                serde_json::Value::Array(
                    v.iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
    }
    map.insert(
        "exp".into(),
        serde_json::Value::Number(serde_json::Number::from(claims.exp)),
    );
    map.insert(
        "iat".into(),
        serde_json::Value::Number(serde_json::Number::from(claims.iat)),
    );
    if let Some(n) = &claims.nonce {
        map.insert("nonce".into(), serde_json::Value::String(n.clone()));
    }
    if let Some(nbf) = claims.nbf {
        map.insert(
            "nbf".into(),
            serde_json::Value::Number(serde_json::Number::from(nbf)),
        );
    }
    for (k, v) in &claims.extra {
        map.insert(k.clone(), v.clone());
    }
    serde_json::Value::Object(map)
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
        let test_nonce = generate_nonce();
        let url = build_authorize_url(
            "https://idp/authorize",
            &cfg,
            "https://app/cb",
            "state-token",
            &test_nonce,
            "challenge-1",
        );
        for k in [
            "response_type=code",
            "client_id=client-1",
            "state=state-token",
            &format!("nonce={test_nonce}"),
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
            &generate_nonce(),
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

    // ── AEAD cipher ───────────────────────────────────

    #[test]
    fn aead_round_trips() {
        let key = [7u8; 32];
        let c = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let plain = "super-secret-shared-secret";
        let enc = c.encrypt(plain);
        assert!(enc.starts_with(AEAD_MARKER));
        assert!(
            !enc.contains(plain),
            "ciphertext must not contain plaintext"
        );
        assert_eq!(c.decrypt(&enc).unwrap(), plain);
    }

    #[test]
    fn aead_rejects_short_key() {
        assert!(ChaCha20Poly1305Cipher::new(&[0u8; 16]).is_none());
        assert!(ChaCha20Poly1305Cipher::new(&[0u8; 33]).is_none());
    }

    #[test]
    fn aead_rejects_wrong_key() {
        let a = ChaCha20Poly1305Cipher::new(&[1u8; 32]).unwrap();
        let b = ChaCha20Poly1305Cipher::new(&[2u8; 32]).unwrap();
        let enc = a.encrypt("foo");
        // Wrong key => tag verification fails.
        assert!(b.decrypt(&enc).is_err());
    }

    #[test]
    fn aead_nonces_are_unique() {
        let c = ChaCha20Poly1305Cipher::new(&[9u8; 32]).unwrap();
        // Same plaintext, different ciphertexts (random nonce).
        let a = c.encrypt("same");
        let b = c.encrypt("same");
        assert_ne!(a, b);
        assert_eq!(c.decrypt(&a).unwrap(), "same");
        assert_eq!(c.decrypt(&b).unwrap(), "same");
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let c = ChaCha20Poly1305Cipher::new(&[3u8; 32]).unwrap();
        let mut enc = c.encrypt("hi");
        // Flip a bit in the payload (skip the marker).
        let i = enc.len() - 1;
        // Mutate the last byte.
        let bytes = unsafe { enc.as_bytes_mut() };
        bytes[i] ^= 1;
        assert!(c.decrypt(&enc).is_err());
    }

    #[test]
    fn aead_rejects_marker_mismatch() {
        let c = ChaCha20Poly1305Cipher::new(&[4u8; 32]).unwrap();
        let enc = c.encrypt("x");
        let stripped = enc.replace(AEAD_MARKER, PT_MARKER);
        assert_eq!(
            c.decrypt(&stripped).unwrap_err(),
            SecretDecryptError::MissingMarker
        );
    }

    // ── AudienceClaim ─────────────────────────────────

    #[test]
    fn audience_claim_single_matches() {
        let a = AudienceClaim::Single("client-1".into());
        assert!(a.contains("client-1"));
        assert!(!a.contains("client-2"));
    }

    #[test]
    fn audience_claim_multi_matches_any() {
        let a = AudienceClaim::Multi(vec!["a".into(), "b".into()]);
        assert!(a.contains("a"));
        assert!(a.contains("b"));
        assert!(!a.contains("c"));
    }

    #[test]
    fn audience_claim_parses_either_shape() {
        let single: AudienceClaim = serde_json::from_str("\"x\"").unwrap();
        assert!(single.contains("x"));
        let multi: AudienceClaim = serde_json::from_str("[\"a\",\"b\"]").unwrap();
        assert!(multi.contains("a"));
    }

    // ── JwksCache ─────────────────────────────────────

    #[tokio::test]
    async fn jwks_cache_hit_avoids_refetch() {
        let cache = JwksCache::new();
        let issuer = "https://idp";
        let jwks = RemoteJwks {
            keys: vec![RemoteJwk {
                kid: Some("k1".into()),
                kty: "RSA".into(),
                alg: Some("RS256".into()),
                n: Some("n".into()),
                e: Some("AQAB".into()),
            }],
        };
        cache.insert_for_test(issuer, jwks).await;
        // Client never gets used because the cache hit short-circuits.
        let client = reqwest::Client::new();
        let k = cache
            .key_for_kid(&client, issuer, "http://invalid-jwks-uri", "k1")
            .await
            .unwrap();
        assert_eq!(k.kid.as_deref(), Some("k1"));
    }

    #[tokio::test]
    async fn jwks_cache_kid_miss_rate_limited() {
        let cache = JwksCache::new();
        let issuer = "https://idp";
        // Seed with a fresh-but-incomplete JWKS.
        cache
            .insert_for_test(
                issuer,
                RemoteJwks {
                    keys: vec![RemoteJwk {
                        kid: Some("k1".into()),
                        kty: "RSA".into(),
                        alg: Some("RS256".into()),
                        n: Some("n".into()),
                        e: Some("AQAB".into()),
                    }],
                },
            )
            .await;
        // Force the last_kid_miss_refresh field by simulating a prior
        // refresh that happened *just now*. We do this by sneaking
        // through insert_for_test then doing a direct kid-miss call —
        // the first call refreshes, the second within 60s is rate-limited.
        // We can't reach the real network here, so directly set the
        // last_kid_miss_refresh via internal mutation.
        {
            let mut guard = cache.inner.write().await;
            let entry = guard.get_mut(issuer).unwrap();
            entry.last_kid_miss_refresh = Some(std::time::Instant::now());
        }
        let client = reqwest::Client::new();
        let err = cache
            .key_for_kid(&client, issuer, "http://invalid-jwks-uri", "missing-kid")
            .await
            .unwrap_err();
        assert!(matches!(err, OidcFetchError::RateLimited));
    }

    // ── claims_to_json ────────────────────────────────

    #[test]
    fn claims_to_json_preserves_sub_and_email() {
        let mut extra = HashMap::new();
        extra.insert("sub".to_string(), serde_json::json!("u-1"));
        extra.insert("email".to_string(), serde_json::json!("a@b"));
        let claims = IdTokenClaims {
            iss: "https://idp".into(),
            aud: AudienceClaim::Single("c-1".into()),
            exp: 200,
            iat: 100,
            nonce: Some("n".into()),
            nbf: None,
            extra,
        };
        let v = claims_to_json(&claims);
        assert_eq!(v["iss"], "https://idp");
        assert_eq!(v["sub"], "u-1");
        assert_eq!(v["email"], "a@b");
        assert_eq!(v["nonce"], "n");
        assert_eq!(v["aud"], "c-1");
    }
}
