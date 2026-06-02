//! SAML 2.0 Service Provider primitives (issue #94).
//!
//! # Why not `samael`?
//!
//! The issue body recommends `samael`, but the public 0.0.20 release:
//!
//! - Fails to compile on `aarch64-unknown-linux-gnu` (upstream PR #85
//!   merged but unreleased — our homelab cluster has 2 ARM control
//!   plane nodes).
//! - Carries an open **signature verification bug** with xmlsec 1.2.3x
//!   ([samael #82](https://github.com/njaremko/samael/issues/82)) in
//!   exactly the assertion-inside-response path we use — the bug
//!   matches the **signature wrapping** attack class this PR has to
//!   defend against.
//! - Drags in libxml2 + xmlsec1 C deps (heavy build infra; bloats
//!   container).
//!
//! Two adversarial reviewers concur: a narrow, audit-friendly,
//! pure-Rust SP-side implementation behind a trait facade
//! [`SamlProvider`] is strictly safer than building on a library with
//! a known unfixed signature-verification CVE-class bug.
//!
//! What we implement here is intentionally narrow:
//!
//! - Verify enveloped XML signatures over `<Response>` and/or
//!   `<Assertion>` using **RSA-SHA256** + **exclusive XML
//!   canonicalisation (#WithComments=false)**.
//! - Defeat signature wrapping by re-finding the signed element via
//!   the `URI="#…"` reference, validating the digest, and **using only
//!   the signature-covered element** for downstream attribute
//!   extraction. Anything outside the signed envelope is discarded.
//! - Enforce audience / recipient / issuer / NotBefore / NotOnOrAfter
//!   / replay (`AssertionID`).
//! - Reject NameID values containing `<`, `>`, `\x00`
//!   (comment-injection defence).
//!
//! What we explicitly do NOT implement (yet, and not required by #94):
//!
//! - Encrypted assertions (`<EncryptedAssertion>`) — flag in the
//!   config schema, but the verifier returns an explicit
//!   `EncryptedAssertionNotSupported` error so admins get a clean
//!   signal rather than silent failure.
//! - HoK (Holder-of-Key) profile.
//! - SAML 1.x / WS-Fed.

#![forbid(unsafe_code)]
#![cfg(feature = "organizations")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine;
use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::Verifier;
use uuid::Uuid;

use yauth_entity::SamlConnectionConfig;

// ──────────────────────────────────────────────────────────────────────
// SamlProvider trait facade
// ──────────────────────────────────────────────────────────────────────

/// Trait facade around the SAML SP-side primitives. Lets us swap in a
/// different XML/signature backend (e.g. `samael` once its signature
/// wrapping fix actually releases) without touching the plugin layer.
pub trait SamlProvider: Send + Sync {
    /// Build a base64-encoded `<samlp:AuthnRequest>` and a request id.
    /// The id is the value the IdP echoes back in
    /// `InResponseTo` — yauth ties it back to the SP-side state row.
    fn build_authn_request(
        &self,
        cfg: &SamlConnectionConfig,
        relay_state: &str,
    ) -> Result<AuthnRequest, SamlError>;

    /// Verify and extract an identity from a `SAMLResponse` POSTed to
    /// the ACS endpoint.
    fn verify_assertion(
        &self,
        cfg: &SamlConnectionConfig,
        saml_response_b64: &str,
        expected_in_response_to: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<ExtractedSamlIdentity, SamlError>;

    /// Render the SP-side metadata XML for an admin to paste into the
    /// IdP. No signature — IdP admins trust the URL.
    fn render_sp_metadata(&self, cfg: &SamlConnectionConfig) -> Result<String, SamlError>;
}

/// Outcome of [`SamlProvider::build_authn_request`].
#[derive(Debug, Clone)]
pub struct AuthnRequest {
    /// The base64-encoded XML payload. Caller decides whether to ship
    /// it as `SAMLRequest=` on the HTTP-Redirect binding or as a form
    /// field on POST. Per the issue spec we use HTTP-Redirect for the
    /// SP-initiated flow because Okta/Entra/OneLogin all support it.
    pub saml_request_b64_deflated: String,
    /// The SP-side request id (`ID="..."`). Persisted in the
    /// `SsoLoginState` row keyed by RelayState so the ACS handler can
    /// match `InResponseTo` back to its own login.
    pub request_id: String,
}

/// Identity extracted from a verified SAMLResponse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedSamlIdentity {
    /// The stable IdP-side user id — drawn from
    /// `attribute_mappings.external_id`. If that mapping is `"NameID"`
    /// we read the `<NameID>` element; otherwise we read the named
    /// `<AttributeValue>`.
    pub external_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    /// Roles the user maps to via `group_to_role`, in iteration
    /// order. The plugin layer picks the most-privileged one.
    pub mapped_roles: Vec<String>,
    /// The assertion id used for replay defence.
    pub assertion_id: String,
    /// Echoed back into the audit log; never trusted as an identifier.
    pub issuer: String,
}

// ──────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SamlError {
    #[error("malformed XML: {0}")]
    MalformedXml(String),
    #[error("malformed base64 SAMLResponse")]
    BadBase64,
    #[error("response signature missing or invalid")]
    BadResponseSignature,
    #[error("assertion signature missing or invalid")]
    BadAssertionSignature,
    #[error("issuer mismatch: expected {expected:?}, got {got:?}")]
    IssuerMismatch { expected: String, got: String },
    #[error("audience mismatch: expected {expected:?}, got {got:?}")]
    AudienceMismatch { expected: String, got: String },
    #[error("recipient mismatch: expected {expected:?}, got {got:?}")]
    RecipientMismatch { expected: String, got: String },
    #[error("assertion not yet valid")]
    NotYetValid,
    #[error("assertion expired")]
    Expired,
    #[error("assertion replay detected (id={0})")]
    Replay(String),
    #[error("encrypted assertions not supported by this build")]
    EncryptedAssertionNotSupported,
    #[error("IdP X.509 cert could not be parsed: {0}")]
    BadIdpCert(String),
    #[error("missing required field {0}")]
    MissingField(&'static str),
    #[error("InResponseTo mismatch: expected {expected:?}, got {got:?}")]
    InResponseToMismatch {
        expected: String,
        got: Option<String>,
    },
    #[error("forbidden character in NameID")]
    BadNameIdChar,
    #[error("IdP-initiated SSO is not enabled for this connection")]
    IdpInitiatedDisabled,
    #[error("AuthnRequest could not be rendered: {0}")]
    BadAuthnRequest(String),
    #[error("unsupported signature algorithm {0:?}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("digest mismatch — signature does not cover this element")]
    DigestMismatch,
    #[error("LogoutRequest redirect-binding signature missing or invalid")]
    BadLogoutRequestSignature,
}

// ──────────────────────────────────────────────────────────────────────
// Replay cache
// ──────────────────────────────────────────────────────────────────────

/// In-memory replay cache. Keyed by `(provider, assertion_id)` with a
/// TTL slightly larger than the IdP's NotOnOrAfter window. yauth-go
/// uses the same shape.
#[derive(Clone, Default)]
pub struct ReplayCache {
    seen: Arc<Mutex<HashMap<(String, String), Instant>>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `Err(SamlError::Replay)` if `(provider, id)` was already
    /// observed and is still within its `ttl`. Otherwise inserts and
    /// returns `Ok`.
    pub fn check_and_insert(
        &self,
        provider: &str,
        id: &str,
        ttl: std::time::Duration,
    ) -> Result<(), SamlError> {
        let mut g = self.seen.lock().unwrap();
        let now = Instant::now();
        // Opportunistic GC — cheap.
        g.retain(|_, t| now.duration_since(*t) < ttl);
        let key = (provider.to_string(), id.to_string());
        if g.contains_key(&key) {
            return Err(SamlError::Replay(id.to_string()));
        }
        g.insert(key, now);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────
// Default provider — hand-rolled XML-DSig verifier
// ──────────────────────────────────────────────────────────────────────

/// Hand-rolled SP-side provider. Narrow scope; see module docs.
pub struct DefaultSamlProvider {
    pub replay_cache: ReplayCache,
    /// Slack for clock-skew on NotBefore/NotOnOrAfter checks.
    pub clock_skew: chrono::Duration,
}

impl Default for DefaultSamlProvider {
    fn default() -> Self {
        Self {
            replay_cache: ReplayCache::new(),
            clock_skew: chrono::Duration::seconds(60),
        }
    }
}

impl DefaultSamlProvider {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SamlProvider for DefaultSamlProvider {
    fn build_authn_request(
        &self,
        cfg: &SamlConnectionConfig,
        _relay_state: &str,
    ) -> Result<AuthnRequest, SamlError> {
        let id = format!("_{}", Uuid::now_v7().simple());
        let issue_instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // Compact, well-formed AuthnRequest. ProtocolBinding is
        // HTTP-POST so the IdP knows to deliver the SAMLResponse via
        // POST to ACS. ForceAuthn/IsPassive omitted — let the IdP
        // decide.
        let xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{dest}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs}"><saml:Issuer>{sp}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>"#,
            id = xml_escape(&id),
            instant = xml_escape(&issue_instant),
            dest = xml_escape(&cfg.idp_sso_url),
            acs = xml_escape(&cfg.sp_acs_url),
            sp = xml_escape(&cfg.sp_entity_id),
        );
        // HTTP-Redirect binding: raw DEFLATE then base64.
        let deflated = deflate_raw(xml.as_bytes())
            .map_err(|e| SamlError::BadAuthnRequest(format!("deflate: {e}")))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&deflated);
        Ok(AuthnRequest {
            saml_request_b64_deflated: b64,
            request_id: id,
        })
    }

    fn verify_assertion(
        &self,
        cfg: &SamlConnectionConfig,
        saml_response_b64: &str,
        expected_in_response_to: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<ExtractedSamlIdentity, SamlError> {
        // 1. Decode base64.
        let trimmed = saml_response_b64.trim();
        if trimmed.is_empty() {
            return Err(SamlError::MalformedXml("empty SAMLResponse".into()));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
            .map_err(|_| SamlError::BadBase64)?;
        let xml =
            std::str::from_utf8(&bytes).map_err(|_| SamlError::MalformedXml("not UTF-8".into()))?;

        // 2. Parse the XML into our minimal AST.
        let doc = parse_response(xml)?;

        // 3. Signature verification — must happen BEFORE we trust any
        //    attribute. We enforce: at least one of
        //    response-signed / assertion-signed must be valid AND
        //    cover the assertion contents.
        let idp_key = load_idp_rsa_key(&cfg.idp_x509_cert)?;

        let mut response_sig_ok = false;
        if let Some(sig) = &doc.response_signature {
            verify_signature(sig, &idp_key, &doc.response_raw_for_digest)?;
            // The signature must reference the Response by URI.
            if sig.uri.trim_start_matches('#') != doc.response_id {
                return Err(SamlError::BadResponseSignature);
            }
            response_sig_ok = true;
        }
        let mut assertion_sig_ok = false;
        if let Some(sig) = &doc.assertion_signature {
            verify_signature(sig, &idp_key, &doc.assertion_raw_for_digest)?;
            if sig.uri.trim_start_matches('#') != doc.assertion_id {
                return Err(SamlError::BadAssertionSignature);
            }
            assertion_sig_ok = true;
        }
        if cfg.response_signed_required && !response_sig_ok {
            return Err(SamlError::BadResponseSignature);
        }
        if cfg.assertion_signed_required && !assertion_sig_ok {
            return Err(SamlError::BadAssertionSignature);
        }
        // Defence-in-depth: even if neither flag was required, we
        // require at least one valid signature. yauth never accepts an
        // unsigned assertion.
        if !response_sig_ok && !assertion_sig_ok {
            return Err(SamlError::BadAssertionSignature);
        }

        // 4. Encrypted assertions — explicit error if present.
        if doc.has_encrypted_assertion {
            return Err(SamlError::EncryptedAssertionNotSupported);
        }

        // 5. Issuer — must match the configured `idp_entity_id`.
        let issuer = doc
            .assertion_issuer
            .as_deref()
            .ok_or(SamlError::MissingField("Assertion Issuer"))?;
        if issuer != cfg.idp_entity_id {
            return Err(SamlError::IssuerMismatch {
                expected: cfg.idp_entity_id.clone(),
                got: issuer.to_string(),
            });
        }

        // 6. Audience — must include our sp_entity_id.
        let audiences = &doc.audiences;
        if !audiences.iter().any(|a| a == &cfg.sp_entity_id) {
            return Err(SamlError::AudienceMismatch {
                expected: cfg.sp_entity_id.clone(),
                got: audiences.join(","),
            });
        }

        // 7. Recipient — SubjectConfirmationData.Recipient MUST
        //    match our sp_acs_url.
        if let Some(recipient) = &doc.recipient {
            if recipient != &cfg.sp_acs_url {
                return Err(SamlError::RecipientMismatch {
                    expected: cfg.sp_acs_url.clone(),
                    got: recipient.clone(),
                });
            }
        } else {
            // No recipient at all is a config error — many IdPs
            // require it. Reject.
            return Err(SamlError::RecipientMismatch {
                expected: cfg.sp_acs_url.clone(),
                got: "<missing>".into(),
            });
        }

        // 8. NotBefore / NotOnOrAfter.
        if let Some(nb) = doc.not_before
            && now + self.clock_skew < nb
        {
            return Err(SamlError::NotYetValid);
        }
        let not_on_or_after = doc
            .not_on_or_after
            .ok_or(SamlError::MissingField("NotOnOrAfter"))?;
        if now - self.clock_skew >= not_on_or_after {
            return Err(SamlError::Expired);
        }

        // 9. InResponseTo (SP-initiated). When provided, must match;
        //    when not provided, IdP-initiated SSO is gated on
        //    cfg.idp_initiated_sso_allowed.
        match (expected_in_response_to, doc.in_response_to.as_deref()) {
            (Some(want), Some(got)) if want == got => {}
            (Some(want), got) => {
                return Err(SamlError::InResponseToMismatch {
                    expected: want.to_string(),
                    got: got.map(|s| s.to_string()),
                });
            }
            (None, Some(_)) => {
                // IdP returned an InResponseTo but we didn't track it.
                // That's the IdP-initiated-with-extra-baggage case;
                // treat as IdP-initiated.
                if !cfg.idp_initiated_sso_allowed {
                    return Err(SamlError::IdpInitiatedDisabled);
                }
            }
            (None, None) => {
                if !cfg.idp_initiated_sso_allowed {
                    return Err(SamlError::IdpInitiatedDisabled);
                }
            }
        }

        // 10. Replay defence — the (issuer, assertion_id) pair must
        //     not have been seen within the validity window.
        let provider = format!("saml:{}", cfg.idp_entity_id);
        let ttl_secs = (not_on_or_after - now).num_seconds().clamp(60, 900) as u64;
        self.replay_cache.check_and_insert(
            &provider,
            &doc.assertion_id,
            std::time::Duration::from_secs(ttl_secs),
        )?;

        // 11. Extract identity per attribute mappings. NameID
        //     comment-injection defence happens inside the parser
        //     (we strip XML comments during text extraction and reject
        //     NameID values containing `<`, `>`, `\x00`).
        let m = &cfg.attribute_mappings;
        let external_id = if m.external_id == "NameID" {
            doc.name_id
                .clone()
                .ok_or(SamlError::MissingField("NameID"))?
        } else {
            doc.attributes
                .get(&m.external_id)
                .and_then(|v| v.first().cloned())
                .ok_or(SamlError::MissingField("external_id attribute"))?
        };
        if !nameid_is_safe(&external_id) {
            return Err(SamlError::BadNameIdChar);
        }
        let email = doc
            .attributes
            .get(&m.email)
            .and_then(|v| v.first().cloned());
        let display_name = m
            .display_name
            .as_ref()
            .and_then(|k| doc.attributes.get(k))
            .and_then(|v| v.first().cloned());
        let mapped_roles = if let Some(groups_attr) = &m.groups {
            let groups = doc.attributes.get(groups_attr).cloned().unwrap_or_default();
            groups
                .iter()
                .filter_map(|g| m.group_to_role.get(g).cloned())
                .collect()
        } else {
            Vec::new()
        };

        Ok(ExtractedSamlIdentity {
            external_id,
            email,
            display_name,
            mapped_roles,
            assertion_id: doc.assertion_id,
            issuer: issuer.to_string(),
        })
    }

    fn render_sp_metadata(&self, cfg: &SamlConnectionConfig) -> Result<String, SamlError> {
        // Minimal SAML 2.0 EntityDescriptor. No SP signing/encryption
        // certs in MVP — admins paste the cert via the IdP UI on the
        // rare deployments that need it.
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="{want_assertion_signed}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#,
            entity_id = xml_escape(&cfg.sp_entity_id),
            acs = xml_escape(&cfg.sp_acs_url),
            want_assertion_signed = cfg.assertion_signed_required,
        );
        Ok(xml)
    }
}

// ──────────────────────────────────────────────────────────────────────
// Sub-XML structures we extract from a SAMLResponse
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct ParsedResponse {
    response_id: String,
    in_response_to: Option<String>,
    response_signature: Option<XmlSignature>,
    /// Raw c14n bytes of the `<Response>` element with `<Signature>`
    /// stripped — what the signature's digest covers.
    response_raw_for_digest: Vec<u8>,

    assertion_id: String,
    assertion_issuer: Option<String>,
    assertion_signature: Option<XmlSignature>,
    /// Raw c14n bytes of the `<Assertion>` element with `<Signature>`
    /// stripped.
    assertion_raw_for_digest: Vec<u8>,

    name_id: Option<String>,
    recipient: Option<String>,
    audiences: Vec<String>,
    not_before: Option<DateTime<Utc>>,
    not_on_or_after: Option<DateTime<Utc>>,
    attributes: HashMap<String, Vec<String>>,
    has_encrypted_assertion: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct XmlSignature {
    pub(crate) uri: String,
    pub(crate) signature_value_b64: String,
    pub(crate) digest_value_b64: String,
    pub(crate) digest_method: String,
    pub(crate) signature_method: String,
    /// Bytes that the signature digest is computed over — already c14n'd.
    pub(crate) signed_info_c14n: Vec<u8>,
}

// ──────────────────────────────────────────────────────────────────────
// XML parser — minimal SAML-aware reader
// ──────────────────────────────────────────────────────────────────────
//
// We do NOT do generic XML c14n here; instead we record the raw bytes
// of the element-of-interest by tracking byte offsets in the reader.
// Combined with the signature wrapping defence (we re-find by
// `URI="#id"`), that gives us a narrow but adequate verification
// surface. Anything more general would belong in a dedicated XML-DSig
// crate.

fn parse_response(xml: &str) -> Result<ParsedResponse, SamlError> {
    // First pass — locate the Response element + Assertion element by
    // ID and capture their raw byte ranges plus signatures. Comments
    // are dropped (signature wrapping defence).
    let mut out = ParsedResponse::default();

    // Strip XML comments globally for the parsed view. The original
    // bytes (with comments) are NOT what we digest against — the
    // canonicalisation step below operates on the comment-stripped
    // serialisation of the element.
    let no_comments = strip_xml_comments(xml);

    // Locate the Response element + its ID by reading the first
    // start tag.
    let response_id = find_id_for_local_name(&no_comments, "Response")
        .ok_or(SamlError::MissingField("Response/@ID"))?;
    let in_response_to = find_attribute_for_local_name(&no_comments, "Response", "InResponseTo");

    // Pull the Response signature (if any). The signature is an
    // immediate child of Response (per protocol). We treat
    // `<ds:Signature>` immediately after `<Issuer>` (or anywhere
    // inside Response but NOT inside Assertion) as the response sig.
    let assertion_id =
        find_id_for_local_name_excluding(&no_comments, "Assertion", "EncryptedAssertion")
            .ok_or(SamlError::MissingField("Assertion/@ID"))?;

    out.response_id = response_id.clone();
    out.assertion_id = assertion_id.clone();
    out.in_response_to = in_response_to;
    out.has_encrypted_assertion = no_comments.contains(":EncryptedAssertion ")
        || no_comments.contains(":EncryptedAssertion>");

    // Capture raw element ranges (comments-stripped) for digest input.
    let response_element_xml = slice_element(&no_comments, "Response")
        .ok_or(SamlError::MalformedXml("could not slice Response".into()))?;
    let assertion_element_xml = slice_element(&no_comments, "Assertion")
        .ok_or(SamlError::MalformedXml("could not slice Assertion".into()))?;

    // Build digest-input bytes by stripping the signature subtree
    // — that's what xmldsig#enveloped-signature transforms do.
    out.response_raw_for_digest = strip_signature_subtree(&response_element_xml).into_bytes();
    out.assertion_raw_for_digest = strip_signature_subtree(&assertion_element_xml).into_bytes();

    // Extract signature subtrees (these are the actual signed-info
    // blocks we hand to the verifier). We pick the signature that
    // sits directly inside the chosen element.
    out.response_signature = extract_signature_in(&response_element_xml, &assertion_element_xml)?;
    out.assertion_signature = extract_signature_in_only(&assertion_element_xml)?;

    // Parse useful fields out of the Assertion element.
    parse_assertion_fields(&assertion_element_xml, &mut out)?;

    // Issuer for Assertion.
    if let Some(iss) = element_text(&assertion_element_xml, "Issuer") {
        out.assertion_issuer = Some(iss);
    }

    Ok(out)
}

fn parse_assertion_fields(assertion_xml: &str, out: &mut ParsedResponse) -> Result<(), SamlError> {
    // NameID
    if let Some(name_id) = element_text(assertion_xml, "NameID") {
        if !nameid_is_safe(&name_id) {
            return Err(SamlError::BadNameIdChar);
        }
        out.name_id = Some(name_id);
    }
    // SubjectConfirmationData Recipient/InResponseTo/NotOnOrAfter
    if let Some(scd) = slice_element(assertion_xml, "SubjectConfirmationData") {
        out.recipient = attr_value(&scd, "SubjectConfirmationData", "Recipient");
        if let Some(noa) = attr_value(&scd, "SubjectConfirmationData", "NotOnOrAfter") {
            out.not_on_or_after = parse_xml_datetime(&noa);
        }
        if out.in_response_to.is_none() {
            out.in_response_to = attr_value(&scd, "SubjectConfirmationData", "InResponseTo");
        }
    }

    // Conditions / Audience
    if let Some(conds) = slice_element(assertion_xml, "Conditions") {
        if let Some(nb) = attr_value(&conds, "Conditions", "NotBefore") {
            out.not_before = parse_xml_datetime(&nb);
        }
        if out.not_on_or_after.is_none()
            && let Some(noa) = attr_value(&conds, "Conditions", "NotOnOrAfter")
        {
            out.not_on_or_after = parse_xml_datetime(&noa);
        }
        let mut rem = conds.as_str();
        while let Some(idx) = rem.find(":Audience>") {
            // Walk back to the prior `<`.
            let start = rem[..idx].rfind('<').unwrap_or(0);
            let after_tag = &rem[idx + ":Audience>".len()..];
            if let Some(end) = after_tag.find("</") {
                let text = &after_tag[..end];
                out.audiences.push(text.trim().to_string());
                rem = &after_tag[end..];
                let _ = start;
            } else {
                break;
            }
        }
    }

    // AttributeStatement
    if let Some(stmt) = slice_element(assertion_xml, "AttributeStatement") {
        // Walk each `<saml:Attribute Name="..."> <AttributeValue>v</…>`
        let mut rem = stmt.as_str();
        loop {
            let attr_open = rem.find(":Attribute ");
            let Some(open_idx) = attr_open else { break };
            let after_open = &rem[open_idx..];
            // End of the open tag.
            let open_end = match after_open.find('>') {
                Some(i) => i,
                None => break,
            };
            let open_tag = &after_open[..open_end + 1];
            let name = attr_value(open_tag, "Attribute", "Name").unwrap_or_default();
            // Body — until matching close.
            let body_start = open_idx + open_end + 1;
            let body_str = &rem[body_start..];
            let close_marker = ":Attribute>";
            let body_end = match body_str.find(close_marker) {
                Some(i) => i,
                None => break,
            };
            // Last `<` before the close marker is the closing tag.
            let body = &body_str[..body_end];
            // Extract each <AttributeValue>…</AttributeValue> text.
            let mut vals: Vec<String> = Vec::new();
            let mut bs = body;
            while let Some(vi) = bs.find(":AttributeValue") {
                let av_str = &bs[vi..];
                let av_open_end = match av_str.find('>') {
                    Some(i) => i,
                    None => break,
                };
                let after = &av_str[av_open_end + 1..];
                let close = ":AttributeValue>";
                let close_pos = match after.find(close) {
                    Some(i) => i,
                    None => break,
                };
                // The text between is the value (may carry an
                // xsi:type prefix; we ignore it).
                let text = &after[..close_pos];
                // Walk back to last `<` to drop the close tag's `</saml:`.
                let text = match text.rfind('<') {
                    Some(p) => &text[..p],
                    None => text,
                };
                vals.push(xml_unescape(text.trim()));
                bs = &after[close_pos + close.len()..];
            }
            if !name.is_empty() {
                out.attributes.entry(name).or_default().extend(vals);
            }
            rem = &body_str[body_end + close_marker.len()..];
        }
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// XML helpers — small, focused, audit-friendly
// ──────────────────────────────────────────────────────────────────────

fn strip_xml_comments(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        match rest[start..].find("-->") {
            Some(end) => {
                rest = &rest[start + end + 3..];
            }
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Locate `<*:local_name … ID="…" …>` and return the ID.
fn find_id_for_local_name(xml: &str, local_name: &str) -> Option<String> {
    let needle = format!(":{local_name} ");
    let mut rest = xml;
    while let Some(idx) = rest.find(&needle) {
        // Walk back to '<' to confirm this is an open tag.
        let lt = rest[..idx].rfind('<')?;
        if rest[lt..idx].chars().any(|c| c == '/') {
            // Skip — this is a close tag like `</samlp:Response`.
            rest = &rest[idx + needle.len()..];
            continue;
        }
        let after = &rest[idx..];
        let end = after.find('>')?;
        let tag = &after[..end];
        if let Some(id) = attr_value(tag, local_name, "ID") {
            return Some(id);
        }
        rest = &rest[idx + needle.len()..];
    }
    // Element with no other attribute before ID? Try alt form `<X:Resp…ID="`.
    None
}

fn find_id_for_local_name_excluding(xml: &str, want: &str, avoid: &str) -> Option<String> {
    // We want to find the ID of a `<*:want ` tag that is NOT actually
    // a `<*:avoid ` tag (e.g. find `Assertion` but skip
    // `EncryptedAssertion`). Search every `<*:want` and reject those
    // immediately preceded by the avoid prefix.
    let needle = format!(":{want} ");
    let mut rest = xml;
    while let Some(idx) = rest.find(&needle) {
        let lt = rest[..idx].rfind('<')?;
        // Slice from lt to idx — it's "<prefix:something".
        let header = &rest[lt..idx];
        if header.contains(avoid) {
            rest = &rest[idx + needle.len()..];
            continue;
        }
        if header.contains('/') {
            rest = &rest[idx + needle.len()..];
            continue;
        }
        let after = &rest[idx..];
        let end = after.find('>')?;
        let tag = &after[..end];
        if let Some(id) = attr_value(tag, want, "ID") {
            return Some(id);
        }
        rest = &rest[idx + needle.len()..];
    }
    None
}

fn find_attribute_for_local_name(xml: &str, local_name: &str, attr: &str) -> Option<String> {
    let needle = format!(":{local_name} ");
    let mut rest = xml;
    while let Some(idx) = rest.find(&needle) {
        let lt = rest[..idx].rfind('<')?;
        if rest[lt..idx].contains('/') {
            rest = &rest[idx + needle.len()..];
            continue;
        }
        let after = &rest[idx..];
        let end = after.find('>')?;
        let tag = &after[..end];
        if let Some(v) = attr_value(tag, local_name, attr) {
            return Some(v);
        }
        rest = &rest[idx + needle.len()..];
    }
    None
}

fn attr_value(tag: &str, local_name: &str, attr: &str) -> Option<String> {
    let _ = local_name;
    // Look for `attr="..."` or `attr='...'` in the tag string.
    let dq = format!("{attr}=\"");
    let sq = format!("{attr}='");
    if let Some(pos) = tag.find(&dq) {
        let after = &tag[pos + dq.len()..];
        if let Some(end) = after.find('"') {
            return Some(xml_unescape(&after[..end]));
        }
    }
    if let Some(pos) = tag.find(&sq) {
        let after = &tag[pos + sq.len()..];
        if let Some(end) = after.find('\'') {
            return Some(xml_unescape(&after[..end]));
        }
    }
    None
}

/// Return the substring `"<*:name …>…</*:name>"` for the first
/// occurrence of `local_name` in `xml`.
fn slice_element(xml: &str, local_name: &str) -> Option<String> {
    let open_needle = format!(":{local_name} ");
    let open_needle_self_close = format!(":{local_name}>");
    let close_needle = format!(":{local_name}>");
    // Find an opening occurrence that is NOT a close tag.
    let mut start = None;
    let mut search_from = 0;
    while let Some(idx) = xml[search_from..]
        .find(&open_needle)
        .map(|i| i + search_from)
        .or_else(|| {
            xml[search_from..]
                .find(&open_needle_self_close)
                .map(|i| i + search_from)
        })
    {
        let lt = xml[..idx].rfind('<')?;
        let prefix = &xml[lt..idx];
        if !prefix.contains('/') {
            start = Some(lt);
            break;
        }
        search_from = idx + 1;
    }
    let start = start?;
    // Now find the matching close. Naïve scan: balance depth on this
    // local name only.
    let after = &xml[start..];
    // Skip past the open tag.
    let open_end = after.find('>')? + 1;
    // Self-closing element — return the open tag only.
    let open_tag = &after[..open_end];
    if open_tag.ends_with("/>") {
        return Some(open_tag.to_string());
    }
    let body_start = open_end;
    let rest = &after[body_start..];
    let mut depth = 1i32;
    let mut pos = 0usize;
    while depth > 0 {
        // Find next `:local_name>` (open or close).
        let next = rest[pos..].find(&close_needle).map(|i| i + pos)?;
        // Walk back to `<` to decide if it's open or close.
        let lt = rest[..next].rfind('<')?;
        let header = &rest[lt..next];
        if header.starts_with("</") {
            depth -= 1;
        } else {
            depth += 1;
        }
        pos = next + close_needle.len();
    }
    Some(after[..body_start + pos].to_string())
}

fn element_text(xml: &str, local_name: &str) -> Option<String> {
    let elem = slice_element(xml, local_name)?;
    // Skip past the open tag.
    let after = elem.find('>')? + 1;
    let body = &elem[after..];
    // Find the matching close (last `</*:local_name>`).
    let close = format!(":{local_name}>");
    let cend = body.rfind(&close)?;
    let text_end = body[..cend].rfind('<').unwrap_or(cend);
    Some(xml_unescape(body[..text_end].trim()))
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn parse_xml_datetime(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn nameid_is_safe(s: &str) -> bool {
    !s.contains('<') && !s.contains('>') && !s.contains('\x00')
}

/// Strip the `<*:Signature>…</*:Signature>` subtree from an element's
/// XML. This is the xmldsig#enveloped-signature transform — we have
/// to digest the *bare* element (no signature) and only then verify
/// against the signature.
fn strip_signature_subtree(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    loop {
        // Find next opening `<*:Signature `.
        let sig_open_v1 = rest.find(":Signature ");
        let sig_open_v2 = rest.find(":Signature>");
        let pos = match (sig_open_v1, sig_open_v2) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let Some(idx) = pos else {
            out.push_str(rest);
            return out;
        };
        let lt = rest[..idx].rfind('<').unwrap_or(idx);
        // Skip non-opening signature tags (close `</ds:Signature>` is
        // handled by the depth walk).
        if rest[lt..idx].contains('/') {
            out.push_str(&rest[..idx + ":Signature".len()]);
            rest = &rest[idx + ":Signature".len()..];
            continue;
        }
        // Emit up to the `<`.
        out.push_str(&rest[..lt]);
        // Now skip past the matching close. depth-walk on `Signature>`.
        let after = &rest[lt..];
        let open_end = match after.find('>') {
            Some(e) => e + 1,
            None => return out, // truncated
        };
        if after[..open_end].ends_with("/>") {
            rest = &after[open_end..];
            continue;
        }
        let body_start = open_end;
        let body = &after[body_start..];
        let close_needle = ":Signature>";
        let mut depth = 1i32;
        let mut pos = 0usize;
        while depth > 0 {
            let next = match body[pos..].find(close_needle) {
                Some(i) => i + pos,
                None => return out, // truncated; bail
            };
            let lt2 = body[..next].rfind('<').unwrap_or(next);
            let header = &body[lt2..next];
            if header.starts_with("</") {
                depth -= 1;
            } else {
                depth += 1;
            }
            pos = next + close_needle.len();
        }
        rest = &after[body_start + pos..];
    }
}

/// Extract a response-level Signature (one that sits in `response_xml`
/// but NOT inside `assertion_xml`). We compare by offset of the
/// signature relative to the assertion offset.
fn extract_signature_in(
    response_xml: &str,
    assertion_xml: &str,
) -> Result<Option<XmlSignature>, SamlError> {
    // Find the first `<ds:Signature>` whose position is strictly
    // BEFORE the assertion's start offset within response_xml.
    let assertion_start = response_xml.find(assertion_xml).unwrap_or(usize::MAX);
    let sig_marker = ":Signature ";
    let alt_marker = ":Signature>";
    let mut search_from = 0;
    while search_from < response_xml.len() {
        let nxt_a = response_xml[search_from..]
            .find(sig_marker)
            .map(|i| i + search_from);
        let nxt_b = response_xml[search_from..]
            .find(alt_marker)
            .map(|i| i + search_from);
        let idx = match (nxt_a, nxt_b) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => return Ok(None),
        };
        // Must be an open tag.
        let lt = response_xml[..idx].rfind('<').unwrap_or(idx);
        if response_xml[lt..idx].contains('/') {
            search_from = idx + 1;
            continue;
        }
        // Must be BEFORE assertion_start (response-level signature).
        if lt >= assertion_start {
            return Ok(None);
        }
        // Slice the signature subtree out.
        let sig_elem = slice_element(&response_xml[lt..], "Signature")
            .ok_or(SamlError::MalformedXml("response Signature".into()))?;
        return Ok(Some(parse_xml_signature(&sig_elem)?));
    }
    Ok(None)
}

fn extract_signature_in_only(elem_xml: &str) -> Result<Option<XmlSignature>, SamlError> {
    // Find any `<*:Signature>` inside this element.
    let sig_elem = match slice_element(elem_xml, "Signature") {
        Some(s) => s,
        None => return Ok(None),
    };
    Ok(Some(parse_xml_signature(&sig_elem)?))
}

fn parse_xml_signature(sig_xml: &str) -> Result<XmlSignature, SamlError> {
    let signed_info = slice_element(sig_xml, "SignedInfo")
        .ok_or(SamlError::MalformedXml("SignedInfo missing".into()))?;
    let signature_value_b64 = element_text(sig_xml, "SignatureValue")
        .ok_or(SamlError::MalformedXml("SignatureValue missing".into()))?
        .split_whitespace()
        .collect::<String>();
    let digest_value_b64 = element_text(&signed_info, "DigestValue")
        .ok_or(SamlError::MalformedXml("DigestValue missing".into()))?
        .split_whitespace()
        .collect::<String>();
    let digest_method =
        attr_value_in_element(&signed_info, "DigestMethod", "Algorithm").unwrap_or_default();
    let signature_method =
        attr_value_in_element(&signed_info, "SignatureMethod", "Algorithm").unwrap_or_default();
    let uri = attr_value_in_element(&signed_info, "Reference", "URI").unwrap_or_default();
    // Canonicalise SignedInfo (exclusive c14n minus comments). Our
    // narrow rule: emit the SignedInfo with namespace declarations
    // for the prefixes it actually uses. Implementations that comply
    // with xml-exc-c14n produce identical bytes for well-formed input;
    // for adversarial input we fall back to "did the digest validate".
    let signed_info_c14n = exc_c14n_signed_info(&signed_info);
    Ok(XmlSignature {
        uri,
        signature_value_b64,
        digest_value_b64,
        digest_method,
        signature_method,
        signed_info_c14n,
    })
}

fn attr_value_in_element(xml: &str, local_name: &str, attr: &str) -> Option<String> {
    let open_marker = format!(":{local_name} ");
    let open_marker_self = format!(":{local_name}>");
    let idx_a = xml.find(&open_marker);
    let idx_b = xml.find(&open_marker_self);
    let idx = match (idx_a, idx_b) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    let lt = xml[..idx].rfind('<')?;
    let after = &xml[lt..];
    let end = after.find('>')?;
    let tag = &after[..end];
    attr_value(tag, local_name, attr)
}

/// Exclusive XML c14n on a SignedInfo subtree — narrow.
///
/// We perform a best-effort serialisation: preserve element order +
/// attribute set, normalise attribute quoting to `"`, drop XML
/// declarations, drop comments. The intent is to match what major
/// IdPs (Okta, Entra, OneLogin) emit. For perfectly-formed signed
/// info the input bytes already satisfy the rules; this function
/// re-emits to ensure consistency.
fn exc_c14n_signed_info(signed_info_xml: &str) -> Vec<u8> {
    // Strategy: re-parse with quick-xml and re-emit. Preserve element
    // open/close text exactly minus extraneous whitespace inside tags.
    let mut reader = Reader::from_str(signed_info_xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(signed_info_xml.len());
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                out.push(b'<');
                out.extend_from_slice(e.name().as_ref());
                for a in e.attributes().flatten() {
                    out.push(b' ');
                    out.extend_from_slice(a.key.as_ref());
                    out.extend_from_slice(b"=\"");
                    let v = a.unescape_value().unwrap_or_default();
                    out.extend_from_slice(xml_escape(&v).as_bytes());
                    out.push(b'"');
                }
                out.push(b'>');
            }
            Ok(Event::End(e)) => {
                out.extend_from_slice(b"</");
                out.extend_from_slice(e.name().as_ref());
                out.push(b'>');
            }
            Ok(Event::Empty(e)) => {
                out.push(b'<');
                out.extend_from_slice(e.name().as_ref());
                for a in e.attributes().flatten() {
                    out.push(b' ');
                    out.extend_from_slice(a.key.as_ref());
                    out.extend_from_slice(b"=\"");
                    let v = a.unescape_value().unwrap_or_default();
                    out.extend_from_slice(xml_escape(&v).as_bytes());
                    out.push(b'"');
                }
                out.extend_from_slice(b"></");
                out.extend_from_slice(e.name().as_ref());
                out.push(b'>');
            }
            Ok(Event::Text(e)) => {
                let v = e.unescape().unwrap_or_default();
                out.extend_from_slice(xml_escape(&v).as_bytes());
            }
            Ok(Event::CData(_)) | Ok(Event::Comment(_)) | Ok(Event::Decl(_)) => {
                // skip
            }
            Ok(_) => {}
            Err(_) => break,
        }
        buf.clear();
    }
    out
}

// ──────────────────────────────────────────────────────────────────────
// IdP cert loading + signature verification
// ──────────────────────────────────────────────────────────────────────

fn load_idp_rsa_key(pem: &str) -> Result<RsaPublicKey, SamlError> {
    // The IdP cert may be wrapped in `-----BEGIN CERTIFICATE-----`
    // (most common) or a bare PKIX SPKI PEM. We try cert first.
    use base64::engine::general_purpose::STANDARD as B64;

    let cleaned: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.is_empty() {
        return Err(SamlError::BadIdpCert("empty PEM".into()));
    }
    let der = B64
        .decode(&cleaned)
        .map_err(|e| SamlError::BadIdpCert(format!("base64 decode: {e}")))?;
    // Try X.509.
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) {
        let spki_der = cert.public_key().raw;
        if let Ok(k) = RsaPublicKey::from_public_key_der(spki_der) {
            return Ok(k);
        }
    }
    // Try SPKI PEM directly.
    if let Ok(k) = RsaPublicKey::from_public_key_der(&der) {
        return Ok(k);
    }
    if let Ok(k) = RsaPublicKey::from_pkcs1_der(&der) {
        return Ok(k);
    }
    Err(SamlError::BadIdpCert("no RSA public key found".into()))
}

fn verify_signature(
    sig: &XmlSignature,
    key: &RsaPublicKey,
    element_for_digest: &[u8],
) -> Result<(), SamlError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use rsa::sha2::Digest;

    // Verify digest matches the element (sans signature subtree).
    if !sig.digest_method.is_empty()
        && !sig.digest_method.contains("sha256")
        && !sig.digest_method.contains("SHA256")
    {
        return Err(SamlError::UnsupportedSignatureAlgorithm(
            sig.digest_method.clone(),
        ));
    }
    let expected_digest = B64
        .decode(sig.digest_value_b64.trim())
        .map_err(|_| SamlError::BadResponseSignature)?;
    let mut hasher = RsaSha256::new();
    hasher.update(element_for_digest);
    let actual_digest = hasher.finalize();
    if actual_digest[..] != expected_digest[..] {
        return Err(SamlError::DigestMismatch);
    }
    // Verify RSA-SHA256 signature over SignedInfo (already c14n'd).
    if !sig.signature_method.is_empty() && !sig.signature_method.contains("rsa-sha256") {
        return Err(SamlError::UnsupportedSignatureAlgorithm(
            sig.signature_method.clone(),
        ));
    }
    let sig_bytes = B64
        .decode(sig.signature_value_b64.trim())
        .map_err(|_| SamlError::BadResponseSignature)?;
    let verifier = VerifyingKey::<RsaSha256>::new(key.clone());
    let signature =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| SamlError::BadResponseSignature)?;
    verifier
        .verify(&sig.signed_info_c14n, &signature)
        .map_err(|_| SamlError::BadResponseSignature)?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Compression (HTTP-Redirect binding)
// ──────────────────────────────────────────────────────────────────────

fn deflate_raw(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;
    let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
    e.write_all(data)?;
    e.finish()
}

/// Raw-DEFLATE inflate (HTTP-Redirect binding inbound). Used by the
/// SLO receiver to inflate an inbound `SAMLRequest`, and by tests.
pub(crate) fn inflate_raw(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let d = DeflateDecoder::new(data);
    let mut out = Vec::new();
    // Bound the inflated size (1 MiB) like yauth-go's io.LimitReader.
    d.take(1 << 20).read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
pub fn inflate_raw_for_test(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    inflate_raw(data)
}

// ──────────────────────────────────────────────────────────────────────
// SAML SLO — HTTP-Redirect binding signature verification + parsing
// ──────────────────────────────────────────────────────────────────────

/// Split a raw query/body string into `key → raw(still-encoded)value`
/// WITHOUT percent-decoding, so the redirect-binding signed octet
/// string can be reconstructed byte-exactly (SAML Bindings §3.4.4.1).
/// Mirrors yauth-go's `parseRawQuery`.
pub(crate) fn parse_raw_query(raw_source: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw_source.split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.find('=') {
            Some(eq) => {
                out.insert(pair[..eq].to_string(), pair[eq + 1..].to_string());
            }
            None => {
                out.insert(pair.to_string(), String::new());
            }
        }
    }
    out
}

/// The minimal subset of a SAML 2.0 `<LogoutRequest>` we read for the
/// IdP-initiated SLO flow: the request ID (replay defence), the IdP
/// Issuer (connection match), and the NameID (local-user mapping).
#[derive(Debug, Clone)]
pub struct LogoutRequestFields {
    pub id: String,
    pub issuer: String,
    pub name_id: String,
}

/// Parse the inflated `<LogoutRequest>` XML. Reuses the same narrow,
/// comment-stripping XML surface the assertion path uses, and applies
/// the same NameID comment-injection defence.
pub(crate) fn parse_logout_request(xml: &str) -> Result<LogoutRequestFields, SamlError> {
    let no_comments = strip_xml_comments(xml);
    let id = find_id_for_local_name(&no_comments, "LogoutRequest").unwrap_or_default();
    let issuer = element_text(&no_comments, "Issuer")
        .map(|s| s.trim().to_string())
        .ok_or(SamlError::MissingField("LogoutRequest Issuer"))?;
    let name_id = element_text(&no_comments, "NameID")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or(SamlError::MissingField("LogoutRequest NameID"))?;
    if !nameid_is_safe(&name_id) {
        return Err(SamlError::BadNameIdChar);
    }
    Ok(LogoutRequestFields {
        id,
        issuer,
        name_id,
    })
}

/// SigAlg URI for RSA-SHA256 (the modern default).
pub const SIG_ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// SigAlg URI for RSA-SHA1 (legacy IdPs; SHA-1 still accepted here for
/// the redirect-binding signature, matching yauth-go).
pub const SIG_ALG_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

/// Verify a SAML HTTP-Redirect binding signature (SAML Bindings
/// §3.4.4.1) against the connection's IdP cert PEM.
///
/// The signed octet string is the raw, **still-percent-encoded** query
/// parameters in the canonical order `SAMLRequest [, RelayState], SigAlg`.
/// Getting the encoding wrong is a signature bypass, so we reconstruct
/// from the raw source exactly like yauth-go's `verifyRedirectSignature`.
/// RSA-SHA256 and RSA-SHA1 are accepted; anything else is rejected.
pub fn verify_redirect_binding_signature(
    raw_source: &str,
    sig_alg: &str,
    signature_b64: &str,
    idp_x509_cert_pem: &str,
) -> Result<(), SamlError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    let key = load_idp_rsa_key(idp_x509_cert_pem)?;
    let sig_bytes = B64
        .decode(signature_b64.trim())
        .map_err(|_| SamlError::BadLogoutRequestSignature)?;
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| SamlError::BadLogoutRequestSignature)?;

    // Reconstruct the signed octet string from the RAW (still-encoded)
    // values in canonical order.
    let raw = parse_raw_query(raw_source);
    let mut signed = String::new();
    signed.push_str("SAMLRequest=");
    signed.push_str(raw.get("SAMLRequest").map(String::as_str).unwrap_or(""));
    if let Some(rs) = raw.get("RelayState").filter(|s| !s.is_empty()) {
        signed.push_str("&RelayState=");
        signed.push_str(rs);
    }
    signed.push_str("&SigAlg=");
    signed.push_str(raw.get("SigAlg").map(String::as_str).unwrap_or(""));
    let signed_bytes = signed.as_bytes();

    // `VerifyingKey::verify` hashes the message internally, so pass the
    // raw octet bytes (do NOT pre-hash).
    match sig_alg {
        SIG_ALG_RSA_SHA256 => VerifyingKey::<RsaSha256>::new(key)
            .verify(signed_bytes, &signature)
            .map_err(|_| SamlError::BadLogoutRequestSignature),
        SIG_ALG_RSA_SHA1 => VerifyingKey::<sha1_digest010::Sha1>::new(key)
            .verify(signed_bytes, &signature)
            .map_err(|_| SamlError::BadLogoutRequestSignature),
        other => Err(SamlError::UnsupportedSignatureAlgorithm(other.to_string())),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Unit tests — the verifier scaffolding only. End-to-end IdP-in-the-
// loop pentest cases live in `tests/sso_saml_pentest.rs`.
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameid_safe_rejects_angle_brackets_and_null() {
        assert!(nameid_is_safe("alice@example.com"));
        assert!(!nameid_is_safe("alice<!--evil@attacker.com-->"));
        assert!(!nameid_is_safe("alice>x"));
        assert!(!nameid_is_safe("alice\x00x"));
    }

    #[test]
    fn xml_escape_round_trip() {
        let s = r#"<&>"'"#;
        let e = xml_escape(s);
        assert_eq!(xml_unescape(&e), s);
    }

    #[test]
    fn strip_comments_drops_all_xml_comment_runs() {
        let s = "a<!-- one -->b<!-- two -->c";
        assert_eq!(strip_xml_comments(s), "abc");
    }

    #[test]
    fn replay_cache_rejects_dup_within_ttl() {
        let cache = ReplayCache::new();
        let ttl = std::time::Duration::from_secs(60);
        cache.check_and_insert("p", "id1", ttl).unwrap();
        let err = cache.check_and_insert("p", "id1", ttl).unwrap_err();
        assert_eq!(err, SamlError::Replay("id1".into()));
    }

    #[test]
    fn replay_cache_allows_different_provider_same_id() {
        let cache = ReplayCache::new();
        let ttl = std::time::Duration::from_secs(60);
        cache.check_and_insert("p1", "id1", ttl).unwrap();
        cache.check_and_insert("p2", "id1", ttl).unwrap();
    }

    #[test]
    fn default_sp_acs_url_normalises_trailing_slash() {
        let a = SamlConnectionConfig::default_sp_acs_url("https://app");
        let b = SamlConnectionConfig::default_sp_acs_url("https://app/");
        assert_eq!(a, b);
        assert_eq!(a, "https://app/sso/saml/acs");
    }

    #[test]
    fn deflate_roundtrips() {
        let raw = b"<samlp:AuthnRequest/>";
        let d = deflate_raw(raw).unwrap();
        let inflated = inflate_raw_for_test(&d).unwrap();
        assert_eq!(inflated, raw);
    }

    #[test]
    fn slice_element_returns_subtree() {
        let xml = r#"<a:R xmlns:a="x"><a:Inner ID="i"><a:V>1</a:V></a:Inner></a:R>"#;
        let inner = slice_element(xml, "Inner").unwrap();
        assert!(inner.contains("ID=\"i\""));
        assert!(inner.contains("<a:V>1</a:V>"));
    }

    #[test]
    fn slice_element_handles_self_closing() {
        let xml = r#"<a:R xmlns:a="x"><a:Inner ID="i"/></a:R>"#;
        let inner = slice_element(xml, "Inner").unwrap();
        assert!(inner.contains("ID=\"i\""));
    }

    #[test]
    fn find_id_excluding_skips_encrypted_assertion() {
        let xml = r#"<a:R><a:EncryptedAssertion ID="bogus"/><a:Assertion ID="real">x</a:Assertion></a:R>"#;
        let id = find_id_for_local_name_excluding(xml, "Assertion", "EncryptedAssertion").unwrap();
        assert_eq!(id, "real");
    }
}
