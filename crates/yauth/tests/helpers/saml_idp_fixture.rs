//! Minimal SAML 2.0 IdP fixture for end-to-end SP tests (issue #94).
//!
//! Generates a fresh RSA-2048 keypair per test, builds a Response +
//! Assertion, and signs the Assertion with RSA-SHA256 + the same
//! narrow exclusive-c14n shape `auth::saml_sp` validates. Keys never
//! leave the test process — no live calls.
//!
//! The fixture is purposely sloppy in the same ways real IdPs are
//! (whitespace inside elements, no XML declaration, multiple
//! namespace prefixes) so the pentest harness exercises a realistic
//! parsing surface.

#![allow(dead_code)]
#![forbid(unsafe_code)]

use base64::Engine;
use chrono::{DateTime, Utc};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use uuid::Uuid;

/// In-memory IdP — owns the keypair + the issuer/entityID it asserts
/// against.
pub struct FixtureIdp {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub issuer: String,
}

impl FixtureIdp {
    pub fn new(issuer: &str) -> Self {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key gen");
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
            issuer: issuer.to_string(),
        }
    }

    /// Build an X.509-shaped PEM for the IdP cert. We bypass the
    /// actual X.509 wrapping by emitting an SPKI PEM — `load_idp_rsa_key`
    /// falls back to SPKI parsing when X.509 fails, so this is fine
    /// for tests.
    pub fn cert_pem(&self) -> String {
        self.public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("spki pem")
    }

    /// Build a SAML Response with the supplied parameters and sign
    /// the assertion. Returns the base64-encoded `SAMLResponse`.
    pub fn sign_response(&self, opts: AssertionOpts<'_>) -> String {
        let assertion_xml = self.build_signed_assertion(&opts);
        let response_xml = build_response_xml(&opts, &assertion_xml);
        base64::engine::general_purpose::STANDARD.encode(response_xml.as_bytes())
    }

    fn build_signed_assertion(&self, opts: &AssertionOpts<'_>) -> String {
        let attr_block = render_attributes(&opts.attributes);
        let raw_assertion = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" Version="2.0" IssueInstant="{instant}"><saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{noa}" Recipient="{recipient}"{in_response_to_attr}/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion>"#,
            aid = opts.assertion_id,
            instant = opts
                .issue_instant
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            issuer = xml_escape(&opts.issuer.unwrap_or(&self.issuer)),
            name_id = xml_escape(opts.name_id),
            noa = opts
                .not_on_or_after
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            nb = opts
                .not_before
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            recipient = xml_escape(opts.recipient),
            audience = xml_escape(opts.audience),
            in_response_to_attr = match opts.in_response_to {
                Some(s) => format!(" InResponseTo=\"{}\"", xml_escape(s)),
                None => "".into(),
            },
            attrs = attr_block,
        );

        if opts.sign_assertion {
            insert_signature(&raw_assertion, opts.assertion_id, &self.private_key)
        } else {
            raw_assertion
        }
    }
}

/// Knobs for one assertion. Pentest cases tweak these one at a time.
#[derive(Clone)]
pub struct AssertionOpts<'a> {
    pub response_id: &'a str,
    pub assertion_id: &'a str,
    /// Override the issuer (defaults to the FixtureIdp.issuer).
    pub issuer: Option<&'a str>,
    pub audience: &'a str,
    pub recipient: &'a str,
    pub name_id: &'a str,
    pub in_response_to: Option<&'a str>,
    pub not_before: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
    pub issue_instant: DateTime<Utc>,
    pub attributes: Vec<(&'a str, Vec<&'a str>)>,
    pub sign_assertion: bool,
}

impl<'a> AssertionOpts<'a> {
    pub fn ok(
        audience: &'a str,
        recipient: &'a str,
        name_id: &'a str,
        in_response_to: Option<&'a str>,
    ) -> Self {
        let now = Utc::now();
        Self {
            response_id: "_resp",
            assertion_id: "_assert",
            issuer: None,
            audience,
            recipient,
            name_id,
            in_response_to,
            not_before: now - chrono::Duration::seconds(30),
            not_on_or_after: now + chrono::Duration::minutes(5),
            issue_instant: now,
            attributes: vec![
                (
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                    vec![name_id],
                ),
                (
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                    vec!["Alice Example"],
                ),
            ],
            sign_assertion: true,
        }
    }
}

fn build_response_xml(opts: &AssertionOpts<'_>, assertion_xml: &str) -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{rid}" Version="2.0" IssueInstant="{instant}" Destination="{recipient}"{in_response_to_attr}><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>"#,
        rid = opts.response_id,
        instant = opts
            .issue_instant
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        recipient = xml_escape(opts.recipient),
        in_response_to_attr = match opts.in_response_to {
            Some(s) => format!(" InResponseTo=\"{}\"", xml_escape(s)),
            None => "".into(),
        },
        issuer = xml_escape(opts.issuer.unwrap_or("urn:idp:default")),
        assertion = assertion_xml,
    )
}

fn render_attributes(attrs: &[(&str, Vec<&str>)]) -> String {
    let mut out = String::new();
    for (name, values) in attrs {
        out.push_str(&format!(r#"<saml:Attribute Name="{}">"#, xml_escape(name)));
        for v in values {
            out.push_str(&format!(
                r#"<saml:AttributeValue>{}</saml:AttributeValue>"#,
                xml_escape(v)
            ));
        }
        out.push_str(r#"</saml:Attribute>"#);
    }
    out
}

/// Insert a `<ds:Signature>` element into the assertion using the
/// enveloped-signature transform that yauth's SP-side verifier
/// accepts.
fn insert_signature(assertion_xml: &str, ref_id: &str, key: &RsaPrivateKey) -> String {
    // The verifier strips the Signature subtree before digesting,
    // so signing the bare assertion works.
    let mut digest = Sha256::new();
    digest.update(assertion_xml.as_bytes());
    let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest.finalize());

    // SignedInfo — narrow, matches what our c14n re-emit will produce.
    let signed_info = format!(
        "{prefix}{ref_id}{mid}{digest_b64}{suffix}",
        prefix = r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#"##,
        ref_id = ref_id,
        mid = r##""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>"##,
        digest_b64 = digest_b64,
        suffix = r##"</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
    );

    // The SignedInfo we sign over MUST be the c14n form. Our verifier
    // re-c14ns by re-emitting via quick-xml; we mirror that here so
    // signed-bytes match verified-bytes.
    let c14n_signed_info = c14n_via_quick_xml(&signed_info);

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::<Sha256>::new(key.clone());
    let signature = signing_key.sign_with_rng(&mut rng, &c14n_signed_info);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    let signature_xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"#,
        signed_info = signed_info,
        sig_b64 = sig_b64,
    );

    // Splice the signature in right after the assertion's `<saml:Issuer>` close
    // (or right after the opening tag if no Issuer was emitted — there always is).
    let needle = "</saml:Issuer>";
    let pos = assertion_xml
        .find(needle)
        .expect("assertion must contain Issuer");
    let split = pos + needle.len();
    format!(
        "{}{}{}",
        &assertion_xml[..split],
        signature_xml,
        &assertion_xml[split..]
    )
}

fn c14n_via_quick_xml(xml: &str) -> Vec<u8> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(xml.len());
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
            Ok(Event::CData(_)) | Ok(Event::Comment(_)) | Ok(Event::Decl(_)) => {}
            Ok(_) => {}
            Err(_) => break,
        }
        buf.clear();
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Helper for the "wrong cert / key rotation" pentest: returns a
/// SAMLResponse signed by `signer` but using `claimed.cert_pem()` as
/// the cert string. The verify path should reject because the signature
/// validates against a different SPKI.
pub fn cross_signed_response(
    signer: &FixtureIdp,
    claimed_issuer: &str,
    opts: AssertionOpts<'_>,
) -> String {
    // Build the response using signer's keys but claiming
    // claimed_issuer in the assertion issuer slot.
    let mut o = opts;
    o.issuer = Some(claimed_issuer);
    signer.sign_response(o)
}

/// Quick helper: build a sample-config that points at a freshly
/// constructed FixtureIdp.
pub fn config_for(
    idp: &FixtureIdp,
    sp_entity_id: &str,
    sp_acs_url: &str,
) -> yauth_entity::SamlConnectionConfig {
    yauth_entity::SamlConnectionConfig {
        idp_entity_id: idp.issuer.clone(),
        idp_sso_url: "https://idp.example/sso".into(),
        idp_slo_url: None,
        idp_x509_cert: idp.cert_pem(),
        sp_entity_id: sp_entity_id.into(),
        sp_acs_url: sp_acs_url.into(),
        sp_private_key: None,
        idp_initiated_sso_allowed: false,
        assertion_signed_required: true,
        response_signed_required: false,
        want_encrypted_assertions: false,
        attribute_mappings: yauth_entity::SamlAttributeMappings::default(),
    }
}

#[doc(hidden)]
pub fn _silence_unused() {
    // Reachable from test crates to suppress dead-code lints when
    // certain helpers aren't used by every test file.
    let _ = Uuid::nil();
}
