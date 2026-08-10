//! Player-plane MFA hardening — issue #263, findings B11 and S2a–S2e.
//!
//! Every test drives the real HTTP surface against the in-memory backend, so
//! what is asserted is what a caller can actually observe:
//!
//! * B11 — TOTP secrets are sealed at rest, and a legacy plaintext row is
//!   rejected rather than silently honoured.
//! * S2a — a code that just succeeded cannot be spent again.
//! * S2b — a pending challenge absorbs a bounded number of guesses.
//! * S2c — backup codes are 48-bit and stored salted (Argon2id PHC).
//! * S2d — each rejection publishes exactly one `MfaVerificationFailed` event.
//! * S2e — enabling TOTP cuts every other session.
//!
//! ```text
//! cargo test --features memory-backend,mfa --test mfa_hardening
//! ```

#![cfg(all(
    feature = "memory-backend",
    feature = "email-password",
    feature = "mfa"
))]

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use totp_rs::{Algorithm, Secret, TOTP};
use tower::ServiceExt;
use uuid::Uuid;

use yauth::backends::memory::InMemoryBackend;
use yauth::plugins::mfa::MFA_UNAVAILABLE_ERROR;
use yauth::prelude::*;

const ISSUER: &str = "YAuth Test";
const PASSWORD: &str = "correct-horse-battery-staple";

// ---------------------------------------------------------------------------
// Test cipher — stands in for the host's KMS-backed implementation
// ---------------------------------------------------------------------------

const ENVELOPE_V1: &str = "tsc.v1.";

/// Reversible, versioned, owner-bound — the three properties the plugin relies
/// on. It is emphatically **not** a real cipher (a single XOR byte protects
/// nothing); it exists to exercise the seam's contract, and in particular to
/// prove that anything `seal` did not produce fails to `open`.
struct TestCipher {
    key: u8,
}

impl TestCipher {
    fn arc(key: u8) -> Arc<dyn TotpSecretCipher> {
        Arc::new(Self { key })
    }

    fn mask(&self, bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            *byte ^= self.key;
        }
    }
}

impl TotpSecretCipher for TestCipher {
    fn seal(&self, user_id: Uuid, secret_base32: &str) -> Result<String, TotpCipherError> {
        let mut payload = format!("{user_id}|{secret_base32}").into_bytes();
        self.mask(&mut payload);
        Ok(format!("{ENVELOPE_V1}{}", B64.encode(payload)))
    }

    fn open(&self, user_id: Uuid, stored: &str) -> Result<String, TotpCipherError> {
        let body = stored
            .strip_prefix(ENVELOPE_V1)
            .ok_or_else(|| TotpCipherError::Open("not a sealed envelope".into()))?;
        let mut raw = B64
            .decode(body)
            .map_err(|e| TotpCipherError::Open(e.to_string()))?;
        self.mask(&mut raw);
        let decoded = String::from_utf8(raw).map_err(|e| TotpCipherError::Open(e.to_string()))?;
        let (owner, secret) = decoded
            .split_once('|')
            .ok_or_else(|| TotpCipherError::Open("malformed payload".into()))?;
        if owner != user_id.to_string() {
            return Err(TotpCipherError::Open("owner mismatch".into()));
        }
        Ok(secret.to_string())
    }
}

// ---------------------------------------------------------------------------
// Event recorder — proves the additive failure event actually fires (S2d)
// ---------------------------------------------------------------------------

/// `(user_id, reason)` pairs seen on the bus.
type Failures = Vec<(Option<Uuid>, String)>;

#[derive(Clone, Default)]
struct EventLog(Arc<Mutex<Failures>>);

impl EventLog {
    fn failures(&self) -> Failures {
        self.0.lock().unwrap().clone()
    }
}

struct RecorderPlugin(EventLog);

impl YAuthPlugin for RecorderPlugin {
    fn name(&self) -> &'static str {
        "test-recorder"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn on_event(&self, event: &AuthEvent, _ctx: &PluginContext) -> EventResponse {
        if let AuthEvent::MfaVerificationFailed { user_id, reason } = event {
            self.0.0.lock().unwrap().push((*user_id, reason.clone()));
        }
        EventResponse::Continue
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    app: Router,
    state: YAuthState,
    events: EventLog,
}

async fn harness(cipher: Option<Arc<dyn TotpSecretCipher>>) -> Harness {
    let events = EventLog::default();
    let backend = InMemoryBackend::new();

    let auth = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "http://localhost:3000".to_string(),
            session_cookie_name: "session".to_string(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            ..Default::default()
        },
    )
    .with_email_password(EmailPasswordConfig {
        min_password_length: 8,
        require_email_verification: false,
        hibp_check: false,
        ..Default::default()
    })
    .with_mfa(MfaConfig {
        issuer: ISSUER.to_string(),
        // Two codes, not the production ten: every enrolment in this file pays
        // one Argon2id hash per code, and debug-profile Argon2 is ~10x release.
        backup_code_count: 2,
        secret_cipher: cipher,
    })
    .with_plugin(Box::new(RecorderPlugin(events.clone())))
    .build()
    .await
    .expect("failed to build YAuth");

    let state = auth.state().clone();
    let app = Router::new()
        .nest("/auth", auth.router())
        .with_state(state.clone());

    Harness { app, state, events }
}

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }

    let body_str = body.map(|b| serde_json::to_string(&b).unwrap());
    let req = req
        .body(axum::body::Body::from(body_str.unwrap_or_default()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_string())
        .map(|c| c.split(';').next().unwrap().to_string());

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    (status, parsed, set_cookie)
}

/// Register a user and return their id. The account has no second factor yet.
async fn register(h: &Harness, email: &str) -> Uuid {
    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/register",
        Some(json!({ "email": email, "password": PASSWORD })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {body}");

    let (status, body, cookie) = login(h, email).await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    let cookie = cookie.expect("login must set a session cookie");

    let (status, body, _) = request(&h.app, "GET", "/auth/session", None, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "session failed: {body}");
    body["user"]["id"].as_str().unwrap().parse().unwrap()
}

async fn login(h: &Harness, email: &str) -> (StatusCode, Value, Option<String>) {
    request(
        &h.app,
        "POST",
        "/auth/login",
        Some(json!({ "email": email, "password": PASSWORD })),
        None,
    )
    .await
}

/// Log in expecting the account to be past the password step but gated on MFA.
async fn login_for_challenge(h: &Harness, email: &str) -> String {
    let (status, body, cookie) = login(h, email).await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    assert!(
        cookie.is_none(),
        "an MFA-gated login must NOT hand out a session cookie: {body}"
    );
    assert_eq!(
        body["mfa_required"],
        json!(true),
        "expected MFA gate: {body}"
    );
    body["pending_session_id"].as_str().unwrap().to_string()
}

fn totp_for(secret_base32: &str, email: &str) -> TOTP {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .unwrap(),
        Some(ISSUER.to_string()),
        email.to_string(),
    )
    .unwrap()
}

/// Code for the TOTP step `steps_ahead` after the current one.
///
/// The plugin builds its TOTP with a ±1 step tolerance, so step +1 verifies
/// just like step 0 while being a *different* string — which is what lets a
/// test enrol and then log in without tripping the single-use marker the way a
/// real user separated by a few seconds would not.
fn code_at(totp: &TOTP, steps_ahead: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp.generate(now - (now % 30) + steps_ahead * 30)
}

/// A six-digit code guaranteed not to be accepted right now.
fn wrong_code(totp: &TOTP) -> String {
    let accepted: Vec<String> = (0..3).map(|i| code_at(totp, i.max(1) - 1)).collect();
    (0..1000u32)
        .map(|n| format!("{n:06}"))
        .find(|candidate| !accepted.contains(candidate))
        .expect("some six-digit code is not currently valid")
}

struct Enrolled {
    user_id: Uuid,
    email: String,
    totp: TOTP,
    backup_codes: Vec<String>,
}

/// Full enrolment: register, log in, `POST /mfa/totp/setup`, confirm.
async fn enrol(h: &Harness, email: &str) -> Enrolled {
    let user_id = register(h, email).await;
    let (_, _, cookie) = login(h, email).await;
    let cookie = cookie.expect("pre-MFA login must set a session cookie");

    let (status, body, _) =
        request(&h.app, "POST", "/auth/mfa/totp/setup", None, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "setup failed: {body}");

    let secret = body["secret"].as_str().unwrap().to_string();
    let backup_codes: Vec<String> = body["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    let totp = totp_for(&secret, email);

    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/mfa/totp/confirm",
        Some(json!({ "code": code_at(&totp, 0) })),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm failed: {body}");

    Enrolled {
        user_id,
        email: email.to_string(),
        totp,
        backup_codes,
    }
}

async fn verify(h: &Harness, pending: &str, code: &str) -> (StatusCode, Value, Option<String>) {
    request(
        &h.app,
        "POST",
        "/auth/mfa/verify",
        Some(json!({ "pending_session_id": pending, "code": code })),
        None,
    )
    .await
}

// ---------------------------------------------------------------------------
// B11 — the secret is sealed at rest, on every touch point
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_is_sealed_on_write_and_opened_on_every_read() {
    let h = harness(Some(TestCipher::arc(0x5a))).await;
    let user_id = register(&h, "seal@test.local").await;
    let (_, _, cookie) = login(&h, "seal@test.local").await;
    let cookie = cookie.unwrap();

    // 1. Enrolment writes ciphertext, not the base32 the app displays.
    let (status, body, _) =
        request(&h.app, "POST", "/auth/mfa/totp/setup", None, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "setup failed: {body}");
    let secret = body["secret"].as_str().unwrap().to_string();

    let stored = h
        .state
        .repos
        .totp
        .find_by_user_id(user_id, Some(false))
        .await
        .unwrap()
        .expect("setup must store an unverified secret");
    assert!(
        stored.encrypted_secret.starts_with(ENVELOPE_V1),
        "stored secret must be a versioned envelope, got {}",
        stored.encrypted_secret
    );
    assert_ne!(
        stored.encrypted_secret, secret,
        "the base32 secret must never hit the column"
    );
    assert!(
        !stored.encrypted_secret.contains(&secret),
        "the base32 secret must not appear inside the envelope either"
    );

    // 2. Enrolment-confirm opens it.
    let totp = totp_for(&secret, "seal@test.local");
    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/mfa/totp/confirm",
        Some(json!({ "code": code_at(&totp, 0) })),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm failed: {body}");

    // 3. Login-verify opens it.
    let pending = login_for_challenge(&h, "seal@test.local").await;
    let (status, body, session_cookie) = verify(&h, &pending, &code_at(&totp, 1)).await;
    assert_eq!(status, StatusCode::OK, "verify failed: {body}");

    let cookie = session_cookie.expect("a passed factor must mint a session");
    let (status, _, _) = request(&h.app, "GET", "/auth/session", None, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "the minted session must work");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_plaintext_secret_is_refused_at_login() {
    // The load-bearing half of B11: a row that survived the cutover unpurged is
    // *unusable*, not silently accepted. Without this, "encrypt the column" is
    // decoration — an attacker who wrote a plaintext row (or a DB restored from
    // before the change) would still authenticate.
    let h = harness(Some(TestCipher::arc(0x5a))).await;
    let email = "legacy@test.local";
    let user_id = register(&h, email).await;

    let plaintext = Secret::generate_secret().to_encoded().to_string();
    h.state
        .repos
        .totp
        .create(yauth_entity::NewTotpSecret {
            id: Uuid::now_v7(),
            user_id,
            encrypted_secret: plaintext.clone(),
            verified: true,
            created_at: chrono::Utc::now().naive_utc(),
        })
        .await
        .expect("seed legacy row");

    let totp = totp_for(&plaintext, email);
    let pending = login_for_challenge(&h, email).await;

    // The code is genuinely correct for the stored secret — it is the *storage
    // format* that must sink it.
    let (status, body, cookie) = verify(&h, &pending, &code_at(&totp, 0)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a plaintext row must not authenticate: {body}"
    );
    assert!(cookie.is_none(), "no session may be minted");
    assert!(
        h.events
            .failures()
            .iter()
            .any(|(id, reason)| *id == Some(user_id) && reason == "secret_unsealable"),
        "operators must be told the row was unreadable, not just that a code was wrong: {:?}",
        h.events.failures()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mfa_fails_closed_when_no_cipher_is_configured() {
    let h = harness(None).await;
    let email = "nocipher@test.local";
    register(&h, email).await;
    let (_, _, cookie) = login(&h, email).await;
    let cookie = cookie.unwrap();

    for uri in ["/auth/mfa/totp/setup", "/auth/mfa/backup-codes/regenerate"] {
        let (status, body, _) = request(&h.app, "POST", uri, None, Some(&cookie)).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{uri} must refuse rather than write plaintext: {body}"
        );
        assert_eq!(body["error"], json!(MFA_UNAVAILABLE_ERROR));
    }

    // And nothing was written on the way out.
    let stored = h
        .state
        .repos
        .totp
        .find_by_user_id(
            request(&h.app, "GET", "/auth/session", None, Some(&cookie))
                .await
                .1["user"]["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            None,
        )
        .await
        .unwrap();
    assert!(stored.is_none(), "a refused setup must leave no secret row");
}

// ---------------------------------------------------------------------------
// S2a — replay closure
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_used_totp_code_cannot_be_replayed() {
    let h = harness(Some(TestCipher::arc(0x31))).await;
    let user = enrol(&h, "replay@test.local").await;
    let code = code_at(&user.totp, 1);

    let pending = login_for_challenge(&h, &user.email).await;
    let (status, body, cookie) = verify(&h, &pending, &code).await;
    assert_eq!(status, StatusCode::OK, "first use must pass: {body}");
    assert!(cookie.is_some());

    // Same code, fresh challenge, still inside the ±1-step window.
    let pending = login_for_challenge(&h, &user.email).await;
    let (status, body, cookie) = verify(&h, &pending, &code).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a replayed code must fail exactly like a wrong one: {body}"
    );
    assert!(cookie.is_none(), "a replay must not mint a session");
    assert!(
        h.events
            .failures()
            .iter()
            .any(|(id, reason)| *id == Some(user.user_id) && reason == "totp_code_replayed"),
        "the replay must be reported distinctly in telemetry: {:?}",
        h.events.failures()
    );
}

// ---------------------------------------------------------------------------
// S2b — bounded guesses per challenge
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn challenge_is_destroyed_after_five_wrong_codes() {
    let h = harness(Some(TestCipher::arc(0x77))).await;
    let user = enrol(&h, "bruteforce@test.local").await;

    let pending = login_for_challenge(&h, &user.email).await;
    let bad = wrong_code(&user.totp);

    for attempt in 1..=5 {
        let (status, body, _) = verify(&h, &pending, &bad).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} should be rejected: {body}"
        );
    }

    // The challenge is gone: even the right code cannot revive it, so the
    // 300s TTL is no longer an unlimited guessing window.
    let (status, body, cookie) = verify(&h, &pending, &code_at(&user.totp, 1)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an exhausted challenge must stay dead: {body}"
    );
    assert!(cookie.is_none());

    // Logging in again issues a fresh challenge, which still works — the bound
    // is per challenge, not a lockout.
    let pending = login_for_challenge(&h, &user.email).await;
    let (status, body, cookie) = verify(&h, &pending, &code_at(&user.totp, 1)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a fresh challenge must work: {body}"
    );
    assert!(cookie.is_some());
}

// ---------------------------------------------------------------------------
// S2c — backup-code strength and storage
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_codes_are_48_bit_and_stored_salted() {
    let h = harness(Some(TestCipher::arc(0x0f))).await;
    let user = enrol(&h, "backup@test.local").await;

    for code in &user.backup_codes {
        assert_eq!(code.len(), 14, "expected xxxx-xxxx-xxxx, got {code}");
        let hex: String = code.chars().filter(|c| *c != '-').collect();
        assert_eq!(hex.len(), 12, "12 hex chars = 48 bits, got {code}");
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "not hex: {code}"
        );
    }

    let stored = h
        .state
        .repos
        .backup_codes
        .find_unused_by_user_id(user.user_id)
        .await
        .unwrap();
    assert_eq!(stored.len(), user.backup_codes.len());

    for row in &stored {
        assert!(
            row.code_hash.starts_with("$argon2id$"),
            "backup codes must be memory-hard PHC strings, got {}",
            row.code_hash
        );
    }
    for code in &user.backup_codes {
        assert!(
            !stored
                .iter()
                .any(|row| row.code_hash == yauth::auth::crypto::hash_token(code)),
            "the unsalted SHA-256 scheme must be gone"
        );
    }

    // Salt: the *same literal* code hashes differently every time, including
    // against the row that was actually stored for it.
    let literal = &user.backup_codes[0];
    let again = yauth::auth::password::hash_password_sync(literal).unwrap();
    let and_again = yauth::auth::password::hash_password_sync(literal).unwrap();
    assert_ne!(
        again, and_again,
        "two hashes of one code must differ (salt)"
    );

    let row_for_literal = stored
        .iter()
        .find(|row| yauth::auth::password::verify_password_sync(literal, &row.code_hash).unwrap())
        .expect("the issued code must verify against one stored row");
    assert_ne!(row_for_literal.code_hash, again);
    assert_ne!(row_for_literal.code_hash, and_again);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_code_authenticates_once_and_is_consumed() {
    let h = harness(Some(TestCipher::arc(0x0f))).await;
    let user = enrol(&h, "backup-use@test.local").await;
    let code = user.backup_codes[0].clone();

    let pending = login_for_challenge(&h, &user.email).await;
    let (status, body, cookie) = verify(&h, &pending, &code).await;
    assert_eq!(status, StatusCode::OK, "backup code must work: {body}");
    assert!(cookie.is_some());

    let remaining = h
        .state
        .repos
        .backup_codes
        .find_unused_by_user_id(user.user_id)
        .await
        .unwrap();
    assert_eq!(
        remaining.len(),
        user.backup_codes.len() - 1,
        "the used code must be consumed"
    );

    let pending = login_for_challenge(&h, &user.email).await;
    let (status, body, cookie) = verify(&h, &pending, &code).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a consumed backup code must not work twice: {body}"
    );
    assert!(cookie.is_none());
}

// ---------------------------------------------------------------------------
// S2e — enabling a factor cuts the other sessions
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirming_totp_revokes_every_other_session() {
    let h = harness(Some(TestCipher::arc(0x21))).await;
    let email = "revoke@test.local";
    register(&h, email).await;

    let (_, _, other) = login(&h, email).await;
    let other = other.expect("first session");
    let (_, _, current) = login(&h, email).await;
    let current = current.expect("second session");

    let (status, body, _) =
        request(&h.app, "POST", "/auth/mfa/totp/setup", None, Some(&current)).await;
    assert_eq!(status, StatusCode::OK, "setup failed: {body}");
    let totp = totp_for(body["secret"].as_str().unwrap(), email);

    // Both sessions are alive right up to the confirm.
    let (status, _, _) = request(&h.app, "GET", "/auth/session", None, Some(&other)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/mfa/totp/confirm",
        Some(json!({ "code": code_at(&totp, 0) })),
        Some(&current),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm failed: {body}");

    let (status, _, _) = request(&h.app, "GET", "/auth/session", None, Some(&other)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a session opened before the factor existed must be cut"
    );
    let (status, _, _) = request(&h.app, "GET", "/auth/session", None, Some(&current)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the caller's own session must survive"
    );
}
