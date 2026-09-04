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
//!   (A *successful* verify is silent, with one deliberate exception: an
//!   unreadable stored secret reports `secret_unsealable` where it happens, so
//!   the operator still sees the broken row on the run where a backup code
//!   recovers the account.)
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

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use yauth::plugins::mfa::MFA_UNAVAILABLE_ERROR;
use yauth::prelude::*;

mod memory_http;
use memory_http::request;

/// The shared harness carries whatever this suite records off the bus.
type Harness = memory_http::Harness<EventLog>;

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

/// `(user_id, method)` pairs from every `MfaEnabled` seen on the bus.
type Enablements = Vec<(Uuid, String)>;

#[derive(Clone, Default)]
struct EventLog {
    failures: Arc<Mutex<Failures>>,
    enablements: Arc<Mutex<Enablements>>,
}

impl EventLog {
    fn failures(&self) -> Failures {
        self.failures.lock().unwrap().clone()
    }

    fn enablements(&self) -> Enablements {
        self.enablements.lock().unwrap().clone()
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
        match event {
            AuthEvent::MfaVerificationFailed { user_id, reason } => {
                self.0
                    .failures
                    .lock()
                    .unwrap()
                    .push((*user_id, reason.clone()));
            }
            AuthEvent::MfaEnabled { user_id, method } => {
                self.0
                    .enablements
                    .lock()
                    .unwrap()
                    .push((*user_id, method.clone()));
            }
            _ => {}
        }
        EventResponse::Continue
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The shared memory-backend app, plus the MFA plugin this suite exists to
/// exercise. `cipher` is the one knob: `None` is the fail-closed posture.
async fn harness(cipher: Option<Arc<dyn TotpSecretCipher>>) -> Harness {
    let events = EventLog::default();
    memory_http::harness(
        events.clone(),
        Box::new(RecorderPlugin(events)),
        |builder| {
            builder.with_mfa(MfaConfig {
                issuer: ISSUER.to_string(),
                // Two codes, not the production ten: every enrolment in this
                // file pays one Argon2id hash per code, and debug-profile
                // Argon2 is ~10x release.
                backup_code_count: 2,
                secret_cipher: cipher,
            })
        },
    )
    .await
}

/// Register a user and return their id. The account has no second factor yet.
async fn register(h: &Harness, email: &str) -> Uuid {
    memory_http::register(h, email, PASSWORD).await.0
}

async fn login(h: &Harness, email: &str) -> (StatusCode, Value, Option<String>) {
    memory_http::login(h, email, PASSWORD).await
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
    code_for_step(totp, current_step() + steps_ahead)
}

/// The 30-second TOTP step the clock is in right now.
fn current_step() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30
}

/// The code for an *absolute* step.
///
/// [`code_at`] is relative to "now", so two of its calls straddling a step
/// boundary silently mean different codes — enough to make a test that spends
/// one code and then wants a different one flaky. A test that has to keep
/// talking about the same two codes captures [`current_step`] once and asks
/// for them by number.
fn code_for_step(totp: &TOTP, step: u64) -> String {
    totp.generate(step * 30)
}

/// A six-digit code guaranteed not to be accepted right now.
fn wrong_code(totp: &TOTP) -> String {
    // The plugin checks with a ±1 step tolerance, so all three of the
    // surrounding steps have to be excluded — including the previous one.
    let step = current_step();
    let accepted: Vec<String> = (step - 1..=step + 1)
        .map(|candidate| code_for_step(totp, candidate))
        .collect();
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

/// Regeneration replaces the set wholesale. Both enrolment paths now hash the
/// whole set concurrently and only then delete-and-insert (review findings 21
/// and F21), so this pins what that reordering must not disturb: every issued
/// code is on file exactly once, none of the superseded ones survives, and the
/// count is the configured one rather than whatever the concurrent hashing
/// happened to finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regenerating_replaces_the_whole_backup_code_set() {
    let h = harness(Some(TestCipher::arc(0x0f))).await;
    let user = enrol(&h, "regen@test.local").await;

    // Regeneration is a protected route, so authenticate through the factor.
    let pending = login_for_challenge(&h, &user.email).await;
    let (status, body, cookie) = verify(&h, &pending, &code_at(&user.totp, 0)).await;
    assert_eq!(status, StatusCode::OK, "verify failed: {body}");
    let cookie = cookie.expect("a completed verify mints a session");

    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/mfa/backup-codes/regenerate",
        None,
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "regenerate failed: {body}");

    let fresh: Vec<String> = body["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        fresh.len(),
        user.backup_codes.len(),
        "the configured number of codes, every time"
    );

    let stored = h
        .state
        .repos
        .backup_codes
        .find_unused_by_user_id(user.user_id)
        .await
        .unwrap();
    assert_eq!(
        stored.len(),
        fresh.len(),
        "one row per issued code — no drops, no duplicates: {stored:?}"
    );

    for code in &fresh {
        let matches = stored
            .iter()
            .filter(|row| {
                yauth::auth::password::verify_password_sync(code, &row.code_hash).unwrap_or(false)
            })
            .count();
        assert_eq!(matches, 1, "every issued code must be on file once: {code}");
    }
    for old in &user.backup_codes {
        assert!(
            !stored.iter().any(|row| {
                yauth::auth::password::verify_password_sync(old, &row.code_hash).unwrap_or(false)
            }),
            "a superseded code must not survive: {old}"
        );
    }
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

/// The sweep above is invisible outside yauth unless it is announced. A host
/// that keeps its own record of where an account is signed in — a device list,
/// a push registry — learns about the cut sessions from `MfaEnabled` or not at
/// all, and would keep showing a killed device as currently signed in (review
/// finding 35).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirming_totp_publishes_mfa_enabled() {
    let h = harness(Some(TestCipher::arc(0x21))).await;
    let email = "mfa-enabled-event@test.local";
    let user_id = register(&h, email).await;

    let (_, _, cookie) = login(&h, email).await;
    let cookie = cookie.expect("pre-MFA login must set a session cookie");

    let (status, body, _) =
        request(&h.app, "POST", "/auth/mfa/totp/setup", None, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "setup failed: {body}");
    assert!(
        h.events.enablements().is_empty(),
        "an unconfirmed setup has not enabled anything: {:?}",
        h.events.enablements()
    );
    let totp = totp_for(body["secret"].as_str().unwrap(), email);

    // A refused confirm announces nothing either.
    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/mfa/totp/confirm",
        Some(json!({ "code": "000000" })),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        h.events.enablements().is_empty(),
        "a refused confirm must not look like an enrolment: {:?}",
        h.events.enablements()
    );

    let (status, body, _) = request(
        &h.app,
        "POST",
        "/auth/mfa/totp/confirm",
        Some(json!({ "code": code_at(&totp, 0) })),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm failed: {body}");

    assert_eq!(
        h.events.enablements(),
        vec![(user_id, "totp".to_string())],
        "exactly one MfaEnabled, carrying the enrolling account and its method"
    );
}

// ---------------------------------------------------------------------------
// Recovery — an unreadable TOTP secret must not close the backup-code door
// ---------------------------------------------------------------------------

/// Seed a verified TOTP row and one usable backup code without going through
/// the enrolment routes, which need a cipher this account may not have.
async fn seed_factor_out_of_band(h: &Harness, user_id: Uuid, stored_secret: &str) -> String {
    h.state
        .repos
        .totp
        .delete_for_user(user_id, None)
        .await
        .expect("clear any existing secret");
    h.state
        .repos
        .totp
        .create(yauth_entity::NewTotpSecret {
            id: Uuid::now_v7(),
            user_id,
            encrypted_secret: stored_secret.to_string(),
            verified: true,
            created_at: chrono::Utc::now().naive_utc(),
        })
        .await
        .expect("seed totp row");

    let backup_code = "dead-beef-cafe".to_string();
    h.state
        .repos
        .backup_codes
        .create(yauth_entity::NewBackupCode {
            id: Uuid::now_v7(),
            user_id,
            code_hash: yauth::auth::password::hash_password_sync(&backup_code).unwrap(),
            used: false,
            created_at: chrono::Utc::now().naive_utc(),
        })
        .await
        .expect("seed backup code");

    backup_code
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_code_still_works_when_the_secret_is_sealed_under_a_foreign_key() {
    // Key rotation, key loss, a restore from another environment: the TOTP row
    // is intact but this deployment's cipher cannot open it. Backup codes are
    // the credential that exists for exactly that, and refusing the request at
    // the `open()` failure made them unreachable — locking every enrolled
    // player out of every factor with no self-service way back (finding 3).
    let h = harness(Some(TestCipher::arc(0x5a))).await;
    let email = "foreign-key@test.local";
    let user_id = register(&h, email).await;

    let secret = Secret::generate_secret().to_encoded().to_string();
    let foreign = TestCipher::arc(0xa5);
    let sealed_elsewhere = foreign.seal(user_id, &secret).unwrap();
    let backup_code = seed_factor_out_of_band(&h, user_id, &sealed_elsewhere).await;

    // The TOTP factor is genuinely unusable — the code is right for the secret,
    // but this deployment cannot read the secret.
    let totp = totp_for(&secret, email);
    let pending = login_for_challenge(&h, email).await;
    let (status, body, cookie) = verify(&h, &pending, &code_at(&totp, 0)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unopenable secret must not authenticate: {body}"
    );
    assert!(cookie.is_none());
    assert_eq!(
        h.events.failures(),
        vec![(Some(user_id), "secret_unsealable".to_string())],
        "the rejection must publish exactly one event, naming the real cause \
         rather than a second, vaguer 'code_invalid' after it (S2d)"
    );

    // The recovery credential works.
    let pending = login_for_challenge(&h, email).await;
    let (status, body, cookie) = verify(&h, &pending, &backup_code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a backup code must survive an unreadable secret: {body}"
    );
    let cookie = cookie.expect("recovery must mint a session");
    let (status, _, _) = request(&h.app, "GET", "/auth/session", None, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "the minted session must work");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_cipher_totp_is_refused_but_backup_codes_still_authenticate() {
    // `secret_cipher: None` is a deployment with the sealing key unset or
    // unparseable. The TOTP factor cannot be evaluated, but the login must not
    // die at that arm: `/login` and `/me` still advertise MFA, and setup,
    // confirm and regenerate all 503, so a hard refusal here leaves the account
    // with no way in and no way to self-remediate (findings 25 and 41).
    let h = harness(None).await;
    let email = "nocipher-verify@test.local";
    let user_id = register(&h, email).await;

    // Seeded as a plaintext base32 row, the shape a pre-sealing deployment left
    // behind; with no cipher the plugin never looks at it.
    let secret = Secret::generate_secret().to_encoded().to_string();
    let backup_code = seed_factor_out_of_band(&h, user_id, &secret).await;
    let totp = totp_for(&secret, email);

    let pending = login_for_challenge(&h, email).await;
    let (status, body, cookie) = verify(&h, &pending, &code_at(&totp, 0)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a correct TOTP code must NOT pass while the secret cannot be sealed: {body}"
    );
    assert!(
        cookie.is_none(),
        "no session may be minted without a readable second factor"
    );
    assert_ne!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the login path must not fail closed past the recovery branch"
    );

    let pending = login_for_challenge(&h, email).await;
    let (status, body, cookie) = verify(&h, &pending, &backup_code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the recovery credential must remain usable with no cipher: {body}"
    );
    assert!(cookie.is_some(), "recovery must mint a session");

    // The write paths stay fail-closed — no cipher, no new secret and no new
    // set of factor-bypassing codes.
    let cookie = cookie.unwrap();
    for uri in ["/auth/mfa/totp/setup", "/auth/mfa/backup-codes/regenerate"] {
        let (status, body, _) = request(&h.app, "POST", uri, None, Some(&cookie)).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{uri} must still refuse: {body}"
        );
        assert_eq!(body["error"], json!(MFA_UNAVAILABLE_ERROR));
    }
}

// ---------------------------------------------------------------------------
// S2a under concurrency, and what a replay costs the user
// ---------------------------------------------------------------------------

/// Number of requests that race on one code in
/// [`simultaneous_verifies_of_one_code_mint_exactly_one_session`].
///
/// One per CPU on the reference box: the racers busy-wait on the rendezvous
/// below, so oversubscribing only deschedules them apart again.
const RACERS: usize = 4;

/// A [`TestCipher`] that, once armed, releases every caller of `open` together.
///
/// The window between "is this code burnt?" and "burn it" is a few microseconds
/// wide, so spawning tasks and hoping they collide is not a test — it passes
/// against the broken implementation most of the time. `open` is the last thing
/// `verify_mfa` does before it touches the marker, so parking every racer there
/// until all of them have arrived puts them all in that window at once.
///
/// This narrows the odds rather than removing them: the assertion is exact, but
/// its power as a *detector* of a read-then-write marker is empirical. Reverting
/// `claim_totp_code` to get-then-set fails this test 16 runs out of 16 on the
/// reference box with the release offset below; at 5 ms it was 14 out of 16, and
/// slower or busier hardware can widen the gap again. Treat a lucky green as
/// noise, not as evidence — the deterministic gate for the backend the platform
/// actually runs is `backends::seaorm_pg::challenge_repo`'s SQL pin and its two
/// live-Postgres cases, which catch the same regression without a race.
struct RendezvousCipher {
    inner: TestCipher,
    parties: usize,
    arrived: AtomicUsize,
    /// Wall-clock nanosecond at which every parked caller leaves, published by
    /// whichever one arrives last. Zero until then.
    release_at: AtomicU64,
    armed: AtomicBool,
}

fn wall_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

impl RendezvousCipher {
    fn arc(key: u8, parties: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: TestCipher { key },
            parties,
            arrived: AtomicUsize::new(0),
            release_at: AtomicU64::new(0),
            armed: AtomicBool::new(false),
        })
    }

    /// Arm the rendezvous. Every `open` from here on parks until `parties` of
    /// them have arrived, so exactly that many requests must be in flight.
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl TotpSecretCipher for RendezvousCipher {
    fn seal(&self, user_id: Uuid, secret_base32: &str) -> Result<String, TotpCipherError> {
        self.inner.seal(user_id, secret_base32)
    }

    fn open(&self, user_id: Uuid, stored: &str) -> Result<String, TotpCipherError> {
        let opened = self.inner.open(user_id, stored);
        if self.armed.load(Ordering::SeqCst) {
            // A busy-wait on a shared *wall-clock* release instant, not a
            // `Barrier`: a condvar hands the sleepers back to the OS scheduler,
            // which wakes them hundreds of microseconds apart — far wider than
            // the window under test, so the race never happens and the test
            // passes against a broken implementation. The last arriver publishes
            // an instant a few milliseconds out and everyone spins until the
            // clock passes it, so all callers leave together. Bounded, so a
            // wrong `parties` fails an assertion instead of hanging the suite.
            // The offset has to cover thread-scheduling jitter on a loaded box,
            // not just the publish: a straggler that reaches the loop after the
            // instant has passed leaves alone and cannot collide with anyone.
            if self.arrived.fetch_add(1, Ordering::SeqCst) + 1 == self.parties {
                self.release_at
                    .store(wall_nanos() + 20_000_000, Ordering::SeqCst);
            }
            let give_up = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let release_at = self.release_at.load(Ordering::SeqCst);
                if (release_at != 0 && wall_nanos() >= release_at)
                    || std::time::Instant::now() >= give_up
                {
                    break;
                }
                std::hint::spin_loop();
            }
        }
        opened
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_verifies_of_one_code_mint_exactly_one_session() {
    // Read-then-write on the replay marker let every concurrent request observe
    // "unused", so all of them minted a session and a duplicated request was
    // silent instead of producing a visible 401 (finding 4).
    let cipher = RendezvousCipher::arc(0x13, RACERS);
    let h = harness(Some(cipher.clone() as Arc<dyn TotpSecretCipher>)).await;
    let user = enrol(&h, "concurrent@test.local").await;
    let code = code_at(&user.totp, 1);

    let mut pendings = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        pendings.push(login_for_challenge(&h, &user.email).await);
    }

    // One OS thread per racer, so the rendezvous cannot deadlock behind a task
    // scheduler that decided to run them one after another.
    cipher.arm();
    let racers: Vec<_> = pendings
        .into_iter()
        .map(|pending| {
            let app = h.app.clone();
            let code = code.clone();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        request(
                            &app,
                            "POST",
                            "/auth/mfa/verify",
                            Some(json!({ "pending_session_id": pending, "code": code })),
                            None,
                        )
                        .await
                    })
            })
        })
        .collect();

    let mut sessions = 0;
    let mut statuses = Vec::with_capacity(RACERS);
    for racer in racers {
        let (status, _, cookie) = racer.join().unwrap();
        statuses.push(status);
        if cookie.is_some() {
            sessions += 1;
        }
    }

    assert_eq!(
        sessions, 1,
        "exactly one of {RACERS} simultaneous verifies of one code may mint a \
         session, got {sessions}: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::UNAUTHORIZED)
            .count(),
        RACERS - 1,
        "every loser must be refused exactly like a replay: {statuses:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replaying_a_genuine_code_does_not_spend_the_guess_budget() {
    // A second device, a second tab, or the frontend re-submitting the field it
    // never cleared: the marker proves the code was *correct*, so charging it
    // against the five-guess budget destroys the challenge and forces the
    // password step again for something that is not a guess (finding 42).
    let h = harness(Some(TestCipher::arc(0x44))).await;
    let user = enrol(&h, "replay-budget@test.local").await;
    // Both codes are pinned to one captured step: the test runs for several
    // seconds, and `code_at(_, 0)` re-read at the end would BE `burnt` if the
    // clock crossed a 30 s boundary in between. `step` stays acceptable
    // throughout by the ±1 tolerance, and is never the code that was spent.
    let step = current_step();
    let burnt = code_for_step(&user.totp, step + 1);
    let fresh = code_for_step(&user.totp, step);

    let pending = login_for_challenge(&h, &user.email).await;
    let (status, body, cookie) = verify(&h, &pending, &burnt).await;
    assert_eq!(status, StatusCode::OK, "first use must pass: {body}");
    assert!(cookie.is_some());

    // A fresh challenge, then more replays than the challenge has guesses.
    let pending = login_for_challenge(&h, &user.email).await;
    for attempt in 1..=(5 + 3) {
        let (status, body, cookie) = verify(&h, &pending, &burnt).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "replay {attempt} must be refused: {body}"
        );
        assert!(cookie.is_none());
    }

    // The challenge survived: a proven-correct code is not a guess.
    let (status, body, cookie) = verify(&h, &pending, &fresh).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the challenge must still be alive for a fresh code: {body}"
    );
    assert!(cookie.is_some());

    // And the rejections still read as replays, not as wrong codes.
    assert!(
        h.events
            .failures()
            .iter()
            .filter(|(id, reason)| *id == Some(user.user_id) && reason == "totp_code_replayed")
            .count()
            >= 8,
        "every replay must be reported as one: {:?}",
        h.events.failures()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_code_does_not_burn_the_step_for_the_right_one() {
    // The marker is claimed before the code is checked, so a claim taken for a
    // guess that then fails has to be released — otherwise a wrong guess would
    // block the genuine code of a later attempt within the same window
    // (finding 4).
    let h = harness(Some(TestCipher::arc(0x66))).await;
    let user = enrol(&h, "release@test.local").await;
    let bad = wrong_code(&user.totp);

    let pending = login_for_challenge(&h, &user.email).await;
    let (status, _, _) = verify(&h, &pending, &bad).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Same wrong string again: it must read as a wrong code, never as a replay
    // of a code this account already spent.
    let (status, _, _) = verify(&h, &pending, &bad).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        h.events
            .failures()
            .iter()
            .all(|(_, reason)| reason != "totp_code_replayed"),
        "a wrong guess must never leave a replay marker behind: {:?}",
        h.events.failures()
    );

    let (status, body, cookie) = verify(&h, &pending, &code_at(&user.totp, 1)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the right code must still work: {body}"
    );
    assert!(cookie.is_some());
}
