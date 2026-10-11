use axum::{
    Extension, Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::{delete, get, post},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use totp_rs::{Algorithm, Secret, TOTP};

use crate::auth::secret_cipher::TotpSecretCipher;
use crate::auth::{crypto, password, session};
use crate::config::MfaConfig;
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Hardening constants (issue #263 / findings B11, S2a-S2e)
// ---------------------------------------------------------------------------

/// Error body returned when MFA cannot operate because no
/// [`TotpSecretCipher`] is configured. Paired with **HTTP 503**
/// (`SERVICE_UNAVAILABLE`) — a deployment problem, not a caller problem.
///
/// Exported so the host can pin the exact contract in its own tests.
pub const MFA_UNAVAILABLE_ERROR: &str = "MFA is temporarily unavailable";

/// Lifetime of a pending MFA challenge, in seconds. Mirrored by the writer in
/// [`MfaPlugin::on_event`]. Attempt updates preserve the stored deadline.
const PENDING_CHALLENGE_TTL_SECS: u64 = 300;

/// Failed `/mfa/verify` attempts tolerated per pending challenge before the
/// challenge is destroyed (finding S2b). Sized to leave room for genuine
/// clock-skew fumbles while closing the "unlimited guesses for the full 300s
/// TTL" window.
const MAX_CHALLENGE_ATTEMPTS: u64 = 5;

/// How long a successfully used TOTP code stays burnt (finding S2a). The TOTP
/// is built with a ±1 step tolerance over 30s steps, so a code stays checkable
/// for ~90s; 120s covers that window with slop.
const TOTP_REPLAY_TTL_SECS: u64 = 120;

/// Challenge-repo key marking one TOTP code as already consumed by one user.
fn totp_replay_key(user_id: Uuid, code: &str) -> String {
    format!("mfa_totp_used:{}:{}", user_id, crypto::hash_token(code))
}

/// Body stored behind a replay marker. Only its *presence* carries meaning.
fn totp_replay_marker() -> serde_json::Value {
    serde_json::json!({ "used": true })
}

/// Has this code already been consumed? Read-only.
///
/// One lookup, one error tag, one 500 mapping, so the enrolment and login
/// handlers cannot drift apart (review finding 20). `verify_mfa` does not read
/// the marker — it takes it with [`claim_totp_code`] before checking the code,
/// which is the same question asked atomically.
async fn totp_code_already_used(state: &YAuthState, replay_key: &str) -> Result<bool, ApiError> {
    state
        .repos
        .challenges
        .get_challenge(replay_key)
        .await
        .map(|marker| marker.is_some())
        .map_err(|e| {
            crate::otel::record_error("mfa_replay_lookup_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })
}

/// Take the single-use marker for this code, or report that someone else holds
/// it. `true` means this request now owns the code for
/// [`TOTP_REPLAY_TTL_SECS`] and must release it if the request does not end in
/// a session.
///
/// Set-if-absent rather than read-then-write (review finding 4): two requests
/// carrying the same valid code used to both observe "unused" and both mint a
/// session, so the S2a single-use property did not survive concurrency.
async fn claim_totp_code(state: &YAuthState, replay_key: &str) -> Result<bool, ApiError> {
    state
        .repos
        .challenges
        .try_claim_challenge(replay_key, totp_replay_marker(), TOTP_REPLAY_TTL_SECS)
        .await
        .map_err(|e| {
            crate::otel::record_error("mfa_replay_claim_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })
}

/// Give back a claim taken for a code that did not authenticate.
///
/// Best-effort by design: the marker expires on its own, and failing to release
/// it costs at most one skipped time-step, so it must never turn a 401 into a
/// 500.
async fn release_totp_code_claim(state: &YAuthState, replay_key: &str) {
    if let Err(e) = state.repos.challenges.delete_challenge(replay_key).await {
        crate::otel::record_error("mfa_replay_marker_release_failed", &e);
    }
}

/// Resolve the configured TOTP-secret cipher, or refuse.
///
/// Fail-closed seam for finding B11: with no cipher there is no safe way to
/// write a new secret or read an existing one, so every path that needs one
/// answers 503 instead of falling back to plaintext.
fn require_cipher(state: &YAuthState) -> Result<&Arc<dyn TotpSecretCipher>, ApiError> {
    state.mfa_config.secret_cipher.as_ref().ok_or_else(|| {
        tracing::error!(
            target: "yauth::mfa",
            "mfa_secret_cipher_unconfigured: MfaConfig.secret_cipher is None — refusing to read or write TOTP secrets"
        );
        api_err(StatusCode::SERVICE_UNAVAILABLE, MFA_UNAVAILABLE_ERROR)
    })
}

fn user_field(user_id: Option<Uuid>) -> String {
    user_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Publish a second-factor rejection: **exactly one** structured log line plus
/// one bus event, for every rejection, whatever its cause (finding S2d).
///
/// Target and message are fixed (`yauth::mfa` / `mfa_verification_failed`) so an
/// operator can alert on the count without parsing free text; `reason`
/// discriminates the cases and `user_id` is present whenever it is known.
///
/// The bus event is additive and advisory (see
/// [`AuthEvent::MfaVerificationFailed`]); yauth deliberately takes no action on
/// it — account lockout is not wired to MFA here, because the caller-side rate
/// limiter plus the per-challenge attempt bound already cover the guessing
/// surface, and locking accounts on second-factor failures hands an attacker a
/// denial-of-service primitive against any account whose email is known.
fn report_mfa_failure(state: &YAuthState, user_id: Option<Uuid>, reason: &str) {
    tracing::warn!(
        target: "yauth::mfa",
        user_id = user_field(user_id),
        reason,
        "mfa_verification_failed"
    );
    emit_mfa_failure(state, user_id, reason);
}

/// Same event at **error** level, carrying the underlying cause.
///
/// Used when the rejection is a server-side problem the caller cannot see or
/// fix — a stored secret the cipher will not open — rather than a wrong code.
/// Still one line, still the same message and fields, so alerting does not have
/// to know the difference; the level and `error` field are what tell an operator
/// this one needs a human.
fn report_mfa_failure_cause(
    state: &YAuthState,
    user_id: Option<Uuid>,
    reason: &str,
    cause: &dyn std::fmt::Display,
) {
    tracing::error!(
        target: "yauth::mfa",
        user_id = user_field(user_id),
        reason,
        error = %cause,
        "mfa_verification_failed"
    );
    emit_mfa_failure(state, user_id, reason);
}

fn emit_mfa_failure(state: &YAuthState, user_id: Option<Uuid>, reason: &str) {
    let _ = state.emit_event(&AuthEvent::MfaVerificationFailed {
        user_id,
        reason: reason.to_string(),
    });
}

// ---------------------------------------------------------------------------
// Plugin struct
// ---------------------------------------------------------------------------

pub struct MfaPlugin;

impl MfaPlugin {
    pub fn new(_config: MfaConfig) -> Self {
        // Config is stored in YAuthState for handler access
        Self
    }
}

impl YAuthPlugin for MfaPlugin {
    fn name(&self) -> &'static str {
        "mfa"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(Router::new().route("/mfa/verify", post(verify_mfa)))
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/mfa/totp/setup", post(setup_totp))
                .route("/mfa/totp/confirm", post(confirm_totp))
                .route("/mfa/totp", delete(disable_totp))
                .route("/mfa/backup-codes", get(get_backup_code_count))
                .route(
                    "/mfa/backup-codes/regenerate",
                    post(regenerate_backup_codes),
                ),
        )
    }

    fn on_event(&self, event: &AuthEvent, ctx: &PluginContext) -> EventResponse {
        match event {
            AuthEvent::LoginSucceeded { user_id, method } => {
                let user_id = *user_id;
                let method = method.clone();
                let repos = ctx.state.repos.clone();

                // Run the async DB lookup synchronously within the current runtime.
                // `on_event` is called from an async context, so Handle::current() is
                // available. We use block_in_place + block_on to avoid nesting runtimes.
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        // Check if user has a verified TOTP secret
                        let has_mfa = match repos.totp.find_by_user_id(user_id, Some(true)).await {
                            Ok(Some(_)) => true,
                            Ok(None) => false,
                            Err(e) => {
                                crate::otel::record_error("mfa_db_status_check_error", &e);
                                return EventResponse::Block {
                                    status: 500,
                                    message: "Internal error".to_string(),
                                };
                            }
                        };

                        if has_mfa {
                            // User has MFA enabled — create a pending session
                            let pending_id = Uuid::now_v7();
                            let key = format!("mfa_pending:{}", pending_id);
                            let value = serde_json::json!({
                                "user_id": user_id.to_string(),
                                "method": method,
                                // Finding S2b: the challenge carries its own
                                // bounded failure counter. Keep the absolute
                                // deadline for older builds during a rolling
                                // deploy; updates now preserve the repository's
                                // original expiry directly.
                                "attempts": 0,
                                "expires_at": chrono::Utc::now().timestamp()
                                    + PENDING_CHALLENGE_TTL_SECS as i64,
                            });

                            if let Err(e) = repos
                                .challenges
                                .set_challenge(&key, value, PENDING_CHALLENGE_TTL_SECS)
                                .await
                            {
                                crate::otel::record_error("mfa_pending_session_store_failed", &e);
                                return EventResponse::Block {
                                    status: 500,
                                    message: "Internal error".to_string(),
                                };
                            }

                            crate::otel::add_event(
                                "mfa_required",
                                #[cfg(feature = "telemetry")]
                                vec![
                                    opentelemetry::KeyValue::new("user.id", user_id.to_string()),
                                    opentelemetry::KeyValue::new(
                                        "pending_session.id",
                                        pending_id.to_string(),
                                    ),
                                ],
                                #[cfg(not(feature = "telemetry"))]
                                vec![],
                            );

                            EventResponse::RequireMfa {
                                user_id,
                                pending_session_id: pending_id,
                            }
                        } else {
                            EventResponse::Continue
                        }
                    })
                })
            }
            _ => EventResponse::Continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConfirmTotpRequest {
    pub code: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyMfaRequest {
    pub pending_session_id: Uuid,
    pub code: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SetupTotpResponse {
    pub otpauth_url: String,
    pub secret: String,
    pub backup_codes: Vec<String>,
    /// Server-rendered QR code as a `data:image/png;base64,...` URL. CLI/mobile
    /// clients render this directly; web clients can fall back to building
    /// their own from `otpauth_url`. Empty string if rendering failed.
    pub qr_code: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MfaMessageResponse {
    pub message: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BackupCodeCountResponse {
    pub remaining: usize,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
}

/// Envelope returned by `POST /mfa/verify` after a TOTP/backup code passes.
/// Matches yauth-go's `MfaVerifyResponse`.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MfaAuthResponse {
    pub user: AuthUser,
}

fn login_success_audit_metadata(login_method: &str) -> serde_json::Value {
    match login_method.strip_prefix("oauth:") {
        Some(provider) => serde_json::json!({
            "method": "oauth",
            "provider": provider,
        }),
        None => serde_json::json!({
            "method": login_method,
        }),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use crate::auth::session::session_set_cookie;

/// Generate `count` one-time backup codes (finding S2c).
///
/// 12 hex chars = **48 bits** of CSPRNG entropy per code, formatted
/// `xxxx-xxxx-xxxx`. The previous 8 hex chars were 32 bits — inside reach of an
/// offline attacker holding the (then unsalted, single-SHA256) hash table, for
/// credentials that never expire and bypass the TOTP factor outright.
fn generate_backup_codes(count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let token = crypto::generate_token();
            format!("{}-{}-{}", &token[..4], &token[4..8], &token[8..12])
        })
        .collect()
}

/// Does `candidate` have the exact literal shape [`generate_backup_codes`]
/// emits — `xxxx-xxxx-xxxx`, twelve hex characters in three dash-separated
/// groups of four?
///
/// Gate for `verify_mfa`'s backup-code branch (review finding 6). Without it a
/// wrong six-digit TOTP code costs one Argon2id verify (~19 MiB, tens of
/// milliseconds) per unused stored code, turning the cheapest possible wrong
/// guess into a memory-hard amplifier and leaking the remaining-code count
/// through response latency.
///
/// Behaviour-preserving: nothing on this path normalises the submitted string
/// — no trimming, no case folding, no dash stripping — so anything this
/// predicate rejects could never have verified against a stored PHC hash of a
/// generated code. Pre-#263 codes were `xxxx-xxxx` and are rejected here, but
/// they were already dead: they are stored as bare SHA-256, which
/// [`verify_backup_code`] refuses for not being a PHC string.
fn is_backup_code_shape(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    bytes.len() == 14
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 9 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// Hash one backup code for storage (finding S2c).
///
/// Argon2id via the same primitives the fork uses for passwords, storing the
/// full PHC string — which embeds a per-code random salt — in the existing
/// `code_hash` column (no schema change beyond widening it). The old scheme was
/// a bare unsalted SHA-256: identical codes across users produced identical
/// rows, and a stolen table could be attacked once for every account at the
/// speed of a hash-per-nanosecond GPU.
///
/// Cost: `Argon2::default()` (~35ms release) on a blocking thread, off the
/// async executor. Enrolment hashes the whole set at once — see
/// [`hash_backup_codes`] — while verification walks them one at a time.
async fn hash_backup_code(code: &str) -> Result<String, password_hash::Error> {
    password::hash_password(code).await
}

/// Generate `count` codes and hash all of them concurrently, returning
/// `(plaintext, PHC hashes)` (review findings 21 and F21).
///
/// **Concurrently**, because serially this is `backup_code_count` × ~35 ms
/// ≈ 0.35 s of dead time on the two enrolment paths, and 20-40× that in a debug
/// build — most of the wall clock of the fork's own MFA suites. Each hash
/// already runs on its own blocking thread; all this does is start them before
/// awaiting any of them. The cost is that the Argon2 memory blocks are now
/// concurrent rather than sequential: `count` × 19 MiB in flight per enrolment
/// instead of 19 MiB. That is bounded by `backup_code_count` and is only
/// reachable by an authenticated caller, but it *is* the amplifier that
/// `POST /mfa/totp/setup` and `/recovery-codes/regenerate` hand to a host that
/// leaves them off its rate-limit table (review finding 6); the host must keep
/// them on it.
///
/// The order of the returned hashes does not track the order of the codes and
/// does not need to: each row stores one independent hash and verification
/// walks the whole unused set.
///
/// Callers must hash **before** deleting the codes on file. The two operations
/// are not one transaction — the repository trait exposes single-row `create`
/// and there is no `create_many` to widen it with — so between the delete and
/// the last insert the player has fewer codes than they hold on paper. A client
/// disconnect drops the handler mid-sequence (hyper half-closes by default), so
/// that window is reachable in practice, not just in theory. Hashing first
/// shrinks it from ~0.35 s of Argon2 to the round-trips alone.
async fn hash_backup_codes(
    count: usize,
) -> Result<(Vec<String>, Vec<String>), (StatusCode, Json<serde_json::Value>)> {
    let codes = generate_backup_codes(count);

    let mut hashing = tokio::task::JoinSet::new();
    for code in &codes {
        let code = code.clone();
        hashing.spawn(async move { hash_backup_code(&code).await });
    }

    let mut hashes = Vec::with_capacity(codes.len());
    while let Some(joined) = hashing.join_next().await {
        let hash = joined
            .expect("backup-code hash task panicked")
            .map_err(|e| {
                crate::otel::record_error("mfa_backup_code_hash_failed", &e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "Internal error" })),
                )
            })?;
        hashes.push(hash);
    }

    Ok((codes, hashes))
}

/// Check a candidate against one stored backup-code hash.
///
/// A stored value that is not a parseable PHC string — i.e. a legacy unsalted
/// SHA-256 row — yields `false` rather than an error: legacy codes are dead by
/// construction, exactly like legacy plaintext TOTP secrets.
async fn verify_backup_code(candidate: &str, stored: &str) -> bool {
    password::verify_password(candidate, stored)
        .await
        .unwrap_or(false)
}

/// Build a `TOTP` instance from the stored base32 secret and config.
fn build_totp(
    secret_base32: &str,
    issuer: &str,
    user_email: &str,
) -> Result<TOTP, (StatusCode, Json<serde_json::Value>)> {
    let secret = Secret::Encoded(secret_base32.to_string());
    let secret_bytes = secret.to_bytes().map_err(|e| {
        crate::otel::record_error("totp_secret_decode_failed", &e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Internal error" })),
        )
    })?;

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        user_email.to_string(),
    )
    .map_err(|e| {
        crate::otel::record_error("totp_build_failed", &e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Internal error" })),
        )
    })
}

/// Insert already-hashed backup codes for a user.
///
/// Sequential on purpose. `BackupCodeRepository` exposes a single-row `create`
/// and nothing else; a batch insert would mean widening a sealed trait across
/// all eleven backend implementations in a vendored fork of an archived
/// upstream, to save `backup_code_count` round-trips on a path a player walks
/// once. The expensive half — the Argon2id hashing — is already done by the
/// time this is called (see [`hash_backup_codes`]), which is what actually
/// shortens the window in which the player holds more codes than the database
/// does.
async fn insert_backup_codes(
    state: &YAuthState,
    user_id: Uuid,
    hashes: Vec<String>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    for code_hash in hashes {
        let now = chrono::Utc::now().naive_utc();
        let new_code = crate::domain::NewBackupCode {
            id: Uuid::now_v7(),
            user_id,
            code_hash,
            used: false,
            created_at: now,
        };
        state
            .repos
            .backup_codes
            .create(new_code)
            .await
            .map_err(|e| {
                crate::otel::record_error("mfa_backup_code_store_failed", &e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "Internal error" })),
                )
            })?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /mfa/totp/setup (protected)
///
/// Generate a TOTP secret, store it unverified, and return the otpauth URI,
/// the base32 secret, and a fresh set of backup codes.
async fn setup_totp(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Fail closed BEFORE touching any row: with no cipher there is no safe way
    // to store a secret, and this handler deletes the user's abandoned
    // unverified secret on its way through (finding B11).
    let cipher = require_cipher(&state)?;

    // Check if user already has a verified TOTP secret
    let existing = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(true))
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if existing.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "TOTP MFA is already enabled. Disable it first to set up a new secret.",
        ));
    }

    // Delete any existing unverified secret for this user (e.g. abandoned setup)
    let _ = state.repos.totp.delete_for_user(user.id, Some(false)).await;

    // Generate TOTP secret
    let secret = Secret::generate_secret();
    let issuer = &state.mfa_config.issuer;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|e| {
            crate::otel::record_error("totp_secret_bytes_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?,
        Some(issuer.to_string()),
        user.email.clone(),
    )
    .map_err(|e| {
        crate::otel::record_error("totp_create_failed", &e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let otpauth_url = totp.get_url();
    let secret_base32 = secret.to_encoded().to_string();

    // Seal before the write — the column stores ciphertext, never the base32
    // secret the authenticator app holds (finding B11).
    let sealed_secret = cipher.seal(user.id, &secret_base32).map_err(|e| {
        tracing::error!(
            target: "yauth::mfa",
            user_id = %user.id,
            error = %e,
            "mfa_totp_secret_seal_failed"
        );
        crate::otel::record_error("totp_secret_seal_failed", &e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Store unverified TOTP secret
    let now = chrono::Utc::now().naive_utc();
    let new_secret = crate::domain::NewTotpSecret {
        id: Uuid::now_v7(),
        user_id: user.id,
        encrypted_secret: sealed_secret,
        verified: false,
        created_at: now,
    };
    state.repos.totp.create(new_secret).await.map_err(|e| {
        crate::otel::record_error("totp_secret_store_failed", &e);
        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Generate and hash the fresh set BEFORE dropping the one on file (review
    // findings 21 and F21): the delete and the inserts are not one transaction,
    // so everything between them is time the player has no usable codes, and a
    // handler that is dropped in that gap — a client disconnect is enough —
    // leaves them with none at all. Hashing first takes the Argon2id half of
    // that window out of it. Hashing here rather than at the top of the handler
    // also means a request that 409s on an already-enabled account, or fails to
    // seal, never pays for it.
    let (backup_codes, code_hashes) = hash_backup_codes(state.mfa_config.backup_code_count).await?;

    // Delete any existing backup codes and store the fresh ones
    let _ = state.repos.backup_codes.delete_all_for_user(user.id).await;

    insert_backup_codes(&state, user.id, code_hashes).await?;

    crate::otel::add_event(
        "mfa_totp_setup",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    let qr_code = render_qr_data_url(&otpauth_url);

    Ok(Json(SetupTotpResponse {
        otpauth_url,
        secret: secret_base32,
        backup_codes,
        qr_code,
    }))
}

/// Encode an otpauth URL into a `data:image/png;base64,…` string. Returns an
/// empty string if rendering fails — callers fall back to `otpauth_url`.
fn render_qr_data_url(otpauth_url: &str) -> String {
    use base64::Engine;
    match qrcode_generator::to_png_to_vec(otpauth_url, qrcode_generator::QrCodeEcc::Medium, 256) {
        Ok(png) => format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(png)
        ),
        Err(e) => {
            log::warn!("qr_code render failed: {e}");
            String::new()
        }
    }
}

/// POST /mfa/totp/confirm (protected)
///
/// Verify the initial TOTP code provided by the user after scanning the QR code.
/// If valid, mark the TOTP secret as verified (MFA is now active).
async fn confirm_totp(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    jar: CookieJar,
    Json(input): Json<ConfirmTotpRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    let cipher = require_cipher(&state)?;

    // Find the unverified TOTP secret for this user
    let totp_record = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(false))
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "No pending TOTP setup found. Call POST /mfa/totp/setup first.",
            )
        })?;

    // Open the sealed secret. A value this cipher did not produce — wrong key,
    // tampered row, or a legacy plaintext base32 secret — is NEVER treated as a
    // raw secret: it fails exactly like a wrong code, loudly in the log and
    // opaquely on the wire (finding B11).
    let secret_base32 = cipher
        .open(user.id, &totp_record.encrypted_secret)
        .map_err(|e| {
            report_mfa_failure_cause(&state, Some(user.id), "secret_unsealable", &e);
            err(
                StatusCode::BAD_REQUEST,
                "Invalid TOTP code. Please try again.",
            )
        })?;

    // Build TOTP from stored secret and verify the code
    let totp = build_totp(&secret_base32, &state.mfa_config.issuer, &user.email)?;
    let code_matches = totp.check_current(&input.code).unwrap_or(false);

    // Replay closure, enrolment side (finding S2a): a code already consumed by a
    // login `verify` is refused here too, so one observed over the user's
    // shoulder cannot be spent at enrolment inside its window. Confirm only
    // *reads* the marker — it never writes one. Enrolment is a one-time,
    // already-authenticated ceremony with no replay value of its own, and
    // burning the confirm code would lock the just-enrolled user out of their
    // own first login for the rest of the window. Only `verify_mfa` burns.
    //
    // The read comes after `check_current` (review finding 51): a code that does
    // not match is rejected either way, so a wrong guess should not pay a
    // round-trip to the challenge store. `verify_mfa` deliberately keeps the
    // opposite order — it must *claim* the marker before checking.
    let replay_key = totp_replay_key(user.id, &input.code);
    let already_used = code_matches && totp_code_already_used(&state, &replay_key).await?;

    let is_valid = code_matches && !already_used;

    if !is_valid {
        crate::otel::add_event(
            "mfa_totp_confirm_failed",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        report_mfa_failure(
            &state,
            Some(user.id),
            if already_used {
                "totp_code_replayed"
            } else {
                "totp_code_invalid"
            },
        );
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Invalid TOTP code. Please try again.",
        ));
    }

    // NB: confirm deliberately does NOT burn the code (see the replay-key
    // comment above) — only `verify_mfa` does. Burning here would 401 the
    // user's own first login if it landed in the same window as enrolment.

    // Mark the secret as verified
    state
        .repos
        .totp
        .mark_verified(totp_record.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("totp_verify_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Enabling a second factor re-establishes the account's security level, so
    // every session that predates it — including one an attacker may already
    // hold — is cut, keeping only the caller's own (finding S2e). Shares
    // `delete_sessions_except` with the two password handlers in
    // `email_password.rs`, which run the same sweep for the same reason.
    session::delete_sessions_except(
        &state,
        user.id,
        jar.get(&state.config.session_cookie_name)
            .map(|cookie| cookie.value()),
    )
    .await;

    // The sweep above kills yauth's own sessions and nothing else. A host that
    // keeps its own view of "where this account is signed in" — a device list,
    // a push-notification registry — has no way to learn that those sessions
    // are gone unless it is told, and would go on presenting a cut device as
    // currently signed in (review finding 35). Emitted here, after the sweep and
    // before the audit-log write, exactly where `change_password` and
    // `reset_password` emit `PasswordChanged` for the identical reason.
    state.emit_event(&AuthEvent::MfaEnabled {
        user_id: user.id,
        method: "totp".to_string(),
    });

    crate::otel::add_event(
        "mfa_totp_enabled",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user.id),
            "mfa_enabled",
            Some(serde_json::json!({ "method": "totp" })),
            None,
        )
        .await;

    Ok(Json(MfaMessageResponse {
        message: "TOTP MFA enabled successfully".to_string(),
    }))
}

/// DELETE /mfa/totp (protected)
///
/// Disable TOTP MFA — deletes the TOTP secret and all backup codes.
async fn disable_totp(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Check if user has any TOTP secret (verified or not) before trying to delete
    let has_verified = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(true))
        .await
        .map_err(|e| {
            crate::otel::record_error("totp_secret_check_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let has_unverified = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(false))
        .await
        .map_err(|e| {
            crate::otel::record_error("totp_secret_check_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if has_verified.is_none() && has_unverified.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "TOTP MFA is not enabled"));
    }

    // Delete TOTP secret (verified or not)
    state
        .repos
        .totp
        .delete_for_user(user.id, None)
        .await
        .map_err(|e| {
            crate::otel::record_error("totp_secret_delete_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Delete all backup codes
    state
        .repos
        .backup_codes
        .delete_all_for_user(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("mfa_backup_codes_delete_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    crate::otel::add_event(
        "mfa_totp_disabled",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user.id),
            "mfa_disabled",
            Some(serde_json::json!({ "method": "totp" })),
            None,
        )
        .await;

    Ok(Json(MfaMessageResponse {
        message: "TOTP MFA disabled successfully".to_string(),
    }))
}

/// Charge one failed guess to a pending challenge (finding S2b).
///
/// Before this, a wrong code cost the attacker nothing: the 401 came back and
/// the challenge row sat there for its full 300s TTL, good for as many guesses
/// as the network allowed. Now each failure increments a counter carried in the
/// challenge without changing its stored expiry; at [`MAX_CHALLENGE_ATTEMPTS`]
/// the challenge is deleted outright and every later attempt against that `pending_session_id`
/// fails as expired — the user has to log in again.
///
/// The increment is deliberately **not** atomic: `ChallengeRepository` gained a
/// set-if-absent primitive for the replay marker
/// ([`ChallengeRepository::try_claim_challenge`]), but no read-modify-write one,
/// so two failures racing in the same instant can still collapse into one
/// increment. The bound therefore holds to within a factor of the request
/// concurrency — O(limit), not exactly the limit — which is all this needs to
/// do. Closing "unlimited guesses for 300s" is the point; the caller-side rate
/// limiter caps concurrency, and an exact counter would need a JSONB increment
/// (or a CAS) across twelve backend impls to bound something that is already
/// bounded. The property that *must* survive concurrency is the single-use
/// marker, and that one is atomic.
///
/// Updating the value is conditional on the challenge still being live. Unlike
/// an upsert, this cannot recreate a challenge that another request consumed or
/// exhausted while this request was validating its factor.
async fn record_failed_attempt(
    state: &YAuthState,
    key: &str,
    pending: &serde_json::Value,
    attempts: u64,
) {
    let next = attempts.saturating_add(1);

    if next >= MAX_CHALLENGE_ATTEMPTS {
        if let Err(e) = state.repos.challenges.delete_challenge(key).await {
            crate::otel::record_error("mfa_challenge_delete_failed", &e);
        }
        // Distinct message on purpose: the rejection itself already logged one
        // `mfa_verification_failed`, and this line says something different —
        // the challenge was destroyed, so the caller must log in again.
        tracing::warn!(
            target: "yauth::mfa",
            user_id = user_field(
                pending
                    .get("user_id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|id| id.parse().ok())
            ),
            attempts = next,
            "mfa_challenge_exhausted"
        );
        return;
    }

    let mut value = pending.clone();
    match value.as_object_mut() {
        Some(object) => {
            object.insert("attempts".to_string(), serde_json::json!(next));
        }
        None => return,
    }

    if let Err(e) = state
        .repos
        .challenges
        .update_challenge_if_live(key, value)
        .await
    {
        // Could not persist the counter — destroy the challenge instead of
        // leaving an unbounded one behind.
        crate::otel::record_error("mfa_challenge_attempt_store_failed", &e);
        let _ = state.repos.challenges.delete_challenge(key).await;
    }
}

/// POST /mfa/verify (public)
///
/// Verify a TOTP or backup code during the login MFA challenge.
/// On success, creates a real session and returns a session cookie.
async fn verify_mfa(
    State(state): State<YAuthState>,
    Json(input): Json<VerifyMfaRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Look up the pending MFA session from the challenge repo
    let key = format!("mfa_pending:{}", input.pending_session_id);
    let pending = state
        .repos
        .challenges
        .get_challenge(&key)
        .await
        .map_err(|e| {
            crate::otel::record_error("mfa_challenge_repo_error", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            // Expired, never issued, or destroyed by the attempt bound below —
            // all three are indistinguishable to the caller by design.
            report_mfa_failure(&state, None, "challenge_missing_or_expired");
            err(
                StatusCode::UNAUTHORIZED,
                "Invalid or expired MFA session. Please log in again.",
            )
        })?;

    // Bounded guess counter carried inside the challenge (finding S2b).
    // Challenges written by an older build have no counter; they start at 0.
    let attempts = pending
        .get("attempts")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    let user_id_str = pending["user_id"].as_str().ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid pending session data",
        )
    })?;
    let user_id: Uuid = user_id_str.parse().map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid pending session data",
        )
    })?;
    // Pending challenges created before this field was introduced remain
    // usable during a rolling deploy; their audit attribution is explicitly
    // unknown rather than losing the completed-login event altogether.
    let login_method = pending["method"].as_str().unwrap_or("unknown").to_string();

    // Load the user's verified TOTP secret
    let totp_record = state
        .repos
        .totp
        .find_by_user_id(user_id, Some(true))
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Load the user for the email (needed to build the TOTP)
    struct UserData {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
        role: String,
        banned: bool,
    }

    let user = {
        let u = state
            .repos
            .users
            .find_by_id(user_id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;
        UserData {
            id: u.id,
            email: u.email,
            display_name: u.display_name,
            email_verified: u.email_verified,
            role: u.role,
            banned: u.banned,
        }
    };

    let mut verified = false;
    let replay_key = totp_replay_key(user_id, &input.code);
    // Set once this request has taken the single-use marker for `input.code`,
    // and is therefore the party responsible for giving it back if the request
    // does not end in a session (review findings 4 and F4).
    let mut holds_replay_claim = false;
    // Set once a factor has published its own `mfa_verification_failed`, so the
    // terminal rejection does not publish a second, vaguer one for the same
    // request (finding S2d: exactly one line and one event per rejection).
    let mut failure_reported = false;

    // 1. Try TOTP verification first.
    //
    // Both halves of this `if let` are *conditions*, not preconditions. A
    // deployment with no cipher configured, or a stored secret this cipher
    // cannot open, skips the TOTP factor and falls through to the backup-code
    // branch below — which is precisely the credential that exists for that
    // recovery (review findings 3 and 25). Refusing the whole request instead
    // would lock every enrolled account out by every factor, with no
    // self-service way back in. The fail-closed 503 stays where it belongs: on
    // the write paths (setup, confirm, regenerate), which cannot proceed
    // without a cipher at all.
    if let (Some(totp_secret), Some(cipher)) = (
        totp_record.as_ref(),
        state.mfa_config.secret_cipher.as_ref(),
    ) {
        match cipher.open(user_id, &totp_secret.encrypted_secret) {
            Ok(secret_base32) => {
                // Replay closure (finding S2a): a TOTP code is single-use for
                // the whole ~90s window it stays checkable in, so
                // shoulder-surfing or replaying a captured request can no longer
                // buy a second session. The marker is CLAIMED here, before the
                // code is checked, so two requests carrying the same valid code
                // cannot both observe "unused" and both mint a session (review
                // finding 4). Losing the claim is indistinguishable from a
                // genuine replay, which is the correct answer for both.
                if claim_totp_code(&state, &replay_key).await? {
                    holds_replay_claim = true;

                    // A stored secret that opens but will not parse is a server
                    // fault, not a wrong code — hand the marker back rather than
                    // burning the caller's code on a 500 (review finding F4).
                    let totp =
                        match build_totp(&secret_base32, &state.mfa_config.issuer, &user.email) {
                            Ok(totp) => totp,
                            Err(e) => {
                                release_totp_code_claim(&state, &replay_key).await;
                                return Err(e);
                            }
                        };

                    if totp.check_current(&input.code).unwrap_or(false) {
                        verified = true;
                    }
                } else {
                    crate::otel::add_event(
                        "mfa_totp_code_replayed",
                        #[cfg(feature = "telemetry")]
                        vec![opentelemetry::KeyValue::new("user.id", user_id.to_string())],
                        #[cfg(not(feature = "telemetry"))]
                        vec![],
                    );
                    report_mfa_failure(&state, Some(user_id), "totp_code_replayed");
                    // Deliberately NOT charged against the per-challenge guess
                    // budget (review finding 42): holding the marker is proof
                    // the code was *correct*, and a second tab, a second device
                    // or a re-submitted form inside the same 30s step is a user,
                    // not an attacker. Spending guesses on a proven-correct code
                    // destroys the challenge and sends them back to the password
                    // step. The 401 body stays byte-identical to a wrong code so
                    // no oracle appears.
                    return Err(err(StatusCode::UNAUTHORIZED, "Invalid MFA code"));
                }
            }
            Err(e) => {
                // Wrong key, tampered row, or a legacy plaintext base32 secret.
                // Never fall through to treating the stored string as a raw
                // secret — that is what makes an un-purged plaintext row
                // unusable — but do not end the request either: backup codes are
                // independent Argon2id credentials and legacy SHA-256 code rows
                // are dead by construction, so letting this reach them cannot
                // resurrect the plaintext bypass (review finding 3). The cause
                // stays visible to operators only. No attempt is charged here;
                // the terminal failure below charges exactly once (review
                // finding 42's rider).
                //
                // Reported at once rather than deferred to the rejection, so
                // that an operator sees the unreadable row even on the run where
                // the player recovers with a backup code — that request
                // succeeds and would otherwise say nothing. It is also the
                // rejection's reason when no backup code follows, which is why
                // the terminal block must not add a second, vaguer event.
                report_mfa_failure_cause(&state, Some(user_id), "secret_unsealable", &e);
                failure_reported = true;
            }
        }
    }

    // 2. If TOTP didn't match, try backup codes.
    //
    // Codes are salted Argon2id (finding S2c), so the old "hash the input, look
    // it up" shortcut is gone: each stored PHC string carries its own salt and
    // has to be verified separately. Bounded by `backup_code_count` (10) and
    // reached only on the rare fallback path — and only for a candidate that
    // actually looks like a backup code, so a wrong six-digit TOTP guess costs
    // one cheap comparison instead of ten Argon2id verifies (review finding 6).
    if !verified && is_backup_code_shape(&input.code) {
        let backup_codes = state
            .repos
            .backup_codes
            .find_unused_by_user_id(user_id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        for bc in backup_codes {
            if verify_backup_code(&input.code, &bc.code_hash).await {
                // Mark backup code as used
                state
                    .repos
                    .backup_codes
                    .mark_used(bc.id)
                    .await
                    .map_err(|e| {
                        crate::otel::record_error("mfa_backup_code_mark_used_failed", &e);
                        err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })?;

                verified = true;
                crate::otel::add_event(
                    "mfa_backup_code_used",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("user.id", user_id.to_string())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                break;
            }
        }
    }

    if !verified {
        // Nothing authenticated, so give the marker back: a wrong guess must not
        // burn a code the genuine authenticator may still emit for the rest of
        // this step, and the claim was taken speculatively (review finding 4).
        if holds_replay_claim {
            release_totp_code_claim(&state, &replay_key).await;
        }
        crate::otel::add_event(
            "mfa_verify_failed",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.id", user_id.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        if !failure_reported {
            report_mfa_failure(&state, Some(user_id), "code_invalid");
        }
        // The single charge against the per-challenge budget. Every other exit
        // from this handler is either a success, a server fault, or a
        // proven-correct code being replayed — none of which is a guess.
        record_failed_attempt(&state, &key, &pending, attempts).await;
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid MFA code"));
    }

    // The TOTP code is already burnt for the rest of its validity window: the
    // claim taken above IS the burn (finding S2a). A backup code needs no
    // marker — `mark_used` on its own row is its single-use record — so the
    // path that never reached the TOTP arm writes nothing here.

    // MFA passed — delete the pending session and create a real session
    let _ = state.repos.challenges.delete_challenge(&key).await;

    let (token, _session_id) = match session::create_session(
        &state,
        user_id,
        None,
        None,
        state.config.session_ttl,
    )
    .await
    {
        Ok(session) => session,
        Err(e) => {
            // The factor passed but no session exists, so the caller will
            // retry with the same code. Release the marker, or a transient
            // fault here refuses their still-valid code for the rest of the
            // step (review finding F4).
            if holds_replay_claim {
                release_totp_code_claim(&state, &replay_key).await;
            }
            crate::otel::record_error("session_create_failed", &e);
            return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"));
        }
    };

    crate::otel::add_event(
        "mfa_verified",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.id", user_id.to_string())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user_id),
            "mfa_verified",
            Some(serde_json::json!({ "method": "totp" })),
            None,
        )
        .await;

    // LoginSucceeded is emitted before session creation so plugins can block
    // or require MFA. For the pending branch, record the durable success only
    // now that the factor passed and a real session exists.
    let login_metadata = login_success_audit_metadata(&login_method);
    state
        .write_audit_log(Some(user_id), "login_succeeded", Some(login_metadata), None)
        .await;

    Ok((
        [(
            SET_COOKIE,
            session_set_cookie(&state, &token, state.config.session_ttl),
        )],
        Json(MfaAuthResponse {
            user: AuthUser {
                id: user.id,
                email: user.email.clone(),
                display_name: user.display_name.clone(),
                email_verified: user.email_verified,
                role: user.role.clone(),
                banned: user.banned,
                auth_method: crate::middleware::AuthMethod::Session,
                scopes: None,
                active_org_id: None,
                org_role: None,
                all_orgs: Vec::new(),
            },
        }),
    ))
}

/// GET /mfa/backup-codes (protected)
///
/// Returns the count of remaining (unused) backup codes.
async fn get_backup_code_count(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<BackupCodeCountResponse>, (StatusCode, Json<serde_json::Value>)> {
    let codes = state
        .repos
        .backup_codes
        .find_unused_by_user_id(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Internal error" })),
            )
        })?;

    Ok(Json(BackupCodeCountResponse {
        remaining: codes.len(),
    }))
}

/// POST /mfa/backup-codes/regenerate (protected)
///
/// Delete all existing backup codes and generate a fresh set.
/// Requires TOTP MFA to be enabled (verified).
async fn regenerate_backup_codes(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<BackupCodesResponse>, (StatusCode, Json<serde_json::Value>)> {
    let err = |status: StatusCode, msg: &str| (status, Json(serde_json::json!({ "error": msg })));

    // Fail closed with no cipher (finding B11): handing out a fresh set of
    // factor-bypassing codes while the server cannot read the TOTP secret those
    // codes back up would leave the account defended by the backup codes alone.
    require_cipher(&state)?;

    // Ensure MFA is enabled
    let has_mfa = state
        .repos
        .totp
        .find_by_user_id(user.id, Some(true))
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if has_mfa.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "TOTP MFA must be enabled before regenerating backup codes",
        ));
    }

    // Hash the replacement set before dropping the one on file — same reason as
    // enrolment (review findings 21 and F21): the delete and the inserts are not
    // one transaction, and a handler dropped in between leaves the player with
    // no codes at all.
    let (codes, code_hashes) = hash_backup_codes(state.mfa_config.backup_code_count).await?;

    // Delete old backup codes
    state
        .repos
        .backup_codes
        .delete_all_for_user(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("mfa_backup_codes_delete_failed", &e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Store the fresh backup codes
    insert_backup_codes(&state, user.id, code_hashes).await?;

    crate::otel::add_event(
        "mfa_backup_codes_regenerated",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user.id.to_string()),
            opentelemetry::KeyValue::new("count", codes.len() as i64),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    Ok(Json(BackupCodesResponse {
        backup_codes: codes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_oauth_mfa_audit_retains_provider_attribution() {
        assert_eq!(
            login_success_audit_metadata("oauth:okta"),
            serde_json::json!({
                "method": "oauth",
                "provider": "okta",
            })
        );
        assert_eq!(
            login_success_audit_metadata("email-password"),
            serde_json::json!({
                "method": "email-password",
            })
        );
    }

    #[test]
    fn backup_codes_carry_48_bits_in_three_groups() {
        for code in generate_backup_codes(8) {
            assert_eq!(code.len(), 14, "expected xxxx-xxxx-xxxx, got {code}");
            let groups: Vec<&str> = code.split('-').collect();
            assert_eq!(groups.len(), 3);
            for group in groups {
                assert_eq!(group.len(), 4);
                assert!(group.chars().all(|c| c.is_ascii_hexdigit()), "{code}");
            }
        }
    }

    #[test]
    fn the_shape_gate_accepts_every_generated_code_and_nothing_else() {
        for code in generate_backup_codes(32) {
            assert!(
                is_backup_code_shape(&code),
                "the gate must never refuse a code we issued: {code}"
            );
        }

        // The case the gate exists for: a six-digit TOTP guess must not reach
        // the Argon2id sweep.
        assert!(!is_backup_code_shape("123456"));
        assert!(!is_backup_code_shape("000000"));

        // Near misses.
        assert!(!is_backup_code_shape(""));
        assert!(!is_backup_code_shape("abcd-ef01-234"), "too short");
        assert!(!is_backup_code_shape("abcd-ef01-23456"), "too long");
        assert!(!is_backup_code_shape("abcdef01-2345"), "missing a dash");
        assert!(
            !is_backup_code_shape("abcd-ef012345-"),
            "dash in the wrong place"
        );
        assert!(!is_backup_code_shape("abc-def01-2345"), "dashes shifted");
        assert!(
            !is_backup_code_shape("abcd ef01 2345"),
            "spaces, not dashes"
        );
        assert!(!is_backup_code_shape("abcd-ef01-234g"), "g is not hex");
        assert!(!is_backup_code_shape("abcd-ef01-2345 "), "trailing space");
        assert!(!is_backup_code_shape(" abcd-ef01-2345"), "leading space");

        // The pre-#263 format is refused. Those rows are stored as bare
        // SHA-256 and could not verify anyway, so nothing usable is lost.
        assert!(!is_backup_code_shape("abcd-ef01"));
    }

    #[test]
    fn backup_codes_are_unique_per_draw() {
        let codes = generate_backup_codes(16);
        let mut deduped = codes.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), codes.len(), "codes must not repeat");
    }

    #[test]
    fn replay_key_is_per_user_and_per_code_and_hides_the_code() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert_ne!(totp_replay_key(a, "123456"), totp_replay_key(b, "123456"));
        assert_ne!(totp_replay_key(a, "123456"), totp_replay_key(a, "654321"));
        assert_eq!(totp_replay_key(a, "123456"), totp_replay_key(a, "123456"));
        assert!(
            !totp_replay_key(a, "123456").ends_with("123456"),
            "the key must not embed the code in the clear"
        );
    }

    #[test]
    fn backup_code_hash_is_salted_and_verifiable() {
        // Same literal, two hashes: different strings (per-hash salt), both
        // valid. The old scheme was a bare SHA-256 — deterministic, so a stolen
        // table was a rainbow-table lookup away from every account's codes.
        let code = "abcd-ef01-2345";
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (first, second) = rt.block_on(async {
            (
                hash_backup_code(code).await.unwrap(),
                hash_backup_code(code).await.unwrap(),
            )
        });

        assert_ne!(first, second);
        assert!(first.starts_with("$argon2id$"));
        assert!(rt.block_on(verify_backup_code(code, &first)));
        assert!(rt.block_on(verify_backup_code(code, &second)));
        assert!(!rt.block_on(verify_backup_code("abcd-ef01-2346", &first)));

        // A legacy unsalted SHA-256 row is dead, not accidentally accepted.
        assert!(!rt.block_on(verify_backup_code(code, &crypto::hash_token(code))));
    }
}
