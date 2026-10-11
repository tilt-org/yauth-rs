//! Pluggable envelope encryption for stored TOTP secrets (finding B11).
//!
//! yauth stores one shared TOTP secret per enrolled user. The column has always
//! been called `encrypted_secret`, but the framework wrote the **raw base32
//! secret** into it: anyone with read access to the auth database — a backup, a
//! read replica, a `SELECT` through a compromised support tool — could mint
//! valid second factors for every MFA user without touching a single password.
//!
//! The fork deliberately ships **no** cipher implementation. Key custody
//! belongs to the host application (KMS, sealed keyring, HSM), not to an auth
//! library. What it ships is this seam: the host implements
//! [`TotpSecretCipher`], hands an `Arc` of it to
//! [`crate::config::MfaConfig::secret_cipher`], and the MFA plugin seals on
//! every write and opens on every read.
//!
//! # Contract
//!
//! * [`TotpSecretCipher::seal`] returns a **versioned, self-describing** string.
//!   Implementations must prefix the ciphertext with a scheme/version tag (e.g.
//!   `"tsc.v1.<base64url>"`) so a future key rotation or algorithm change can be
//!   told apart from the current one by inspection, without a schema migration.
//! * [`TotpSecretCipher::open`] **must error on any value that `seal` did not
//!   produce** — including a bare legacy base32 secret. This property is
//!   load-bearing, not cosmetic: it is what makes an un-purged plaintext row
//!   *unusable* rather than silently accepted. An `open` that fell back to
//!   "looks like base32, must be a raw secret" would re-open exactly the hole
//!   this seam closes, and would do it silently.
//! * `user_id` is passed to both halves so implementations can bind the
//!   ciphertext to its owner (AAD / associated data). A row copied from one
//!   user to another then fails to open instead of enrolling the attacker's
//!   authenticator against the victim's account.
//! * Both halves are synchronous and are called on the request path. Keep them
//!   cheap — a local symmetric operation with a cached data key, not a network
//!   round-trip per call.
//!
//! # Failure handling in the plugin
//!
//! * No cipher configured → every path that would **write or read a secret**
//!   refuses: enrolment, confirmation and backup-code regeneration answer HTTP
//!   503 ([`crate::plugins::mfa::MFA_UNAVAILABLE_ERROR`]). It never degrades to
//!   plaintext.
//! * `open` returns `Err` (wrong key, tampered row, legacy plaintext) →
//!   enrolment-confirm treats it as a failed attempt, the same response as a
//!   wrong code.
//! * On **login verify**, both of the above skip the TOTP factor rather than
//!   ending the request, so the caller drops through to the backup-code branch:
//!   a lost or rotated key must not take the recovery credential down with the
//!   one it is there to recover. Either way one `tracing::error!` carries the
//!   `user_id`, so operators can see the difference the caller cannot.

use uuid::Uuid;

/// Error raised by a [`TotpSecretCipher`].
///
/// Messages are logged, never returned to the caller — a caller that could
/// tell "wrong key" from "wrong code" would learn whether a given account has
/// a corrupt or legacy secret row.
#[derive(Debug, thiserror::Error)]
pub enum TotpCipherError {
    /// The secret could not be sealed for storage (key unavailable, encrypt
    /// failed). The enrolment is aborted; nothing is written.
    #[error("failed to seal TOTP secret: {0}")]
    Seal(String),

    /// The stored value could not be opened: wrong or rotated key, tampered
    /// ciphertext, a value bound to a different user, or a legacy plaintext
    /// base32 row written before this seam existed.
    #[error("failed to open TOTP secret: {0}")]
    Open(String),
}

/// Seals and opens the TOTP shared secret at rest.
///
/// Implemented by the host application; see the module docs for the contract
/// that makes this seam actually protect anything.
///
/// # Examples
///
/// A minimal implementation, showing the three properties the plugin leans on.
/// It is **not** a cipher — it does not encrypt anything — but it is shaped like
/// one, and the assertions below are the contract a real implementation has to
/// satisfy:
///
/// ```
/// use uuid::Uuid;
/// use yauth::auth::secret_cipher::{TotpCipherError, TotpSecretCipher};
///
/// struct TaggingCipher;
///
/// const TAG: &str = "example.v1.";
///
/// impl TotpSecretCipher for TaggingCipher {
///     fn seal(&self, user_id: Uuid, secret_base32: &str) -> Result<String, TotpCipherError> {
///         // Versioned, and the owner is bound into the payload.
///         Ok(format!("{TAG}{user_id}.{secret_base32}"))
///     }
///
///     fn open(&self, user_id: Uuid, stored: &str) -> Result<String, TotpCipherError> {
///         // Anything this implementation did not produce is refused outright —
///         // never guessed at, never passed through.
///         let body = stored
///             .strip_prefix(TAG)
///             .ok_or_else(|| TotpCipherError::Open("unrecognised envelope".into()))?;
///         let (owner, secret) = body
///             .split_once('.')
///             .ok_or_else(|| TotpCipherError::Open("malformed envelope".into()))?;
///         if owner != user_id.to_string() {
///             return Err(TotpCipherError::Open("owner mismatch".into()));
///         }
///         Ok(secret.to_string())
///     }
/// }
///
/// let owner = Uuid::now_v7();
/// let sealed = TaggingCipher.seal(owner, "JBSWY3DPEHPK3PXP").unwrap();
///
/// // 1. The stored value is versioned, and it round-trips for its owner.
/// assert!(sealed.starts_with(TAG));
/// assert_eq!(TaggingCipher.open(owner, &sealed).unwrap(), "JBSWY3DPEHPK3PXP");
///
/// // 2. A legacy plaintext row does NOT open. This is the load-bearing one: it
/// //    is what makes an un-purged pre-sealing secret unusable rather than
/// //    silently honoured as a live second factor.
/// assert!(TaggingCipher.open(owner, "JBSWY3DPEHPK3PXP").is_err());
///
/// // 3. A row copied onto another account does not open either, so a stolen
/// //    ciphertext cannot enrol the attacker's authenticator against a victim.
/// let attacker = Uuid::now_v7();
/// assert!(TaggingCipher.open(attacker, &sealed).is_err());
/// ```
///
/// The host implementation the platform ships is `casino-crypto`'s
/// `TotpSecretSealer`: XChaCha20-Poly1305 under a single 32-byte data key, a
/// fixed `tsc.v1.` envelope tag, and the `user_id` bound in as associated data.
pub trait TotpSecretCipher: Send + Sync {
    /// Encrypt `secret_base32` for storage, returning a versioned,
    /// self-describing string.
    fn seal(&self, user_id: Uuid, secret_base32: &str) -> Result<String, TotpCipherError>;

    /// Decrypt a value previously produced by [`seal`](Self::seal) for the same
    /// `user_id`, returning the base32 secret.
    ///
    /// MUST return `Err` for any input `seal` did not produce, including a bare
    /// base32 secret.
    fn open(&self, user_id: Uuid, stored: &str) -> Result<String, TotpCipherError>;
}
