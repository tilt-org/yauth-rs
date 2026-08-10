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
//! * No cipher configured → the MFA plugin refuses to read or write secrets and
//!   returns HTTP 503 ([`crate::plugins::mfa::MFA_UNAVAILABLE_ERROR`]). It never
//!   degrades to plaintext.
//! * `open` returns `Err` (wrong key, tampered row, legacy plaintext) → treated
//!   as a failed authentication attempt (the same response as a wrong code),
//!   plus one `tracing::error!` carrying the `user_id` so operators can see the
//!   difference the caller cannot.

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal cipher exercising the documented contract: a version tag, the
    /// owner bound into the payload, and a hard rejection of anything that does
    /// not carry the tag. Not a real cipher — it does not encrypt — it exists
    /// to pin the *shape* the plugin depends on.
    struct TaggingCipher;

    const TAG: &str = "test.v1.";

    impl TotpSecretCipher for TaggingCipher {
        fn seal(&self, user_id: Uuid, secret_base32: &str) -> Result<String, TotpCipherError> {
            Ok(format!("{TAG}{user_id}.{secret_base32}"))
        }

        fn open(&self, user_id: Uuid, stored: &str) -> Result<String, TotpCipherError> {
            let body = stored
                .strip_prefix(TAG)
                .ok_or_else(|| TotpCipherError::Open("unrecognised envelope".into()))?;
            let (owner, secret) = body
                .split_once('.')
                .ok_or_else(|| TotpCipherError::Open("malformed envelope".into()))?;
            if owner != user_id.to_string() {
                return Err(TotpCipherError::Open("owner mismatch".into()));
            }
            Ok(secret.to_string())
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let uid = Uuid::now_v7();
        let sealed = TaggingCipher.seal(uid, "JBSWY3DPEHPK3PXP").unwrap();
        assert!(sealed.starts_with(TAG), "sealed value must be versioned");
        assert_eq!(
            TaggingCipher.open(uid, &sealed).unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn open_rejects_legacy_plaintext_base32() {
        // The load-bearing property: a row written before the seam existed must
        // NOT open, so it cannot be used as a live second factor.
        let uid = Uuid::now_v7();
        assert!(TaggingCipher.open(uid, "JBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn open_rejects_another_users_row() {
        let owner = Uuid::now_v7();
        let attacker = Uuid::now_v7();
        let sealed = TaggingCipher.seal(owner, "JBSWY3DPEHPK3PXP").unwrap();
        assert!(TaggingCipher.open(attacker, &sealed).is_err());
    }
}
