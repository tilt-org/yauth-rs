//! Short-lived OIDC login state (issue #93, Phase B).
//!
//! A [`SsoLoginState`] row is created at `/sso/login` time and consumed
//! by `/sso/callback`. It binds the opaque random `state` token to:
//!
//! - the originating `connection_id`,
//! - the IdP `issuer` (so cross-IdP token replay is impossible),
//! - the `nonce` we sent on the authorize request,
//! - the PKCE `code_verifier` we'll replay at token-exchange time,
//! - an optional `redirect_to` (in-app path, never an external URL).
//!
//! Rows are **one-shot**: the callback handler MUST delete the row in
//! the same transaction as a successful lookup. Anything older than
//! `STATE_TTL_SECS` (10 minutes) is expired and `find_and_delete`
//! returns `None`.
//!
//! Why a dedicated table instead of re-using `yauth_oauth_states`? The
//! OIDC client flow stores extra material (PKCE verifier, IdP issuer,
//! connection id) that doesn't fit the `oauth` plugin's shape. Adding
//! columns there would muddy the OAuth-2 third-party-login plugin and
//! force an opt-in feature dance. A small dedicated table is cheap and
//! reads cleanly.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Short-lived state row binding an authorize request to its callback.
///
/// The `state` column is the random opaque token sent on the
/// authorize URL and returned by the IdP on the callback. It is the
/// table's primary lookup key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoLoginState {
    /// Random opaque token. 64-hex chars (32 bytes of entropy).
    pub state: String,
    pub connection_id: Uuid,
    /// IdP issuer at authorize-time. Callback compares against the
    /// id_token's `iss` claim — if these differ, reject with 400.
    pub issuer: String,
    pub nonce: String,
    /// PKCE verifier (RFC 7636 §4). Sent on the token-exchange
    /// request to prove possession of the original keypair.
    pub pkce_verifier: String,
    /// Where to redirect the user after a successful login. Bounded
    /// to in-app paths by the callback handler — never an external
    /// URL. `None` => default landing page.
    pub redirect_to: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

/// Insert payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSsoLoginState {
    pub state: String,
    pub connection_id: Uuid,
    pub issuer: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub redirect_to: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

/// State row TTL — 10 minutes, matches OAuth plugin's existing budget.
pub const STATE_TTL_SECS: i64 = 10 * 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_state_round_trips_json() {
        let row = SsoLoginState {
            state: "abc".into(),
            connection_id: Uuid::nil(),
            issuer: "https://idp/".into(),
            nonce: "n".into(),
            pkce_verifier: "v".into(),
            redirect_to: Some("/app".into()),
            created_at: chrono::Utc::now().naive_utc(),
            expires_at: chrono::Utc::now().naive_utc(),
        };
        let s = serde_json::to_string(&row).unwrap();
        let back: SsoLoginState = serde_json::from_str(&s).unwrap();
        assert_eq!(back, row);
    }

    #[test]
    fn ttl_is_ten_minutes() {
        assert_eq!(STATE_TTL_SECS, 600);
    }
}
