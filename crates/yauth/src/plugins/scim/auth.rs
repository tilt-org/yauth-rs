//! SCIM bearer-key validation.
//!
//! IdPs (Okta / Entra / OneLogin) authenticate to a SCIM endpoint via
//! `Authorization: Bearer <key>`. yauth uses an **org-scoped API key**
//! (issue #91) as that bearer — the IdP admin generates a key bound to
//! their organization, then pastes it into the IdP's SCIM connector
//! config.
//!
//! This module is the thin layer that:
//!
//! 1. Parses `Authorization: Bearer <key>` (RFC 6750 §2.1).
//! 2. Resolves the key through the existing
//!    [`crate::plugins::api_key::validate_api_key`] code-path.
//! 3. Asserts the key is **org-scoped** (not user-scoped) and that the
//!    bound `org_id` matches the URL's `{org_id}` path parameter.
//! 4. Surfaces SCIM-shaped error JSON (RFC 7644 §3.12) rather than the
//!    normal yauth `{ "error": "..." }` envelope.
//!
//! Returning a [`ScimPrincipal`] gives handlers a stable struct to
//! work against — they don't have to know about [`crate::middleware::Principal`].

#![forbid(unsafe_code)]

use axum::http::StatusCode;
use uuid::Uuid;

use crate::middleware::Principal;
use crate::state::YAuthState;

use super::error::ScimResponseError;
use super::types::ScimError;

/// What the SCIM handler runs as.
#[derive(Debug, Clone)]
pub struct ScimPrincipal {
    /// The organization the API key is scoped to. Always equal to the
    /// `{org_id}` path parameter on the request (auth would have
    /// rejected the call otherwise).
    pub org_id: Uuid,
    /// `yauth_api_keys.id` of the presented key. Logged on every audit
    /// event; NEVER logged is the key's plaintext or hash.
    pub key_id: Uuid,
    /// User who originally minted the key. Audit trail.
    pub created_by: Uuid,
}

/// Resolve the bearer token on the request to a [`ScimPrincipal`].
///
/// Errors map to RFC 7644 §3.12 shapes — `401` for missing/invalid auth,
/// `403` for cross-org leakage. Never logs the bearer key, even masked.
pub async fn authenticate(
    state: &YAuthState,
    auth_header: Option<&str>,
    expected_org_id: Uuid,
) -> Result<ScimPrincipal, ScimResponseError> {
    let header = auth_header.ok_or_else(|| {
        ScimResponseError::new(
            StatusCode::UNAUTHORIZED,
            ScimError::new(
                401,
                Some("invalidCredentials"),
                "missing Authorization header",
            ),
        )
    })?;
    let token = header.strip_prefix("Bearer ").ok_or_else(|| {
        ScimResponseError::new(
            StatusCode::UNAUTHORIZED,
            ScimError::new(
                401,
                Some("invalidCredentials"),
                "Authorization header must use the Bearer scheme",
            ),
        )
    })?;
    if token.trim().is_empty() {
        return Err(ScimResponseError::new(
            StatusCode::UNAUTHORIZED,
            ScimError::new(401, Some("invalidCredentials"), "empty bearer token"),
        ));
    }

    // Reuse the existing org-scoped api-key validator. Returns a Principal
    // that is either User or ServiceAccount; SCIM requires ServiceAccount.
    let (_auth_user, principal) = crate::plugins::api_key::validate_api_key(token, state)
        .await
        .map_err(|_e| {
            // The error string from validate_api_key carries no
            // secret material, but we intentionally do not
            // re-surface it — IdPs don't act on the difference
            // between "wrong key", "expired key", and "revoked key";
            // they retry on 401. Logging happens via add_event in
            // validate_api_key itself.
            ScimResponseError::new(
                StatusCode::UNAUTHORIZED,
                ScimError::new(401, Some("invalidCredentials"), "invalid bearer token"),
            )
        })?;

    let (org_id, key_id, created_by) = match principal {
        Principal::ServiceAccount {
            org_id,
            key_id,
            created_by,
        } => (org_id, key_id, created_by),
        Principal::User(_) => {
            return Err(ScimResponseError::new(
                StatusCode::FORBIDDEN,
                ScimError::new(
                    403,
                    Some("invalidValue"),
                    "SCIM requires an org-scoped API key, not a user-scoped key",
                ),
            ));
        }
    };

    if org_id != expected_org_id {
        return Err(ScimResponseError::new(
            StatusCode::FORBIDDEN,
            ScimError::new(
                403,
                Some("invalidValue"),
                "API key is bound to a different organization",
            ),
        ));
    }

    Ok(ScimPrincipal {
        org_id,
        key_id,
        created_by,
    })
}

#[cfg(test)]
mod tests {
    // The full flow is exercised by integration tests against a live
    // YAuthState (tests/scim_pentest.rs). These local tests only cover
    // shape — that the header strip is strict, etc.

    #[test]
    fn missing_header_means_no_token_to_strip() {
        let opt: Option<&str> = None;
        assert!(opt.is_none());
    }

    #[test]
    fn bearer_scheme_required() {
        assert!("Basic abc".strip_prefix("Bearer ").is_none());
        assert_eq!("Bearer foo".strip_prefix("Bearer "), Some("foo"));
    }
}
