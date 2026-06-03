//! OIDC RP-Initiated Logout 1.0 — the `end_session` endpoint.
//!
//! Logs out the End-User's current browser session and, when a validated
//! `post_logout_redirect_uri` is supplied, redirects back to the RP.
//!
//! Security: a `post_logout_redirect_uri` is honored ONLY when it exactly
//! matches one registered for the client identified by `id_token_hint` (its
//! `aud`) or the `client_id` parameter. An unrecognized URI is never redirected
//! to — this is the open-redirect guard. If `id_token_hint` is present but its
//! signature does not validate, no redirect is performed (RP-Initiated Logout
//! 1.0 §2). The endpoint is public: it must work whether or not a session is
//! still active, and accepts both GET (query string) and POST (form body).
//!
//! This is RP-Initiated Logout only — it does NOT fan out Back-Channel Logout
//! (a sub-only logout_token would kill the user's other devices). BCL is
//! reserved for offboarding (suspend / ban / SCIM-deprovision).

use axum::{
    extract::{Form, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::state::YAuthState;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct EndSessionParams {
    #[serde(default)]
    pub id_token_hint: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

/// `GET /oauth/end_session` — params come from the query string.
pub(crate) async fn end_session_get(
    State(state): State<YAuthState>,
    jar: CookieJar,
    Query(params): Query<EndSessionParams>,
) -> Response {
    handle_end_session(state, jar, params).await
}

/// `POST /oauth/end_session` — params come from the form body.
pub(crate) async fn end_session_post(
    State(state): State<YAuthState>,
    jar: CookieJar,
    Form(params): Form<EndSessionParams>,
) -> Response {
    handle_end_session(state, jar, params).await
}

async fn handle_end_session(
    state: YAuthState,
    jar: CookieJar,
    params: EndSessionParams,
) -> Response {
    // Identify the client (for redirect validation) and whether a present hint
    // was cryptographically valid. `hint_valid` starts true: a hint that is
    // *absent* is fine; only a *present-but-unverifiable* hint blocks redirects.
    let mut client_id: Option<String> = None;
    let mut hint_valid = true;
    if let Some(ref hint) = params.id_token_hint {
        match verify_id_token_hint(&state, hint) {
            Ok(claims) => {
                if let Some(aud) = claims.get("aud").and_then(|v| v.as_str()) {
                    client_id = Some(aud.to_string());
                }
            }
            // A bad hint MUST NOT be trusted to authorize a redirect.
            Err(_) => hint_valid = false,
        }
    }
    if client_id.is_none()
        && let Some(ref cid) = params.client_id
        && !cid.is_empty()
    {
        client_id = Some(cid.clone());
    }

    // Terminate the current browser session (instant local logout), regardless
    // of whether we ultimately redirect.
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let _ = crate::auth::session::delete_session(&state, cookie.value()).await;
    }
    let clear_cookie = clear_session_cookie(&state);

    // No redirect requested → render a minimal logged-out page.
    let Some(redirect_uri) = params
        .post_logout_redirect_uri
        .as_deref()
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::OK,
            [
                (header::SET_COOKIE, clear_cookie),
                (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            LOGGED_OUT_HTML,
        )
            .into_response();
    };

    // A redirect was requested but the hint (if any) was invalid, or we cannot
    // identify the client → refuse to redirect (open-redirect guard).
    let Some(client_id) = client_id.filter(|_| hint_valid) else {
        return with_clear_cookie(
            clear_cookie,
            oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "post_logout_redirect_uri requires a valid id_token_hint or client_id",
            ),
        );
    };

    // Look up the client and exact-match the redirect URI against its
    // registered post_logout_redirect_uris.
    let client = match state
        .repos
        .oauth2_clients
        .find_by_client_id(&client_id)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return with_clear_cookie(
                clear_cookie,
                oauth2_error(StatusCode::BAD_REQUEST, "invalid_request", "unknown client"),
            );
        }
        Err(e) => {
            crate::otel::record_error("end_session_client_lookup_failed", &e);
            return with_clear_cookie(
                clear_cookie,
                oauth2_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "lookup client",
                ),
            );
        }
    };

    let registered: Vec<String> = client
        .post_logout_redirect_uris
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    if !registered.iter().any(|u| u == redirect_uri) {
        return with_clear_cookie(
            clear_cookie,
            oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "post_logout_redirect_uri not registered for client",
            ),
        );
    }

    // Validated: redirect back to the RP, echoing `state` if present.
    let dest = match params.state {
        Some(ref st) if !st.is_empty() => match url::Url::parse(redirect_uri) {
            Ok(mut u) => {
                u.query_pairs_mut().append_pair("state", st);
                u.to_string()
            }
            Err(_) => redirect_uri.to_string(),
        },
        _ => redirect_uri.to_string(),
    };

    (
        StatusCode::FOUND,
        [(header::SET_COOKIE, clear_cookie), (header::LOCATION, dest)],
    )
        .into_response()
}

const LOGGED_OUT_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Logged out</title></head><body><p>You have been logged out.</p></body></html>";

/// Build a session-cookie deletion header mirroring the host cookie config.
fn clear_session_cookie(state: &YAuthState) -> String {
    let mut c = format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        state.config.session_cookie_name
    );
    if state.config.secure_cookies {
        c.push_str("; Secure");
    }
    c
}

/// Attach the session-clearing Set-Cookie to an existing error response, so the
/// browser is logged out even when we refuse to redirect.
fn with_clear_cookie(clear_cookie: String, resp: Response) -> Response {
    let mut resp = resp;
    if let Ok(value) = header::HeaderValue::from_str(&clear_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, value);
    }
    resp
}

fn oauth2_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

/// Verify an `id_token_hint`'s signature against the OP's own signing key while
/// tolerating expiry — RP-Initiated Logout 1.0 §2 explicitly permits an expired
/// hint. Returns the claims on a valid signature.
///
/// Unlike normal id_token validation this disables `validate_exp` and clears
/// `required_spec_claims` (the default `{"exp"}` would otherwise reject a token
/// we deliberately accept past expiry), and disables `validate_aud` (we read
/// `aud` ourselves to identify the client rather than match a fixed audience).
fn verify_id_token_hint(
    state: &YAuthState,
    raw: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    let header = decode_header(raw).map_err(|e| format!("bad JWT header: {e}"))?;

    // Determine the expected algorithm + decoding key from the OP's signer,
    // mirroring sign_jwt's asym-or-HS256 fallback.
    #[cfg(feature = "asymmetric-jwt")]
    let (expected_alg, decoding_key): (Algorithm, DecodingKey) =
        if let Some(ref keys) = state.signing_keys {
            (alg_to_jwt(keys.alg), keys.decoding_key.clone())
        } else {
            (
                Algorithm::HS256,
                DecodingKey::from_secret(state.bearer_config.jwt_secret.as_bytes()),
            )
        };
    #[cfg(not(feature = "asymmetric-jwt"))]
    let (expected_alg, decoding_key): (Algorithm, DecodingKey) = (
        Algorithm::HS256,
        DecodingKey::from_secret(state.bearer_config.jwt_secret.as_bytes()),
    );

    // alg-confusion guard: the hint must be signed with the OP's own alg.
    if header.alg != expected_alg {
        return Err(format!(
            "unexpected alg {:?}; OP signs with {:?}",
            header.alg, expected_alg
        ));
    }

    let mut validation = Validation::new(expected_alg);
    validation.validate_exp = false;
    validation.required_spec_claims = std::collections::HashSet::new();
    validation.validate_aud = false;

    let data =
        decode::<serde_json::Map<String, serde_json::Value>>(raw, &decoding_key, &validation)
            .map_err(|e| format!("id_token_hint verification failed: {e}"))?;
    Ok(data.claims)
}

#[cfg(feature = "asymmetric-jwt")]
fn alg_to_jwt(alg: crate::config::SigningAlgorithm) -> jsonwebtoken::Algorithm {
    match alg {
        crate::config::SigningAlgorithm::Hs256 => jsonwebtoken::Algorithm::HS256,
        crate::config::SigningAlgorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
        crate::config::SigningAlgorithm::Es256 => jsonwebtoken::Algorithm::ES256,
    }
}
