//! OIDC Back-Channel Logout 1.0 — OP-side emitter.
//!
//! When a user is offboarded (banned, suspended, or SCIM-deprovisioned) this
//! plugin notifies every RP the user authorized that registered a
//! `backchannel_logout_uri`, by POSTing a signed `logout_token`. That closes
//! the "RP validates its access token locally" gap in instant termination: the
//! RP can terminate its own session for the user on receipt.
//!
//! We deliberately do NOT fan out on a routine `Logout`: our logout_token is
//! sub-only (no `sid`), which instructs the RP to kill ALL of the user's
//! sessions. That is correct for offboarding but wrong for a single-device
//! logout (it would force-log-out the user's other devices). RP-Initiated
//! Logout (`end_session`) and Back-Channel Logout are kept decoupled until
//! per-session `sid` tracking exists.
//!
//! Delivery is asynchronous + best-effort: the fan-out is `tokio::spawn`ed off
//! the triggering request (mirroring the webhooks plugin), each RP is POSTed in
//! its own task with a bounded timeout, and the HTTP client follows NO
//! redirects — a compromised/misconfigured RP must not be able to 302 the POST
//! toward an internal address (SSRF defense-in-depth).

use std::time::Duration;

use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::state::YAuthState;
use axum::Router;
use uuid::Uuid;

/// The OIDC Back-Channel Logout 1.0 event identifier that MUST appear (as a key
/// with an empty-object value) in the logout_token's `events` claim.
pub(crate) const BACKCHANNEL_LOGOUT_EVENT: &str =
    "http://schemas.openid.net/event/backchannel-logout";

/// Test-only delivery hook, invoked after each delivery attempt with
/// `(client_id, status_code_or_0, ok)`. `None` in production.
#[cfg(test)]
pub(crate) static BCL_DELIVERY_HOOK: std::sync::Mutex<
    Option<Box<dyn Fn(&str, u16, bool) + Send + Sync>>,
> = std::sync::Mutex::new(None);

pub struct BackchannelLogoutEmitterPlugin {
    issuer: String,
    timeout: Duration,
}

impl BackchannelLogoutEmitterPlugin {
    pub fn new(issuer: String, timeout: Duration) -> Self {
        Self { issuer, timeout }
    }
}

impl YAuthPlugin for BackchannelLogoutEmitterPlugin {
    fn name(&self) -> &'static str {
        "backchannel-logout-emitter"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn on_event(&self, event: &AuthEvent, ctx: &PluginContext) -> EventResponse {
        // Only offboarding events trigger a sub-only "kill all sessions" fan-out.
        let user_id = match event {
            AuthEvent::UserBanned { user_id } | AuthEvent::UserSuspended { user_id } => *user_id,
            _ => return EventResponse::Continue,
        };

        let state = ctx.state.clone();
        let issuer = self.issuer.clone();
        let timeout = self.timeout;
        tokio::spawn(async move {
            fan_out_backchannel_logout(state, issuer, timeout, user_id).await;
        });

        EventResponse::Continue
    }
}

/// Send a logout_token to every RP the user authorized (per stored consents)
/// that registered a back-channel logout endpoint. Best-effort.
async fn fan_out_backchannel_logout(
    state: YAuthState,
    issuer: String,
    timeout: Duration,
    user_id: Uuid,
) {
    let consents = match state.repos.consents.list_by_user_id(user_id).await {
        Ok(c) => c,
        Err(e) => {
            crate::otel::record_error("bcl_list_consents_failed", &e);
            return;
        }
    };

    let mut seen = std::collections::HashSet::new();
    for consent in consents {
        if !seen.insert(consent.client_id.clone()) {
            continue;
        }
        let client = match state
            .repos
            .oauth2_clients
            .find_by_client_id(&consent.client_id)
            .await
        {
            Ok(Some(c)) => c,
            _ => continue,
        };
        let Some(uri) = client.backchannel_logout_uri.filter(|u| !u.is_empty()) else {
            continue;
        };

        let token = match sign_logout_token(&state, &issuer, &client.client_id, user_id) {
            Ok(t) => t,
            Err(e) => {
                crate::otel::record_error("bcl_sign_logout_token_failed", &e);
                continue;
            }
        };
        let client_id = client.client_id.clone();
        tokio::spawn(async move {
            deliver_logout_token(&uri, &client_id, &token, timeout).await;
        });
    }
}

/// Build + sign an OIDC Back-Channel Logout 1.0 logout_token for
/// (audience=client_id, sub=user_id). Per §2.4 it carries the backchannel event
/// and a `jti`, and — critically — MUST NOT carry a `nonce`. We send a sub-only
/// token (no `sid`): the RP terminates all of the user's sessions.
///
/// Signed with the OP's asymmetric key (RS256/ES256, with `kid`) when present,
/// else HS256 with the bearer `jwt_secret` — mirroring `sign_jwt`.
pub(crate) fn sign_logout_token(
    state: &YAuthState,
    issuer: &str,
    audience: &str,
    user_id: Uuid,
) -> Result<String, String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let now = chrono::Utc::now().timestamp();
    let jti = crate::auth::crypto::generate_token();
    let claims = serde_json::json!({
        "iss": issuer,
        "aud": audience,
        "sub": user_id.to_string(),
        "iat": now,
        "jti": jti,
        "events": {
            BACKCHANNEL_LOGOUT_EVENT: {},
        },
    });

    #[cfg(feature = "asymmetric-jwt")]
    if let Some(ref keys) = state.signing_keys {
        let mut header = Header::new(alg_to_jwt(keys.alg));
        header.kid = Some(keys.kid.clone());
        return encode(&header, &claims, &keys.encoding_key)
            .map_err(|e| format!("logout_token encode failed: {e}"));
    }

    let secret = state.bearer_config.jwt_secret.as_bytes();
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| format!("logout_token encode failed: {e}"))
}

/// POST the logout_token to the RP's back-channel logout endpoint as
/// `application/x-www-form-urlencoded` (OIDC BCL §2.5). Best-effort. The HTTP
/// client follows NO redirects (SSRF defense) and is bounded by `timeout`.
async fn deliver_logout_token(endpoint: &str, client_id: &str, token: &str, timeout: Duration) {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            report_delivery(client_id, 0, false);
            return;
        }
    };

    let result = client
        .post(endpoint)
        .form(&[("logout_token", token)])
        .send()
        .await;

    match result {
        Ok(resp) => report_delivery(client_id, resp.status().as_u16(), true),
        Err(_) => report_delivery(client_id, 0, false),
    }
}

#[allow(unused_variables)]
fn report_delivery(client_id: &str, status: u16, ok: bool) {
    #[cfg(test)]
    if let Ok(guard) = BCL_DELIVERY_HOOK.lock()
        && let Some(ref hook) = *guard
    {
        hook(client_id, status, ok);
    }
}

#[cfg(feature = "asymmetric-jwt")]
fn alg_to_jwt(alg: crate::config::SigningAlgorithm) -> jsonwebtoken::Algorithm {
    match alg {
        crate::config::SigningAlgorithm::Hs256 => jsonwebtoken::Algorithm::HS256,
        crate::config::SigningAlgorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
        crate::config::SigningAlgorithm::Es256 => jsonwebtoken::Algorithm::ES256,
    }
}
