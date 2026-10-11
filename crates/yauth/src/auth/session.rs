use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::crypto;
use crate::config::BindingAction;
use crate::state::YAuthState;

pub fn session_set_cookie(state: &YAuthState, token: &str, ttl: std::time::Duration) -> String {
    let max_age = ttl.as_secs();
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        state.config.session_cookie_name, token, max_age
    );
    if state.config.secure_cookies {
        cookie.push_str("; Secure");
    }
    if let Some(domain) = state.config.cookie_domain.domain() {
        // Validate domain to prevent cookie attribute injection via semicolons,
        // newlines, or other control characters in the domain value.
        let is_safe = !domain.contains(';')
            && !domain.contains('\n')
            && !domain.contains('\r')
            && !domain.contains(' ');
        if is_safe {
            cookie.push_str(&format!("; Domain={}", domain));
        }
    }
    cookie
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
    /// Active organization on this session, if any (issue #89).
    #[serde(default)]
    pub active_org_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct SessionError(pub String);

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SessionError {}

impl From<String> for SessionError {
    fn from(e: String) -> Self {
        SessionError(e)
    }
}

impl From<crate::repo::RepoError> for SessionError {
    fn from(e: crate::repo::RepoError) -> Self {
        SessionError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Session operations — delegate storage to state.repos.session_ops
// ---------------------------------------------------------------------------

pub async fn create_session(
    state: &YAuthState,
    user_id: Uuid,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ttl: std::time::Duration,
) -> Result<(String, Uuid), SessionError> {
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);

    let session_id = state
        .repos
        .session_ops
        .create_session(user_id, token_hash, ip_address, user_agent, ttl)
        .await?;

    // Issue #89: apply the active-org selection rules. Best-effort —
    // backends without `set_active_org` implemented (column not shipped)
    // silently leave `active_org_id` as `None`. With the `organizations`
    // feature disabled this is a no-op (the helper returns `None`).
    if let Some(org_id) = pick_default_active_org(state, user_id).await {
        let _ = state
            .repos
            .session_ops
            .set_active_org(session_id, Some(org_id))
            .await;
    }

    Ok((token, session_id))
}

/// Compute the default active organization for a user on session creation
/// (issue #89).
///
/// Selection rules:
///
/// 1. Zero memberships → `None`.
/// 2. Exactly one active membership → that org.
/// 3. Multiple → first sorted by `created_at` (a deterministic fallback for
///    `most_recently_used_org_id`, which is tracked as a follow-up).
///
/// With the `organizations` feature disabled this returns `None`
/// unconditionally — no behaviour change for single-tenant deployments.
#[cfg(feature = "organizations")]
async fn pick_default_active_org(state: &YAuthState, user_id: Uuid) -> Option<Uuid> {
    use yauth_entity::MembershipStatus;

    let memberships = state.repos.memberships.list_by_user(user_id).await.ok()?;
    let mut active: Vec<_> = memberships
        .into_iter()
        .filter(|m| m.status == MembershipStatus::Active)
        .collect();
    if active.is_empty() {
        return None;
    }
    if active.len() == 1 {
        return Some(active[0].organization_id);
    }
    // Deterministic fallback: oldest membership wins. Follow-up #89-FU will
    // track `User.most_recently_used_org_id` and prefer that.
    active.sort_by_key(|m| m.created_at);
    Some(active[0].organization_id)
}

#[cfg(not(feature = "organizations"))]
async fn pick_default_active_org(_state: &YAuthState, _user_id: Uuid) -> Option<Uuid> {
    None
}

pub async fn validate_session(
    state: &YAuthState,
    token: &str,
    request_ip: Option<&str>,
    request_ua: Option<&str>,
) -> Result<Option<SessionUser>, SessionError> {
    let token_hash = crypto::hash_token(token);

    let session = state
        .repos
        .session_ops
        .validate_session(&token_hash)
        .await?;

    crate::otel::set_attribute("yauth.session_found", session.is_some());

    match session {
        Some(s) => {
            let binding = &state.config.session_binding;

            if binding.bind_ip
                && let (Some(session_ip), Some(req_ip)) = (&s.ip_address, request_ip)
                && session_ip != req_ip
            {
                crate::otel::add_event(
                    "session_ip_mismatch",
                    #[cfg(feature = "telemetry")]
                    vec![
                        opentelemetry::KeyValue::new("session_id", s.id.to_string()),
                        opentelemetry::KeyValue::new("session_ip", session_ip.clone()),
                        opentelemetry::KeyValue::new("request_ip", req_ip.to_string()),
                    ],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                if binding.ip_mismatch_action == BindingAction::Invalidate {
                    if let Err(e) = state.repos.session_ops.delete_session(&token_hash).await {
                        log::warn!("Failed to delete invalidated session: {e}");
                    }
                    return Ok(None);
                }
            }

            if binding.bind_user_agent
                && let (Some(session_ua), Some(req_ua)) = (&s.user_agent, request_ua)
                && session_ua != req_ua
            {
                crate::otel::add_event(
                    "session_ua_mismatch",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("session_id", s.id.to_string())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                if binding.ua_mismatch_action == BindingAction::Invalidate {
                    if let Err(e) = state.repos.session_ops.delete_session(&token_hash).await {
                        log::warn!("Failed to delete invalidated session: {e}");
                    }
                    return Ok(None);
                }
            }

            Ok(Some(SessionUser {
                user_id: s.user_id,
                session_id: s.id,
                active_org_id: s.active_org_id,
            }))
        }
        None => Ok(None),
    }
}

pub async fn delete_session(state: &YAuthState, token: &str) -> Result<bool, SessionError> {
    let token_hash = crypto::hash_token(token);
    Ok(state.repos.session_ops.delete_session(&token_hash).await?)
}

pub async fn delete_all_user_sessions(
    state: &YAuthState,
    user_id: Uuid,
) -> Result<u64, SessionError> {
    Ok(state
        .repos
        .session_ops
        .delete_all_sessions_for_user(user_id)
        .await?)
}

pub async fn delete_other_user_sessions(
    state: &YAuthState,
    user_id: Uuid,
    keep_token: &str,
) -> Result<u64, SessionError> {
    let keep_hash = crypto::hash_token(keep_token);
    Ok(state
        .repos
        .session_ops
        .delete_other_sessions_for_user(user_id, &keep_hash)
        .await?)
}

/// Cut every session for `user_id` except the one `keep_token` names, and
/// swallow the failure (review finding 44).
///
/// The security sweep three handlers run after re-establishing an account's
/// credentials: password change, password reset and TOTP enrolment. Each had
/// its own byte-identical copy of the `Some(cookie)` / `None` branch, and
/// upstream is archived, so the drift would have been purely in-house.
///
/// `keep_token` is `None` when the caller has no session of their own to
/// preserve — the reset flow proves ownership with an emailed token, not a
/// cookie — and every session goes.
///
/// **The result is deliberately swallowed**, preserving what all three call
/// sites already did. The sweep is defence in depth layered on top of a
/// credential change that has already been committed by the time it runs;
/// failing the request here would tell the caller their password or second
/// factor did not change when it did, and would leave them without the new
/// credential *and* without the session sweep. The count is returned so a
/// future caller can act on it, and the error is logged at `warn` so a
/// repository that is quietly failing the sweep is visible to operators rather
/// than only to whoever reads the source.
pub async fn delete_sessions_except(
    state: &YAuthState,
    user_id: Uuid,
    keep_token: Option<&str>,
) -> Option<u64> {
    let swept = match keep_token {
        Some(token) => delete_other_user_sessions(state, user_id, token).await,
        None => delete_all_user_sessions(state, user_id).await,
    };

    match swept {
        Ok(count) => Some(count),
        Err(e) => {
            tracing::warn!(
                target: "yauth::session",
                user_id = %user_id,
                error = %e,
                "session_sweep_failed"
            );
            None
        }
    }
}
