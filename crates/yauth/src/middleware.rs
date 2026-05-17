use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::api_err;
use crate::state::YAuthState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub auth_method: AuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Active organization claim (issue #89). `None` for single-tenant
    /// deployments or users with no memberships. Populated from the session
    /// row (cookie auth) or from the JWT's `org` claim (bearer auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub active_org_id: Option<Uuid>,
    /// The caller's role in `active_org_id`. Resolved at auth time from the
    /// membership row (cookie) or from the JWT's `role` claim. `None` when
    /// `active_org_id` is `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub org_role: Option<String>,
    /// Compact membership list — one entry per organization the user
    /// belongs to. Populated alongside `active_org_id`. Empty when the
    /// `organizations` feature is off or the user has no memberships.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub all_orgs: Vec<OrgMembership>,
}

/// Compact membership descriptor surfaced on [`AuthUser`] (issue #89).
///
/// Lightweight enough to drop into JWT claims and SSR-render org switchers
/// without a follow-up API roundtrip.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OrgMembership {
    pub organization_id: Uuid,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum AuthMethod {
    Session,
    Bearer,
    ApiKey,
}

/// OAuth 2.0 Client Credentials grant type identifier (RFC 6749 §4.4).
#[cfg(feature = "oauth2-server")]
pub const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";

/// A non-human caller authenticated via OAuth 2.0 Client Credentials grant
/// (RFC 6749 §4.4) or another M2M flow. Sibling of [`AuthUser`].
///
/// Populated as a request extension by [`auth_middleware`] when the incoming
/// `Authorization: Bearer <jwt>` header carries a client_credentials token.
/// Handlers that only care "someone authenticated" keep matching
/// `Extension<AuthUser>` — they will not see machine callers. Handlers that
/// need to distinguish use [`Authenticated::from_extensions`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MachineCaller {
    pub client_id: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub audience: Option<String>,
    pub jti: String,
    pub auth_method: MachineAuthMethod,
    /// Custom claims passed through from token issuance. Empty until the
    /// token endpoint's per-client allow-list admits non-reserved claims.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub custom_claims: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum MachineAuthMethod {
    /// RFC 6749 §4.4 Client Credentials grant, HS256 JWT.
    ClientCredentials,
    // Future: PrivateKeyJwt (see M3 plan).
}

/// The authenticated principal on the request. Either a human user or a
/// machine caller. Obtained via [`Authenticated::from_extensions`] inside
/// handlers that need to distinguish the two.
///
/// For handlers that only care about one principal type, prefer the concrete
/// `Extension<AuthUser>` / `Extension<MachineCaller>` extractors — they avoid
/// the enum-wrap allocation that this helper performs on every call.
#[derive(Debug, Clone)]
pub enum Authenticated {
    User(AuthUser),
    Machine(MachineCaller),
}

/// The actor behind the request — issue #91.
///
/// `AuthUser` answers *which human looks like the caller*; `Principal`
/// answers *what owns the credential being used*. They diverge for
/// org-scoped API keys ("service accounts"): the `AuthUser` carries
/// the creator's identity for the audit trail, but `Principal` is the
/// org. Handlers that care about *ownership* (e.g. data scoping, audit
/// log key_id population) read `Principal`; handlers that just want
/// "who authenticated" can keep using `AuthUser`.
///
/// Installed alongside `AuthUser` by the API key middleware. For
/// session / bearer / user-scoped API key auth the variant is always
/// `Principal::User`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Principal {
    /// A human user. `Uuid` is the user's id.
    User(Uuid),
    /// An org-scoped API key (a "service account") — issue #91.
    ServiceAccount {
        /// The organization the key belongs to.
        org_id: Uuid,
        /// The `yauth_api_keys.id` of the key being presented.
        key_id: Uuid,
        /// The human who minted the key. Audit trail.
        created_by: Uuid,
    },
}

impl Authenticated {
    pub fn from_extensions(req: &Request) -> Option<Self> {
        if let Some(user) = req.extensions().get::<AuthUser>() {
            return Some(Self::User(user.clone()));
        }
        if let Some(machine) = req.extensions().get::<MachineCaller>() {
            return Some(Self::Machine(machine.clone()));
        }
        None
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        match self {
            Self::User(u) => u
                .scopes
                .as_ref()
                .is_some_and(|s| s.iter().any(|x| x == scope)),
            Self::Machine(m) => m.scopes.iter().any(|x| x == scope),
        }
    }
}

/// Record authenticated user context on the current (SERVER) span.
fn record_auth_user_on_span(user: &AuthUser) {
    crate::otel::set_attribute("user.id", user.id.to_string());
    // PII: user.email is intentionally omitted. Use user.id for correlation.
    crate::otel::set_attribute("user.roles", user.role.clone());
    crate::otel::set_attribute(
        "yauth.auth_method",
        match &user.auth_method {
            AuthMethod::Session => "session",
            AuthMethod::Bearer => "bearer",
            AuthMethod::ApiKey => "api_key",
        },
    );
}

/// Record machine-caller context on the current (SERVER) span. Never sets
/// `user.id` — that attribute is reserved for human callers so dashboards
/// filtering on it don't silently include M2M traffic.
#[cfg(feature = "oauth2-server")]
fn record_machine_caller_on_span(caller: &MachineCaller) {
    crate::otel::set_attribute("client.id", caller.client_id.clone());
    crate::otel::set_attribute("yauth.auth_method", GRANT_TYPE_CLIENT_CREDENTIALS);
    if !caller.scopes.is_empty() {
        crate::otel::set_attribute("yauth.scopes", caller.scopes.join(" "));
    }
}

pub async fn auth_middleware(
    State(state): State<YAuthState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Response {
    // If a prior middleware (e.g. API key auth) already set AuthUser, skip re-checking.
    if req.extensions().get::<AuthUser>().is_some() {
        return next.run(req).await;
    }

    let request_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string())
        });
    let request_ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    // Try session cookie first
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let token = cookie.value();
        match crate::auth::session::validate_session(
            &state,
            token,
            request_ip.as_deref(),
            request_ua.as_deref(),
        )
        .await
        {
            Ok(Some(session_user)) => {
                match lookup_user(&state, session_user.user_id, AuthMethod::Session).await {
                    Ok(mut auth_user) => {
                        if auth_user.banned {
                            return api_err(StatusCode::FORBIDDEN, "Account suspended")
                                .into_response();
                        }
                        // Issue #89: stamp active-org context from the session row.
                        attach_org_context(&state, &mut auth_user, session_user.active_org_id)
                            .await;
                        record_auth_user_on_span(&auth_user);
                        let user_id = auth_user.id;
                        req.extensions_mut().insert(auth_user);
                        // Issue #91: install a Principal::User so handlers that
                        // discriminate principal type see a consistent extension.
                        req.extensions_mut().insert(Principal::User(user_id));
                        return next.run(req).await;
                    }
                    Err(e) => {
                        crate::otel::record_error("user_lookup_failed", &e);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                crate::otel::record_error("session_validation_error", &e);
            }
        }
    }

    // Try Bearer token. Dispatch by claim shape (not by error string) — tokens
    // carrying `client_id` + no `email` go to the client path; everything else
    // goes to the user path. The dispatcher peek is unverified; the selected
    // validator still performs full signature + exp + aud + JTI checks.
    #[cfg(feature = "bearer")]
    #[allow(clippy::collapsible_if)]
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                let is_machine = crate::plugins::bearer::is_machine_token(token);
                #[cfg(feature = "oauth2-server")]
                if is_machine {
                    if let Ok(caller) =
                        crate::plugins::bearer::validate_jwt_as_client(token, &state).await
                    {
                        record_machine_caller_on_span(&caller);
                        req.extensions_mut().insert(caller);
                        return next.run(req).await;
                    }
                }
                if !is_machine
                    && let Ok(auth_user) = crate::plugins::bearer::validate_jwt(token, &state).await
                {
                    record_auth_user_on_span(&auth_user);
                    let user_id = auth_user.id;
                    req.extensions_mut().insert(auth_user);
                    // Issue #91: stamp Principal::User for handler discriminate.
                    req.extensions_mut().insert(Principal::User(user_id));
                    return next.run(req).await;
                }
            }
        }
    }

    // Try API key
    #[cfg(feature = "api-key")]
    #[allow(clippy::collapsible_if)]
    if let Some(api_key_header) = headers.get("x-api-key") {
        if let Ok(key_str) = api_key_header.to_str() {
            if let Ok((auth_user, principal)) =
                crate::plugins::api_key::validate_api_key(key_str, &state).await
            {
                record_auth_user_on_span(&auth_user);
                // Issue #91: stamp service-account marker on the SERVER span
                // so audit / dashboards can distinguish org-scoped traffic.
                if let Principal::ServiceAccount {
                    org_id,
                    key_id,
                    created_by,
                } = &principal
                {
                    crate::otel::set_attribute("yauth.principal", "service_account");
                    crate::otel::set_attribute("organization.id", org_id.to_string());
                    crate::otel::set_attribute("api_key.id", key_id.to_string());
                    crate::otel::set_attribute("api_key.created_by", created_by.to_string());
                }
                req.extensions_mut().insert(auth_user);
                req.extensions_mut().insert(principal);
                return next.run(req).await;
            }
        }
    }

    let _ = &headers;

    api_err(StatusCode::UNAUTHORIZED, "Authentication required").into_response()
}

async fn lookup_user(
    state: &YAuthState,
    user_id: Uuid,
    method: AuthMethod,
) -> Result<AuthUser, String> {
    let user = state
        .repos
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "User not found".to_string())?;

    Ok(AuthUser {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        email_verified: user.email_verified,
        role: user.role,
        banned: user.banned,
        auth_method: method,
        scopes: None,
        active_org_id: None,
        org_role: None,
        all_orgs: Vec::new(),
    })
}

/// Populate the org-related fields on [`AuthUser`] from the user's
/// memberships (issue #89). No-op when the `organizations` feature is off.
///
/// `requested_active_org` is the org_id surfaced by the auth carrier — the
/// `active_org_id` column on the session row, or the `org` claim on a JWT.
/// If the user is no longer a member of that org (membership revoked
/// between auth events) the resolver gracefully degrades: it surfaces an
/// `active_org_id` of `None` rather than 500'ing the request.
#[cfg(feature = "organizations")]
async fn attach_org_context(
    state: &YAuthState,
    auth_user: &mut AuthUser,
    requested_active_org: Option<uuid::Uuid>,
) {
    use yauth_entity::MembershipStatus;

    let memberships = match state.repos.memberships.list_by_user(auth_user.id).await {
        Ok(m) => m,
        Err(e) => {
            crate::otel::record_error("membership_list_failed", &e);
            return;
        }
    };
    auth_user.all_orgs = memberships
        .iter()
        .filter(|m| m.status == MembershipStatus::Active)
        .map(|m| OrgMembership {
            organization_id: m.organization_id,
            role: m.role.clone(),
        })
        .collect();

    if let Some(org_id) = requested_active_org
        && let Some(m) = memberships
            .iter()
            .find(|m| m.organization_id == org_id && m.status == MembershipStatus::Active)
    {
        auth_user.active_org_id = Some(org_id);
        auth_user.org_role = Some(m.role.clone());
    }
}

#[cfg(not(feature = "organizations"))]
async fn attach_org_context(
    _state: &YAuthState,
    _auth_user: &mut AuthUser,
    _requested_active_org: Option<uuid::Uuid>,
) {
}

pub fn require_scope(
    scope: &'static str,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    move |req: Request, next: Next| {
        Box::pin(async move {
            // Machine callers are checked first — their scopes are always a
            // concrete list (never `None`). A caller with no scopes fails any
            // `require_scope` gate, which is the stricter default.
            if let Some(machine) = req.extensions().get::<MachineCaller>() {
                if !machine.scopes.iter().any(|s| s == scope) {
                    return insufficient_scope(scope);
                }
                return next.run(req).await;
            }
            if let Some(user) = req.extensions().get::<AuthUser>() {
                // Legacy semantics: `scopes: None` on a human user means
                // "unrestricted" — preserve that for backwards compatibility.
                if let Some(ref scopes) = user.scopes
                    && !scopes.iter().any(|s| s == scope)
                {
                    return insufficient_scope(scope);
                }
                return next.run(req).await;
            }
            api_err(StatusCode::UNAUTHORIZED, "Authentication required").into_response()
        })
    }
}

fn insufficient_scope(required: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": "insufficient_scope",
            "error_description": format!("Required scope: {}", required)
        })),
    )
        .into_response()
}

pub async fn require_admin(State(state): State<YAuthState>, req: Request, next: Next) -> Response {
    if let Some(user) = req.extensions().get::<AuthUser>() {
        if user.role == "admin" {
            return next.run(req).await;
        }
        return api_err(StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    // Machine callers: only admitted when explicitly opted in via AdminConfig
    // AND carrying the `admin` scope. This expands the blast radius of a
    // compromised client_id, so we emit a span event for auditability.
    #[cfg(all(feature = "admin", feature = "oauth2-server"))]
    if let Some(machine) = req.extensions().get::<MachineCaller>()
        && state.admin_config.allow_machine_callers
        && machine.scopes.iter().any(|s| s == "admin")
    {
        crate::otel::add_event(
            "admin_machine_call_allowed",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new(
                "client.id",
                machine.client_id.clone(),
            )],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return next.run(req).await;
    }
    let _ = state;

    if req.extensions().get::<MachineCaller>().is_some() {
        return api_err(StatusCode::FORBIDDEN, "Admin access required").into_response();
    }
    api_err(StatusCode::UNAUTHORIZED, "Authentication required").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user() -> AuthUser {
        AuthUser {
            id: Uuid::nil(),
            email: "test@example.com".into(),
            display_name: Some("Test User".into()),
            email_verified: true,
            role: "user".into(),
            banned: false,
            auth_method: AuthMethod::Session,
            scopes: None,
            active_org_id: None,
            org_role: None,
            all_orgs: Vec::new(),
        }
    }

    #[test]
    fn auth_user_serialization_roundtrip() {
        let user = sample_user();
        let json = serde_json::to_string(&user).unwrap();
        let parsed: AuthUser = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, user.id);
        assert_eq!(parsed.email, "test@example.com");
        assert_eq!(parsed.display_name, Some("Test User".into()));
        assert!(parsed.email_verified);
    }

    #[test]
    fn auth_method_variants_serialize() {
        for method in [AuthMethod::Session, AuthMethod::Bearer, AuthMethod::ApiKey] {
            let json = serde_json::to_string(&method).unwrap();
            let _: AuthMethod = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn auth_user_with_no_display_name() {
        let user = AuthUser {
            display_name: None,
            ..sample_user()
        };
        let json = serde_json::to_string(&user).unwrap();
        let parsed: AuthUser = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.display_name, None);
    }
}
