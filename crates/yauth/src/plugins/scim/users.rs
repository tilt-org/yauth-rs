//! SCIM Users endpoint handlers.
//!
//! Maps the SCIM `User` resource onto yauth's
//! `User` + `Membership` + `ExternalIdentity` entities. The "scim id"
//! exposed to IdPs is the yauth `User.id` (UUIDv7) rendered as a
//! string — IdPs treat ids as opaque, so any stable handle works.
//!
//! ## Operations
//!
//! | Method | Path                       | Effect                                                                  |
//! |--------|----------------------------|-------------------------------------------------------------------------|
//! | POST   | `/Users`                    | Create or attach. Idempotent on `externalId` (returns existing as 200). |
//! | GET    | `/Users`                    | Paginated list of users *with an active membership in this org*.        |
//! | GET    | `/Users/{id}`               | Fetch one (404 if not a member of this org).                            |
//! | PUT    | `/Users/{id}`               | Full replace — updates display name, active, and membership-via-groups. |
//! | PATCH  | `/Users/{id}`               | RFC 7644 §3.5.2 add/replace/remove on a small attribute set.            |
//! | DELETE | `/Users/{id}`               | Remove the user's membership in this org. User row persists for audit.  |
//!
//! ## Idempotency
//!
//! - POST with an `externalId` that already maps to a user inside this
//!   org → return existing record as **200 OK**, not 201/409.
//! - DELETE on a user with no membership in this org → **404** (mirror
//!   the spec's "is the resource actually in this scope" check; quiet
//!   204 would mask a wrong-org client).
//!
//! ## Anti-takeover
//!
//! POST/PUT/PATCH that would set a user's email to one already in use
//! by **another existing yauth user** → **409 `uniqueness`**. We never
//! silently merge.

#![forbid(unsafe_code)]

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::rbac::{self, roles};
use crate::state::YAuthState;
use yauth_entity::{
    ExternalIdentity, MembershipStatus, NewExternalIdentity, NewMembership, NewUser,
    UpdateMembership, UpdateUser, User,
};

use super::auth::{ScimPrincipal, authenticate};
use super::error::{ScimResponseError, scim_json_response};
use super::filter::Filter;
use super::types::{
    CORE_USER_SCHEMA, ListResponse, PATCH_OP_SCHEMA, ResourceMeta, ScimEmail, ScimGroupRef,
    ScimUser, validate_schemas,
};

/// Provider string written to `ExternalIdentity.provider` for SCIM
/// links. The org_id is embedded so two orgs running SCIM through the
/// same yauth deployment can each link the same IdP `externalId`
/// without colliding (`provider` + `external_id` is deployment-wide
/// unique per #93).
fn scim_provider(org_id: Uuid) -> String {
    format!("scim:{org_id}")
}

fn naive_iso8601(t: chrono::NaiveDateTime) -> String {
    // chrono's NaiveDateTime serialises as "2026-05-17T12:34:56.000".
    // SCIM clients accept either with-Z or without; we emit with `Z`
    // since callers expect UTC.
    format!("{}Z", t.format("%Y-%m-%dT%H:%M:%S"))
}

fn build_meta(state: &YAuthState, org_id: Uuid, user: &User) -> ResourceMeta {
    let base = state.config.base_url.trim_end_matches('/');
    ResourceMeta {
        resource_type: "User".into(),
        created: naive_iso8601(user.created_at),
        last_modified: naive_iso8601(user.updated_at),
        location: format!(
            "{base}/api/scim/v2/organizations/{org_id}/Users/{}",
            user.id
        ),
    }
}

async fn external_id_for(
    state: &YAuthState,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Option<ExternalIdentity>, ScimResponseError> {
    let provider = scim_provider(org_id);
    let list = state
        .repos
        .external_identities
        .list_for_user(user_id)
        .await?;
    Ok(list.into_iter().find(|x| x.provider == provider))
}

/// Project a yauth `User` (plus an optional `ExternalIdentity` linking
/// it to the SCIM-side id) into a `ScimUser` shape.
fn project_user(
    state: &YAuthState,
    org_id: Uuid,
    user: &User,
    ext: Option<&ExternalIdentity>,
    membership_status: MembershipStatus,
    group_refs: Vec<ScimGroupRef>,
) -> ScimUser {
    ScimUser {
        id: Some(user.id.to_string()),
        schemas: vec![CORE_USER_SCHEMA.into()],
        external_id: ext.map(|e| e.external_id.clone()),
        user_name: Some(user.email.clone()),
        display_name: user.display_name.clone(),
        name: None,
        emails: vec![ScimEmail {
            value: user.email.clone(),
            r#type: Some("work".into()),
            primary: Some(true),
            display: None,
        }],
        active: Some(membership_status == MembershipStatus::Active),
        groups: group_refs,
        meta: Some(build_meta(state, org_id, user)),
    }
}

/// Resolve the SCIM-side role string for a user in this org.
///
/// IdPs send `groups[]` on POST/PUT. If the org's connection carries a
/// `group_to_role` mapping we honour it (most-privileged wins);
/// otherwise we treat each group as a literal role name and only
/// accept entries that are built-in roles.
async fn role_from_groups(
    state: &YAuthState,
    org_id: Uuid,
    groups: &[ScimGroupRef],
) -> Result<Option<String>, ScimResponseError> {
    if groups.is_empty() {
        return Ok(None);
    }
    let group_names: Vec<String> = groups
        .iter()
        .map(|g| g.display.clone().unwrap_or_else(|| g.value.clone()))
        .collect();

    // Find the org's first SsoConnection, if any, so we can read its
    // attribute mappings.
    let connections = state.repos.sso_connections.list_for_org(org_id).await?;
    let mapping = connections
        .iter()
        .find_map(|c| c.oidc_config().map(|cfg| cfg.claim_mappings.group_to_role));

    let mut mapped_roles: Vec<String> = Vec::new();
    if let Some(map) = mapping {
        for g in &group_names {
            if let Some(role) = map.get(g) {
                mapped_roles.push(role.clone());
            }
        }
    } else {
        // No mapping configured — accept literal built-in role names.
        for g in &group_names {
            if roles::is_builtin(&g.to_ascii_lowercase()) {
                mapped_roles.push(g.to_ascii_lowercase());
            }
        }
    }
    if mapped_roles.is_empty() {
        return Ok(None);
    }
    let refs: Vec<&str> = mapped_roles.iter().map(|s| s.as_str()).collect();
    Ok(rbac::most_privileged_role(&refs).map(|s| s.to_string()))
}

async fn audit_scim(state: &YAuthState, principal: &ScimPrincipal, event: &str, target: &str) {
    state
        .write_audit_log(
            Some(principal.created_by),
            event,
            Some(serde_json::json!({
                "actor": format!("scim_api_key:{}", principal.key_id),
                "org_id": principal.org_id,
                "target": target,
            })),
            None,
        )
        .await;
}

// ──────────────────────────────────────────────
// SCIM active → global lifecycle
// ──────────────────────────────────────────────

/// Marks a suspension as SCIM-originated. Only suspensions carrying this exact
/// reason are auto-cleared by a subsequent SCIM `active:true`, so a manual admin
/// offboard survives routine IdP profile-sync PUTs (which default `active:true`).
pub(super) const SCIM_SUSPEND_REASON: &str = "SCIM deprovisioned";

/// Maps the SCIM `active` attribute onto the user's **global** lifecycle, not
/// just their membership in one org. SCIM is the workforce system of record:
/// `active:false` suspends the account globally (sets `suspended_at`) and trips
/// the kill switch — terminating every session and revoking every refresh token,
/// for an instant lockout everywhere. `active:true` reverses it, but ONLY for
/// SCIM-originated suspensions (reason == [`SCIM_SUSPEND_REASON`]) so a routine
/// sync never silently undoes an admin's manual offboard.
///
/// Idempotent. Kill-switch errors are best-effort (ignored); only the
/// `update` write is surfaced. Mirrors yauth-go's `applyScimActiveLifecycle`.
pub(super) async fn apply_scim_active_lifecycle(
    state: &YAuthState,
    user: &yauth_entity::User,
    active: bool,
    now: chrono::NaiveDateTime,
) -> Result<(), ScimResponseError> {
    if !active {
        if user.suspended_at.is_none() {
            state
                .repos
                .users
                .update(
                    user.id,
                    UpdateUser {
                        suspended_at: Some(Some(now)),
                        suspended_reason: Some(Some(SCIM_SUSPEND_REASON.to_string())),
                        updated_at: Some(now),
                        ..Default::default()
                    },
                )
                .await?;
        }
        // Always (re-)assert the kill switch on active:false so a repeated
        // de-provision flushes any sessions/tokens minted in between.
        scim_kill_switch(state, user.id).await;
        // Offboarding event → OIDC Back-Channel Logout fan-out to the user's RPs.
        let _ = state.emit_event(&crate::plugin::AuthEvent::UserSuspended { user_id: user.id });
        return Ok(());
    }

    // active:true → reactivate, but never silently override an admin offboard.
    if user.suspended_at.is_none() {
        return Ok(());
    }
    if user.suspended_reason.as_deref() != Some(SCIM_SUSPEND_REASON) {
        // Manually-suspended (or unknown-origin): leave it locked. An operator
        // must reactivate via the admin API on purpose.
        return Ok(());
    }
    state
        .repos
        .users
        .update(
            user.id,
            UpdateUser {
                suspended_at: Some(None),
                suspended_reason: Some(None),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

/// Best-effort kill switch: terminate sessions + revoke refresh tokens.
pub(super) async fn scim_kill_switch(state: &YAuthState, user_id: Uuid) {
    let _ = crate::auth::session::delete_all_user_sessions(state, user_id).await;
    #[cfg(feature = "bearer")]
    {
        let _ = state
            .repos
            .refresh_tokens
            .revoke_all_user_refresh_tokens(user_id)
            .await;
    }
}

// ──────────────────────────────────────────────
// POST /Users
// ──────────────────────────────────────────────

pub async fn create_user(
    State(state): State<YAuthState>,
    Path(org_id): Path<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<ScimUser>,
) -> Response {
    match create_user_inner(&state, org_id, &headers, payload).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn create_user_inner(
    state: &YAuthState,
    org_id: Uuid,
    headers: &HeaderMap,
    payload: ScimUser,
) -> Result<Response, ScimResponseError> {
    let principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;

    if payload.schemas.is_empty() {
        return Err(ScimResponseError::bad_request("schemas[] is required"));
    }
    if let Err(e) = validate_schemas(&payload.schemas, CORE_USER_SCHEMA) {
        return Err(ScimResponseError {
            status: StatusCode::BAD_REQUEST,
            body: e,
        });
    }

    let email = payload
        .canonical_email()
        .ok_or_else(|| ScimResponseError::bad_request("user must have userName or emails[]"))?;

    let display_name = payload.pick_display_name();
    let now = Utc::now().naive_utc();

    // Idempotency: if externalId is set and we already have a link for
    // this org, return the existing user with 200.
    if let Some(ext_id) = payload.external_id.as_deref() {
        let provider = scim_provider(org_id);
        if let Some(existing) = state
            .repos
            .external_identities
            .find_by_provider_external_id(&provider, ext_id)
            .await?
        {
            let user = state
                .repos
                .users
                .find_by_id(existing.user_id)
                .await?
                .ok_or_else(ScimResponseError::internal)?;
            let membership = state
                .repos
                .memberships
                .find_by_org_user(org_id, user.id)
                .await?;
            let status_now = membership
                .as_ref()
                .map_or(MembershipStatus::Active, |m| m.status);
            let scim_user = project_user(state, org_id, &user, Some(&existing), status_now, vec![]);
            audit_scim(
                state,
                &principal,
                "scim_user_create_idempotent",
                &user.id.to_string(),
            )
            .await;
            return Ok(scim_json_response(StatusCode::OK, scim_user));
        }
    }

    // No existing link for this org's externalId. Check email
    // uniqueness — if a yauth user already has this email but is NOT
    // linked to this org's SCIM provider, fail with 409 (anti-takeover).
    let existing_email = state.repos.users.find_by_email(&email).await?;
    let user = match existing_email {
        Some(u) => {
            // Belt-and-braces: confirm no SCIM link for this org under a
            // different externalId exists either. If there IS a SCIM
            // link with a different externalId, the IdP rotated the
            // externalId — refuse (409).
            let provider = scim_provider(org_id);
            let already_linked_for_org = state
                .repos
                .external_identities
                .list_for_user(u.id)
                .await?
                .into_iter()
                .find(|x| x.provider == provider);
            if let Some(existing_link) = already_linked_for_org
                && let Some(claimed_id) = payload.external_id.as_deref()
                && existing_link.external_id != claimed_id
            {
                return Err(ScimResponseError::conflict(
                    "user already linked via a different externalId in this org",
                ));
            }
            u
        }
        None => {
            // Genuinely new yauth user.
            let id = Uuid::now_v7();
            state
                .repos
                .users
                .create(NewUser {
                    id,
                    email: email.clone(),
                    display_name: display_name.clone(),
                    email_verified: true,
                    role: "user".to_string(),
                    banned: false,
                    banned_reason: None,
                    banned_until: None,
                    suspended_at: None,
                    suspended_reason: None,
                    activates_at: None,
                    created_at: now,
                    updated_at: now,
                })
                .await?;
            state
                .repos
                .users
                .find_by_id(id)
                .await?
                .ok_or_else(ScimResponseError::internal)?
        }
    };

    // Link external identity for this org's SCIM provider (if absent).
    let ext = if let Some(ext_id) = payload.external_id.as_deref() {
        // We already checked above for cross-externalId collisions.
        match state
            .repos
            .external_identities
            .create(NewExternalIdentity {
                id: Uuid::now_v7(),
                user_id: user.id,
                provider: scim_provider(org_id),
                external_id: ext_id.to_string(),
                linked_at: now,
                last_login_at: now,
            })
            .await
        {
            Ok(e) => Some(e),
            Err(crate::repo::RepoError::Conflict(_)) => {
                // Race: another POST raced us. Re-fetch.
                state
                    .repos
                    .external_identities
                    .find_by_provider_external_id(&scim_provider(org_id), ext_id)
                    .await?
            }
            Err(other) => return Err(other.into()),
        }
    } else {
        None
    };

    // Membership: active by default unless `active: false` came in.
    let desired_status = match payload.active {
        Some(false) => MembershipStatus::Suspended,
        _ => MembershipStatus::Active,
    };
    let role = role_from_groups(state, org_id, &payload.groups)
        .await?
        .unwrap_or_else(|| roles::MEMBER.to_string());

    let existing_membership = state
        .repos
        .memberships
        .find_by_org_user(org_id, user.id)
        .await?;
    match existing_membership {
        Some(m) => {
            state
                .repos
                .memberships
                .update(
                    m.id,
                    UpdateMembership {
                        role: Some(role.clone()),
                        status: Some(desired_status),
                        joined_at: None,
                        updated_at: Some(now),
                    },
                )
                .await?;
        }
        None => {
            state
                .repos
                .memberships
                .create(NewMembership {
                    id: Uuid::now_v7(),
                    organization_id: org_id,
                    user_id: user.id,
                    role,
                    status: desired_status,
                    invited_at: None,
                    joined_at: Some(now),
                    created_at: now,
                    updated_at: now,
                })
                .await?;
        }
    }

    let fresh = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(ScimResponseError::internal)?;

    // SCIM `active` maps to the global lifecycle (instant lockout on
    // de-provision), not only the org membership status above.
    let active = payload.active.unwrap_or(true);
    apply_scim_active_lifecycle(state, &fresh, active, now).await?;
    let fresh = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(ScimResponseError::internal)?;

    let scim_user = project_user(state, org_id, &fresh, ext.as_ref(), desired_status, vec![]);
    audit_scim(
        state,
        &principal,
        "scim_user_created",
        &fresh.id.to_string(),
    )
    .await;
    Ok(scim_json_response(StatusCode::CREATED, scim_user))
}

// ──────────────────────────────────────────────
// GET /Users (list)
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub filter: Option<String>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<i64>,
    pub count: Option<i64>,
    /// Tolerated but ignored — RFC 7644 §3.4.3 attribute selection.
    pub attributes: Option<String>,
    #[serde(rename = "excludedAttributes")]
    pub excluded_attributes: Option<String>,
}

const DEFAULT_ITEMS_PER_PAGE: usize = 100;
const MAX_ITEMS_PER_PAGE: usize = 500;

pub(super) fn clamp_pagination(start: Option<i64>, count: Option<i64>) -> (usize, usize) {
    // RFC 7644 §3.4.2 — `startIndex` is 1-based. Values < 1 clamp to 1.
    // Wildly large values are accepted as-is (the slice will be empty).
    let start = start.unwrap_or(1).max(1) as usize;
    let count = match count {
        Some(c) if c < 0 => 0,
        Some(c) => (c as usize).min(MAX_ITEMS_PER_PAGE),
        None => DEFAULT_ITEMS_PER_PAGE,
    };
    (start, count)
}

pub async fn list_users(
    State(state): State<YAuthState>,
    Path(org_id): Path<Uuid>,
    Query(q): Query<ListUsersQuery>,
    headers: HeaderMap,
) -> Response {
    match list_users_inner(&state, org_id, q, &headers).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn list_users_inner(
    state: &YAuthState,
    org_id: Uuid,
    q: ListUsersQuery,
    headers: &HeaderMap,
) -> Result<Response, ScimResponseError> {
    let _principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;

    let parsed_filter = match q.filter.as_deref() {
        Some(s) => Some(super::filter::parse(s).map_err(|e| ScimResponseError {
            status: StatusCode::BAD_REQUEST,
            body: e,
        })?),
        None => None,
    };
    let (start_index, count) = clamp_pagination(q.start_index, q.count);

    let memberships = state.repos.memberships.list_by_org(org_id).await?;
    let mut users_in_org: Vec<(User, MembershipStatus, Option<ExternalIdentity>)> = Vec::new();
    for m in memberships {
        let user = match state.repos.users.find_by_id(m.user_id).await? {
            Some(u) => u,
            None => continue,
        };
        let ext = external_id_for(state, org_id, m.user_id).await?;
        users_in_org.push((user, m.status, ext));
    }

    // Apply filter.
    let filtered: Vec<_> = users_in_org
        .into_iter()
        .filter(|(u, status, ext)| {
            parsed_filter
                .as_ref()
                .map(|f| user_matches_filter(u, *status, ext.as_ref(), f))
                .unwrap_or(true)
        })
        .collect();

    let total = filtered.len();
    let skip = start_index.saturating_sub(1);
    let page: Vec<_> = filtered.into_iter().skip(skip).take(count).collect();

    let resources: Vec<ScimUser> = page
        .iter()
        .map(|(u, s, e)| project_user(state, org_id, u, e.as_ref(), *s, vec![]))
        .collect();

    Ok(scim_json_response(
        StatusCode::OK,
        ListResponse::new(total, start_index, resources.len(), resources),
    ))
}

fn user_matches_filter(
    u: &User,
    status: MembershipStatus,
    ext: Option<&ExternalIdentity>,
    f: &Filter,
) -> bool {
    f.matches(|atom| match atom.attr.to_ascii_lowercase().as_str() {
        "username" => atom.value.matches_string(atom.op, &u.email),
        "emails" | "emails.value" => atom.value.matches_string(atom.op, &u.email),
        "displayname" => u
            .display_name
            .as_deref()
            .map(|d| atom.value.matches_string(atom.op, d))
            .unwrap_or(false),
        "externalid" => ext
            .map(|e| atom.value.matches_string(atom.op, &e.external_id))
            .unwrap_or(false),
        "active" => atom
            .value
            .matches_bool(atom.op, status == MembershipStatus::Active),
        "id" => atom.value.matches_string(atom.op, &u.id.to_string()),
        _ => false,
    })
}

// ──────────────────────────────────────────────
// GET /Users/{id}
// ──────────────────────────────────────────────

pub async fn get_user(
    State(state): State<YAuthState>,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response {
    match get_user_inner(&state, org_id, user_id, &headers).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn get_user_inner(
    state: &YAuthState,
    org_id: Uuid,
    user_id: Uuid,
    headers: &HeaderMap,
) -> Result<Response, ScimResponseError> {
    let _principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    let user = require_user_in_org(state, org_id, user_id).await?;
    let ext = external_id_for(state, org_id, user.id).await?;
    let membership = state
        .repos
        .memberships
        .find_by_org_user(org_id, user.id)
        .await?
        .ok_or_else(|| ScimResponseError::not_found("user not in this org"))?;
    let scim_user = project_user(
        state,
        org_id,
        &user,
        ext.as_ref(),
        membership.status,
        vec![],
    );
    Ok(scim_json_response(StatusCode::OK, scim_user))
}

async fn require_user_in_org(
    state: &YAuthState,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<User, ScimResponseError> {
    let membership = state
        .repos
        .memberships
        .find_by_org_user(org_id, user_id)
        .await?;
    if membership.is_none() {
        return Err(ScimResponseError::not_found("user not in this org"));
    }
    let user = state
        .repos
        .users
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| ScimResponseError::not_found("user not found"))?;
    Ok(user)
}

// ──────────────────────────────────────────────
// PUT /Users/{id}
// ──────────────────────────────────────────────

pub async fn put_user(
    State(state): State<YAuthState>,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(payload): Json<ScimUser>,
) -> Response {
    match put_user_inner(&state, org_id, user_id, &headers, payload).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn put_user_inner(
    state: &YAuthState,
    org_id: Uuid,
    user_id: Uuid,
    headers: &HeaderMap,
    payload: ScimUser,
) -> Result<Response, ScimResponseError> {
    let principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    if let Err(e) = validate_schemas(&payload.schemas, CORE_USER_SCHEMA) {
        return Err(ScimResponseError {
            status: StatusCode::BAD_REQUEST,
            body: e,
        });
    }
    let user = require_user_in_org(state, org_id, user_id).await?;

    // Email change → check collision against any other yauth user.
    let new_email = payload.canonical_email();
    if let Some(ref new_email) = new_email
        && !new_email.eq_ignore_ascii_case(&user.email)
        && let Some(other) = state.repos.users.find_by_email(new_email).await?
        && other.id != user.id
    {
        return Err(ScimResponseError::conflict(
            "email already in use by another user",
        ));
    }

    let display_name = payload.pick_display_name();
    let now = Utc::now().naive_utc();
    state
        .repos
        .users
        .update(
            user.id,
            UpdateUser {
                email: new_email.clone(),
                display_name: Some(display_name.clone()),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await?;

    let desired_status = match payload.active {
        Some(false) => MembershipStatus::Suspended,
        _ => MembershipStatus::Active,
    };
    let role = role_from_groups(state, org_id, &payload.groups).await?;
    let membership = state
        .repos
        .memberships
        .find_by_org_user(org_id, user.id)
        .await?
        .ok_or_else(|| ScimResponseError::not_found("user not in this org"))?;
    state
        .repos
        .memberships
        .update(
            membership.id,
            UpdateMembership {
                role,
                status: Some(desired_status),
                joined_at: None,
                updated_at: Some(now),
            },
        )
        .await?;

    // SCIM `active` maps to the global lifecycle. PUT is a full replace, so an
    // absent `active` defaults to true (RFC 7644) — which, per the sentinel
    // rule, only clears SCIM-originated suspensions.
    let fresh = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(ScimResponseError::internal)?;
    let active = payload.active.unwrap_or(true);
    apply_scim_active_lifecycle(state, &fresh, active, now).await?;

    let fresh = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(ScimResponseError::internal)?;
    let ext = external_id_for(state, org_id, fresh.id).await?;
    let scim_user = project_user(state, org_id, &fresh, ext.as_ref(), desired_status, vec![]);
    audit_scim(
        state,
        &principal,
        "scim_user_replaced",
        &fresh.id.to_string(),
    )
    .await;
    Ok(scim_json_response(StatusCode::OK, scim_user))
}

// ──────────────────────────────────────────────
// PATCH /Users/{id}
// ──────────────────────────────────────────────

pub async fn patch_user(
    State(state): State<YAuthState>,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(payload): Json<super::types::PatchOp>,
) -> Response {
    match patch_user_inner(&state, org_id, user_id, &headers, payload).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn patch_user_inner(
    state: &YAuthState,
    org_id: Uuid,
    user_id: Uuid,
    headers: &HeaderMap,
    payload: super::types::PatchOp,
) -> Result<Response, ScimResponseError> {
    let principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    if let Err(e) = validate_schemas(&payload.schemas, PATCH_OP_SCHEMA) {
        return Err(ScimResponseError {
            status: StatusCode::BAD_REQUEST,
            body: e,
        });
    }
    let user = require_user_in_org(state, org_id, user_id).await?;
    let now = Utc::now().naive_utc();
    let mut new_email: Option<String> = None;
    let mut new_display_name: Option<Option<String>> = None;
    let mut new_active: Option<bool> = None;

    for op in payload.operations {
        let op_lc = op.op.to_ascii_lowercase();
        let path_lc = op
            .path
            .as_deref()
            .map(|p| p.to_ascii_lowercase())
            .unwrap_or_default();
        match (op_lc.as_str(), path_lc.as_str()) {
            ("replace" | "add", "active") | ("replace" | "add", "") => {
                // No-path replace: the value is expected to be an
                // object with a subset of attributes.
                if let Some(v) = op.value.clone() {
                    if path_lc == "active" {
                        if let Some(b) = v.as_bool() {
                            new_active = Some(b);
                        }
                    } else if let Some(obj) = v.as_object() {
                        if let Some(b) = obj.get("active").and_then(|v| v.as_bool()) {
                            new_active = Some(b);
                        }
                        if let Some(s) = obj.get("displayName").and_then(|v| v.as_str()) {
                            new_display_name = Some(Some(s.to_string()));
                        }
                        if let Some(s) = obj.get("userName").and_then(|v| v.as_str()) {
                            new_email = Some(s.to_string());
                        }
                    }
                }
            }
            ("replace" | "add", "displayname") => {
                new_display_name = Some(
                    op.value
                        .as_ref()
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                );
            }
            ("replace" | "add", "username")
            | ("replace" | "add", "emails[primary eq true].value") => {
                if let Some(s) = op.value.as_ref().and_then(|v| v.as_str()) {
                    new_email = Some(s.to_string());
                }
            }
            ("remove", "displayname") => {
                new_display_name = Some(None);
            }
            ("remove", _) => {
                // Tolerate but ignore — IdPs send removes on multi-valued
                // attributes (`emails`) we don't model individually.
            }
            _ => {
                // Unknown path — quietly tolerate. IdPs frequently
                // patch attributes that don't exist on our side
                // (`addresses`, `phoneNumbers`); rejecting would block
                // an entire sync.
            }
        }
    }

    // Email collision check.
    if let Some(ref e) = new_email
        && !e.eq_ignore_ascii_case(&user.email)
        && let Some(other) = state.repos.users.find_by_email(e).await?
        && other.id != user.id
    {
        return Err(ScimResponseError::conflict(
            "email already in use by another user",
        ));
    }

    state
        .repos
        .users
        .update(
            user.id,
            UpdateUser {
                email: new_email.clone(),
                display_name: new_display_name.clone(),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await?;

    if let Some(b) = new_active {
        let m = state
            .repos
            .memberships
            .find_by_org_user(org_id, user.id)
            .await?
            .ok_or_else(|| ScimResponseError::not_found("user not in this org"))?;
        let next = if b {
            MembershipStatus::Active
        } else {
            MembershipStatus::Suspended
        };
        state
            .repos
            .memberships
            .update(
                m.id,
                UpdateMembership {
                    role: None,
                    status: Some(next),
                    joined_at: None,
                    updated_at: Some(now),
                },
            )
            .await?;

        // SCIM `active` maps to the global lifecycle. PATCH is partial, so we
        // only touch lifecycle when `active` was explicitly present.
        let current = state
            .repos
            .users
            .find_by_id(user.id)
            .await?
            .ok_or_else(ScimResponseError::internal)?;
        apply_scim_active_lifecycle(state, &current, b, now).await?;
    }

    let fresh = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(ScimResponseError::internal)?;
    let ext = external_id_for(state, org_id, fresh.id).await?;
    let status = state
        .repos
        .memberships
        .find_by_org_user(org_id, fresh.id)
        .await?
        .map(|m| m.status)
        .unwrap_or(MembershipStatus::Active);
    let scim_user = project_user(state, org_id, &fresh, ext.as_ref(), status, vec![]);
    audit_scim(
        state,
        &principal,
        "scim_user_patched",
        &fresh.id.to_string(),
    )
    .await;
    Ok(scim_json_response(StatusCode::OK, scim_user))
}

// ──────────────────────────────────────────────
// DELETE /Users/{id}
// ──────────────────────────────────────────────

pub async fn delete_user(
    State(state): State<YAuthState>,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response {
    match delete_user_inner(&state, org_id, user_id, &headers).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn delete_user_inner(
    state: &YAuthState,
    org_id: Uuid,
    user_id: Uuid,
    headers: &HeaderMap,
) -> Result<Response, ScimResponseError> {
    let principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    let membership = state
        .repos
        .memberships
        .find_by_org_user(org_id, user_id)
        .await?
        .ok_or_else(|| ScimResponseError::not_found("user not in this org"))?;
    state.repos.memberships.delete(membership.id).await?;

    // Also delete the SCIM external-identity link for this org so a
    // subsequent POST with the same externalId provisions cleanly.
    if let Some(ext) = external_id_for(state, org_id, user_id).await? {
        let _ = state.repos.external_identities.delete(ext.id).await;
    }

    // Deprovision is a removal: trip the kill switch so any live access is
    // revoked immediately. We deliberately do NOT set suspended_at here (unlike
    // active:false) so a later re-POST provisions a clean, usable account.
    scim_kill_switch(state, user_id).await;

    audit_scim(state, &principal, "scim_user_deleted", &user_id.to_string()).await;

    // 204 No Content per RFC 7644 §3.6.
    let mut resp = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| Response::new(axum::body::Body::empty()));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(super::error::SCIM_CONTENT_TYPE),
    );
    Ok(resp)
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_pagination_defaults() {
        assert_eq!(clamp_pagination(None, None), (1, DEFAULT_ITEMS_PER_PAGE));
    }

    #[test]
    fn clamp_pagination_clamps_low_start_index() {
        assert_eq!(clamp_pagination(Some(0), None).0, 1);
        assert_eq!(clamp_pagination(Some(-5), None).0, 1);
    }

    #[test]
    fn clamp_pagination_caps_count_at_max() {
        assert_eq!(
            clamp_pagination(None, Some(99_999_999)).1,
            MAX_ITEMS_PER_PAGE
        );
    }

    #[test]
    fn clamp_pagination_allows_large_start_index_no_overflow() {
        let (start, _) = clamp_pagination(Some(99_999_999_999), Some(10));
        assert!(start >= 99_999_999_999_usize);
    }

    #[test]
    fn scim_provider_includes_org() {
        let id = Uuid::nil();
        assert_eq!(scim_provider(id), format!("scim:{id}"));
    }
}
