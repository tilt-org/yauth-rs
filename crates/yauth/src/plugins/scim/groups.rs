//! SCIM Groups endpoint handlers.
//!
//! yauth doesn't have a first-class "group" entity — org membership is
//! a (user, org, role) triple. We expose SCIM Groups as **virtual role
//! buckets**: one Group per built-in role per org.
//!
//! ## Why virtual groups
//!
//! Real IdP-driven group sync (Okta groups, Entra groups) is a
//! superset of what yauth's RBAC currently models. Rather than
//! invent a brand-new `Group` entity in this PR, we project the role
//! roster as groups so an IdP can:
//!
//! 1. List the available "groups" — equivalent to listing built-in
//!    roles (`owner`, `admin`, `billing_admin`, `member`, `viewer`).
//! 2. List members of a group — equivalent to listing memberships with
//!    that role.
//! 3. PATCH a group's members — equivalent to flipping a member's role
//!    to the corresponding role string. Useful for IdP-driven
//!    promote/demote.
//!
//! A future PR can extend this to a real `Group` entity if a customer
//! needs free-form groups; this PR keeps the surface stable while
//! satisfying every mainstream IdP's "group sync" flow.
//!
//! ## Group id encoding
//!
//! The SCIM-side group id is `role:{role_name}` (e.g. `role:admin`). It
//! is stable across reboots and unique per org because the URL path
//! already scopes by org.

#![forbid(unsafe_code)]

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::rbac::roles;
use crate::state::YAuthState;
use yauth_entity::{MembershipStatus, UpdateMembership};

use super::auth::authenticate;
use super::error::{ScimResponseError, scim_json_response};
use super::types::{
    CORE_GROUP_SCHEMA, ListResponse, PATCH_OP_SCHEMA, ResourceMeta, ScimGroup, ScimGroupMember,
    validate_schemas,
};

const GROUP_ID_PREFIX: &str = "role:";

fn role_to_group_id(role: &str) -> String {
    format!("{GROUP_ID_PREFIX}{role}")
}

fn group_id_to_role(group_id: &str) -> Option<&str> {
    group_id.strip_prefix(GROUP_ID_PREFIX)
}

fn group_meta(state: &YAuthState, org_id: Uuid, group_id: &str) -> ResourceMeta {
    let base = state.config.base_url.trim_end_matches('/');
    let now = format!("{}Z", Utc::now().format("%Y-%m-%dT%H:%M:%S"));
    ResourceMeta {
        resource_type: "Group".into(),
        created: now.clone(),
        last_modified: now,
        location: format!("{base}/api/scim/v2/organizations/{org_id}/Groups/{group_id}"),
    }
}

async fn project_group(
    state: &YAuthState,
    org_id: Uuid,
    role: &str,
) -> Result<ScimGroup, ScimResponseError> {
    let memberships = state.repos.memberships.list_by_org(org_id).await?;
    let mut members: Vec<ScimGroupMember> = Vec::new();
    for m in memberships {
        if m.role.eq_ignore_ascii_case(role) && m.status == MembershipStatus::Active {
            let user = match state.repos.users.find_by_id(m.user_id).await? {
                Some(u) => u,
                None => continue,
            };
            members.push(ScimGroupMember {
                value: user.id.to_string(),
                display: user.display_name.clone().or(Some(user.email.clone())),
                r#type: Some("User".into()),
                ref_url: Some(format!(
                    "/api/scim/v2/organizations/{org_id}/Users/{}",
                    user.id
                )),
            });
        }
    }
    let id = role_to_group_id(role);
    Ok(ScimGroup {
        id: Some(id.clone()),
        schemas: vec![CORE_GROUP_SCHEMA.into()],
        external_id: None,
        display_name: Some(role.to_string()),
        members,
        meta: Some(group_meta(state, org_id, &id)),
    })
}

fn known_roles() -> Vec<&'static str> {
    roles::ALL.to_vec()
}

// ──────────────────────────────────────────────
// POST /Groups
// ──────────────────────────────────────────────

/// SCIM Group POST. Since yauth groups are virtual (one per built-in
/// role), this endpoint only accepts a `displayName` that exactly
/// matches a built-in role string. Otherwise 400.
///
/// Idempotent — if the role already exists (it always does), we return
/// the existing group as 200.
pub async fn create_group(
    State(state): State<YAuthState>,
    Path(org_id): Path<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<ScimGroup>,
) -> Response {
    match create_group_inner(&state, org_id, &headers, payload).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn create_group_inner(
    state: &YAuthState,
    org_id: Uuid,
    headers: &HeaderMap,
    payload: ScimGroup,
) -> Result<Response, ScimResponseError> {
    let _principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    if let Err(e) = validate_schemas(&payload.schemas, CORE_GROUP_SCHEMA) {
        return Err(ScimResponseError {
            status: StatusCode::BAD_REQUEST,
            body: e,
        });
    }
    let name = payload
        .display_name
        .as_deref()
        .ok_or_else(|| ScimResponseError::bad_request("displayName required"))?
        .to_ascii_lowercase();
    if !roles::is_builtin(&name) {
        return Err(ScimResponseError::bad_request(format!(
            "yauth supports only built-in role names as groups; got {name}"
        )));
    }
    // Apply members from payload — each becomes a membership in this role.
    if !payload.members.is_empty() {
        let now = Utc::now().naive_utc();
        for member in &payload.members {
            let uid: Uuid = match Uuid::parse_str(&member.value) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let m = state
                .repos
                .memberships
                .find_by_org_user(org_id, uid)
                .await?;
            if let Some(m) = m {
                state
                    .repos
                    .memberships
                    .update(
                        m.id,
                        UpdateMembership {
                            role: Some(name.clone()),
                            status: Some(MembershipStatus::Active),
                            joined_at: None,
                            updated_at: Some(now),
                        },
                    )
                    .await?;
            }
        }
    }
    let group = project_group(state, org_id, &name).await?;
    Ok(scim_json_response(StatusCode::OK, group))
}

// ──────────────────────────────────────────────
// GET /Groups (list)
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListGroupsQuery {
    pub filter: Option<String>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<i64>,
    pub count: Option<i64>,
}

pub async fn list_groups(
    State(state): State<YAuthState>,
    Path(org_id): Path<Uuid>,
    Query(q): Query<ListGroupsQuery>,
    headers: HeaderMap,
) -> Response {
    match list_groups_inner(&state, org_id, q, &headers).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn list_groups_inner(
    state: &YAuthState,
    org_id: Uuid,
    q: ListGroupsQuery,
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
    let (start_index, count) = super::users::clamp_pagination(q.start_index, q.count);

    let mut groups: Vec<ScimGroup> = Vec::new();
    for role in known_roles() {
        let g = project_group(state, org_id, role).await?;
        if let Some(f) = &parsed_filter {
            let matched = f.matches(|atom| match atom.attr.to_ascii_lowercase().as_str() {
                "displayname" => g
                    .display_name
                    .as_deref()
                    .map(|d| atom.value.matches_string(atom.op, d))
                    .unwrap_or(false),
                "id" => {
                    g.id.as_deref()
                        .map(|d| atom.value.matches_string(atom.op, d))
                        .unwrap_or(false)
                }
                _ => false,
            });
            if !matched {
                continue;
            }
        }
        groups.push(g);
    }
    let total = groups.len();
    let skip = start_index.saturating_sub(1);
    let page: Vec<_> = groups.into_iter().skip(skip).take(count).collect();
    Ok(scim_json_response(
        StatusCode::OK,
        ListResponse::new(total, start_index, page.len(), page),
    ))
}

// ──────────────────────────────────────────────
// GET /Groups/{id}
// ──────────────────────────────────────────────

pub async fn get_group(
    State(state): State<YAuthState>,
    Path((org_id, group_id)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Response {
    match get_group_inner(&state, org_id, &group_id, &headers).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn get_group_inner(
    state: &YAuthState,
    org_id: Uuid,
    group_id: &str,
    headers: &HeaderMap,
) -> Result<Response, ScimResponseError> {
    let _principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    let role = group_id_to_role(group_id)
        .ok_or_else(|| ScimResponseError::not_found("group id must have form role:<name>"))?;
    if !roles::is_builtin(&role.to_ascii_lowercase()) {
        return Err(ScimResponseError::not_found("group does not exist"));
    }
    let g = project_group(state, org_id, role).await?;
    Ok(scim_json_response(StatusCode::OK, g))
}

// ──────────────────────────────────────────────
// PUT /Groups/{id}
// ──────────────────────────────────────────────

pub async fn put_group(
    State(state): State<YAuthState>,
    Path((org_id, group_id)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Json(payload): Json<ScimGroup>,
) -> Response {
    match put_group_inner(&state, org_id, &group_id, &headers, payload).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn put_group_inner(
    state: &YAuthState,
    org_id: Uuid,
    group_id: &str,
    headers: &HeaderMap,
    payload: ScimGroup,
) -> Result<Response, ScimResponseError> {
    let _principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    if let Err(e) = validate_schemas(&payload.schemas, CORE_GROUP_SCHEMA) {
        return Err(ScimResponseError {
            status: StatusCode::BAD_REQUEST,
            body: e,
        });
    }
    let role = group_id_to_role(group_id)
        .ok_or_else(|| ScimResponseError::not_found("group does not exist"))?;
    if !roles::is_builtin(&role.to_ascii_lowercase()) {
        return Err(ScimResponseError::not_found("group does not exist"));
    }
    // PUT replaces the full membership set for this group. Members
    // listed → set to this role. Members previously in this role but
    // NOT in the payload → demoted to `MEMBER` (yauth doesn't have an
    // "ungrouped" state; demoting is the safest interpretation).
    let now = Utc::now().naive_utc();
    let memberships = state.repos.memberships.list_by_org(org_id).await?;
    let target_uuids: std::collections::HashSet<Uuid> = payload
        .members
        .iter()
        .filter_map(|m| Uuid::parse_str(&m.value).ok())
        .collect();
    for m in memberships {
        let in_target = target_uuids.contains(&m.user_id);
        if in_target && !m.role.eq_ignore_ascii_case(role) {
            state
                .repos
                .memberships
                .update(
                    m.id,
                    UpdateMembership {
                        role: Some(role.to_string()),
                        status: Some(MembershipStatus::Active),
                        joined_at: None,
                        updated_at: Some(now),
                    },
                )
                .await?;
        } else if !in_target && m.role.eq_ignore_ascii_case(role) {
            state
                .repos
                .memberships
                .update(
                    m.id,
                    UpdateMembership {
                        role: Some(roles::MEMBER.to_string()),
                        status: None,
                        joined_at: None,
                        updated_at: Some(now),
                    },
                )
                .await?;
        }
    }
    let g = project_group(state, org_id, role).await?;
    Ok(scim_json_response(StatusCode::OK, g))
}

// ──────────────────────────────────────────────
// PATCH /Groups/{id}
// ──────────────────────────────────────────────

pub async fn patch_group(
    State(state): State<YAuthState>,
    Path((org_id, group_id)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Json(payload): Json<super::types::PatchOp>,
) -> Response {
    match patch_group_inner(&state, org_id, &group_id, &headers, payload).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn patch_group_inner(
    state: &YAuthState,
    org_id: Uuid,
    group_id: &str,
    headers: &HeaderMap,
    payload: super::types::PatchOp,
) -> Result<Response, ScimResponseError> {
    let _principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    if let Err(e) = validate_schemas(&payload.schemas, PATCH_OP_SCHEMA) {
        return Err(ScimResponseError {
            status: StatusCode::BAD_REQUEST,
            body: e,
        });
    }
    let role = group_id_to_role(group_id)
        .ok_or_else(|| ScimResponseError::not_found("group does not exist"))?;
    if !roles::is_builtin(&role.to_ascii_lowercase()) {
        return Err(ScimResponseError::not_found("group does not exist"));
    }
    let now = Utc::now().naive_utc();

    for op in payload.operations {
        let op_lc = op.op.to_ascii_lowercase();
        let path_lc = op
            .path
            .as_deref()
            .map(|p| p.to_ascii_lowercase())
            .unwrap_or_default();
        match (op_lc.as_str(), path_lc.as_str()) {
            ("add", "members") => {
                if let Some(arr) = op.value.as_ref().and_then(|v| v.as_array()) {
                    for entry in arr {
                        if let Some(val) = entry.get("value").and_then(|v| v.as_str())
                            && let Ok(uid) = Uuid::parse_str(val)
                        {
                            let m = state
                                .repos
                                .memberships
                                .find_by_org_user(org_id, uid)
                                .await?;
                            if let Some(m) = m {
                                state
                                    .repos
                                    .memberships
                                    .update(
                                        m.id,
                                        UpdateMembership {
                                            role: Some(role.to_string()),
                                            status: Some(MembershipStatus::Active),
                                            joined_at: None,
                                            updated_at: Some(now),
                                        },
                                    )
                                    .await?;
                            }
                        }
                    }
                }
            }
            ("remove", p) if p.starts_with("members") => {
                // RFC 7644 PATCH on multi-valued: `members[value eq
                // "uuid"]` or `members` with value array. We accept
                // both forms — IdPs send a mix.
                if let Some(arr) = op.value.as_ref().and_then(|v| v.as_array()) {
                    for entry in arr {
                        if let Some(val) = entry.get("value").and_then(|v| v.as_str())
                            && let Ok(uid) = Uuid::parse_str(val)
                        {
                            demote(state, org_id, uid, now).await?;
                        }
                    }
                }
                // Filter form: members[value eq "..."]
                if let Some(needle) = parse_member_filter_eq(p)
                    && let Ok(uid) = Uuid::parse_str(needle)
                {
                    demote(state, org_id, uid, now).await?;
                }
            }
            ("replace", "displayname") => {
                // Renaming a built-in role is rejected — would break
                // RBAC. Tolerate but ignore (some IdPs PUT-then-PATCH
                // displayName redundantly).
            }
            _ => {
                // Unknown ops on Groups are tolerated.
            }
        }
    }

    let g = project_group(state, org_id, role).await?;
    Ok(scim_json_response(StatusCode::OK, g))
}

/// Parse `members[value eq "<uuid>"]` into the uuid string.
fn parse_member_filter_eq(path: &str) -> Option<&str> {
    let start = path.find("value eq \"")? + "value eq \"".len();
    let rest = &path[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

async fn demote(
    state: &YAuthState,
    org_id: Uuid,
    uid: Uuid,
    now: chrono::NaiveDateTime,
) -> Result<(), ScimResponseError> {
    if let Some(m) = state
        .repos
        .memberships
        .find_by_org_user(org_id, uid)
        .await?
    {
        state
            .repos
            .memberships
            .update(
                m.id,
                UpdateMembership {
                    role: Some(roles::MEMBER.to_string()),
                    status: None,
                    joined_at: None,
                    updated_at: Some(now),
                },
            )
            .await?;
    }
    Ok(())
}

// ──────────────────────────────────────────────
// DELETE /Groups/{id}
// ──────────────────────────────────────────────

/// DELETE on a built-in role is meaningless (the role is implicit in
/// the role taxonomy). We treat it as "demote everyone in this role
/// to MEMBER" — matches what an IdP admin probably means by
/// "remove the group". Returns 204.
pub async fn delete_group(
    State(state): State<YAuthState>,
    Path((org_id, group_id)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Response {
    match delete_group_inner(&state, org_id, &group_id, &headers).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn delete_group_inner(
    state: &YAuthState,
    org_id: Uuid,
    group_id: &str,
    headers: &HeaderMap,
) -> Result<Response, ScimResponseError> {
    let _principal = authenticate(state, header_value(headers, "authorization"), org_id).await?;
    let role = group_id_to_role(group_id)
        .ok_or_else(|| ScimResponseError::not_found("group does not exist"))?;
    if !roles::is_builtin(&role.to_ascii_lowercase()) {
        return Err(ScimResponseError::not_found("group does not exist"));
    }
    let now = Utc::now().naive_utc();
    let memberships = state.repos.memberships.list_by_org(org_id).await?;
    for m in memberships {
        if m.role.eq_ignore_ascii_case(role) {
            state
                .repos
                .memberships
                .update(
                    m.id,
                    UpdateMembership {
                        role: Some(roles::MEMBER.to_string()),
                        status: None,
                        joined_at: None,
                        updated_at: Some(now),
                    },
                )
                .await?;
        }
    }
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

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_round_trip() {
        for r in known_roles() {
            let id = role_to_group_id(r);
            assert_eq!(group_id_to_role(&id), Some(r));
        }
    }

    #[test]
    fn parse_member_filter_eq_handles_uuid() {
        let path = "members[value eq \"00000000-0000-0000-0000-000000000000\"]";
        assert_eq!(
            parse_member_filter_eq(path),
            Some("00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn parse_member_filter_eq_returns_none_on_garbage() {
        assert!(parse_member_filter_eq("bogus").is_none());
    }
}
