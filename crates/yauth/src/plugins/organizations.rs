//! Organizations plugin (issues #87, #88) — multi-tenancy + RBAC.
//!
//! Adds organization CRUD + membership listing + invitation create/accept
//! (#87) plus the org-scoped RBAC surface (#88): change-role,
//! transfer-ownership, list-permissions. With the `organizations` Cargo
//! feature off, none of this is compiled and the routes are not mounted.
//!
//! Role enforcement lives in [`crate::auth::rbac`]. This module wires the
//! enforcement helpers into the route handlers and exposes the RBAC
//! endpoints.

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::crypto;
use crate::auth::rbac::{self, roles};
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::repo::RepoError;
use crate::state::YAuthState;
use yauth_entity::{
    DomainStatus, Invitation, Membership, MembershipStatus, NewInvitation, NewMembership,
    NewOrganization, NewOrganizationDomain, Organization, OrganizationDomain, UpdateMembership,
    UpdateOrganization, UpdateOrganizationDomain, domain_from_email,
};

use crate::auth::domain_verifier;

const INVITATION_TTL_HOURS: i64 = 168; // 7 days

// Rate limit budgets (security review H-3). Conservative defaults; will be
// surfaced via `OrganizationsConfig` in a follow-up if tenants need to tune.
//
// Format: `(max_requests, window_seconds)`.
const RATE_LIMIT_ORG_CREATE: (u32, u64) = (20, 3600); // 20 / hour / user
const RATE_LIMIT_INVITATION_CREATE: (u32, u64) = (50, 3600); // 50 / hour / org
const RATE_LIMIT_MEMBER_LIST: (u32, u64) = (100, 60); // 100 / minute / user
// Issue #90: domain claim + verify rate limits. Conservative defaults; domain
// claim is a once-or-twice-per-tenant operation, verify is a manual retry button.
const RATE_LIMIT_DOMAIN_CLAIM: (u32, u64) = (10, 3600); // 10 / hour / org
const RATE_LIMIT_DOMAIN_VERIFY: (u32, u64) = (60, 3600); // 60 / hour / org

/// Plugin entry point. Mounts org CRUD routes on the protected router.
pub struct OrganizationsPlugin;

impl YAuthPlugin for OrganizationsPlugin {
    fn name(&self) -> &'static str {
        "organizations"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/organizations", get(list_orgs).post(create_org))
                .route(
                    "/organizations/{id}",
                    get(get_org).patch(update_org).delete(delete_org),
                )
                .route("/organizations/{id}/members", get(list_members))
                .route(
                    "/organizations/{id}/members/{user_id}/role",
                    post(change_member_role),
                )
                .route(
                    "/organizations/{id}/members/{user_id}",
                    axum::routing::delete(remove_member),
                )
                .route(
                    "/organizations/{id}/transfer-ownership",
                    post(transfer_ownership_route),
                )
                .route("/organizations/{id}/permissions", get(list_my_permissions))
                .route("/organizations/{id}/invitations", post(create_invitation))
                .route("/invitations/accept", post(accept_invitation))
                // ── Issue #90: verified email domains ─────────────────
                .route(
                    "/organizations/{id}/domains",
                    get(list_domains).post(create_domain),
                )
                .route(
                    "/organizations/{id}/domains/{did}",
                    axum::routing::patch(update_domain).delete(delete_domain),
                )
                .route(
                    "/organizations/{id}/domains/{did}/verify",
                    post(verify_domain_route),
                )
                // ── Issue #91: org-scoped API keys (service accounts) ──
                // Only mount when the api-key plugin is also enabled.
                .merge(api_keys_router())
                // ── Issue #89: active-org switcher ─────────────────────
                .route(
                    "/sessions/active-org",
                    get(get_active_org)
                        .post(set_active_org_route)
                        .delete(clear_active_org),
                ),
        )
    }
}

// ──────────────────────────────────────────────
// Request/response shapes
// ──────────────────────────────────────────────

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateOrgRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub display_name: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OrganizationResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

impl From<Organization> for OrganizationResponse {
    fn from(o: Organization) -> Self {
        Self {
            id: o.id,
            name: o.name,
            slug: o.slug,
            display_name: o.display_name,
            avatar_url: o.avatar_url,
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
    }
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MembershipResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub status: String,
    pub joined_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
}

impl From<Membership> for MembershipResponse {
    fn from(m: Membership) -> Self {
        Self {
            id: m.id,
            organization_id: m.organization_id,
            user_id: m.user_id,
            role: m.role,
            status: m.status.as_str().to_string(),
            joined_at: m.joined_at,
            created_at: m.created_at,
        }
    }
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateInvitationResponse {
    pub invitation: InvitationResponse,
    /// Plaintext token — returned exactly once at creation. Caller is
    /// responsible for delivering it to the invitee (email, etc.).
    pub token: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InvitationResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: String,
    pub expires_at: chrono::NaiveDateTime,
    pub created_at: chrono::NaiveDateTime,
}

impl From<Invitation> for InvitationResponse {
    fn from(i: Invitation) -> Self {
        Self {
            id: i.id,
            organization_id: i.organization_id,
            email: i.email,
            role: i.role,
            expires_at: i.expires_at,
            created_at: i.created_at,
        }
    }
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AcceptInvitationRequest {
    pub token: String,
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

fn forbid(msg: &str) -> ApiError {
    api_err(StatusCode::FORBIDDEN, msg)
}

/// Run a rate-limit check and return `429 Too Many Requests` if the budget
/// is exhausted. A repo error never blocks the request — we fail open so a
/// flaky rate-limit backend doesn't take down org management.
async fn enforce_rate_limit(
    state: &YAuthState,
    key: &str,
    limit: u32,
    window_secs: u64,
) -> Result<(), ApiError> {
    let allowed = state
        .repos
        .rate_limits
        .check_rate_limit(key, limit, window_secs)
        .await
        .map(|r| r.allowed)
        .unwrap_or(true);
    if !allowed {
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }
    Ok(())
}

/// Admin-or-owner gate — both roles can mutate org-management state.
async fn require_org_admin(
    state: &YAuthState,
    user: &AuthUser,
    org_id: Uuid,
) -> Result<rbac::OrgRole, ApiError> {
    rbac::require_org_admin_or_owner(&state.repos, user, org_id).await
}

fn perm_id(p: rbac::Permission) -> &'static str {
    use rbac::BillingPerm::*;
    use rbac::MemberPerm::*;
    use rbac::SettingsPerm::*;
    match p {
        rbac::Permission::Members(Invite) => "members:invite",
        rbac::Permission::Members(Remove) => "members:remove",
        rbac::Permission::Members(ChangeRole) => "members:change_role",
        rbac::Permission::Billing(View) => "billing:view",
        rbac::Permission::Billing(Update) => "billing:update",
        rbac::Permission::Billing(Cancel) => "billing:cancel",
        rbac::Permission::Settings(Read) => "settings:read",
        rbac::Permission::Settings(Write) => "settings:write",
    }
}

// ──────────────────────────────────────────────
// Handlers
// ──────────────────────────────────────────────

async fn create_org(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateOrgRequest>,
) -> Result<(StatusCode, Json<OrganizationResponse>), ApiError> {
    // H-3: rate-limit per-user to prevent enumeration/DoS.
    let (limit, window) = RATE_LIMIT_ORG_CREATE;
    enforce_rate_limit(&state, &format!("org-create:{}", user.id), limit, window).await?;

    if req.name.trim().is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "name is required"));
    }
    if req.slug.trim().is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "slug is required"));
    }
    let now = Utc::now().naive_utc();
    let org_id = Uuid::now_v7();
    let org = state
        .repos
        .organizations
        .create(NewOrganization {
            id: org_id,
            name: req.name,
            slug: req.slug,
            display_name: req.display_name,
            avatar_url: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .map_err(|e| match e {
            RepoError::Conflict(msg) => api_err(StatusCode::CONFLICT, &msg),
            other => other.into(),
        })?;

    // Creator becomes the org owner automatically (RBAC #88: every org has
    // exactly one owner). Demotion/removal is blocked by the owner-protection
    // guard until ownership is transferred via
    // `POST /organizations/:id/transfer-ownership`.
    state
        .repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org.id,
            user_id: user.id,
            role: roles::OWNER.to_string(),
            status: MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await?;

    Ok((StatusCode::CREATED, Json(org.into())))
}

async fn list_orgs(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<OrganizationResponse>>, ApiError> {
    let orgs = state.repos.organizations.list_for_user(user.id).await?;
    Ok(Json(orgs.into_iter().map(Into::into).collect()))
}

async fn get_org(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    // Membership gate.
    state
        .repos
        .memberships
        .find_by_org_user(id, user.id)
        .await?
        .ok_or_else(|| forbid("not a member of this organization"))?;

    let org = state
        .repos
        .organizations
        .find_by_id(id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "organization not found"))?;
    Ok(Json(org.into()))
}

async fn update_org(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateOrgRequest>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    require_org_admin(&state, &user, id).await?;
    let now = Utc::now().naive_utc();
    let updated = state
        .repos
        .organizations
        .update(
            id,
            UpdateOrganization {
                name: req.name,
                slug: req.slug,
                display_name: req.display_name,
                avatar_url: req.avatar_url,
                metadata: None,
                updated_at: Some(now),
            },
        )
        .await
        .map_err(|e| match e {
            RepoError::Conflict(msg) => api_err(StatusCode::CONFLICT, &msg),
            other => other.into(),
        })?;
    Ok(Json(updated.into()))
}

async fn delete_org(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_org_admin(&state, &user, id).await?;
    state.repos.organizations.delete(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_members(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<MembershipResponse>>, ApiError> {
    // H-3: soft rate-limit per-user to prevent enumeration grinding.
    let (limit, window) = RATE_LIMIT_MEMBER_LIST;
    enforce_rate_limit(&state, &format!("org-members:{}", user.id), limit, window).await?;

    state
        .repos
        .memberships
        .find_by_org_user(id, user.id)
        .await?
        .ok_or_else(|| forbid("not a member of this organization"))?;
    let members = state.repos.memberships.list_by_org(id).await?;
    Ok(Json(members.into_iter().map(Into::into).collect()))
}

async fn create_invitation(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<CreateInvitationResponse>), ApiError> {
    require_org_admin(&state, &user, id).await?;
    // H-3: rate-limit per-org. Invitations typically trigger outbound email
    // delivery in consuming apps, which makes this both a DoS vector and a
    // potential spam amplifier.
    let (limit, window) = RATE_LIMIT_INVITATION_CREATE;
    enforce_rate_limit(&state, &format!("org-invite:{id}"), limit, window).await?;

    if req.email.trim().is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "email is required"));
    }
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let now = Utc::now().naive_utc();
    let expires_at = now + chrono::Duration::hours(INVITATION_TTL_HOURS);
    let role = req.role.unwrap_or_else(|| roles::MEMBER.to_string());

    let inv = state
        .repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: id,
            email: req.email,
            role,
            token_hash,
            invited_by_user_id: user.id,
            expires_at,
            accepted_at: None,
            created_at: now,
        })
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateInvitationResponse {
            invitation: inv.into(),
            token,
        }),
    ))
}

async fn accept_invitation(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<AcceptInvitationRequest>,
) -> Result<(StatusCode, Json<MembershipResponse>), ApiError> {
    let token_hash = crypto::hash_token(&req.token);
    let inv = state
        .repos
        .invitations
        .find_by_token_hash(&token_hash)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "invitation not found or expired"))?;

    // Email check is intentionally case-insensitive — IdP-driven email
    // capitalization should not block accept.
    if inv.email.to_lowercase() != user.email.to_lowercase() {
        return Err(forbid("invitation email does not match authenticated user"));
    }

    // H-2: require email verification before accepting an invitation. Without
    // this gate, an attacker who registers `victim@partner.com` without
    // verifying it can be admitted to the partner org once the legitimate
    // invitation email is delivered. Verification proves the actor controls
    // the mailbox, closing the account-takeover-by-invite path.
    if !user.email_verified {
        return Err(forbid(
            "Verify your email address before accepting an organization invitation.",
        ));
    }

    let now = Utc::now().naive_utc();
    state.repos.invitations.mark_accepted(inv.id, now).await?;

    let membership = state
        .repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: inv.organization_id,
            user_id: user.id,
            role: inv.role,
            status: MembershipStatus::Active,
            invited_at: Some(inv.created_at),
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await
        .map_err(|e| match e {
            RepoError::Conflict(_) => api_err(
                StatusCode::CONFLICT,
                "already a member of this organization",
            ),
            other => other.into(),
        })?;

    Ok((StatusCode::CREATED, Json(membership.into())))
}

// ──────────────────────────────────────────────
// RBAC (issue #88) — change role, transfer ownership, list permissions
// ──────────────────────────────────────────────

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChangeRoleRequest {
    /// New role to assign. Must be a built-in role (`admin`,
    /// `billing_admin`, `member`, `viewer`) or a custom string the
    /// application recognizes. `owner` is rejected — use the
    /// transfer-ownership endpoint instead.
    pub role: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TransferOwnershipRequest {
    /// UUID of the existing member who should become the new owner.
    pub new_owner_user_id: Uuid,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PermissionsResponse {
    pub organization_id: Uuid,
    pub role: String,
    /// Permission identifiers in `domain:verb` form (e.g.
    /// `members:invite`, `billing:view`). Stable identifiers — safe to
    /// pin in UI guards.
    pub permissions: Vec<String>,
}

/// `POST /organizations/:id/members/:user_id/role` — change a member's
/// role.
///
/// Caller must hold the `members:change_role` permission. Demoting the
/// last owner without an ownership transfer is rejected with 409.
/// Promoting to `owner` is rejected — callers must use
/// `/transfer-ownership`.
async fn change_member_role(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path((id, target_user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<ChangeRoleRequest>,
) -> Result<Json<MembershipResponse>, ApiError> {
    rbac::require_org_permission(
        &state.repos,
        &user,
        id,
        rbac::Permission::Members(rbac::MemberPerm::ChangeRole),
    )
    .await?;

    let new_role = req.role.trim();
    if new_role.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "role is required"));
    }

    let target = state
        .repos
        .memberships
        .find_by_org_user(id, target_user_id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "member not found"))?;

    // Owner-protection: cannot demote the last owner, cannot promote
    // anyone to owner via this endpoint.
    rbac::guard_role_change(&state.repos, id, target.id, new_role).await?;

    let now = Utc::now().naive_utc();
    let updated = state
        .repos
        .memberships
        .update(
            target.id,
            UpdateMembership {
                role: Some(new_role.to_string()),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await?;
    Ok(Json(updated.into()))
}

/// `DELETE /organizations/:id/members/:user_id` — remove a member from
/// the org.
///
/// Caller must hold the `members:remove` permission. Removing the last
/// owner is rejected; the owner must transfer ownership first.
async fn remove_member(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path((id, target_user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    rbac::require_org_permission(
        &state.repos,
        &user,
        id,
        rbac::Permission::Members(rbac::MemberPerm::Remove),
    )
    .await?;

    let target = state
        .repos
        .memberships
        .find_by_org_user(id, target_user_id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "member not found"))?;

    rbac::guard_delete(&state.repos, id, target.id).await?;
    state.repos.memberships.delete(target.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /organizations/:id/transfer-ownership` — transfer ownership of
/// the org to another existing member.
///
/// Caller must be the current owner. Target must already be a member.
/// On success the previous owner is demoted to `admin` and the target
/// becomes `owner`.
async fn transfer_ownership_route(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(req): Json<TransferOwnershipRequest>,
) -> Result<StatusCode, ApiError> {
    rbac::require_org_role(&state.repos, &user, id, roles::OWNER).await?;
    rbac::transfer_ownership(&state.repos, id, user.id, req.new_owner_user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /organizations/:id/permissions` — list the calling user's
/// effective permissions in this org.
///
/// Useful for frontends that want to render conditional UI without
/// hardcoding role logic. Returns 403 if the caller is not a member.
async fn list_my_permissions(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<PermissionsResponse>, ApiError> {
    let cur = rbac::get_org_role(&state.repos, id, user.id).await?;
    let pset = rbac::default_permissions(&cur.role);
    let mut perms: Vec<String> = Vec::new();
    for p in &pset.members {
        perms.push(perm_id(rbac::Permission::Members(*p)).to_string());
    }
    for p in &pset.billing {
        perms.push(perm_id(rbac::Permission::Billing(*p)).to_string());
    }
    for p in &pset.settings {
        perms.push(perm_id(rbac::Permission::Settings(*p)).to_string());
    }
    Ok(Json(PermissionsResponse {
        organization_id: id,
        role: cur.role,
        permissions: perms,
    }))
}

// ──────────────────────────────────────────────
// Active-org switcher (issue #89)
// ──────────────────────────────────────────────

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SetActiveOrgRequest {
    pub organization_id: Uuid,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ActiveOrgEntry {
    pub organization_id: Uuid,
    pub role: String,
    pub slug: Option<String>,
    pub display_name: Option<String>,
}

/// Response payload for the active-org switcher endpoints.
///
/// `active_org_id` is the currently-active org (or `None` if cleared).
/// `orgs` is the full membership list the caller can switch into — small
/// and bounded, so we always return it (saves a follow-up roundtrip when
/// rendering an org picker).
///
/// `bearer_access_token` is populated ONLY for bearer-auth callers on
/// switch: cookie sessions update server-side and need no token rotation,
/// while JWT bearer requires a freshly-issued token carrying the new
/// `org`/`role`/`orgs` claims.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ActiveOrgResponse {
    pub active_org_id: Option<Uuid>,
    pub orgs: Vec<ActiveOrgEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_access_token: Option<String>,
}

/// Build the response body. Looks up org slugs to make the payload
/// directly UI-renderable. Best-effort on slug lookups — a deleted org
/// surfaces as `slug = None` rather than 500'ing the whole switcher.
async fn build_active_org_response(
    state: &YAuthState,
    user_id: Uuid,
    active_org_id: Option<Uuid>,
    bearer_token: Option<String>,
) -> Result<ActiveOrgResponse, ApiError> {
    let memberships = state
        .repos
        .memberships
        .list_by_user(user_id)
        .await?
        .into_iter()
        .filter(|m| m.status == MembershipStatus::Active);

    let mut orgs = Vec::new();
    for m in memberships {
        let org = state
            .repos
            .organizations
            .find_by_id(m.organization_id)
            .await
            .ok()
            .flatten();
        orgs.push(ActiveOrgEntry {
            organization_id: m.organization_id,
            role: m.role,
            slug: org.as_ref().map(|o| o.slug.clone()),
            display_name: org.and_then(|o| o.display_name),
        });
    }

    Ok(ActiveOrgResponse {
        active_org_id,
        orgs,
        bearer_access_token: bearer_token,
    })
}

/// `GET /sessions/active-org` — return the caller's active org plus the
/// membership list. Works for both cookie and bearer auth.
async fn get_active_org(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<ActiveOrgResponse>, ApiError> {
    build_active_org_response(&state, user.id, user.active_org_id, None)
        .await
        .map(Json)
}

/// `POST /sessions/active-org` — switch into an organization.
///
/// Authorization: caller must be an active member of the target org —
/// non-members get `403`. The 403 is the pentest acceptance criterion
/// from issue #89.
///
/// Carrier semantics:
/// - **Cookie session** — update the `active_org_id` column on the
///   session row. No cookie rotation; the existing cookie continues to
///   work.
/// - **Bearer JWT** — issue a NEW access token with refreshed `org`,
///   `role`, `orgs` claims. The old token keeps working until expiry
///   (clients must adopt the new one).
async fn set_active_org_route(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    jar: CookieJar,
    Json(req): Json<SetActiveOrgRequest>,
) -> Result<Json<ActiveOrgResponse>, ApiError> {
    // Authorization: must be an active member of the target org.
    let membership = state
        .repos
        .memberships
        .find_by_org_user(req.organization_id, user.id)
        .await?
        .filter(|m| m.status == MembershipStatus::Active)
        .ok_or_else(|| forbid("not a member of this organization"))?;

    let mut bearer_token: Option<String> = None;

    match user.auth_method {
        crate::middleware::AuthMethod::Session => {
            // Resolve the current session id from the cookie so we know
            // which row to mutate.
            let cookie = jar
                .get(&state.config.session_cookie_name)
                .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Session cookie missing"))?;
            let token_hash = crate::auth::crypto::hash_token(cookie.value());
            let session = state
                .repos
                .session_ops
                .validate_session(&token_hash)
                .await?
                .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Session expired"))?;
            state
                .repos
                .session_ops
                .set_active_org(session.id, Some(req.organization_id))
                .await?;
        }
        crate::middleware::AuthMethod::Bearer => {
            // Re-issue a JWT with the new active org baked in. Client
            // MUST adopt the new token; the old one keeps validating
            // (carries the old `org` claim) until exp.
            #[cfg(feature = "bearer")]
            {
                let all_orgs: Vec<Uuid> = state
                    .repos
                    .memberships
                    .list_by_user(user.id)
                    .await?
                    .into_iter()
                    .filter(|m| m.status == MembershipStatus::Active)
                    .map(|m| m.organization_id)
                    .collect();
                let jwt_user = crate::plugins::bearer::JwtUser {
                    id: user.id,
                    email: user.email.clone(),
                    role: user.role.clone(),
                    active_org_id: Some(req.organization_id),
                    org_role: Some(membership.role.clone()),
                    all_orgs,
                };
                let (token, _) = crate::plugins::bearer::create_jwt(&jwt_user, &state, None)?;
                bearer_token = Some(token);
            }
        }
        crate::middleware::AuthMethod::ApiKey => {
            // Issue #89: API keys are org-scoped at creation time —
            // switching is intentionally not supported.
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "API key sessions cannot switch active org",
            ));
        }
    }
    let _ = membership; // Suppress unused warning on the non-bearer path.

    state
        .write_audit_log(
            Some(user.id),
            "active_org_switched",
            Some(serde_json::json!({ "organization_id": req.organization_id })),
            None,
        )
        .await;

    build_active_org_response(&state, user.id, Some(req.organization_id), bearer_token)
        .await
        .map(Json)
}

/// `DELETE /sessions/active-org` — clear the active org. Returns to the
/// "no active org" state (legacy single-tenant path runs in app code).
async fn clear_active_org(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    jar: CookieJar,
) -> Result<Json<ActiveOrgResponse>, ApiError> {
    let mut bearer_token: Option<String> = None;
    match user.auth_method {
        crate::middleware::AuthMethod::Session => {
            let cookie = jar
                .get(&state.config.session_cookie_name)
                .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Session cookie missing"))?;
            let token_hash = crate::auth::crypto::hash_token(cookie.value());
            let session = state
                .repos
                .session_ops
                .validate_session(&token_hash)
                .await?
                .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Session expired"))?;
            state
                .repos
                .session_ops
                .set_active_org(session.id, None)
                .await?;
        }
        crate::middleware::AuthMethod::Bearer => {
            #[cfg(feature = "bearer")]
            {
                let all_orgs: Vec<Uuid> = state
                    .repos
                    .memberships
                    .list_by_user(user.id)
                    .await?
                    .into_iter()
                    .filter(|m| m.status == MembershipStatus::Active)
                    .map(|m| m.organization_id)
                    .collect();
                let jwt_user = crate::plugins::bearer::JwtUser {
                    id: user.id,
                    email: user.email.clone(),
                    role: user.role.clone(),
                    active_org_id: None,
                    org_role: None,
                    all_orgs,
                };
                let (token, _) = crate::plugins::bearer::create_jwt(&jwt_user, &state, None)?;
                bearer_token = Some(token);
            }
        }
        crate::middleware::AuthMethod::ApiKey => {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "API key sessions cannot clear active org",
            ));
        }
    }

    build_active_org_response(&state, user.id, None, bearer_token)
        .await
        .map(Json)
}

// ──────────────────────────────────────────────
// Verified email domains (issue #90)
// ──────────────────────────────────────────────

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateDomainRequest {
    /// Domain to claim (e.g. `"acme.com"`). Canonicalized to lowercase.
    pub domain: String,
    /// Auto-add matching users to the org on signup / email verification.
    /// Defaults to `false` — the org must explicitly opt in.
    #[serde(default)]
    pub auto_join_on_signup: bool,
    /// Role granted on auto-join. Defaults to `"member"`.
    #[serde(default)]
    pub default_role_on_auto_join: Option<String>,
    /// Auto-join only after the user has verified their address.
    /// Defaults to `true` (anti-abuse).
    #[serde(default)]
    pub require_email_verified: Option<bool>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDomainRequest {
    pub auto_join_on_signup: Option<bool>,
    pub default_role_on_auto_join: Option<String>,
    pub require_email_verified: Option<bool>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DomainResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub domain: String,
    pub status: String,
    pub verified_at: Option<chrono::NaiveDateTime>,
    pub last_checked_at: Option<chrono::NaiveDateTime>,
    pub auto_join_on_signup: bool,
    pub default_role_on_auto_join: String,
    pub require_email_verified: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

impl From<OrganizationDomain> for DomainResponse {
    fn from(d: OrganizationDomain) -> Self {
        Self {
            id: d.id,
            organization_id: d.organization_id,
            domain: d.domain,
            status: d.status.as_str().to_string(),
            verified_at: d.verified_at,
            last_checked_at: d.last_checked_at,
            auto_join_on_signup: d.auto_join_on_signup,
            default_role_on_auto_join: d.default_role_on_auto_join,
            require_email_verified: d.require_email_verified,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// Returned by `POST /organizations/:id/domains` — wraps the claim plus
/// the **verification token**, which is returned exactly once at claim
/// time. Clients must surface it to the operator so they can publish the
/// DNS TXT record `_yauth-domain-verify.<domain>` containing the token.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateDomainResponse {
    pub domain: DomainResponse,
    pub verification_token: String,
    pub dns_record_name: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyDomainResponse {
    pub domain: DomainResponse,
    pub verified: bool,
}

async fn create_domain(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<CreateDomainResponse>), ApiError> {
    require_org_admin(&state, &user, id).await?;
    let (limit, window) = RATE_LIMIT_DOMAIN_CLAIM;
    enforce_rate_limit(&state, &format!("org-domain-claim:{id}"), limit, window).await?;

    let canonical = req.domain.trim().to_lowercase();
    if canonical.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "domain is required"));
    }
    // Basic shape gate — reject obvious garbage. Real validity is enforced
    // by DNS lookup at verify time.
    if !canonical.contains('.') || canonical.contains(char::is_whitespace) {
        return Err(api_err(StatusCode::BAD_REQUEST, "invalid domain"));
    }

    let token = crypto::generate_token();
    let now = Utc::now().naive_utc();
    let domain = state
        .repos
        .organization_domains
        .create(NewOrganizationDomain {
            id: Uuid::now_v7(),
            organization_id: id,
            domain: canonical.clone(),
            status: DomainStatus::Pending,
            verification_token: token.clone(),
            verified_at: None,
            last_checked_at: None,
            auto_join_on_signup: req.auto_join_on_signup,
            default_role_on_auto_join: req
                .default_role_on_auto_join
                .unwrap_or_else(|| roles::MEMBER.to_string()),
            // Anti-abuse default: require verified email for auto-join.
            require_email_verified: req.require_email_verified.unwrap_or(true),
            created_at: now,
            updated_at: now,
        })
        .await
        .map_err(|e| match e {
            RepoError::Conflict(msg) => api_err(StatusCode::CONFLICT, &msg),
            other => other.into(),
        })?;

    state
        .write_audit_log(
            Some(user.id),
            "org_domain_claimed",
            Some(serde_json::json!({
                "organization_id": id,
                "domain": canonical,
            })),
            None,
        )
        .await;

    let dns_record_name = domain_verifier::challenge_fqdn(&canonical);
    Ok((
        StatusCode::CREATED,
        Json(CreateDomainResponse {
            domain: domain.into(),
            verification_token: token,
            dns_record_name,
        }),
    ))
}

async fn list_domains(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<DomainResponse>>, ApiError> {
    // Any active member can view claimed domains for their org.
    state
        .repos
        .memberships
        .find_by_org_user(id, user.id)
        .await?
        .ok_or_else(|| forbid("not a member of this organization"))?;
    let rows = state.repos.organization_domains.list_for_org(id).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn update_domain(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path((id, did)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<DomainResponse>, ApiError> {
    require_org_admin(&state, &user, id).await?;
    let row = state
        .repos
        .organization_domains
        .find_by_id(did)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "domain not found"))?;
    if row.organization_id != id {
        return Err(forbid("domain does not belong to this organization"));
    }
    let now = Utc::now().naive_utc();
    let updated = state
        .repos
        .organization_domains
        .update(
            did,
            UpdateOrganizationDomain {
                auto_join_on_signup: req.auto_join_on_signup,
                default_role_on_auto_join: req.default_role_on_auto_join,
                require_email_verified: req.require_email_verified,
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await?;
    Ok(Json(updated.into()))
}

async fn delete_domain(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path((id, did)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    require_org_admin(&state, &user, id).await?;
    let row = state
        .repos
        .organization_domains
        .find_by_id(did)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "domain not found"))?;
    if row.organization_id != id {
        return Err(forbid("domain does not belong to this organization"));
    }
    state.repos.organization_domains.delete(did).await?;
    state
        .write_audit_log(
            Some(user.id),
            "org_domain_removed",
            Some(serde_json::json!({
                "organization_id": id,
                "domain": row.domain,
            })),
            None,
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_domain_route(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path((id, did)): Path<(Uuid, Uuid)>,
) -> Result<Json<VerifyDomainResponse>, ApiError> {
    require_org_admin(&state, &user, id).await?;
    let (limit, window) = RATE_LIMIT_DOMAIN_VERIFY;
    enforce_rate_limit(&state, &format!("org-domain-verify:{id}"), limit, window).await?;

    let row = state
        .repos
        .organization_domains
        .find_by_id(did)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "domain not found"))?;
    if row.organization_id != id {
        return Err(forbid("domain does not belong to this organization"));
    }

    let outcome = domain_verifier::verify_domain(
        &row.domain,
        &row.verification_token,
        &domain_verifier::VerifyConfig::default(),
    )
    .await;

    let now = Utc::now().naive_utc();
    let verified = matches!(outcome, domain_verifier::VerifyOutcome::Verified);
    let new_status = if verified {
        DomainStatus::Verified
    } else {
        DomainStatus::Failed
    };
    let updated = state
        .repos
        .organization_domains
        .update(
            did,
            UpdateOrganizationDomain {
                status: Some(new_status),
                verified_at: if verified { Some(Some(now)) } else { None },
                last_checked_at: Some(Some(now)),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await?;

    state
        .write_audit_log(
            Some(user.id),
            if verified {
                "org_domain_verified"
            } else {
                "org_domain_verify_failed"
            },
            Some(serde_json::json!({
                "organization_id": id,
                "domain": row.domain,
            })),
            None,
        )
        .await;

    Ok(Json(VerifyDomainResponse {
        domain: updated.into(),
        verified,
    }))
}

// ──────────────────────────────────────────────
// Auto-join hook (JIT membership)
// ──────────────────────────────────────────────

/// Auto-join the given user into every organization whose verified domain
/// matches the user's email and is configured to auto-join.
///
/// Call sites:
/// - `email_password::register` — when `require_email_verification = false`
///   and the user is created already-verified, we run the hook with
///   `is_email_verified = true`.
/// - `email_password::verify_email` — once verification succeeds, we run
///   the hook with `is_email_verified = true`.
///
/// Returns the list of org ids the user was newly added to. Errors are
/// swallowed — JIT is best-effort, never blocking signup. Each call logs
/// to audit. Already-existing memberships are skipped.
pub async fn auto_join_verified_domain(
    state: &YAuthState,
    user_id: Uuid,
    email: &str,
    is_email_verified: bool,
) -> Vec<Uuid> {
    let Some(domain) = domain_from_email(email) else {
        return Vec::new();
    };

    let row = match state
        .repos
        .organization_domains
        .find_by_domain(&domain)
        .await
    {
        Ok(Some(r)) => r,
        _ => return Vec::new(),
    };

    if row.status != DomainStatus::Verified {
        return Vec::new();
    }
    if !row.auto_join_on_signup {
        return Vec::new();
    }
    if row.require_email_verified && !is_email_verified {
        return Vec::new();
    }

    // Idempotency — already a member? Skip.
    if let Ok(Some(_)) = state
        .repos
        .memberships
        .find_by_org_user(row.organization_id, user_id)
        .await
    {
        return Vec::new();
    }

    let now = Utc::now().naive_utc();
    let new_membership = NewMembership {
        id: Uuid::now_v7(),
        organization_id: row.organization_id,
        user_id,
        role: row.default_role_on_auto_join.clone(),
        status: MembershipStatus::Active,
        invited_at: None,
        joined_at: Some(now),
        created_at: now,
        updated_at: now,
    };
    match state.repos.memberships.create(new_membership).await {
        Ok(_) => {
            state
                .write_audit_log(
                    Some(user_id),
                    "org_domain_auto_join",
                    Some(serde_json::json!({
                        "organization_id": row.organization_id,
                        "domain": row.domain,
                        "role": row.default_role_on_auto_join,
                    })),
                    None,
                )
                .await;
            vec![row.organization_id]
        }
        // Conflict means the membership already exists — treat as no-op.
        Err(RepoError::Conflict(_)) => Vec::new(),
        Err(e) => {
            crate::otel::record_error("auto_join_create_failed", &e);
            Vec::new()
        }
    }
}

// ──────────────────────────────────────────────
// Issue #91 — Org-scoped API keys (service accounts)
// ──────────────────────────────────────────────

/// Build the org-scoped API keys subrouter. When the `api-key` feature is
/// off the router is empty — the parent route table simply gains no
/// routes.
fn api_keys_router() -> Router<YAuthState> {
    #[cfg(feature = "api-key")]
    {
        Router::new()
            .route(
                "/organizations/{id}/api-keys",
                get(list_org_api_keys).post(create_org_api_key),
            )
            .route(
                "/organizations/{id}/api-keys/{key_id}",
                axum::routing::delete(delete_org_api_key),
            )
            .route(
                "/organizations/{id}/api-keys/{key_id}/rotate",
                post(rotate_org_api_key),
            )
            .route(
                "/organizations/{id}/api-keys/{key_id}/usage",
                get(get_org_api_key_usage),
            )
    }
    #[cfg(not(feature = "api-key"))]
    {
        Router::new()
    }
}

#[cfg(feature = "api-key")]
const ROTATION_GRACE_HOURS: i64 = 24;

#[cfg(feature = "api-key")]
const RATE_LIMIT_API_KEY_CREATE: (u32, u64) = (20, 3600); // 20 / hour / org
#[cfg(feature = "api-key")]
const RATE_LIMIT_API_KEY_ROTATE: (u32, u64) = (10, 3600); // 10 / hour / org

#[cfg(feature = "api-key")]
#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateOrgApiKeyRequest {
    pub name: String,
    /// Org-role the bearer acts as. Must be one of the built-in roles
    /// except `owner` (defense-in-depth: a leaked service-account key
    /// must not be able to delete the org). Defaults to `member`.
    pub role: Option<String>,
    /// Free-form permission list. The handler enforces that every
    /// requested permission is a subset of what the caller's own role
    /// allows by default.
    pub permissions: Option<Vec<String>>,
    pub expires_in_days: Option<u32>,
}

#[cfg(feature = "api-key")]
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OrgApiKeyResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub prefix: String,
    pub role: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub created_by_user_id: Uuid,
    pub last_used_at: Option<chrono::NaiveDateTime>,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
}

#[cfg(feature = "api-key")]
impl OrgApiKeyResponse {
    fn from_domain(k: yauth_entity::ApiKey) -> Self {
        let permissions = k
            .scopes
            .as_ref()
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok());
        Self {
            id: k.id,
            organization_id: k.organization_id.unwrap_or(Uuid::nil()),
            name: k.name,
            prefix: k.key_prefix,
            role: k.role,
            permissions,
            created_by_user_id: k.created_by_user_id,
            last_used_at: k.last_used_at,
            expires_at: k.expires_at,
            created_at: k.created_at,
        }
    }
}

#[cfg(feature = "api-key")]
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateOrgApiKeyResponse {
    pub api_key: OrgApiKeyResponse,
    /// Plaintext secret — returned exactly once at creation.
    pub secret: String,
}

#[cfg(feature = "api-key")]
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OrgApiKeyUsageResponse {
    pub id: Uuid,
    pub last_used_at: Option<chrono::NaiveDateTime>,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
}

/// Validate a requested service-account role against the caller's role.
///
/// Returns `Err` if:
///   * the requested role is empty,
///   * the requested role is `owner` (defense-in-depth),
///   * the caller's role does not strictly dominate the requested role.
#[cfg(feature = "api-key")]
fn validate_service_account_role(caller_role: &str, requested: &str) -> Result<(), ApiError> {
    use rbac::roles;

    if requested.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "role is required"));
    }
    if requested == roles::OWNER {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "cannot grant 'owner' to a service account",
        ));
    }
    // Rank built-in roles; non-builtin custom roles always fall below
    // admin (caller must be admin/owner to mint a service account at
    // all, enforced separately).
    fn rank(role: &str) -> u8 {
        match role {
            roles::OWNER => 5,
            roles::ADMIN => 4,
            roles::BILLING_ADMIN => 3,
            roles::MEMBER => 2,
            roles::VIEWER => 1,
            _ => 0,
        }
    }
    if rank(requested) > rank(caller_role) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "cannot grant a role higher than your own",
        ));
    }
    Ok(())
}

/// Validate requested permissions against the caller's role-bounded
/// default permission set. Every requested permission must be present
/// in the caller's defaults (modeled as `domain:verb` strings — see
/// [`perm_id`]). Custom permission strings the caller doesn't have
/// access to are rejected.
#[cfg(feature = "api-key")]
fn validate_service_account_permissions(
    caller_role: &str,
    requested: &[String],
) -> Result<(), ApiError> {
    if requested.is_empty() {
        return Ok(());
    }
    let allowed = rbac::default_permissions(caller_role);
    // Build the set of permission ids the caller's role allows. Custom
    // permission strings outside the yauth-shipped catalogue are
    // accepted only when the caller is admin/owner — apps layer their
    // own resource-level perms on top of the built-in set.
    let yauth_perms: std::collections::HashSet<&'static str> = {
        use rbac::{BillingPerm::*, MemberPerm::*, Permission, SettingsPerm::*};
        [
            Permission::Members(Invite),
            Permission::Members(Remove),
            Permission::Members(ChangeRole),
            Permission::Billing(View),
            Permission::Billing(Update),
            Permission::Billing(Cancel),
            Permission::Settings(Read),
            Permission::Settings(Write),
        ]
        .into_iter()
        .filter(|p| allowed.contains(*p))
        .map(perm_id)
        .collect()
    };

    let is_caller_admin_or_owner =
        caller_role == rbac::roles::ADMIN || caller_role == rbac::roles::OWNER;
    for p in requested {
        let known = matches!(
            p.as_str(),
            "members:invite"
                | "members:remove"
                | "members:change_role"
                | "billing:view"
                | "billing:update"
                | "billing:cancel"
                | "settings:read"
                | "settings:write"
        );
        if known {
            if !yauth_perms.contains(p.as_str()) {
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    &format!("permission '{p}' is not in your role's default permission set"),
                ));
            }
        } else if !is_caller_admin_or_owner {
            return Err(api_err(
                StatusCode::FORBIDDEN,
                &format!("custom permission '{p}' requires admin or owner role"),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "api-key")]
async fn create_org_api_key(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateOrgApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateOrgApiKeyResponse>), ApiError> {
    // Only org admin or owner may mint service accounts.
    let caller = require_org_admin(&state, &user, id).await?;

    // Rate limit per-org.
    let (limit, window) = RATE_LIMIT_API_KEY_CREATE;
    enforce_rate_limit(&state, &format!("org-api-key-create:{id}"), limit, window).await?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "name is required"));
    }

    let requested_role = req
        .role
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(rbac::roles::MEMBER)
        .to_string();
    validate_service_account_role(&caller.role, &requested_role)?;

    let permissions = req.permissions.clone().unwrap_or_default();
    validate_service_account_permissions(&caller.role, &permissions)?;

    // Generate key material — same format as user-scoped keys.
    let prefix = crate::auth::crypto::generate_token()[..8].to_string();
    let secret = crate::auth::crypto::generate_token();
    let full_key = format!("yauth_{}_{}", prefix, secret);
    let key_hash = crate::auth::crypto::hash_token(&full_key);

    let now = Utc::now().naive_utc();
    let expires_at = req
        .expires_in_days
        .map(|days| (chrono::Utc::now() + chrono::Duration::days(i64::from(days))).naive_utc());

    let scopes_json = if permissions.is_empty() {
        None
    } else {
        Some(serde_json::json!(permissions))
    };

    let key_id = Uuid::now_v7();

    let new_key = yauth_entity::NewApiKey {
        id: key_id,
        user_id: None,
        organization_id: Some(id),
        key_prefix: prefix.clone(),
        key_hash,
        name: name.clone(),
        scopes: scopes_json,
        role: Some(requested_role.clone()),
        expires_at,
        created_at: now,
        created_by_user_id: user.id,
    };

    state.repos.api_keys.create(new_key).await.map_err(|e| {
        crate::otel::record_error("org_api_key_create_failed", &e);
        ApiError::from(e)
    })?;

    crate::otel::add_event(
        "org_api_key_created",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("organization.id", id.to_string()),
            opentelemetry::KeyValue::new("api_key.id", key_id.to_string()),
            opentelemetry::KeyValue::new("api_key.role", requested_role.clone()),
            opentelemetry::KeyValue::new("created_by_user.id", user.id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(user.id),
            "org_api_key_created",
            Some(serde_json::json!({
                "organization_id": id,
                "key_id": key_id,
                "name": name,
                "prefix": prefix,
                "role": requested_role,
                "permissions": permissions,
            })),
            None,
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(CreateOrgApiKeyResponse {
            api_key: OrgApiKeyResponse {
                id: key_id,
                organization_id: id,
                name,
                prefix,
                role: Some(requested_role),
                permissions: if permissions.is_empty() {
                    None
                } else {
                    Some(permissions)
                },
                created_by_user_id: user.id,
                last_used_at: None,
                expires_at,
                created_at: now,
            },
            secret: full_key,
        }),
    ))
}

#[cfg(feature = "api-key")]
async fn list_org_api_keys(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<OrgApiKeyResponse>>, ApiError> {
    require_org_admin(&state, &user, id).await?;
    let keys = state.repos.api_keys.list_by_org_id(id).await?;
    Ok(Json(
        keys.into_iter()
            .map(OrgApiKeyResponse::from_domain)
            .collect(),
    ))
}

#[cfg(feature = "api-key")]
async fn delete_org_api_key(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    require_org_admin(&state, &user, id).await?;
    // Ownership check — refuse to delete keys that don't belong to this org.
    let existing = state
        .repos
        .api_keys
        .find_by_id_and_org(key_id, id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "api key not found"))?;
    state.repos.api_keys.delete(existing.id).await?;
    state
        .write_audit_log(
            Some(user.id),
            "org_api_key_deleted",
            Some(serde_json::json!({
                "organization_id": id,
                "key_id": key_id,
                "created_by_user_id": existing.created_by_user_id,
            })),
            None,
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(feature = "api-key")]
async fn rotate_org_api_key(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<CreateOrgApiKeyResponse>), ApiError> {
    require_org_admin(&state, &user, id).await?;

    // Rate limit rotations per-org.
    let (limit, window) = RATE_LIMIT_API_KEY_ROTATE;
    enforce_rate_limit(&state, &format!("org-api-key-rotate:{id}"), limit, window).await?;

    let existing = state
        .repos
        .api_keys
        .find_by_id_and_org(key_id, id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "api key not found"))?;

    // Mint replacement.
    let prefix = crate::auth::crypto::generate_token()[..8].to_string();
    let secret = crate::auth::crypto::generate_token();
    let full_key = format!("yauth_{}_{}", prefix, secret);
    let key_hash = crate::auth::crypto::hash_token(&full_key);
    let now = Utc::now().naive_utc();

    let new_id = Uuid::now_v7();
    let new_key = yauth_entity::NewApiKey {
        id: new_id,
        user_id: None,
        organization_id: Some(id),
        key_prefix: prefix.clone(),
        key_hash,
        name: format!("{} (rotated)", existing.name),
        scopes: existing.scopes.clone(),
        role: existing.role.clone(),
        expires_at: existing.expires_at,
        created_at: now,
        created_by_user_id: user.id,
    };

    state.repos.api_keys.create(new_key).await?;

    // Grace period — stamp the old key with a 24h expiry. Best-effort:
    // if this errors we still surface the new key to the caller; an
    // operator-side audit query catches lingering pre-rotation keys.
    let grace = now + chrono::Duration::hours(ROTATION_GRACE_HOURS);
    if let Err(e) = state
        .repos
        .api_keys
        .set_expires_at(existing.id, grace)
        .await
    {
        crate::otel::record_error("org_api_key_rotate_grace_failed", &e);
    }

    state
        .write_audit_log(
            Some(user.id),
            "org_api_key_rotated",
            Some(serde_json::json!({
                "organization_id": id,
                "old_key_id": existing.id,
                "new_key_id": new_id,
                "grace_expires_at": grace,
            })),
            None,
        )
        .await;

    let permissions = existing
        .scopes
        .as_ref()
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok());

    Ok((
        StatusCode::CREATED,
        Json(CreateOrgApiKeyResponse {
            api_key: OrgApiKeyResponse {
                id: new_id,
                organization_id: id,
                name: format!("{} (rotated)", existing.name),
                prefix,
                role: existing.role,
                permissions,
                created_by_user_id: user.id,
                last_used_at: None,
                expires_at: existing.expires_at,
                created_at: now,
            },
            secret: full_key,
        }),
    ))
}

#[cfg(feature = "api-key")]
async fn get_org_api_key_usage(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<OrgApiKeyUsageResponse>, ApiError> {
    require_org_admin(&state, &user, id).await?;
    let existing = state
        .repos
        .api_keys
        .find_by_id_and_org(key_id, id)
        .await?
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "api key not found"))?;
    Ok(Json(OrgApiKeyUsageResponse {
        id: existing.id,
        last_used_at: existing.last_used_at,
        expires_at: existing.expires_at,
        created_at: existing.created_at,
    }))
}
