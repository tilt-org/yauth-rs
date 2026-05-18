//! Organizations plugin (issue #87) — multi-tenancy primitive.
//!
//! Adds organization CRUD + membership listing + invitation creation/accept
//! when the `organizations` Cargo feature is on. With the feature off,
//! nothing in this module is compiled and the routes are not mounted.
//!
//! This is intentionally a minimal route surface — RBAC (#88), the active-org
//! session claim (#89), and verified-domain auto-join (#90) live in
//! follow-up issues. Roles are stored as free-form strings; the only
//! authorization check inside these handlers is "is the caller a member of
//! the org?". Caller-side guards layer on top.

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::crypto;
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::repo::RepoError;
use crate::state::YAuthState;
use yauth_entity::{
    Invitation, Membership, MembershipStatus, NewInvitation, NewMembership, NewOrganization,
    Organization, UpdateOrganization,
};

const ROLE_ADMIN: &str = "admin";
const ROLE_MEMBER: &str = "member";
const INVITATION_TTL_HOURS: i64 = 168; // 7 days

// Rate limit budgets (security review H-3). Conservative defaults; will be
// surfaced via `OrganizationsConfig` in a follow-up if tenants need to tune.
//
// Format: `(max_requests, window_seconds)`.
const RATE_LIMIT_ORG_CREATE: (u32, u64) = (20, 3600); // 20 / hour / user
const RATE_LIMIT_INVITATION_CREATE: (u32, u64) = (50, 3600); // 50 / hour / org
const RATE_LIMIT_MEMBER_LIST: (u32, u64) = (100, 60); // 100 / minute / user

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
                .route("/organizations/{id}/invitations", post(create_invitation))
                .route("/invitations/accept", post(accept_invitation)),
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

async fn require_org_admin(
    state: &YAuthState,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Membership, ApiError> {
    let m = state
        .repos
        .memberships
        .find_by_org_user(org_id, user_id)
        .await?
        .ok_or_else(|| forbid("not a member of this organization"))?;
    if m.role != ROLE_ADMIN {
        return Err(forbid("organization admin role required"));
    }
    Ok(m)
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

    // Creator becomes admin automatically.
    state
        .repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org.id,
            user_id: user.id,
            role: ROLE_ADMIN.to_string(),
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
    require_org_admin(&state, id, user.id).await?;
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
    require_org_admin(&state, id, user.id).await?;
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
    require_org_admin(&state, id, user.id).await?;
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
    let role = req.role.unwrap_or_else(|| ROLE_MEMBER.to_string());

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
