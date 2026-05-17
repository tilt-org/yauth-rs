//! Org-scoped Role-Based Access Control (issue #88).
//!
//! Built on top of the organization + membership primitive from #87.
//! Provides:
//!
//! 1. **Built-in role constants** — `OWNER`, `ADMIN`, `BILLING_ADMIN`,
//!    `MEMBER`, `VIEWER`. Custom strings allowed.
//! 2. **Permission catalogue** — the default permission grants per built-in
//!    role.
//! 3. **Enforcement helpers** — `require_org_role` /
//!    `require_org_permission` for route handlers.
//! 4. **Owner-protection guards** — helpers that wrap the membership repo
//!    to reject changes that would demote or remove the last owner of an
//!    organization without an ownership transfer.
//!
//! # Feature gating
//!
//! Compiled only when the `organizations` Cargo feature is on. With the
//! feature off, the module is invisible — single-tenant deployments are
//! entirely unaffected.
//!
//! # Backward compatibility
//!
//! `User.role` (the global, deployment-wide role) is unchanged. The
//! per-org role lives on `Membership.role` and is queried via the
//! enforcement helpers in this module. The two axes are intentionally
//! independent.

#![cfg(feature = "organizations")]

use std::collections::BTreeSet;

use axum::http::StatusCode;
use uuid::Uuid;

use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::repo::Repositories;

// ──────────────────────────────────────────────
// Built-in role string constants
// ──────────────────────────────────────────────

/// Built-in role string constants.
///
/// These are the roles yauth ships with default permission grants for.
/// Consumers may store any free-form string in `Membership.role`; custom
/// roles fall through to an empty default permission set and the calling
/// application is responsible for their semantics.
pub mod roles {
    /// Sole holder of the organization. Exactly one per org. Cannot be
    /// demoted or removed without transferring ownership first.
    pub const OWNER: &str = "owner";

    /// Can manage members, billing, and settings.
    pub const ADMIN: &str = "admin";

    /// Can manage billing only — no membership or settings changes.
    pub const BILLING_ADMIN: &str = "billing_admin";

    /// Default role for invited / auto-joined users.
    pub const MEMBER: &str = "member";

    /// Read-only access. No mutating actions.
    pub const VIEWER: &str = "viewer";

    /// True if `role` is one of the built-in role strings.
    pub fn is_builtin(role: &str) -> bool {
        matches!(role, OWNER | ADMIN | BILLING_ADMIN | MEMBER | VIEWER)
    }

    /// All built-in role strings in canonical order.
    pub const ALL: &[&str] = &[OWNER, ADMIN, BILLING_ADMIN, MEMBER, VIEWER];

    /// Privilege ordinal for a built-in role. Lower number = more
    /// privileged. Unknown roles get a high number so they sort to
    /// the bottom (least privileged) when picking a winner from a
    /// list.
    pub fn privilege_ordinal(role: &str) -> u8 {
        match role {
            OWNER => 0,
            ADMIN => 1,
            BILLING_ADMIN => 2,
            MEMBER => 3,
            VIEWER => 4,
            _ => 100,
        }
    }
}

/// Pick the most-privileged role from a list, by [`roles::privilege_ordinal`].
///
/// Used by the SSO callback when a user is in multiple IdP groups
/// that map to different yauth roles — we don't want to demote them
/// just because their group list happened to put a lower-privileged
/// match first.
///
/// Returns `None` only when the slice is empty.
pub fn most_privileged_role<'a>(candidates: &'a [&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .min_by_key(|r| roles::privilege_ordinal(r))
}

// ──────────────────────────────────────────────
// Permission catalogue
// ──────────────────────────────────────────────

/// Permission verb domains.
///
/// yauth itself only ships the org-management permissions; downstream
/// applications layer their own resource-specific permissions on top of
/// the role string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberPerm {
    /// Invite a new user to the org.
    Invite,
    /// Remove a member from the org.
    Remove,
    /// Change a member's role.
    ChangeRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BillingPerm {
    View,
    Update,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettingsPerm {
    Read,
    Write,
}

/// A single permission across all three yauth-shipped domains.
///
/// The flat enum makes route guards readable:
/// `require_org_permission(ctx, org, Permission::Members(MemberPerm::Invite))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Members(MemberPerm),
    Billing(BillingPerm),
    Settings(SettingsPerm),
}

/// Bundle of permissions yauth-shipped roles grant by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermissionSet {
    pub members: BTreeSet<MemberPerm>,
    pub billing: BTreeSet<BillingPerm>,
    pub settings: BTreeSet<SettingsPerm>,
}

impl PermissionSet {
    /// True if this permission set contains `perm`.
    pub fn contains(&self, perm: Permission) -> bool {
        match perm {
            Permission::Members(p) => self.members.contains(&p),
            Permission::Billing(p) => self.billing.contains(&p),
            Permission::Settings(p) => self.settings.contains(&p),
        }
    }
}

/// Default permission grants for a role string.
///
/// Built-in roles get the documented grants; any unknown role string
/// returns an empty `PermissionSet` — the calling application is
/// responsible for defining permissions for custom roles. `owner` is the
/// superset and always inherits every yauth-shipped permission.
pub fn default_permissions(role: &str) -> PermissionSet {
    use BillingPerm::*;
    use MemberPerm::*;
    use SettingsPerm::*;

    match role {
        roles::OWNER => PermissionSet {
            members: [Invite, Remove, ChangeRole].into_iter().collect(),
            billing: [View, Update, Cancel].into_iter().collect(),
            settings: [Read, Write].into_iter().collect(),
        },
        roles::ADMIN => PermissionSet {
            members: [Invite, Remove, ChangeRole].into_iter().collect(),
            // Admins can view billing but not mutate it — `billing_admin`
            // owns the mutate side. Apps that want admins to do both can
            // wire a custom role.
            billing: [View].into_iter().collect(),
            settings: [Read, Write].into_iter().collect(),
        },
        roles::BILLING_ADMIN => PermissionSet {
            members: BTreeSet::new(),
            billing: [View, Update, Cancel].into_iter().collect(),
            settings: [Read].into_iter().collect(),
        },
        roles::MEMBER => PermissionSet {
            members: BTreeSet::new(),
            billing: BTreeSet::new(),
            settings: [Read].into_iter().collect(),
        },
        roles::VIEWER => PermissionSet {
            members: BTreeSet::new(),
            billing: BTreeSet::new(),
            settings: [Read].into_iter().collect(),
        },
        _ => PermissionSet::default(),
    }
}

// ──────────────────────────────────────────────
// Enforcement helpers (handler-side)
// ──────────────────────────────────────────────

/// Result of a permission/role lookup.
#[derive(Debug, Clone)]
pub struct OrgRole {
    pub membership_id: Uuid,
    pub role: String,
}

fn forbid(msg: &str) -> ApiError {
    api_err(StatusCode::FORBIDDEN, msg)
}

/// Look up the caller's role in `org_id`, returning the role string.
///
/// Returns 403 if the user is not a member of the org. Callers that want
/// to detect non-membership without an HTTP status can use the
/// `MembershipRepository::find_by_org_user` method directly.
pub async fn get_org_role(
    repos: &Repositories,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<OrgRole, ApiError> {
    let m = repos
        .memberships
        .find_by_org_user(org_id, user_id)
        .await?
        .ok_or_else(|| forbid("not a member of this organization"))?;
    Ok(OrgRole {
        membership_id: m.id,
        role: m.role,
    })
}

/// Enforce exact role match — useful when a route is reserved for a
/// specific role like `owner`.
pub async fn require_org_role(
    repos: &Repositories,
    user: &AuthUser,
    org_id: Uuid,
    expected: &str,
) -> Result<OrgRole, ApiError> {
    let cur = get_org_role(repos, org_id, user.id).await?;
    if cur.role != expected {
        return Err(forbid(&format!("organization role '{expected}' required")));
    }
    Ok(cur)
}

/// Enforce role-at-least semantics: `owner` ⊇ `admin` for org-management
/// purposes. Used by mutation routes that should also be available to the
/// owner (since the owner can do everything admins can).
pub async fn require_org_admin_or_owner(
    repos: &Repositories,
    user: &AuthUser,
    org_id: Uuid,
) -> Result<OrgRole, ApiError> {
    let cur = get_org_role(repos, org_id, user.id).await?;
    if cur.role != roles::ADMIN && cur.role != roles::OWNER {
        return Err(forbid("organization admin role required"));
    }
    Ok(cur)
}

/// Enforce a single permission, looking up the caller's role and
/// consulting `default_permissions`.
pub async fn require_org_permission(
    repos: &Repositories,
    user: &AuthUser,
    org_id: Uuid,
    perm: Permission,
) -> Result<OrgRole, ApiError> {
    let cur = get_org_role(repos, org_id, user.id).await?;
    if !default_permissions(&cur.role).contains(perm) {
        return Err(forbid("insufficient permissions for this action"));
    }
    Ok(cur)
}

// ──────────────────────────────────────────────
// Owner-protection invariant
// ──────────────────────────────────────────────

/// Returned by the owner-protection guards when an operation would leave
/// an organization without an owner.
///
/// Maps to HTTP 409 Conflict via the standard `ApiError` conversion —
/// this is a state-level conflict, not a permission error.
pub const OWNER_PROTECTION_MSG: &str =
    "Cannot demote or remove the last owner of an organization. Transfer ownership first.";

fn owner_protection_err() -> ApiError {
    api_err(StatusCode::CONFLICT, OWNER_PROTECTION_MSG)
}

/// Defense-in-depth check before calling `MembershipRepository::update`
/// with a role change.
///
/// Returns `Err` if the membership being updated is currently `owner`
/// and the requested role is anything else, **and** this is the only
/// owner-membership in the org. Callers that genuinely want to demote
/// the owner must first call [`transfer_ownership`].
pub async fn guard_role_change(
    repos: &Repositories,
    org_id: Uuid,
    membership_id: Uuid,
    new_role: &str,
) -> Result<(), ApiError> {
    if new_role == roles::OWNER {
        // Promoting *to* owner is also dangerous — there must be at most
        // one owner per org. Caller should be using `transfer_ownership`
        // instead.
        return Err(api_err(
            StatusCode::CONFLICT,
            "Use transfer-ownership to change the org owner.",
        ));
    }
    let target = repos
        .memberships
        .find_by_id(membership_id)
        .await?
        .ok_or(crate::repo::RepoError::NotFound)?;
    if target.role == roles::OWNER {
        // Demoting the (one and only) owner — block.
        let owners = count_owners(repos, org_id).await?;
        if owners <= 1 {
            return Err(owner_protection_err());
        }
    }
    Ok(())
}

/// Defense-in-depth check before calling `MembershipRepository::delete`
/// (or removing a member by any other path).
pub async fn guard_delete(
    repos: &Repositories,
    org_id: Uuid,
    membership_id: Uuid,
) -> Result<(), ApiError> {
    let target = repos
        .memberships
        .find_by_id(membership_id)
        .await?
        .ok_or(crate::repo::RepoError::NotFound)?;
    if target.role == roles::OWNER {
        let owners = count_owners(repos, org_id).await?;
        if owners <= 1 {
            return Err(owner_protection_err());
        }
    }
    Ok(())
}

/// Count active owner-memberships in an org. Used by the owner-protection
/// guards.
pub async fn count_owners(repos: &Repositories, org_id: Uuid) -> Result<usize, ApiError> {
    let members = repos.memberships.list_by_org(org_id).await?;
    Ok(members.iter().filter(|m| m.role == roles::OWNER).count())
}

/// Atomically transfer ownership from the current owner to a new owner.
///
/// 1. Caller MUST be the current owner.
/// 2. Target user MUST already be a member of the org.
/// 3. Current owner is demoted to `admin`; target is promoted to `owner`.
///
/// The transfer is *not* a two-phase commit — between the two writes the
/// org may briefly have two owners. The memory backend's owner-protection
/// guard explicitly permits one additional owner during the transfer
/// window. A future enhancement could wrap this in a
/// `Repositories::transaction()` once that primitive lands.
pub async fn transfer_ownership(
    repos: &Repositories,
    org_id: Uuid,
    current_owner_user_id: Uuid,
    new_owner_user_id: Uuid,
) -> Result<(), ApiError> {
    if current_owner_user_id == new_owner_user_id {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Cannot transfer ownership to yourself.",
        ));
    }
    let now = chrono::Utc::now().naive_utc();

    let current = repos
        .memberships
        .find_by_org_user(org_id, current_owner_user_id)
        .await?
        .ok_or_else(|| forbid("not a member of this organization"))?;
    if current.role != roles::OWNER {
        return Err(forbid("only the current owner can transfer ownership"));
    }
    let target = repos
        .memberships
        .find_by_org_user(org_id, new_owner_user_id)
        .await?
        .ok_or_else(|| {
            api_err(
                StatusCode::BAD_REQUEST,
                "Target user is not a member of this organization.",
            )
        })?;

    // Promote target first — if this fails, the org still has its
    // original owner. Promoting first avoids the zero-owners window
    // that would otherwise hit the owner-protection guard against the
    // second write.
    repos
        .memberships
        .update(
            target.id,
            yauth_entity::UpdateMembership {
                role: Some(roles::OWNER.to_string()),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await?;

    // Demote previous owner to admin (sensible default — caller can
    // further change via the regular change-role endpoint).
    repos
        .memberships
        .update(
            current.id,
            yauth_entity::UpdateMembership {
                role: Some(roles::ADMIN.to_string()),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

// ──────────────────────────────────────────────
// Unit tests (no DB; pure logic)
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_recognized() {
        for r in roles::ALL {
            assert!(roles::is_builtin(r), "{r} should be builtin");
        }
        assert!(!roles::is_builtin("custom_role"));
    }

    #[test]
    fn owner_inherits_all_permissions() {
        let p = default_permissions(roles::OWNER);
        assert!(p.contains(Permission::Members(MemberPerm::Invite)));
        assert!(p.contains(Permission::Members(MemberPerm::Remove)));
        assert!(p.contains(Permission::Members(MemberPerm::ChangeRole)));
        assert!(p.contains(Permission::Billing(BillingPerm::View)));
        assert!(p.contains(Permission::Billing(BillingPerm::Update)));
        assert!(p.contains(Permission::Billing(BillingPerm::Cancel)));
        assert!(p.contains(Permission::Settings(SettingsPerm::Read)));
        assert!(p.contains(Permission::Settings(SettingsPerm::Write)));
    }

    #[test]
    fn admin_cannot_mutate_billing() {
        let p = default_permissions(roles::ADMIN);
        assert!(p.contains(Permission::Billing(BillingPerm::View)));
        assert!(!p.contains(Permission::Billing(BillingPerm::Update)));
        assert!(!p.contains(Permission::Billing(BillingPerm::Cancel)));
    }

    #[test]
    fn billing_admin_cannot_manage_members() {
        let p = default_permissions(roles::BILLING_ADMIN);
        assert!(!p.contains(Permission::Members(MemberPerm::Invite)));
        assert!(!p.contains(Permission::Members(MemberPerm::Remove)));
        assert!(!p.contains(Permission::Members(MemberPerm::ChangeRole)));
        assert!(p.contains(Permission::Billing(BillingPerm::Update)));
    }

    #[test]
    fn viewer_is_read_only() {
        let p = default_permissions(roles::VIEWER);
        assert!(p.contains(Permission::Settings(SettingsPerm::Read)));
        assert!(!p.contains(Permission::Settings(SettingsPerm::Write)));
        assert!(p.members.is_empty());
        assert!(p.billing.is_empty());
    }

    #[test]
    fn member_is_minimal() {
        let p = default_permissions(roles::MEMBER);
        assert!(p.contains(Permission::Settings(SettingsPerm::Read)));
        assert!(!p.contains(Permission::Settings(SettingsPerm::Write)));
        assert!(p.members.is_empty());
        assert!(p.billing.is_empty());
    }

    #[test]
    fn custom_role_grants_nothing_by_default() {
        let p = default_permissions("some_app_specific_role");
        assert!(p.members.is_empty());
        assert!(p.billing.is_empty());
        assert!(p.settings.is_empty());
    }

    #[test]
    fn most_privileged_picks_owner_over_admin() {
        let r = most_privileged_role(&["admin", "owner"]).unwrap();
        assert_eq!(r, "owner");
    }

    #[test]
    fn most_privileged_picks_admin_over_member_over_viewer() {
        let r = most_privileged_role(&["viewer", "member", "admin"]).unwrap();
        assert_eq!(r, "admin");
    }

    #[test]
    fn most_privileged_falls_through_unknown_roles() {
        // Custom roles get a high ordinal — fall through to built-in.
        let r = most_privileged_role(&["custom-app-role", "member"]).unwrap();
        assert_eq!(r, "member");
    }

    #[test]
    fn most_privileged_returns_only_candidate() {
        let r = most_privileged_role(&["my-role"]).unwrap();
        assert_eq!(r, "my-role");
    }

    #[test]
    fn most_privileged_handles_empty() {
        assert!(most_privileged_role(&[]).is_none());
    }
}
