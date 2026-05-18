//! Organization, Membership, and Invitation domain types.
//!
//! These types power yauth's multi-tenancy primitive (issue #87). They are
//! always compiled — the runtime decision to expose org features lives behind
//! the `organizations` Cargo feature on the `yauth` crate, not here. Keeping
//! the types unconditional lets downstream apps reference them without
//! double-gating.
//!
//! The shape is deliberately close to Better Auth's `organization` plugin
//! and WorkOS/Stytch — see issue #87 for the prior-art table.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Multi-tenant boundary. Users join via `Membership`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    /// Internal name. Human-readable but not necessarily URL-safe.
    pub name: String,
    /// URL-safe identifier, globally unique. Case-insensitive on lookup.
    pub slug: String,
    /// Optional display override (e.g. for org switcher UI).
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    /// Free-form JSON for callers — billing IDs, SAML config, etc.
    pub metadata: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Input payload for `OrganizationRepository::create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrganization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Partial update for an `Organization`. Each `Some` overwrites; nested
/// `Option<Option<T>>` lets callers clear nullable fields explicitly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateOrganization {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub display_name: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
    pub metadata: Option<Option<serde_json::Value>>,
    pub updated_at: Option<NaiveDateTime>,
}

/// Lifecycle state for a `Membership`.
///
/// Stored as a `VARCHAR` rather than an SQL enum so each backend can ship
/// the column with no DDL drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MembershipStatus {
    /// Invitation accepted; user is a full member.
    Active,
    /// Invitation outstanding (used for the convenience listing on the org
    /// page — the canonical pending record lives in `Invitation`).
    Invited,
    /// Member retained for audit/history but cannot act on the org.
    Suspended,
}

impl MembershipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            MembershipStatus::Active => "active",
            MembershipStatus::Invited => "invited",
            MembershipStatus::Suspended => "suspended",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "invited" => Some(Self::Invited),
            "suspended" => Some(Self::Suspended),
            _ => None,
        }
    }
}

/// Join row tying a `User` to an `Organization` with a per-org role.
///
/// Roles are free-form strings — RBAC enforcement is a separate plugin
/// (issue #88) and intentionally not gated by this primitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub status: MembershipStatus,
    pub invited_at: Option<NaiveDateTime>,
    pub joined_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMembership {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub status: MembershipStatus,
    pub invited_at: Option<NaiveDateTime>,
    pub joined_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateMembership {
    pub role: Option<String>,
    pub status: Option<MembershipStatus>,
    pub joined_at: Option<Option<NaiveDateTime>>,
    pub updated_at: Option<NaiveDateTime>,
}

/// Pending invitation to join an organization.
///
/// `token_hash` stores a hashed representation of the token; the plaintext
/// is only sent in the invitation email. Single-use semantics enforced by
/// `accepted_at` plus `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: String,
    pub token_hash: String,
    pub invited_by_user_id: Uuid,
    pub expires_at: NaiveDateTime,
    pub accepted_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewInvitation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: String,
    pub token_hash: String,
    pub invited_by_user_id: Uuid,
    pub expires_at: NaiveDateTime,
    pub accepted_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_status_round_trip() {
        for s in [
            MembershipStatus::Active,
            MembershipStatus::Invited,
            MembershipStatus::Suspended,
        ] {
            assert_eq!(MembershipStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(MembershipStatus::parse("nope"), None);
    }
}
