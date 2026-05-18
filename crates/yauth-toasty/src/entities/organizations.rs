//! Toasty model for `yauth_organizations`.
//!
//! Multi-tenant boundary. Parent entity declaring `#[has_many]` inverse
//! relationships to memberships and invitations. The FK ON DELETE CASCADE
//! semantics from the migration tear down both children when the org is
//! deleted; the relations here let Toasty express that link in the schema.

use super::{YauthInvitation, YauthMembership};
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "organizations"]
pub struct YauthOrganization {
    #[key]
    pub id: Uuid,

    pub name: String,

    /// URL-safe identifier, globally unique. Case-insensitive lookups happen
    /// in the repo layer (Toasty has no ILIKE — we lowercase on write and
    /// scan in-application for matches).
    #[unique]
    pub slug: String,

    pub display_name: Option<String>,
    pub avatar_url: Option<String>,

    /// Free-form JSON for callers — billing IDs, SAML config, etc.
    #[serialize(json, nullable)]
    pub metadata: Option<serde_json::Value>,

    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,

    // Inverse relationships. Toasty doesn't auto-cascade on delete via the
    // entity API at the time of writing — the repo `delete` method deletes
    // child rows explicitly first so the semantics match the diesel-pg
    // backend (which gets cascade from the FK declaration).
    #[has_many]
    pub memberships: toasty::HasMany<YauthMembership>,
    #[has_many]
    pub invitations: toasty::HasMany<YauthInvitation>,
}
