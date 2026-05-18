//! Toasty model for `yauth_memberships`.
//!
//! Join row tying a `YauthUser` to a `YauthOrganization` with a per-org role.
//! Both FKs are declared `belongs_to` here — Toasty requires non-optional FK
//! fields on a `BelongsTo` relationship.

use super::{YauthOrganization, YauthUser};
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "memberships"]
pub struct YauthMembership {
    #[key]
    pub id: Uuid,

    #[index]
    pub organization_id: Uuid,

    // Field name `yauth_organization` is required by Toasty's relation
    // pairing — `YauthOrganization::has_many(memberships)` looks up
    // `verify_pair_belongs_to_exists_for_yauth_organization` on the child.
    #[belongs_to(key = organization_id, references = id)]
    pub yauth_organization: toasty::BelongsTo<YauthOrganization>,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub yauth_user: toasty::BelongsTo<YauthUser>,

    pub role: String,
    pub status: String,
    pub invited_at: Option<jiff::Timestamp>,
    pub joined_at: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}
