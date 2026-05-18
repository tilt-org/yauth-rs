//! Toasty model for `yauth_invitations`.
//!
//! Pending invitation to join an organization. Single-use, time-limited.
//! `token_hash` stores a hashed representation of the token; the plaintext
//! is only sent in the invitation email.

use super::{YauthOrganization, YauthUser};
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "invitations"]
pub struct YauthInvitation {
    #[key]
    pub id: Uuid,

    #[index]
    pub organization_id: Uuid,

    // Field name `yauth_organization` is required by Toasty's relation
    // pairing — `YauthOrganization::has_many(invitations)` looks up
    // `verify_pair_belongs_to_exists_for_yauth_organization` on the child.
    #[belongs_to(key = organization_id, references = id)]
    pub yauth_organization: toasty::BelongsTo<YauthOrganization>,

    pub email: String,
    pub role: String,

    #[unique]
    pub token_hash: String,

    pub invited_by_user_id: Uuid,

    #[belongs_to(key = invited_by_user_id, references = id)]
    pub invited_by: toasty::BelongsTo<YauthUser>,

    pub expires_at: jiff::Timestamp,
    pub accepted_at: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
}
