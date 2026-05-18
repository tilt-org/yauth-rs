use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An API key — bearer credential issued either to a user or to an
/// organization ("service account", issue #91).
///
/// # Invariants
///
/// - Exactly one of `user_id` / `organization_id` is `Some` and the other
///   is `None`. Enforced at the repository layer with `RepoError::Conflict`
///   on create, and (where supported) at the database with a CHECK
///   constraint or partial unique index.
/// - `created_by_user_id` records the human who minted the key. For
///   user-scoped keys this is the same user as `user_id`; for org-scoped
///   keys it is the admin/owner who created the service account. The
///   field is never `None` — the audit trail does not allow it.
/// - `role` is `Some` only for org-scoped keys. It carries the org-role
///   the bearer acts as (e.g. `member`, `admin`). Cannot be `owner`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    /// User owner — `Some` for user-scoped keys, `None` for org-scoped.
    pub user_id: Option<Uuid>,
    /// Org owner — `Some` for org-scoped keys, `None` for user-scoped.
    pub organization_id: Option<Uuid>,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Option<serde_json::Value>,
    /// Org-role the bearer acts as (`member`, `admin`, …). Only set for
    /// org-scoped keys.
    pub role: Option<String>,
    pub last_used_at: Option<NaiveDateTime>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    /// Human who minted the key. Audit trail. Always set.
    pub created_by_user_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewApiKey {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Option<serde_json::Value>,
    pub role: Option<String>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub created_by_user_id: Uuid,
}

impl NewApiKey {
    /// Convenience constructor for user-scoped keys (the legacy shape).
    /// Sets `organization_id = None`, `role = None`, and
    /// `created_by_user_id = user_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn for_user(
        id: Uuid,
        user_id: Uuid,
        key_prefix: String,
        key_hash: String,
        name: String,
        scopes: Option<serde_json::Value>,
        expires_at: Option<NaiveDateTime>,
        created_at: NaiveDateTime,
    ) -> Self {
        Self {
            id,
            user_id: Some(user_id),
            organization_id: None,
            key_prefix,
            key_hash,
            name,
            scopes,
            role: None,
            expires_at,
            created_at,
            created_by_user_id: user_id,
        }
    }
}
