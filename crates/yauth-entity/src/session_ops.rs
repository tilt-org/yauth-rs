use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A session record as stored by the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    /// Active organization claim (issue #89). `None` for single-tenant
    /// deployments, for users with no memberships, or for backends that
    /// have not yet shipped the active-org column.
    #[serde(default)]
    pub active_org_id: Option<Uuid>,
}
