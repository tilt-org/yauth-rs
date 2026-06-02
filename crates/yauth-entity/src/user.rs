use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<NaiveDateTime>,
    /// `suspended_at` globally disables the account (offboarding) — distinct
    /// from `banned`, which is for security incidents. A suspended user cannot
    /// log in, receive tokens, or pass auth resolution; the account is retained.
    #[serde(default)]
    pub suspended_at: Option<NaiveDateTime>,
    #[serde(default)]
    pub suspended_reason: Option<String>,
    /// `activates_at` schedules a start: while it is in the future the user is
    /// "staged" and cannot authenticate yet (onboarding ahead of a start date).
    #[serde(default)]
    pub activates_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl User {
    /// Reports whether the user has a scheduled start still in the future.
    pub fn staged(&self, now: NaiveDateTime) -> bool {
        self.activates_at.is_some_and(|at| now < at)
    }

    /// Reports whether the user may currently sign in or receive tokens: not
    /// banned, not suspended, and past any scheduled start.
    pub fn can_authenticate(&self, now: NaiveDateTime) -> bool {
        !self.banned && self.suspended_at.is_none() && !self.staged(now)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<NaiveDateTime>,
    #[serde(default)]
    pub suspended_at: Option<NaiveDateTime>,
    #[serde(default)]
    pub suspended_reason: Option<String>,
    #[serde(default)]
    pub activates_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub display_name: Option<Option<String>>,
    pub email_verified: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub banned_reason: Option<Option<String>>,
    pub banned_until: Option<Option<NaiveDateTime>>,
    pub suspended_at: Option<Option<NaiveDateTime>>,
    pub suspended_reason: Option<Option<String>>,
    pub activates_at: Option<Option<NaiveDateTime>>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    /// Active organization claim (issue #89). `None` means no active org —
    /// the default for single-tenant deployments and for users with zero
    /// memberships. The field is always present in the domain type; SQL
    /// backends that have not yet shipped the column persist `None`.
    #[serde(default)]
    pub active_org_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    /// Initial active organization (issue #89). See `Session::active_org_id`.
    #[serde(default)]
    pub active_org_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn base_user() -> User {
        let now = Utc::now().naive_utc();
        User {
            id: Uuid::now_v7(),
            email: "u@example.com".into(),
            display_name: None,
            email_verified: true,
            role: "user".into(),
            banned: false,
            banned_reason: None,
            banned_until: None,
            suspended_at: None,
            suspended_reason: None,
            activates_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn clean_user_can_authenticate() {
        let now = Utc::now().naive_utc();
        let u = base_user();
        assert!(u.can_authenticate(now));
        assert!(!u.staged(now));
    }

    #[test]
    fn banned_cannot_authenticate() {
        let now = Utc::now().naive_utc();
        let mut u = base_user();
        u.banned = true;
        assert!(!u.can_authenticate(now));
    }

    #[test]
    fn suspended_cannot_authenticate() {
        let now = Utc::now().naive_utc();
        let mut u = base_user();
        u.suspended_at = Some(now - Duration::hours(1));
        assert!(!u.can_authenticate(now));
    }

    #[test]
    fn staged_future_start_cannot_authenticate() {
        let now = Utc::now().naive_utc();
        let mut u = base_user();
        u.activates_at = Some(now + Duration::hours(1));
        assert!(u.staged(now));
        assert!(!u.can_authenticate(now));
    }

    #[test]
    fn past_activation_can_authenticate() {
        let now = Utc::now().naive_utc();
        let mut u = base_user();
        u.activates_at = Some(now - Duration::hours(1));
        assert!(!u.staged(now));
        assert!(u.can_authenticate(now));
    }
}
