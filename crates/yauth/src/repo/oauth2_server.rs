use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for OAuth2 server clients.
pub trait Oauth2ClientRepository: sealed::Sealed + Send + Sync {
    fn find_by_client_id(&self, client_id: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>>;

    fn create(&self, input: domain::NewOauth2Client) -> RepoFuture<'_, ()>;

    /// Set the ban state for a client. `Some((reason, when))` marks banned,
    /// `None` clears the ban. Returns `true` if the row was updated.
    fn set_banned(
        &self,
        client_id: &str,
        banned: Option<(Option<String>, chrono::NaiveDateTime)>,
    ) -> RepoFuture<'_, bool>;

    /// Replace the registered public signing key for `private_key_jwt`.
    /// Returns `true` if the row was updated.
    fn rotate_public_key(
        &self,
        client_id: &str,
        public_key_pem: Option<String>,
    ) -> RepoFuture<'_, bool>;

    /// List clients currently banned, newest ban first. Used by the admin
    /// list endpoint; other read paths stay on `find_by_client_id`.
    fn list_banned(&self) -> RepoFuture<'_, Vec<domain::Oauth2Client>>;

    /// Set the OIDC logout configuration for a client (RP-Initiated Logout +
    /// Back-Channel Logout). The repo is a dumb writer — callers are
    /// responsible for sanitizing/validating the URIs before persisting.
    /// Returns `true` if the row was updated.
    fn set_logout_config(
        &self,
        client_id: &str,
        post_logout_redirect_uris: Option<serde_json::Value>,
        backchannel_logout_uri: Option<String>,
        backchannel_logout_session_required: bool,
    ) -> RepoFuture<'_, bool>;

    /// Stamp the last successful token-endpoint use of a client. Called
    /// best-effort on every token issuance (errors are ignored by callers) so
    /// the stale-client sweep never reclaims an actively-used client. No-op
    /// effect on the response — purely an activity marker.
    fn touch_last_used(&self, client_id: &str, at: chrono::NaiveDateTime) -> RepoFuture<'_, ()>;

    /// Purge dynamically-registered (RFC 7591) public clients whose last use
    /// (or creation, if never used) predates `cutoff`. Admin-provisioned and
    /// banned clients are never touched. Transactional: dependent consents,
    /// authorization codes, and device codes (keyed by `client_id`, no FK
    /// cascade) are deleted in the same transaction. Returns the swept
    /// `client_id`s.
    fn purge_stale_dynamic_clients(
        &self,
        cutoff: chrono::NaiveDateTime,
    ) -> RepoFuture<'_, Vec<String>>;
}

/// Repository for authorization codes.
///
/// # Invariants
///
/// - **`find_by_code_hash`**: MUST return `None` if expired or already used.
pub trait AuthorizationCodeRepository: sealed::Sealed + Send + Sync {
    fn find_by_code_hash(
        &self,
        code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::AuthorizationCode>>;

    fn create(&self, input: domain::NewAuthorizationCode) -> RepoFuture<'_, ()>;

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()>;
}

/// Repository for user consent records.
pub trait ConsentRepository: sealed::Sealed + Send + Sync {
    fn find_by_user_and_client(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> RepoFuture<'_, Option<domain::Consent>>;

    fn create(&self, input: domain::NewConsent) -> RepoFuture<'_, ()>;

    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()>;

    /// List every consent the user has granted, used by Back-Channel Logout
    /// fan-out to find the RPs that should be notified on offboarding.
    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::Consent>>;
}

/// Repository for device authorization flow codes.
pub trait DeviceCodeRepository: sealed::Sealed + Send + Sync {
    fn find_by_user_code_pending(
        &self,
        user_code: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>>;

    fn find_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>>;

    fn create(&self, input: domain::NewDeviceCode) -> RepoFuture<'_, ()>;

    /// Update status, user_id, and/or other fields on a device code.
    fn update_status(&self, id: Uuid, status: &str, user_id: Option<Uuid>) -> RepoFuture<'_, ()>;

    fn update_last_polled(&self, id: Uuid) -> RepoFuture<'_, ()>;

    fn update_interval(&self, id: Uuid, interval: i32) -> RepoFuture<'_, ()>;
}
