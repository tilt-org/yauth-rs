use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Filter parameters for `list`. All `None` means no filter on that axis.
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub user_id: Option<Uuid>,
    pub event_type: Option<String>,
}

/// Repository for audit log entries.
///
/// Insert-only — audit logs are never updated or deleted. The `list` query
/// is admin-facing and orders newest-first.
pub trait AuditLogRepository: sealed::Sealed + Send + Sync {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()>;

    /// Return up to `limit` audit log rows starting at `offset`, ordered
    /// `created_at` descending. Filters are AND-combined.
    fn list(
        &self,
        filter: AuditLogFilter,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, Vec<domain::AuditLog>>;
}
