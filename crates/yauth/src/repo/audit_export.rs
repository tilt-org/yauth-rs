#![forbid(unsafe_code)]
//! Repository traits for the audit-export plugin (issue #96).
//!
//! Memory backend is canonical. SQL backends stub these traits with
//! `RepoError::NotImplemented` — same precedent as Phase A/B / SAML / SCIM.

use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AuditExportDestinationRepository
// ---------------------------------------------------------------------------

/// Filter for listing destinations.
#[derive(Debug, Clone, Default)]
pub struct AuditExportDestinationFilter {
    /// `Some(None)` selects deployment-wide destinations (org_id IS NULL).
    /// `Some(Some(org_id))` selects rows for that org only.
    /// `None` returns every row.
    pub organization_id: Option<Option<Uuid>>,
    pub status: Option<domain::DestinationStatus>,
}

/// Repository for `AuditExportDestination` rows (both deployment-wide and
/// per-org). Sealed — first-party backends only.
pub trait AuditExportDestinationRepository: sealed::Sealed + Send + Sync {
    fn create(
        &self,
        input: domain::NewAuditExportDestination,
    ) -> RepoFuture<'_, domain::AuditExportDestination>;

    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::AuditExportDestination>>;

    fn list(
        &self,
        filter: AuditExportDestinationFilter,
    ) -> RepoFuture<'_, Vec<domain::AuditExportDestination>>;

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateAuditExportDestination,
    ) -> RepoFuture<'_, domain::AuditExportDestination>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;
}

// ---------------------------------------------------------------------------
// AuditOutboxRepository
// ---------------------------------------------------------------------------

/// Filter for `claim_pending`. The dispatcher reads ONE row at a time per
/// destination and atomically transitions `pending -> sent` after success.
#[derive(Debug, Clone)]
pub struct ClaimOutboxBatch {
    pub destination_id: Uuid,
    pub limit: usize,
}

/// Repository for the outbox queue. The memory backend uses a tokio Mutex
/// to serialize claim/insert across the audit-insert critical section.
pub trait AuditOutboxRepository: sealed::Sealed + Send + Sync {
    /// Insert one outbox row per active destination that matches `org_id`
    /// (deployment-wide rows + per-org rows for `org_id`, if `Some`). The
    /// insert is transactional with `audit_log.create` — memory backend
    /// holds a single mutex spanning both inserts. SQL backends stub.
    fn enqueue_for_audit(
        &self,
        audit_log_id: Uuid,
        organization_id: Option<Uuid>,
    ) -> RepoFuture<'_, Vec<Uuid>>;

    /// Atomically reserve up to `batch.limit` pending entries for the given
    /// destination. Returns rows transitioned to a `claimed` state (memory
    /// backend marks them `Pending` + bumps `last_attempt_at` as a sentinel;
    /// the worker writes `Sent` / `Failed` / `DeadLetter` afterward).
    fn claim_pending(
        &self,
        batch: ClaimOutboxBatch,
    ) -> RepoFuture<'_, Vec<domain::AuditOutboxEntry>>;

    fn mark_sent(&self, id: Uuid) -> RepoFuture<'_, ()>;

    fn mark_failed(&self, id: Uuid, attempts: i32, error: String) -> RepoFuture<'_, ()>;

    fn mark_dead_letter(&self, id: Uuid, attempts: i32, error: String) -> RepoFuture<'_, ()>;

    /// Stats helper for the `audit_export_lag_seconds` gauge — returns the
    /// `created_at` of the oldest pending row for `destination_id`, or
    /// `None` if the destination has no pending work.
    fn oldest_pending(&self, destination_id: Uuid)
    -> RepoFuture<'_, Option<chrono::NaiveDateTime>>;

    /// Dead-letter counter for the metric.
    fn dead_letter_count(&self, destination_id: Uuid) -> RepoFuture<'_, u64>;

    /// Re-enqueue a previously-sent / dead-lettered audit row for the given
    /// destinations. Used by the replay endpoint. Returns the new outbox
    /// row ids.
    fn replay(&self, audit_log_id: Uuid, destination_ids: &[Uuid]) -> RepoFuture<'_, Vec<Uuid>>;

    /// List outbox entries for an admin destination-status panel.
    fn list_for_destination(
        &self,
        destination_id: Uuid,
        limit: usize,
    ) -> RepoFuture<'_, Vec<domain::AuditOutboxEntry>>;
}
