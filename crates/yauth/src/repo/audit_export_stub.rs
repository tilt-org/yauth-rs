#![forbid(unsafe_code)]
//! Backend-agnostic stub implementations of the audit-export repos
//! (issue #96). Used by SQL backends as a temporary placeholder until each
//! ORM gets a real implementation. Memory backend ships the full impl.

use super::{
    AuditExportDestinationFilter, AuditExportDestinationRepository, AuditOutboxRepository,
    ClaimOutboxBatch, RepoError, RepoFuture, sealed,
};
use crate::domain;
use uuid::Uuid;

fn pending(backend: &'static str, trait_name: &'static str, op: &'static str) -> RepoError {
    RepoError::NotImplemented(format!("{backend}::{trait_name}::{op}"))
}

// ---------------------------------------------------------------------------
// AuditExportDestinationRepository stub
// ---------------------------------------------------------------------------

pub struct StubAuditExportDestinationRepo {
    backend: &'static str,
}

impl StubAuditExportDestinationRepo {
    pub fn new(backend: &'static str) -> Self {
        Self { backend }
    }
}

impl sealed::Sealed for StubAuditExportDestinationRepo {}

impl AuditExportDestinationRepository for StubAuditExportDestinationRepo {
    fn create(
        &self,
        _input: domain::NewAuditExportDestination,
    ) -> RepoFuture<'_, domain::AuditExportDestination> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditExportDestinationRepository",
                "create",
            ))
        })
    }
    fn find_by_id(&self, _id: Uuid) -> RepoFuture<'_, Option<domain::AuditExportDestination>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditExportDestinationRepository",
                "find_by_id",
            ))
        })
    }
    fn list(
        &self,
        _filter: AuditExportDestinationFilter,
    ) -> RepoFuture<'_, Vec<domain::AuditExportDestination>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditExportDestinationRepository",
                "list",
            ))
        })
    }
    fn update(
        &self,
        _id: Uuid,
        _changes: domain::UpdateAuditExportDestination,
    ) -> RepoFuture<'_, domain::AuditExportDestination> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditExportDestinationRepository",
                "update",
            ))
        })
    }
    fn delete(&self, _id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditExportDestinationRepository",
                "delete",
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// AuditOutboxRepository stub
// ---------------------------------------------------------------------------

pub struct StubAuditOutboxRepo {
    backend: &'static str,
}

impl StubAuditOutboxRepo {
    pub fn new(backend: &'static str) -> Self {
        Self { backend }
    }
}

impl sealed::Sealed for StubAuditOutboxRepo {}

impl AuditOutboxRepository for StubAuditOutboxRepo {
    fn enqueue_for_audit(
        &self,
        _audit_log_id: Uuid,
        _organization_id: Option<Uuid>,
    ) -> RepoFuture<'_, Vec<Uuid>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditOutboxRepository",
                "enqueue_for_audit",
            ))
        })
    }
    fn claim_pending(
        &self,
        _batch: ClaimOutboxBatch,
    ) -> RepoFuture<'_, Vec<domain::AuditOutboxEntry>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditOutboxRepository",
                "claim_pending",
            ))
        })
    }
    fn mark_sent(&self, _id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move { Err(pending(self.backend, "AuditOutboxRepository", "mark_sent")) })
    }
    fn mark_failed(&self, _id: Uuid, _attempts: i32, _error: String) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditOutboxRepository",
                "mark_failed",
            ))
        })
    }
    fn mark_dead_letter(&self, _id: Uuid, _attempts: i32, _error: String) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditOutboxRepository",
                "mark_dead_letter",
            ))
        })
    }
    fn oldest_pending(
        &self,
        _destination_id: Uuid,
    ) -> RepoFuture<'_, Option<chrono::NaiveDateTime>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditOutboxRepository",
                "oldest_pending",
            ))
        })
    }
    fn dead_letter_count(&self, _destination_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditOutboxRepository",
                "dead_letter_count",
            ))
        })
    }
    fn replay(&self, _audit_log_id: Uuid, _destination_ids: &[Uuid]) -> RepoFuture<'_, Vec<Uuid>> {
        Box::pin(async move { Err(pending(self.backend, "AuditOutboxRepository", "replay")) })
    }
    fn list_for_destination(
        &self,
        _destination_id: Uuid,
        _limit: usize,
    ) -> RepoFuture<'_, Vec<domain::AuditOutboxEntry>> {
        Box::pin(async move {
            Err(pending(
                self.backend,
                "AuditOutboxRepository",
                "list_for_destination",
            ))
        })
    }
}
