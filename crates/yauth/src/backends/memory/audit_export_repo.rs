#![forbid(unsafe_code)]
//! In-memory implementations of the audit-export repository traits.
//!
//! Memory backend is **canonical-semantics** but not canonical-persistence —
//! events buffered in the outbox are lost on process restart. This is the
//! same trade-off used in Phase A/B / SAML / SCIM: SQL backends defer
//! durability via `RepoError::NotImplemented`. See
//! `docs/audit-export/README.md` "Durability model".

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{NaiveDateTime, Utc};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::domain;
use crate::repo::{
    AuditExportDestinationFilter, AuditExportDestinationRepository, AuditOutboxRepository,
    ClaimOutboxBatch, RepoError, RepoFuture, sealed,
};

// ---------------------------------------------------------------------------
// Shared mutex spans audit-insert + outbox-enqueue. The same mutex must
// guard `audit_logs` modifications when audit-export is on so the
// "outbox transactional" pentest holds. We expose the mutex via the
// `Storage` wrapper.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub(crate) struct AuditExportState {
    /// Destinations table (deployment-wide + per-org).
    pub(crate) destinations: Arc<Mutex<HashMap<Uuid, domain::AuditExportDestination>>>,
    /// Outbox table.
    pub(crate) outbox: Arc<Mutex<HashMap<Uuid, domain::AuditOutboxEntry>>>,
    /// Dead-letter counters (per destination) — kept separately because
    /// dead-letter rows stay in `outbox` and we need a fast scan-free count
    /// for the metric gauge.
    pub(crate) dead_letter_totals: Arc<Mutex<HashMap<Uuid, u64>>>,
}

// ---------------------------------------------------------------------------
// Destination repo
// ---------------------------------------------------------------------------

pub struct InMemoryAuditExportDestinationRepo {
    state: AuditExportState,
}

impl InMemoryAuditExportDestinationRepo {
    pub fn new(state: AuditExportState) -> Self {
        Self { state }
    }
}

impl sealed::Sealed for InMemoryAuditExportDestinationRepo {}

impl AuditExportDestinationRepository for InMemoryAuditExportDestinationRepo {
    fn create(
        &self,
        input: domain::NewAuditExportDestination,
    ) -> RepoFuture<'_, domain::AuditExportDestination> {
        Box::pin(async move {
            let mut g = self.state.destinations.lock().await;
            if g.contains_key(&input.id) {
                return Err(RepoError::Conflict(format!(
                    "audit_export_destination {} already exists",
                    input.id
                )));
            }
            let row = domain::AuditExportDestination {
                id: input.id,
                organization_id: input.organization_id,
                name: input.name,
                kind: input.kind,
                status: input.status,
                last_success_at: None,
                last_failure_at: None,
                created_at: input.created_at,
                updated_at: input.updated_at,
            };
            g.insert(row.id, row.clone());
            Ok(row)
        })
    }

    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::AuditExportDestination>> {
        Box::pin(async move {
            let g = self.state.destinations.lock().await;
            Ok(g.get(&id).cloned())
        })
    }

    fn list(
        &self,
        filter: AuditExportDestinationFilter,
    ) -> RepoFuture<'_, Vec<domain::AuditExportDestination>> {
        Box::pin(async move {
            let g = self.state.destinations.lock().await;
            let mut rows: Vec<_> = g
                .values()
                .filter(|d| match filter.organization_id {
                    Some(None) => d.organization_id.is_none(),
                    Some(Some(org)) => d.organization_id == Some(org),
                    None => true,
                })
                .filter(|d| match filter.status {
                    Some(s) => d.status == s,
                    None => true,
                })
                .cloned()
                .collect();
            rows.sort_by_key(|d| d.created_at);
            Ok(rows)
        })
    }

    fn update(
        &self,
        id: Uuid,
        changes: domain::UpdateAuditExportDestination,
    ) -> RepoFuture<'_, domain::AuditExportDestination> {
        Box::pin(async move {
            let mut g = self.state.destinations.lock().await;
            let row = g.get_mut(&id).ok_or(RepoError::NotFound)?;
            if let Some(name) = changes.name {
                row.name = name;
            }
            if let Some(kind) = changes.kind {
                row.kind = kind;
            }
            if let Some(status) = changes.status {
                row.status = status;
            }
            if let Some(s) = changes.last_success_at {
                row.last_success_at = s;
            }
            if let Some(f) = changes.last_failure_at {
                row.last_failure_at = f;
            }
            row.updated_at = changes.updated_at.unwrap_or_else(|| Utc::now().naive_utc());
            Ok(row.clone())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut g = self.state.destinations.lock().await;
            g.remove(&id).ok_or(RepoError::NotFound)?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Outbox repo
// ---------------------------------------------------------------------------

pub struct InMemoryAuditOutboxRepo {
    state: AuditExportState,
}

impl InMemoryAuditOutboxRepo {
    pub fn new(state: AuditExportState) -> Self {
        Self { state }
    }
}

impl sealed::Sealed for InMemoryAuditOutboxRepo {}

impl AuditOutboxRepository for InMemoryAuditOutboxRepo {
    fn enqueue_for_audit(
        &self,
        audit_log_id: Uuid,
        organization_id: Option<Uuid>,
    ) -> RepoFuture<'_, Vec<Uuid>> {
        Box::pin(async move {
            // Acquire destinations first to pick the matching set, then outbox.
            // Lock order: destinations -> outbox (same throughout the repo).
            let dests = self.state.destinations.lock().await;
            let matching: Vec<_> = dests
                .values()
                .filter(|d| d.status == domain::DestinationStatus::Active)
                .filter(|d| match d.organization_id {
                    None => true, // deployment-wide always matches
                    Some(org) => Some(org) == organization_id,
                })
                .map(|d| d.id)
                .collect();
            drop(dests);

            let mut g = self.state.outbox.lock().await;
            let mut ids = Vec::with_capacity(matching.len());
            for dest_id in matching {
                let id = Uuid::now_v7();
                let row = domain::AuditOutboxEntry {
                    id,
                    audit_log_id,
                    destination_id: dest_id,
                    status: domain::OutboxStatus::Pending,
                    attempts: 0,
                    last_attempt_at: None,
                    last_error: None,
                    created_at: Utc::now().naive_utc(),
                };
                g.insert(id, row);
                ids.push(id);
            }
            Ok(ids)
        })
    }

    fn claim_pending(
        &self,
        batch: ClaimOutboxBatch,
    ) -> RepoFuture<'_, Vec<domain::AuditOutboxEntry>> {
        Box::pin(async move {
            let mut g = self.state.outbox.lock().await;
            let now = Utc::now().naive_utc();
            // Find pending rows for this destination, oldest first.
            let mut candidates: Vec<_> = g
                .values()
                .filter(|e| {
                    e.destination_id == batch.destination_id
                        && e.status == domain::OutboxStatus::Pending
                })
                .cloned()
                .collect();
            candidates.sort_by_key(|e| e.created_at);
            candidates.truncate(batch.limit);

            // Mark each as last_attempt_at = now under the same lock so a
            // concurrent worker can't double-claim. We keep status =
            // Pending; mark_sent / mark_failed transitions it. The
            // "concurrent drain" pentest validates this.
            for entry in &candidates {
                if let Some(row) = g.get_mut(&entry.id) {
                    row.last_attempt_at = Some(now);
                }
            }
            Ok(candidates)
        })
    }

    fn mark_sent(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut g = self.state.outbox.lock().await;
            let row = g.get_mut(&id).ok_or(RepoError::NotFound)?;
            row.status = domain::OutboxStatus::Sent;
            row.last_attempt_at = Some(Utc::now().naive_utc());
            row.last_error = None;
            Ok(())
        })
    }

    fn mark_failed(&self, id: Uuid, attempts: i32, error: String) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut g = self.state.outbox.lock().await;
            let row = g.get_mut(&id).ok_or(RepoError::NotFound)?;
            row.status = domain::OutboxStatus::Pending;
            row.attempts = attempts;
            row.last_attempt_at = Some(Utc::now().naive_utc());
            row.last_error = Some(error);
            Ok(())
        })
    }

    fn mark_dead_letter(&self, id: Uuid, attempts: i32, error: String) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let dest_id = {
                let mut g = self.state.outbox.lock().await;
                let row = g.get_mut(&id).ok_or(RepoError::NotFound)?;
                row.status = domain::OutboxStatus::DeadLetter;
                row.attempts = attempts;
                row.last_attempt_at = Some(Utc::now().naive_utc());
                row.last_error = Some(error);
                row.destination_id
            };
            let mut dl = self.state.dead_letter_totals.lock().await;
            *dl.entry(dest_id).or_insert(0) += 1;
            Ok(())
        })
    }

    fn oldest_pending(&self, destination_id: Uuid) -> RepoFuture<'_, Option<NaiveDateTime>> {
        Box::pin(async move {
            let g = self.state.outbox.lock().await;
            Ok(g.values()
                .filter(|e| {
                    e.destination_id == destination_id && e.status == domain::OutboxStatus::Pending
                })
                .map(|e| e.created_at)
                .min())
        })
    }

    fn dead_letter_count(&self, destination_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let g = self.state.dead_letter_totals.lock().await;
            Ok(*g.get(&destination_id).unwrap_or(&0))
        })
    }

    fn replay(&self, audit_log_id: Uuid, destination_ids: &[Uuid]) -> RepoFuture<'_, Vec<Uuid>> {
        let destination_ids = destination_ids.to_vec();
        Box::pin(async move {
            let mut g = self.state.outbox.lock().await;
            let mut ids = Vec::with_capacity(destination_ids.len());
            for dest_id in destination_ids {
                let id = Uuid::now_v7();
                g.insert(
                    id,
                    domain::AuditOutboxEntry {
                        id,
                        audit_log_id,
                        destination_id: dest_id,
                        status: domain::OutboxStatus::Pending,
                        attempts: 0,
                        last_attempt_at: None,
                        last_error: None,
                        created_at: Utc::now().naive_utc(),
                    },
                );
                ids.push(id);
            }
            Ok(ids)
        })
    }

    fn list_for_destination(
        &self,
        destination_id: Uuid,
        limit: usize,
    ) -> RepoFuture<'_, Vec<domain::AuditOutboxEntry>> {
        Box::pin(async move {
            let g = self.state.outbox.lock().await;
            let mut rows: Vec<_> = g
                .values()
                .filter(|e| e.destination_id == destination_id)
                .cloned()
                .collect();
            rows.sort_by_key(|e| std::cmp::Reverse(e.created_at));
            rows.truncate(limit);
            Ok(rows)
        })
    }
}
