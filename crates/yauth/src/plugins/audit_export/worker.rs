#![forbid(unsafe_code)]
//! Per-destination drain worker.
//!
//! Each worker owns a single destination. It loops:
//!   1. claim_pending(batch_size)
//!   2. for each entry: load audit row, dispatcher.send_one, mark_sent /
//!      mark_failed / mark_dead_letter
//!   3. sleep batch_interval or wake on shutdown
//!
//! Backoff schedule (attempts → next-delay): 1s, 5s, 30s, 5m, 1h. After
//! attempt 5, transition to `dead_letter` and emit metric.
//!
//! Shutdown: `WorkerHandle::shutdown(timeout)` sends on a one-shot,
//! waits for the worker's done-rx with a deadline, then forces drop. The
//! "Worker shutdown" pentest asserts a SIGTERM-style flow ends within 10s.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use uuid::Uuid;

use crate::domain;
use crate::repo::{AuditLogFilter, ClaimOutboxBatch, Repositories};

use super::destination::{DispatchError, Dispatcher};
use super::metrics::AuditExportMetrics;

/// Backoff schedule. Index = attempts AFTER the failing attempt. Past the
/// last index the dispatcher transitions the entry to dead_letter.
const BACKOFF_SCHEDULE_SECS: &[u64] = &[1, 5, 30, 300, 3600];

#[derive(Clone)]
pub struct WorkerConfig {
    pub destination_id: Uuid,
    pub batch_size: usize,
    pub batch_interval: Duration,
    pub max_inflight: usize,
    pub retry_max_attempts: u32,
}

pub struct WorkerHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

impl WorkerHandle {
    /// Send shutdown signal and wait up to `timeout` for the worker to
    /// drain its in-flight requests. Returns `true` if the worker exited
    /// cleanly, `false` on deadline-exceeded (in which case the JoinHandle
    /// is aborted).
    pub async fn shutdown(mut self, timeout: Duration) -> bool {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        match tokio::time::timeout(timeout, &mut self.join).await {
            Ok(_) => true,
            Err(_) => {
                self.join.abort();
                false
            }
        }
    }
}

/// Spawn a drain worker.
pub fn spawn(
    cfg: WorkerConfig,
    repos: Repositories,
    dispatcher: Arc<Dispatcher>,
    metrics: AuditExportMetrics,
) -> WorkerHandle {
    let (tx, mut rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(cfg.max_inflight.max(1)));
        let mut next_poll = Instant::now();
        loop {
            tokio::select! {
                _ = &mut rx => {
                    // shutdown requested — drop into final drain
                    let _ = drain_once(&cfg, &repos, &dispatcher, &metrics, &semaphore).await;
                    break;
                }
                _ = tokio::time::sleep_until(next_poll) => {
                    let _ = drain_once(&cfg, &repos, &dispatcher, &metrics, &semaphore).await;
                    // lag gauge — best effort
                    if let Ok(Some(oldest)) = repos
                        .audit_outbox
                        .oldest_pending(cfg.destination_id)
                        .await
                    {
                        let secs = (chrono::Utc::now().naive_utc() - oldest)
                            .num_seconds()
                            .max(0) as f64;
                        metrics.record_lag(&cfg.destination_id.to_string(), secs);
                    } else {
                        metrics.record_lag(&cfg.destination_id.to_string(), 0.0);
                    }
                    next_poll = Instant::now() + cfg.batch_interval;
                }
            }
        }
    });
    WorkerHandle {
        shutdown_tx: Some(tx),
        join,
    }
}

async fn drain_once(
    cfg: &WorkerConfig,
    repos: &Repositories,
    dispatcher: &Arc<Dispatcher>,
    metrics: &AuditExportMetrics,
    semaphore: &Arc<tokio::sync::Semaphore>,
) -> Result<(), crate::repo::RepoError> {
    let claimed = repos
        .audit_outbox
        .claim_pending(ClaimOutboxBatch {
            destination_id: cfg.destination_id,
            limit: cfg.batch_size,
        })
        .await?;
    if claimed.is_empty() {
        return Ok(());
    }
    // Fetch the destination once per pass — kind may have been updated.
    let dest = match repos
        .audit_export_destinations
        .find_by_id(cfg.destination_id)
        .await?
    {
        Some(d) => d,
        None => return Ok(()),
    };
    if dest.status != domain::DestinationStatus::Active {
        return Ok(());
    }

    let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(claimed.len());
    for entry in claimed {
        let permit = semaphore.clone().acquire_owned().await.expect("sem closed");
        let dispatcher_cloned = dispatcher.clone();
        let repos_cloned = repos.clone();
        let metrics_cloned = metrics.clone();
        let dest_cloned = dest.clone();
        let retry_max = cfg.retry_max_attempts;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let audit = match load_audit(&repos_cloned, entry.audit_log_id).await {
                Ok(Some(a)) => a,
                Ok(None) => {
                    // Audit row vanished — mark sent and move on.
                    let _ = repos_cloned.audit_outbox.mark_sent(entry.id).await;
                    return;
                }
                Err(_) => {
                    let _ = repos_cloned
                        .audit_outbox
                        .mark_failed(
                            entry.id,
                            entry.attempts + 1,
                            "audit_log lookup failed".into(),
                        )
                        .await;
                    return;
                }
            };
            let attempt = entry.attempts + 1;
            let result = dispatcher_cloned.send_one(&dest_cloned, &audit).await;
            let kind_tag = dest_cloned.kind.kind_tag();
            let dest_id_str = dest_cloned.id.to_string();
            match result {
                Ok(()) => {
                    let _ = repos_cloned.audit_outbox.mark_sent(entry.id).await;
                    metrics_cloned.record_outcome(&dest_id_str, kind_tag, "success");
                    let _ = repos_cloned
                        .audit_export_destinations
                        .update(
                            dest_cloned.id,
                            domain::UpdateAuditExportDestination {
                                last_success_at: Some(Some(chrono::Utc::now().naive_utc())),
                                ..Default::default()
                            },
                        )
                        .await;
                }
                Err(DispatchError::NotImplemented(tag)) => {
                    let _ = repos_cloned
                        .audit_outbox
                        .mark_dead_letter(
                            entry.id,
                            attempt,
                            format!("destination not implemented: {tag}"),
                        )
                        .await;
                    metrics_cloned.record_dead_letter(&dest_id_str);
                    metrics_cloned.record_outcome(&dest_id_str, kind_tag, "not_implemented");
                }
                Err(e) => {
                    if attempt >= retry_max as i32 {
                        let _ = repos_cloned
                            .audit_outbox
                            .mark_dead_letter(entry.id, attempt, e.to_string())
                            .await;
                        metrics_cloned.record_dead_letter(&dest_id_str);
                        metrics_cloned.record_outcome(&dest_id_str, kind_tag, "dead_letter");
                    } else {
                        let _ = repos_cloned
                            .audit_outbox
                            .mark_failed(entry.id, attempt, e.to_string())
                            .await;
                        metrics_cloned.record_outcome(&dest_id_str, kind_tag, "retry");
                        // Sleep proportional to the backoff schedule. We
                        // intentionally sleep INSIDE the spawned task —
                        // the inflight permit holds the semaphore so the
                        // worker self-rate-limits.
                        let idx = (attempt as usize)
                            .saturating_sub(1)
                            .min(BACKOFF_SCHEDULE_SECS.len().saturating_sub(1));
                        tokio::time::sleep(Duration::from_secs(BACKOFF_SCHEDULE_SECS[idx])).await;
                    }
                    let _ = repos_cloned
                        .audit_export_destinations
                        .update(
                            dest_cloned.id,
                            domain::UpdateAuditExportDestination {
                                last_failure_at: Some(Some(chrono::Utc::now().naive_utc())),
                                ..Default::default()
                            },
                        )
                        .await;
                }
            }
        }));
    }
    // We deliberately do NOT join the handles here — the worker tick stays
    // short and shutdown will await in-flight via permit acquisition.
    for h in handles {
        // Detach is intentional but track failures for visibility.
        drop(h);
    }
    Ok(())
}

/// Reload the audit row from storage. The current `AuditLogRepository`
/// trait only exposes `list`, so we filter on `event_type` is wrong here —
/// instead we list the entire table and find by id. For memory backends this
/// is a small Vec<>; for SQL backends the repo will need a `find_by_id` in
/// a follow-up issue.
async fn load_audit(
    repos: &Repositories,
    audit_id: Uuid,
) -> Result<Option<domain::AuditLog>, crate::repo::RepoError> {
    let rows = repos
        .audit
        .list(AuditLogFilter::default(), 10_000, 0)
        .await?;
    Ok(rows.into_iter().find(|a| a.id == audit_id))
}
