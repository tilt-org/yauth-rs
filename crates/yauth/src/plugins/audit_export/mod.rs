#![forbid(unsafe_code)]
//! Audit log SIEM/syslog export plugin (issue #96).
//!
//! See `docs/audit-export/README.md` for the architecture overview, durability
//! model, and per-SIEM integration guides.
//!
//! ## Module layout
//!
//! - [`format`] — pluggable output formatters (JSON, RFC 5424, CEF stub).
//! - [`destination`] — pluggable dispatchers (Webhook, Syslog, S3, Splunk stub,
//!   Datadog stub).
//! - [`worker`] — per-destination drain loop with exponential backoff,
//!   inflight cap, and clean shutdown.
//! - [`routes`] — admin CRUD + replay endpoint.
//! - [`metrics`] — OTel counters/gauges.

pub mod destination;
pub mod format;
pub mod metrics;
pub mod routes;
pub mod worker;

use axum::Router;

use crate::config::AuditExportConfig;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

pub struct AuditExportPlugin {
    config: AuditExportConfig,
}

impl AuditExportPlugin {
    pub fn new(config: AuditExportConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &AuditExportConfig {
        &self.config
    }
}

impl YAuthPlugin for AuditExportPlugin {
    fn name(&self) -> &'static str {
        "audit-export"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(routes::router(ctx, self.config.clone()))
    }
}

// ---------------------------------------------------------------------------
// Worker orchestration
// ---------------------------------------------------------------------------

use std::sync::Arc;

use destination::Dispatcher;
use metrics::AuditExportMetrics;
use worker::{WorkerConfig, WorkerHandle};

/// Manages the per-destination drain workers. Callers spawn one set at app
/// boot and call `shutdown(timeout)` on app shutdown.
pub struct AuditExportWorkers {
    handles: Vec<WorkerHandle>,
}

impl AuditExportWorkers {
    /// Spawn one drain worker per currently-active destination. Future
    /// rotations (new destination created at runtime) are handled by
    /// `refresh()`, which the operator can call periodically; or simply
    /// shut down + re-spawn on a SIGHUP.
    pub async fn spawn(
        state: &YAuthState,
        config: &crate::config::AuditExportConfig,
    ) -> Result<Self, crate::repo::RepoError> {
        Self::spawn_with_dispatcher(
            state,
            config,
            Arc::new(Dispatcher::new(
                config.http_timeout,
                config.signature_window,
            )),
        )
        .await
    }

    /// Test-only / advanced: spawn with a pre-built dispatcher (e.g. with
    /// test hooks attached for the pentest harness).
    pub async fn spawn_with_dispatcher(
        state: &YAuthState,
        config: &crate::config::AuditExportConfig,
        dispatcher: Arc<Dispatcher>,
    ) -> Result<Self, crate::repo::RepoError> {
        let metrics = build_metrics();
        let dests = state
            .repos
            .audit_export_destinations
            .list(crate::repo::AuditExportDestinationFilter {
                organization_id: None,
                status: Some(crate::domain::DestinationStatus::Active),
            })
            .await?;
        let mut handles = Vec::with_capacity(dests.len());
        for d in dests {
            let cfg = WorkerConfig {
                destination_id: d.id,
                batch_size: config.batch_size,
                batch_interval: config.batch_interval,
                max_inflight: config.max_inflight,
                retry_max_attempts: config.retry_max_attempts,
            };
            handles.push(worker::spawn(
                cfg,
                state.repos.clone(),
                dispatcher.clone(),
                metrics.clone(),
            ));
        }
        Ok(Self { handles })
    }

    pub fn worker_count(&self) -> usize {
        self.handles.len()
    }

    /// Initiate clean shutdown of every worker, waiting up to `timeout`
    /// for each to drain in-flight requests.
    pub async fn shutdown(self, timeout: std::time::Duration) -> ShutdownReport {
        let mut clean = 0usize;
        let mut forced = 0usize;
        for h in self.handles {
            if h.shutdown(timeout).await {
                clean += 1;
            } else {
                forced += 1;
            }
        }
        ShutdownReport { clean, forced }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ShutdownReport {
    pub clean: usize,
    pub forced: usize,
}

#[cfg(feature = "telemetry")]
fn build_metrics() -> AuditExportMetrics {
    let provider = opentelemetry::global::meter_provider();
    AuditExportMetrics::init(&provider.meter("yauth-audit-export"))
}

#[cfg(not(feature = "telemetry"))]
fn build_metrics() -> AuditExportMetrics {
    AuditExportMetrics::noop()
}
