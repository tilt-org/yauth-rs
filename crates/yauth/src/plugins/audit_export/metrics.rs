#![forbid(unsafe_code)]
//! OTel metrics for the audit-export pipeline.
//!
//! Metrics:
//!   - `yauth_audit_export_events_total{destination, format, outcome}` (counter)
//!   - `yauth_audit_export_lag_seconds{destination}` (gauge)
//!   - `yauth_audit_export_dead_letter_total{destination}` (counter)
//!
//! When the `telemetry` feature is off these compile to no-ops. The struct
//! returned by `init()` is `Send + Sync + 'static` so the worker can hold it
//! across threads.

#[cfg(feature = "telemetry")]
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Gauge, Meter},
};

#[derive(Clone)]
pub struct AuditExportMetrics {
    #[cfg(feature = "telemetry")]
    events_total: Counter<u64>,
    #[cfg(feature = "telemetry")]
    lag_seconds: Gauge<f64>,
    #[cfg(feature = "telemetry")]
    dead_letter_total: Counter<u64>,
}

impl AuditExportMetrics {
    #[cfg(feature = "telemetry")]
    pub fn init(meter: &Meter) -> Self {
        Self {
            events_total: meter
                .u64_counter("yauth_audit_export_events_total")
                .with_description("Audit-export events shipped (or attempted) per destination.")
                .build(),
            lag_seconds: meter
                .f64_gauge("yauth_audit_export_lag_seconds")
                .with_description("Seconds since the oldest pending outbox entry per destination.")
                .build(),
            dead_letter_total: meter
                .u64_counter("yauth_audit_export_dead_letter_total")
                .with_description("Outbox entries transitioned to dead_letter.")
                .build(),
        }
    }

    #[cfg(not(feature = "telemetry"))]
    pub fn noop() -> Self {
        Self {}
    }

    pub fn record_outcome(&self, _destination: &str, _format: &str, _outcome: &str) {
        #[cfg(feature = "telemetry")]
        self.events_total.add(
            1,
            &[
                KeyValue::new("destination", _destination.to_string()),
                KeyValue::new("format", _format.to_string()),
                KeyValue::new("outcome", _outcome.to_string()),
            ],
        );
    }

    pub fn record_lag(&self, _destination: &str, _seconds: f64) {
        #[cfg(feature = "telemetry")]
        self.lag_seconds.record(
            _seconds,
            &[KeyValue::new("destination", _destination.to_string())],
        );
    }

    pub fn record_dead_letter(&self, _destination: &str) {
        #[cfg(feature = "telemetry")]
        self.dead_letter_total
            .add(1, &[KeyValue::new("destination", _destination.to_string())]);
    }
}
