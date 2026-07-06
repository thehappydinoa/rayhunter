//! Liveness/health endpoint and a test-event injector.
//!
//! `GET /api/health` gives an external supervisor (e.g. Muninn) a single view
//! of whether this sensor is alive and working: uptime, whether a recording is
//! active (which implies DIAG is open and being read), which analyzers are
//! running, the last serving cell seen, and the report schema version.
//!
//! `POST /api/inject-test-event` pushes a synthetic warning through the live
//! broadcast so the whole detection→SSE pipeline can be validated end-to-end
//! without waiting for a real event.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use rayhunter::analysis::analyzer::{
    AnalyzerId, AnalyzerMetadata, Event, EventType, Harness, REPORT_VERSION,
};
use rayhunter::analysis::cell_info::ServingCellInfo;
use serde::Serialize;

use crate::events::LiveEvent;
use crate::server::ServerState;

/// A point-in-time liveness snapshot of the daemon.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct HealthStatus {
    /// Seconds since this daemon instance started.
    pub uptime_seconds: u64,
    /// True if running without DIAG/device access (frontend-only).
    pub debug_mode: bool,
    /// True if a recording is active, which implies DIAG is open and being read.
    pub recording_active: bool,
    /// Name of the active recording, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_recording: Option<String>,
    /// The analyzers currently enabled, with their versions.
    pub analyzers: Vec<AnalyzerMetadata>,
    /// The most recently observed serving cell, if any SIB1 has been seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_cell: Option<ServingCellInfo>,
    /// The analysis report schema version this daemon emits.
    pub report_version: u32,
}

/// Report daemon liveness and working state.
#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/health",
    tag = "Statistics",
    responses(
        (status = 200, description = "Daemon health snapshot", body = HealthStatus)
    ),
    summary = "Health/heartbeat",
    description = "A single liveness view: uptime, recording/DIAG state, enabled analyzers, last-seen serving cell, and report schema version."
))]
pub async fn get_health(State(state): State<Arc<ServerState>>) -> Json<HealthStatus> {
    let (recording_active, current_recording) = {
        let store = state.qmdl_store_lock.read().await;
        match store.current_entry {
            Some(idx) => (true, Some(store.manifest.entries[idx].name.clone())),
            None => (false, None),
        }
    };

    // Reuse the harness to list exactly the analyzers that would run, with
    // their versions, without duplicating the config→analyzer mapping here.
    let analyzers = Harness::new_with_config(&state.config.analyzers)
        .get_metadata()
        .analyzers;

    Json(HealthStatus {
        uptime_seconds: state.start_time.elapsed().as_secs(),
        debug_mode: state.config.debug_mode,
        recording_active,
        current_recording,
        analyzers,
        last_cell: state.last_cell.read().await.clone(),
        report_version: REPORT_VERSION,
    })
}

/// Result of injecting a test event.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct InjectResult {
    /// Number of live SSE subscribers the test event was delivered to.
    pub delivered_to: usize,
}

/// Inject a synthetic warning into the live event stream.
#[cfg_attr(feature = "apidocs", utoipa::path(
    post,
    path = "/api/inject-test-event",
    tag = "Statistics",
    responses(
        (status = 200, description = "Test event broadcast", body = InjectResult)
    ),
    summary = "Inject a test event",
    description = "Broadcast a synthetic High-severity warning to all `/api/events` SSE subscribers, to validate the detection pipeline end-to-end. Does not touch recordings or analysis files."
))]
pub async fn inject_test_event(State(state): State<Arc<ServerState>>) -> Json<InjectResult> {
    let event = Event {
        event_type: EventType::High,
        message: "Injected test event".to_string(),
        analyzer: Some(AnalyzerId {
            name: "Test Injection".to_string(),
            version: 1,
        }),
        confidence: None,
        cell: state.last_cell.read().await.clone(),
    };
    let live = LiveEvent {
        timestamp: None,
        position: None,
        event,
    };
    // `send` errs only if there are no subscribers; report 0 in that case.
    let delivered_to = state.event_broadcast.send(live).unwrap_or(0);
    Json(InjectResult { delivered_to })
}
