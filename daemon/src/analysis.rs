use std::cmp;
use std::sync::Arc;

use axum::Json;
use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use log::{error, info, warn};
use rayhunter::analysis::analyzer::{AnalyzerConfig, EventType, Harness, Position};

use crate::events::{EventSender, LiveEvent};
use rayhunter::diag::{DiagParsingError, Message, MessagesContainer};
use rayhunter::qmdl::QmdlMessageReader;
use serde::Serialize;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{RwLock, RwLockWriteGuard};
use tokio_util::task::TaskTracker;

use crate::qmdl_store::{FileKind, RecordingStore};
use crate::server::ServerState;

pub struct AnalysisWriter {
    writer: BufWriter<File>,
    harness: Harness,
    /// When set (live recording), each warning is broadcast to SSE subscribers.
    /// `None` for offline re-analysis, which must not emit live events.
    event_broadcast: Option<EventSender>,
}

// We write our analysis results to a file immediately to minimize the amount of
// state Rayhunter has to keep track of in memory. The analysis file's format is
// Newline Delimited JSON
// (https://docs.mulesoft.com/dataweave/latest/dataweave-formats-ndjson), which
// lets us simply append new rows to the end without parsing the entire JSON
// object beforehand.
impl AnalysisWriter {
    pub async fn new(
        file: File,
        analyzer_config: &AnalyzerConfig,
        event_broadcast: Option<EventSender>,
    ) -> Result<Self, std::io::Error> {
        let harness = Harness::new_with_config(analyzer_config);

        let mut result = Self {
            writer: BufWriter::new(file),
            harness,
            event_broadcast,
        };
        let metadata = result.harness.get_metadata();
        result.write(&metadata).await?;
        Ok(result)
    }

    /// The most recently observed serving cell for this recording, if any.
    pub fn current_serving_cell(&self) -> Option<rayhunter::analysis::cell_info::ServingCellInfo> {
        self.harness.current_serving_cell()
    }

    /// A display summary of the operator(s) observed during this recording,
    /// derived from the serving-cell PLMNs seen. `None` until a PLMN is seen.
    pub fn observed_carrier(&self) -> Option<String> {
        self.harness.observed_carrier()
    }

    /// Publish each warning event in a written row to SSE subscribers. Skips
    /// informational events. A send error just means no subscribers, which is
    /// fine — the row is already persisted to the analysis file.
    fn broadcast_row(&self, row: &rayhunter::analysis::analyzer::AnalysisRow) {
        let Some(sender) = &self.event_broadcast else {
            return;
        };
        for event in row.events.iter().flatten() {
            if event.event_type > EventType::Informational {
                let _ = sender.send(LiveEvent {
                    timestamp: row.packet_timestamp,
                    position: row.position,
                    event: event.clone(),
                });
            }
        }
    }

    // Runs the analysis harness on the given container, serializing the results
    // to the analysis file, returning the whether any warnings were detected.
    // `position` is the GPS fix in effect for these packets, if any, and is
    // stamped onto each written row so detections can be geolocated.
    pub async fn analyze_container(
        &mut self,
        container: MessagesContainer,
        position: Option<Position>,
    ) -> Result<EventType, std::io::Error> {
        let mut max_type = EventType::Informational;

        for mut row in self.harness.analyze_qmdl_messages(container) {
            if !row.is_empty() {
                row.position = position;
                self.write(&row).await?;
                self.broadcast_row(&row);
            }
            max_type = cmp::max(max_type, row.get_max_event_type());
        }
        Ok(max_type)
    }

    pub async fn analyze_message(
        &mut self,
        maybe_qmdl_msg: Result<Message, DiagParsingError>,
        position: Option<Position>,
    ) -> Result<EventType, std::io::Error> {
        let mut row = self.harness.analyze_qmdl_message(maybe_qmdl_msg);
        if !row.is_empty() {
            row.position = position;
            self.write(&row).await?;
            self.broadcast_row(&row);
        }
        Ok(row.get_max_event_type())
    }

    async fn write<T: Serialize>(&mut self, value: &T) -> Result<(), std::io::Error> {
        let mut value_str = serde_json::to_string(value).unwrap();
        value_str.push('\n');
        self.writer.write_all(value_str.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    // Flushes any pending I/O to disk before dropping the writer
    pub async fn close(mut self) -> Result<(), std::io::Error> {
        self.writer.flush().await?;
        Ok(())
    }
}

/// The system status relating to QMDL file analysis
#[derive(Debug, Serialize, Clone)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct AnalysisStatus {
    /// The vector array of queued files
    queued: Vec<String>,
    /// The file currently being analyzed
    running: Option<String>,
    /// The vector array of finished files
    finished: Vec<String>,
}

impl AnalysisStatus {
    pub fn new(store: &RecordingStore) -> Self {
        let existing_recordings: Vec<String> = store
            .manifest
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        AnalysisStatus {
            queued: Vec::new(),
            running: None,
            finished: existing_recordings,
        }
    }
}

pub enum AnalysisCtrlMessage {
    NewFilesQueued,
    RecordingFinished(String),
    Exit,
}

async fn queued_len(analysis_status_lock: Arc<RwLock<AnalysisStatus>>) -> usize {
    analysis_status_lock.read().await.queued.len()
}

async fn dequeue_to_running(analysis_status_lock: Arc<RwLock<AnalysisStatus>>) -> String {
    let mut analysis_status = analysis_status_lock.write().await;
    let name = analysis_status.queued.remove(0);
    assert!(analysis_status.running.is_none());
    analysis_status.running = Some(name.clone());
    name
}

async fn finish_running_analysis(analysis_status_lock: Arc<RwLock<AnalysisStatus>>) {
    let mut analysis_status = analysis_status_lock.write().await;
    let finished = analysis_status.running.take().unwrap();
    analysis_status.finished.push(finished);
}

async fn perform_analysis(
    name: &str,
    qmdl_store_lock: Arc<RwLock<RecordingStore>>,
    analyzer_config: &AnalyzerConfig,
) -> Result<(), String> {
    info!("Opening QMDL and analysis file for {name}...");
    let (analysis_file, mut qmdl_reader) = {
        let mut qmdl_store = qmdl_store_lock.write().await;
        let (entry_index, _) = qmdl_store
            .entry_for_name(name)
            .ok_or(format!("failed to find QMDL store entry for {name}"))?;
        let analysis_file = qmdl_store
            .clear_and_open_entry_analysis(entry_index)
            .await
            .map_err(|e| format!("{e:?}"))?;
        let qmdl_file = qmdl_store
            .open_file(entry_index, FileKind::Qmdl)
            .await
            .map_err(|e| format!("{e:?}"))?
            .ok_or("QMDL file not found")?;
        let qmdl_reader = QmdlMessageReader::new(qmdl_file)
            .await
            .map_err(|e| format!("{e:?}"))?;

        (analysis_file, qmdl_reader)
    };

    // Offline re-analysis must not emit live SSE events.
    let mut analysis_writer = AnalysisWriter::new(analysis_file, analyzer_config, None)
        .await
        .map_err(|e| format!("{e:?}"))?;

    info!("Starting analysis for {name}...");
    while let Some(maybe_message) = qmdl_reader
        .get_next_message()
        .await
        .expect("failed to get message")
    {
        // Offline re-analysis does not fuse GPS here; position is recovered by
        // joining the separately-stored per-entry GPS records on timestamp.
        let _ = analysis_writer
            .analyze_message(maybe_message, None)
            .await
            .map_err(|e| format!("{e:?}"))?;
    }

    // Capture the observed operator(s) before `close` consumes the writer, then
    // persist it to the recording's manifest entry.
    let carrier = analysis_writer.observed_carrier();

    analysis_writer
        .close()
        .await
        .map_err(|e| format!("{e:?}"))?;

    if let Some(carrier) = carrier {
        let mut qmdl_store = qmdl_store_lock.write().await;
        if let Err(e) = qmdl_store.set_entry_carrier(name, carrier).await {
            warn!("failed to persist carrier for {name}: {e:?}");
        }
    }
    info!("Analysis for {name} complete!");

    Ok(())
}

pub fn run_analysis_thread(
    task_tracker: &TaskTracker,
    mut analysis_rx: Receiver<AnalysisCtrlMessage>,
    qmdl_store_lock: Arc<RwLock<RecordingStore>>,
    analysis_status_lock: Arc<RwLock<AnalysisStatus>>,
    analyzer_config: AnalyzerConfig,
) {
    task_tracker.spawn(async move {
        loop {
            match analysis_rx.recv().await {
                Some(AnalysisCtrlMessage::NewFilesQueued) => {
                    let count = queued_len(analysis_status_lock.clone()).await;
                    for _ in 0..count {
                        let name = dequeue_to_running(analysis_status_lock.clone()).await;
                        if let Err(err) =
                            perform_analysis(&name, qmdl_store_lock.clone(), &analyzer_config).await
                        {
                            error!("failed to analyze {name}: {err}");
                        }
                        finish_running_analysis(analysis_status_lock.clone()).await;
                    }
                }
                Some(AnalysisCtrlMessage::RecordingFinished(name)) => {
                    let mut status = analysis_status_lock.write().await;
                    status.finished.push(name);
                }
                Some(AnalysisCtrlMessage::Exit) | None => return,
            }
        }
    });
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/analysis",
    tag = "Recordings",
    responses(
        (status = StatusCode::OK, description = "Success", body = AnalysisStatus)
    ),
    summary = "Analysis status",
    description = "Show analysis status for all QMDL files."
))]
pub async fn get_analysis_status(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<AnalysisStatus>, (StatusCode, String)> {
    Ok(Json(state.analysis_status_lock.read().await.clone()))
}

fn queue_qmdl(name: &str, analysis_status: &mut RwLockWriteGuard<AnalysisStatus>) -> bool {
    if analysis_status.queued.iter().any(|n| n == name)
        || analysis_status.running.iter().any(|n| n == name)
    {
        return false;
    }
    analysis_status.queued.push(name.to_string());
    true
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    post,
    path = "/api/analysis/{name}",
    tag = "Recordings",
    responses(
        (status = StatusCode::ACCEPTED, description = "Success"),
        (status = StatusCode::INTERNAL_SERVER_ERROR, description = "Unable to queue analysis file")
    ),
    params(
        ("name" = String, Path, description = "QMDL file to analyze")
    ),
    summary = "Start analysis",
    description = "Begin analysis of QMDL file {name}."
))]
pub async fn start_analysis(
    State(state): State<Arc<ServerState>>,
    Path(qmdl_name): Path<String>,
) -> Result<(StatusCode, Json<AnalysisStatus>), (StatusCode, String)> {
    let mut analysis_status = state.analysis_status_lock.write().await;
    let store = state.qmdl_store_lock.read().await;
    let queued = if qmdl_name.is_empty() {
        let mut entry_names: Vec<&str> = store
            .manifest
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        if let Some(current_entry) = store.current_entry {
            entry_names.remove(current_entry);
        }
        entry_names
            .iter()
            .any(|name| queue_qmdl(name, &mut analysis_status))
    } else {
        queue_qmdl(&qmdl_name, &mut analysis_status)
    };
    if queued {
        state
            .analysis_sender
            .send(AnalysisCtrlMessage::NewFilesQueued)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to queue new analysis files: {e:?}"),
                )
            })?;
    }
    Ok((StatusCode::ACCEPTED, Json(analysis_status.clone())))
}
