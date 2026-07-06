//! Server-Sent Events stream of live detections.
//!
//! Warnings are time-sensitive, so rather than making clients poll the
//! analysis report, the live analysis path broadcasts each warning as it
//! fires and `GET /api/events` streams them to any number of subscribers over
//! SSE. This lets an external system (e.g. Muninn) react in near-real-time.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Sse;
use axum::response::sse::{Event as SseEvent, KeepAlive};
use chrono::{DateTime, FixedOffset};
use futures::Stream;
use log::warn;
use rayhunter::analysis::analyzer::{Event, Position};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::server::ServerState;

/// The channel over which the live analysis path publishes detections to SSE
/// subscribers. A bounded broadcast: slow subscribers lag and miss events
/// rather than blocking the analysis loop.
pub type EventSender = broadcast::Sender<LiveEvent>;

/// Capacity of the broadcast buffer. Warnings are infrequent, so this is
/// generous; a subscriber that falls this far behind will skip missed events.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// A single live detection pushed to SSE subscribers: one warning [`Event`]
/// plus the capture context (timestamp, position) needed to place it.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct LiveEvent {
    /// Packet (modem clock) timestamp of the detection, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<FixedOffset>>,
    /// GPS position in effect when the detection fired, if a fix was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<Position>,
    /// The warning event, including severity, message, analyzer, and serving cell.
    pub event: Event,
}

/// Stream live warning detections over Server-Sent Events.
#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/events",
    tag = "Statistics",
    responses(
        (status = 200, description = "An SSE stream of live detections", content_type = "text/event-stream")
    ),
    summary = "Live event stream",
    description = "Server-Sent Events stream that emits a JSON `LiveEvent` for each warning as it is detected during recording. Subscribers that fall behind will skip missed events."
))]
pub async fn get_events(
    State(state): State<Arc<ServerState>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.event_broadcast.subscribe();
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(live) => {
                    let sse_event = match SseEvent::default().json_data(&live) {
                        Ok(ev) => ev,
                        Err(e) => {
                            warn!("failed to serialize live event for SSE: {e}");
                            continue;
                        }
                    };
                    return Some((Ok(sse_event), rx));
                }
                // The subscriber lagged and missed some events; keep going with
                // whatever is still buffered rather than closing the stream.
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("SSE subscriber lagged, skipped {skipped} events");
                    continue;
                }
                // All senders dropped (daemon shutting down/restarting).
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
