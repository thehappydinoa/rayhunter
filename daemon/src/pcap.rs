use crate::gps::{GpsRecord, load_gps_records};
use crate::qmdl_store::FileKind;
use crate::server::ServerState;

use crate::config::GpsMode;
use anyhow::Error;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use log::error;
use rayhunter::gsmtap::parser as gsmtap_parser;
use rayhunter::pcap::{GpsPoint, GsmtapPcapWriter};
use rayhunter::qmdl::QmdlMessageReader;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf, duplex};
use tokio::time::Sleep;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

/// How often the live PCAP stream re-checks the growing QMDL file for new
/// data once it's caught up with the end of the file.
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Reader for a QMDL file that's still being recorded. Reaching the end of
/// the file means "no new data yet", not end-of-stream, so instead of
/// reporting EOF this waits and retries until `stop` is cancelled. This has
/// to wrap the raw file rather than the parsed message stream: QMDL files
/// are gzipped, and both the decoder's stream state and QmdlAsyncReader's
/// sticky EOF handling mean the layers above can't resume after seeing EOF.
struct FollowFile {
    file: File,
    stop: CancellationToken,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl FollowFile {
    fn new(file: File, stop: CancellationToken) -> Self {
        FollowFile {
            file,
            stop,
            sleep: None,
        }
    }
}

impl AsyncRead for FollowFile {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(sleep) = this.sleep.as_mut() {
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => this.sleep = None,
                    Poll::Pending => return Poll::Pending,
                }
            }
            let filled_before = buf.filled().len();
            match Pin::new(&mut this.file).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() == filled_before => {
                    if this.stop.is_cancelled() {
                        return Poll::Ready(Ok(()));
                    }
                    this.sleep = Some(Box::pin(tokio::time::sleep(FOLLOW_POLL_INTERVAL)));
                }
                res => return res,
            }
        }
    }
}

impl AsyncSeek for FollowFile {
    fn start_seek(self: Pin<&mut Self>, position: std::io::SeekFrom) -> std::io::Result<()> {
        Pin::new(&mut self.get_mut().file).start_seek(position)
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Pin::new(&mut self.get_mut().file).poll_complete(cx)
    }
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/pcap/{name}",
    tag = "Recordings",
    responses(
        (status = StatusCode::OK, description = "PCAP conversion successful", content_type = "application/vnd.tcpdump.pcap"),
        (status = StatusCode::NOT_FOUND, description = "Could not find file {name}"),
        (status = StatusCode::SERVICE_UNAVAILABLE, description = "QMDL file is empty")
    ),
    params(
        ("name" = String, Path, description = "QMDL filename to convert and download, or \"live\" to stream the current recording as it grows")
    ),
    summary = "Download a PCAP file",
    description = "Stream a PCAP file to a client in chunks by converting the QMDL data for file {name} written so far. Passing \"live\" as the name follows the currently-active recording: the response keeps streaming new packets as they're captured, ending when the recording stops."
))]
pub async fn get_pcap(
    State(state): State<Arc<ServerState>>,
    Path(mut qmdl_name): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let qmdl_store = state.qmdl_store_lock.read().await;
    if qmdl_name.ends_with("pcapng") {
        qmdl_name = qmdl_name.trim_end_matches(".pcapng").to_string();
    }
    let follow = qmdl_name == "live";
    let (entry_index, entry) = if follow {
        qmdl_store.get_current_entry().ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "No QMDL data's being recorded, try starting a new recording!".to_string(),
        ))?
    } else {
        qmdl_store.entry_for_name(&qmdl_name).ok_or((
            StatusCode::NOT_FOUND,
            format!("couldn't find manifest entry with name {qmdl_name}"),
        ))?
    };
    if entry.qmdl_size_bytes == 0 {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "QMDL file is empty, try again in a bit!".to_string(),
        ));
    }
    let entry_name = entry.name.clone();
    let qmdl_file = qmdl_store
        .open_file(entry_index, FileKind::Qmdl)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))?
        .ok_or((StatusCode::NOT_FOUND, "QMDL file not found".to_string()))?;
    let (reader, writer) = duplex(1024);
    let gps_records = load_gps_records_for_entry(&state, entry_index).await;
    drop(qmdl_store);

    if follow {
        let stop = CancellationToken::new();
        let qmdl_reader = QmdlMessageReader::new(FollowFile::new(qmdl_file, stop.clone()))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))?;

        // Watch for the recording we're following being stopped out from
        // under us (deleted, or rotated by a stop/start) and unstick the
        // FollowFile if so. A normal stop also ends the stream on its own,
        // since closing the QmdlWriter writes the gzip footer.
        let store_lock = state.qmdl_store_lock.clone();
        let watcher_stop = stop.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = watcher_stop.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        if !store_lock.read().await.is_current_entry(&entry_name) {
                            watcher_stop.cancel();
                            break;
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            // also stops the watcher once we're done, e.g. if the client
            // disconnected
            let _stop_guard = stop.drop_guard();
            if let Err(e) = generate_pcap_data(writer, qmdl_reader, gps_records).await {
                error!("failed to generate live PCAP: {e:?}");
            }
        });
    } else {
        let qmdl_reader = QmdlMessageReader::new(qmdl_file)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))?;
        tokio::spawn(async move {
            if let Err(e) = generate_pcap_data(writer, qmdl_reader, gps_records).await {
                error!("failed to generate PCAP: {e:?}");
            }
        });
    }

    let headers = [(CONTENT_TYPE, "application/vnd.tcpdump.pcap")];
    let body = Body::from_stream(ReaderStream::new(reader));
    Ok((headers, body).into_response())
}

pub(crate) async fn load_gps_records_for_entry(
    state: &Arc<ServerState>,
    entry_index: usize,
) -> Vec<GpsRecord> {
    let qmdl_store = state.qmdl_store_lock.read().await;
    match qmdl_store.open_file(entry_index, FileKind::Gps).await {
        Ok(Some(file)) => load_gps_records(file).await,
        Ok(None) => {
            let gps_mode = qmdl_store
                .manifest
                .entries
                .get(entry_index)
                .and_then(|e| e.gps_mode);
            if gps_mode.is_some_and(|m| m != GpsMode::Disabled) {
                error!(
                    "GPS storage expected for entry {entry_index} (mode: {gps_mode:?}) but not found"
                );
            }
            vec![]
        }
        Err(e) => {
            error!("failed to open GPS storage: {e}");
            vec![]
        }
    }
}

fn record_timestamp(r: &GpsRecord) -> i64 {
    r.latest_packet_timestamp.unwrap_or(i64::MIN)
}

fn find_nearest_gps(records: &[GpsRecord], packet_timestamp: i64) -> Option<GpsPoint> {
    if records.is_empty() {
        return None;
    }
    let idx = records.partition_point(|r| record_timestamp(r) <= packet_timestamp);
    let record = if idx == 0 {
        &records[0]
    } else if idx >= records.len() {
        &records[records.len() - 1]
    } else {
        let (before, after) = (&records[idx - 1], &records[idx]);
        let before_delta = packet_timestamp - record_timestamp(before);
        let after_delta = record_timestamp(after) - packet_timestamp;
        if before_delta <= after_delta {
            before
        } else {
            after
        }
    };
    Some(GpsPoint {
        latitude: record.lat,
        longitude: record.lon,
        unix_ts: record_timestamp(record),
    })
}

pub async fn generate_pcap_data<R, W>(
    writer: W,
    mut reader: QmdlMessageReader<R>,
    gps_records: Vec<GpsRecord>,
) -> Result<(), Error>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + AsyncSeek + Unpin,
{
    let mut pcap_writer = GsmtapPcapWriter::new(writer).await?;
    pcap_writer.write_iface_header().await?;

    while let Some(maybe_msg) = reader.get_next_message().await? {
        match maybe_msg {
            Ok(msg) => {
                let maybe_gsmtap_msg = gsmtap_parser::parse(msg)?;
                if let Some((timestamp, gsmtap_msg)) = maybe_gsmtap_msg {
                    let packet_unix_ts = timestamp.to_datetime().timestamp();
                    let gps = find_nearest_gps(&gps_records, packet_unix_ts);
                    pcap_writer
                        .write_gsmtap_message(gsmtap_msg, timestamp, gps.as_ref())
                        .await?;
                }
            }
            Err(e) => error!("error parsing message: {e:?}"),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn test_follow_file_reads_data_appended_after_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qmdl");
        tokio::fs::write(&path, b"hello").await.unwrap();

        let stop = CancellationToken::new();
        let file = File::open(&path).await.unwrap();
        let mut follow = FollowFile::new(file, stop.clone());

        let mut buf = [0u8; 16];
        let n = follow.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // append after the reader has caught up with EOF; paused time
        // auto-advances through the poll interval
        let mut appender = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .unwrap();
        appender.write_all(b" world").await.unwrap();
        appender.flush().await.unwrap();

        let n = follow.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b" world");

        // cancelling the token turns "wait for more data" into a real EOF
        stop.cancel();
        assert_eq!(follow.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_follow_file_cancelled_mid_wait_reports_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qmdl");
        tokio::fs::write(&path, b"").await.unwrap();

        let stop = CancellationToken::new();
        let file = File::open(&path).await.unwrap();
        let mut follow = FollowFile::new(file, stop.clone());

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            follow.read(&mut buf).await.unwrap()
        });
        // let the reader hit EOF and park on its poll interval
        tokio::task::yield_now().await;
        stop.cancel();
        assert_eq!(read_task.await.unwrap(), 0);
    }

    fn rec(latest_packet_timestamp: i64, lat: f64, lon: f64) -> GpsRecord {
        GpsRecord {
            latest_packet_timestamp: Some(latest_packet_timestamp),
            system_time: 0,
            lat,
            lon,
        }
    }

    #[test]
    fn test_empty_returns_none() {
        assert!(find_nearest_gps(&[], 100).is_none());
    }

    #[test]
    fn test_single_record_always_returned() {
        let records = vec![rec(100, 1.0, 2.0)];
        assert_eq!(find_nearest_gps(&records, 0).unwrap().unix_ts, 100);
        assert_eq!(find_nearest_gps(&records, 200).unwrap().unix_ts, 100);
    }

    #[test]
    fn test_before_all_records_returns_first() {
        let records = vec![rec(100, 1.0, 2.0), rec(200, 3.0, 4.0)];
        assert_eq!(find_nearest_gps(&records, 50).unwrap().unix_ts, 100);
    }

    #[test]
    fn test_after_all_records_returns_last() {
        let records = vec![rec(100, 1.0, 2.0), rec(200, 3.0, 4.0)];
        assert_eq!(find_nearest_gps(&records, 300).unwrap().unix_ts, 200);
    }

    #[test]
    fn test_exact_match() {
        let records = vec![rec(100, 1.0, 2.0), rec(200, 3.0, 4.0), rec(300, 5.0, 6.0)];
        assert_eq!(find_nearest_gps(&records, 200).unwrap().unix_ts, 200);
    }

    #[test]
    fn test_closer_to_before() {
        // packet at 130: delta to before(100)=30, delta to after(200)=70 → picks before
        let records = vec![rec(100, 1.0, 2.0), rec(200, 3.0, 4.0)];
        assert_eq!(find_nearest_gps(&records, 130).unwrap().unix_ts, 100);
    }

    #[test]
    fn test_closer_to_after() {
        // packet at 170: delta to before(100)=70, delta to after(200)=30 → picks after
        let records = vec![rec(100, 1.0, 2.0), rec(200, 3.0, 4.0)];
        assert_eq!(find_nearest_gps(&records, 170).unwrap().unix_ts, 200);
    }

    #[test]
    fn test_equidistant_prefers_before() {
        // packet at 150: delta to before(100)=50, delta to after(200)=50 → tie, picks before
        let records = vec![rec(100, 1.0, 2.0), rec(200, 3.0, 4.0)];
        assert_eq!(find_nearest_gps(&records, 150).unwrap().unix_ts, 100);
    }
}
