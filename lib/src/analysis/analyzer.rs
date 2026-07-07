use chrono::{DateTime, FixedOffset};
use log::debug;
use pcap_file_tokio::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Write as _;

use crate::analysis::diagnostic::DiagnosticAnalyzer;
use crate::diag::diaglog::{LogBody, ml1};
use crate::diag::{DiagParsingError, Message};
use crate::gsmtap::{GsmtapHeader, GsmtapMessage, GsmtapType};
use crate::util::RuntimeMetadata;
use crate::{diag::MessagesContainer, gsmtap::parser as gsmtap_parser};

use super::{
    attach_reject_storm::AttachRejectStormAnalyzer,
    auth_anomaly::AuthAnomalyAnalyzer,
    cell_info::{ServingCellInfo, ServingCellTracker},
    connection_redirect_downgrade::ConnectionRedirect2GDowngradeAnalyzer,
    imsi_paging::ImsiPagingAnalyzer,
    imsi_requested::ImsiRequestedAnalyzer,
    incomplete_sib::IncompleteSibAnalyzer,
    information_element::InformationElement,
    nas_null_cipher::NasNullCipherAnalyzer,
    null_cipher::NullCipherAnalyzer,
    priority_2g_downgrade::LteSib6And7DowngradeAnalyzer,
    test_analyzer::TestAnalyzer,
    type0_sms::Type0SmsAnalyzer,
};

/// A list of booleans which stores information about which analyzers are enabled
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct AnalyzerConfig {
    pub diagnostic_analyzer: bool,
    pub connection_redirect_2g_downgrade: bool,
    pub lte_sib6_and_7_downgrade: bool,
    pub null_cipher: bool,
    pub nas_null_cipher: bool,
    pub incomplete_sib: bool,
    pub test_analyzer: bool,
    pub imsi_requested: bool,
    pub auth_anomaly: bool,
    pub type0_sms: bool,
    pub attach_reject_storm: bool,
    pub imsi_paging: bool,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        AnalyzerConfig {
            imsi_requested: true,
            diagnostic_analyzer: true,
            connection_redirect_2g_downgrade: true,
            lte_sib6_and_7_downgrade: true,
            null_cipher: true,
            nas_null_cipher: true,
            incomplete_sib: true,
            test_analyzer: false,
            auth_anomaly: true,
            type0_sms: true,
            attach_reject_storm: true,
            imsi_paging: true,
        }
    }
}

// History of backwards-compatible, additive schema changes:
//   3: Event gained serving-cell context and per-event analyzer identity.
//   4: AnalysisRow gained an optional GPS position.
pub const REPORT_VERSION: u32 = 4;

/// The severity level of an event.
///
/// Informational does not result in any alert on the display.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub enum EventType {
    #[default]
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(tag = "type")]
        enum OldEventType {
            QualitativeWarning { severity: String },
            Informational,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum EventTypeHelper {
            New(String),
            Old(OldEventType),
        }

        match EventTypeHelper::deserialize(deserializer)? {
            EventTypeHelper::New(s) => match s.as_str() {
                "Informational" => Ok(EventType::Informational),
                "Low" => Ok(EventType::Low),
                "Medium" => Ok(EventType::Medium),
                "High" => Ok(EventType::High),
                _ => Err(D::Error::custom(format!("unknown EventType: {s}"))),
            },
            EventTypeHelper::Old(old) => match old {
                OldEventType::Informational => Ok(EventType::Informational),
                OldEventType::QualitativeWarning { severity } => match severity.as_str() {
                    "Low" => Ok(EventType::Low),
                    "Medium" => Ok(EventType::Medium),
                    "High" => Ok(EventType::High),
                    _ => Err(D::Error::custom(format!("unknown severity: {severity}"))),
                },
            },
        }
    }
}

/// Identifies the [Analyzer] that produced an [Event], for downstream
/// per-analyzer false-positive tuning. Stamped centrally by the [Harness].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct AnalyzerId {
    /// The analyzer's user-facing name (see [`Analyzer::get_name`]).
    pub name: String,
    /// The analyzer's version (see [`Analyzer::get_version`]).
    pub version: u32,
}

/// Events are user-facing signals that can be emitted by an [Analyzer] upon a
/// message being received. They can be used to signifiy an IC detection
/// warning, or just to display some relevant information to the user.
///
/// Beyond the human-readable `message`, events optionally carry structured
/// context for machine consumers: which `analyzer` fired, its `confidence`,
/// and the serving `cell` in effect when it fired. These are additive and
/// omitted from serialization when unset, so older consumers are unaffected.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Event {
    pub event_type: EventType,
    pub message: String,
    /// The analyzer that produced this event. Stamped by the [Harness].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyzer: Option<AnalyzerId>,
    /// Optional analyzer-supplied confidence in the detection, in `[0.0, 1.0]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// The serving cell in effect when this event fired. Stamped by the
    /// [Harness] from the most recently observed SIB1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<ServingCellInfo>,
}

/// An [Analyzer] represents one type of heuristic for detecting an IMSI Catcher
/// (IC). While maintaining some amount of state is useful, be mindful of how
/// much memory your [Analyzer] uses at runtime, since rayhunter may run for
/// many hours at a time with dozens of [Analyzers](Analyzer) working in parallel.
pub trait Analyzer {
    /// Returns a user-friendly, concise name for your heuristic.
    fn get_name(&self) -> Cow<'_, str>;

    /// Returns a user-friendly description of what your heuristic looks for,
    /// the types of [Events](Event) it may return, as well as possible false-positive
    /// conditions that may trigger an [Event]. If different [Events](Event) have
    /// different false-positive conditions, consider including them in its
    /// `message` field.
    fn get_description(&self) -> Cow<'_, str>;

    /// Analyze a single [InformationElement], possibly returning an [Event] if your
    /// heuristic deems it relevant. Again, be mindful of any state your
    /// [Analyzer] updates per message, since it may be run over hundreds or
    /// thousands of them alongside many other [Analyzers](Analyzer).
    fn analyze_information_element(
        &mut self,
        ie: &InformationElement,
        packet_num: usize,
    ) -> Option<Event>;

    /// Returns a version number for this Analyzer. This should only ever
    /// increase in value, and do so whenever substantial changes are made to
    /// the Analyzer's heuristic.
    fn get_version(&self) -> u32;
}

/// Specific information on a given analyzer
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct AnalyzerMetadata {
    /// The analyzer name
    pub name: String,
    /// A description of what the analyzer does
    pub description: String,
    /// The deployed version of the analyzer code
    pub version: u32,
}

/// The metadata for an analyzed report
#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
#[derive(Default)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct ReportMetadata {
    /// A vector array of which analyzers were in use for the analysis
    pub analyzers: Vec<AnalyzerMetadata>,
    /// The runtime metadata for rayhunter during the recording and analysis
    pub rayhunter: RuntimeMetadata,
    /// The version of the reporting format used
    // anytime the format of the report changes, bump this by 1
    //
    // the default is 0. we consider our legacy (unversioned) heuristics to be v0 -- this'll let us
    // clearly differentiate some known false-positive-results from the pre-versioned era from v1
    // heuristics
    pub report_version: u32,
}

impl ReportMetadata {
    /// Normalize the report metadata to the current version
    pub fn normalize(&mut self) {
        self.report_version = REPORT_VERSION;
    }
}

/// Normalizer for analysis report lines that maintains state internally.
/// The first line is expected to be ReportMetadata, and subsequent lines
/// are expected to be AnalysisRow entries.
pub struct AnalysisLineNormalizer {
    is_first: bool,
}

impl Default for AnalysisLineNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisLineNormalizer {
    pub fn new() -> Self {
        Self { is_first: true }
    }

    /// Normalize a single line from an analysis report.
    /// Returns the normalized JSON string with a newline appended.
    pub fn normalize_line(&mut self, line: String) -> String {
        if self.is_first {
            self.is_first = false;
            // the first line is the report metadata. we overwrite the report version there to
            // latest, because the output of the remaining lines will follow latest versions
            if let Ok(mut metadata) = serde_json::from_str::<ReportMetadata>(&line) {
                metadata.normalize();
                serde_json::to_string(&metadata).unwrap_or(line) + "\n"
            } else {
                line + "\n"
            }
        } else {
            // Remaining lines are AnalysisRow, roundtrip them through serde to normalize them.
            if let Ok(row) = serde_json::from_str::<AnalysisRow>(&line) {
                serde_json::to_string(&row).unwrap_or(line) + "\n"
            } else {
                line + "\n"
            }
        }
    }
}

/// A geographic position in WGS84 decimal degrees, attached to an analysis
/// row so a detection can be placed on a map. Sourced by the daemon from the
/// active GPS fix (external API or fixed coordinates); the analysis library
/// itself never populates it.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct Position {
    pub lat: f64,
    pub lon: f64,
}

#[derive(Serialize, Debug, Default)]
pub struct AnalysisRow {
    pub packet_timestamp: Option<DateTime<FixedOffset>>,
    pub skipped_message_reason: Option<String>,
    pub events: Vec<Option<Event>>,
    /// The GPS position in effect when this row's packet was captured, if a
    /// fix was available. Stamped by the daemon, not the analysis library.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<Position>,
}

impl AnalysisRow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.skipped_message_reason.is_none() && !self.contains_warnings()
    }

    pub fn contains_warnings(&self) -> bool {
        self.get_max_event_type() != EventType::Informational
    }

    pub fn get_max_event_type(&self) -> EventType {
        self.events
            .iter()
            .flatten()
            .map(|event| event.event_type)
            .max()
            .unwrap_or(EventType::Informational)
    }
}

impl<'de> Deserialize<'de> for AnalysisRow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct V1AnalysisEntry {
            timestamp: DateTime<FixedOffset>,
            events: Vec<Option<Event>>,
        }

        #[derive(Deserialize)]
        struct V1Format {
            timestamp: DateTime<FixedOffset>,
            skipped_message_reasons: Vec<String>,
            analysis: Vec<V1AnalysisEntry>,
        }

        #[derive(Deserialize)]
        struct V2Format {
            packet_timestamp: Option<DateTime<FixedOffset>>,
            skipped_message_reason: Option<String>,
            events: Vec<Option<Event>>,
            #[serde(default)]
            position: Option<Position>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RowFormat {
            V1(V1Format),
            V2(V2Format),
        }

        match RowFormat::deserialize(deserializer)? {
            RowFormat::V1(v1) => {
                // For v1 format, we can only deserialize the first non-skipped analysis entry
                // The caller needs to handle multiple rows differently for v1
                if let Some(first_analysis) = v1.analysis.first() {
                    Ok(AnalysisRow {
                        packet_timestamp: Some(first_analysis.timestamp),
                        skipped_message_reason: None,
                        events: first_analysis.events.clone(),
                        ..Default::default()
                    })
                } else if let Some(first_reason) = v1.skipped_message_reasons.first() {
                    Ok(AnalysisRow {
                        packet_timestamp: Some(v1.timestamp),
                        skipped_message_reason: Some(first_reason.clone()),
                        events: Vec::new(),
                        ..Default::default()
                    })
                } else {
                    Err(D::Error::custom(
                        "V1 format has no analysis entries or skipped reasons",
                    ))
                }
            }
            RowFormat::V2(v2) => Ok(AnalysisRow {
                packet_timestamp: v2.packet_timestamp,
                skipped_message_reason: v2.skipped_message_reason,
                events: v2.events,
                position: v2.position,
            }),
        }
    }
}

pub struct Harness {
    analyzers: Vec<Box<dyn Analyzer + Send>>,
    packet_num: usize,
    serving_cell: ServingCellTracker,
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
            packet_num: 0,
            serving_cell: ServingCellTracker::new(),
        }
    }

    pub fn new_with_config(analyzer_config: &AnalyzerConfig) -> Self {
        let mut harness = Harness::new();

        if analyzer_config.imsi_requested {
            harness.add_analyzer(Box::new(ImsiRequestedAnalyzer::new()));
        }
        if analyzer_config.connection_redirect_2g_downgrade {
            harness.add_analyzer(Box::new(ConnectionRedirect2GDowngradeAnalyzer {}));
        }
        if analyzer_config.lte_sib6_and_7_downgrade {
            harness.add_analyzer(Box::new(LteSib6And7DowngradeAnalyzer::new()));
        }
        if analyzer_config.null_cipher {
            harness.add_analyzer(Box::new(NullCipherAnalyzer {}));
        }

        if analyzer_config.nas_null_cipher {
            harness.add_analyzer(Box::new(NasNullCipherAnalyzer {}))
        }

        if analyzer_config.incomplete_sib {
            harness.add_analyzer(Box::new(IncompleteSibAnalyzer {}))
        }

        if analyzer_config.test_analyzer {
            harness.add_analyzer(Box::new(TestAnalyzer {}))
        }

        if analyzer_config.auth_anomaly {
            harness.add_analyzer(Box::new(AuthAnomalyAnalyzer::new()));
        }

        if analyzer_config.type0_sms {
            harness.add_analyzer(Box::new(Type0SmsAnalyzer {}));
        }

        if analyzer_config.attach_reject_storm {
            harness.add_analyzer(Box::new(AttachRejectStormAnalyzer::new()));
        }

        if analyzer_config.imsi_paging {
            harness.add_analyzer(Box::new(ImsiPagingAnalyzer {}));
        }

        if analyzer_config.diagnostic_analyzer {
            harness.add_analyzer(Box::new(DiagnosticAnalyzer {}));
        }

        harness
    }

    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer + Send>) {
        self.analyzers.push(analyzer);
    }

    /// The most recently observed serving cell, if any SIB1 has been seen. Used
    /// to surface a "last-seen cell" health signal.
    pub fn current_serving_cell(&self) -> Option<ServingCellInfo> {
        self.serving_cell.current()
    }

    /// A display summary of the operator(s) seen during this run, derived from
    /// the distinct serving-cell PLMNs observed (e.g. "T-Mobile US (United
    /// States)"). Returns `None` if no PLMN has been observed yet. Multiple
    /// operators are joined with ", ".
    pub fn observed_carrier(&self) -> Option<String> {
        let names: std::collections::BTreeSet<String> = self
            .serving_cell
            .observed_plmns()
            .map(|plmn| plmn.display_name())
            .collect();
        if names.is_empty() {
            None
        } else {
            Some(names.into_iter().collect::<Vec<_>>().join(", "))
        }
    }

    pub fn analyze_pcap_packet(&mut self, packet: EnhancedPacketBlock) -> AnalysisRow {
        self.packet_num += 1;

        let epoch = DateTime::parse_from_rfc3339("1980-01-06T00:00:00-00:00").unwrap();
        let mut row = AnalysisRow {
            packet_timestamp: Some(epoch + packet.timestamp),
            skipped_message_reason: None,
            events: Vec::new(),
            ..Default::default()
        };
        let gsmtap_offset = 20 + 8;
        let gsmtap_data = &packet.data[gsmtap_offset..];
        // the type and subtype are at byte offsets 3 and 13, respectively
        let gsmtap_header = match GsmtapType::new(gsmtap_data[2], gsmtap_data[12]) {
            Ok(gsmtap_type) => GsmtapHeader::new(gsmtap_type),
            Err(err) => {
                row.skipped_message_reason = Some(format!("failed to read GsmtapHeader: {err:?}"));
                return row;
            }
        };
        let packet_offset = gsmtap_offset + 16;
        let packet_data = &packet.data[packet_offset..];
        let gsmtap_message = GsmtapMessage {
            header: gsmtap_header,
            payload: packet_data.to_vec(),
        };
        row.events = match InformationElement::try_from(&gsmtap_message) {
            Ok(element) => self.analyze_information_element(&element),
            Err(err) => {
                let msg = format!(
                    "in packet {}, failed to convert gsmtap message to IE: {err:?}",
                    self.packet_num
                );
                debug!("{msg}");
                row.skipped_message_reason = Some(msg);
                return row;
            }
        };
        row
    }

    pub fn analyze_qmdl_message(
        &mut self,
        maybe_qmdl_message: Result<Message, DiagParsingError>,
    ) -> AnalysisRow {
        let mut row = AnalysisRow::new();
        self.packet_num += 1;

        let qmdl_message = match maybe_qmdl_message {
            Ok(msg) => msg,
            Err(err) => {
                row.skipped_message_reason = Some(format!("{err:?}"));
                return row;
            }
        };

        // Record physical-layer serving-cell context from the raw log packet
        // before gsmtap parsing consumes the message. This is available even
        // when an RRC payload fails to decode, and the gsmtap path would
        // otherwise drop it (PCI), truncate it (EARFCN), or ignore it (ML1).
        match &qmdl_message {
            Message::Log {
                body: LogBody::LteRrcOtaMessage { packet, .. },
                ..
            } => {
                self.serving_cell
                    .observe_physical(packet.get_phy_cell_id(), packet.get_earfcn());
            }
            Message::Log {
                body: LogBody::LteMl1ServingCellMeas { body },
                ..
            } => {
                if let Some(m) = ml1::ServingCellMeasurement::parse(body) {
                    self.serving_cell.observe_signal(m.rsrp, m.rsrq);
                }
            }
            _ => {}
        }

        let gsmtap_message = match gsmtap_parser::parse(qmdl_message) {
            Ok(msg) => msg,
            Err(err) => {
                row.skipped_message_reason = Some(format!("{err:?}"));
                return row;
            }
        };

        let Some((timestamp, gsmtap_msg)) = gsmtap_message else {
            return row;
        };
        row.packet_timestamp = Some(timestamp.to_datetime());

        let element = match InformationElement::try_from(&gsmtap_msg) {
            Ok(element) => element,
            Err(err) => {
                row.skipped_message_reason = Some(format!("{err:?}"));
                return row;
            }
        };

        row.events = self.analyze_information_element(&element);
        row
    }

    pub fn analyze_qmdl_messages(&mut self, container: MessagesContainer) -> Vec<AnalysisRow> {
        container
            .messages()
            .drain(..)
            .map(|maybe_message| self.analyze_qmdl_message(maybe_message))
            .collect()
    }

    fn analyze_information_element(&mut self, ie: &InformationElement) -> Vec<Option<Event>> {
        // This method is private because incrementing packet_num is currently handled entirely by the other
        // methods that call this one. This could be changed with some careful refactoring, but
        // while this method is only used by other Harness methods, let's keep it private to help
        // ensure we always bump packet_num exactly once for each processed packet.

        // Update the serving-cell context from this element before running the
        // analyzers, so an event emitted on the same SIB1 that establishes the
        // cell identity is stamped with it.
        self.serving_cell.observe(ie);
        // Borrow (don't clone) the serving cell: most messages produce no event,
        // so we only clone it into an event on the rare path where one fires.
        let current_cell = self.serving_cell.current_ref();
        let packet_num = self.packet_num;

        self.analyzers
            .iter_mut()
            .map(|analyzer| {
                let mut maybe_event = analyzer.analyze_information_element(ie, packet_num);
                if let Some(ref mut event) = maybe_event {
                    // Build the "(packet N)" suffix only when an event fires,
                    // appending in place to avoid a per-message allocation.
                    let _ = write!(event.message, " (packet {packet_num})");
                    // Stamp structured context centrally so individual analyzers
                    // don't have to. An analyzer may still set its own cell (e.g.
                    // for a neighbor rather than the serving cell); respect that.
                    event.analyzer.get_or_insert_with(|| AnalyzerId {
                        name: analyzer.get_name().into_owned(),
                        version: analyzer.get_version(),
                    });
                    if event.cell.is_none()
                        && let Some(cell) = current_cell
                        && !cell.is_empty()
                    {
                        event.cell = Some(cell.clone());
                    }
                }
                maybe_event
            })
            .collect()
    }

    pub fn get_metadata(&self) -> ReportMetadata {
        let mut analyzers = Vec::new();
        for analyzer in &self.analyzers {
            analyzers.push(AnalyzerMetadata {
                name: analyzer.get_name().to_string(),
                description: analyzer.get_description().to_string(),
                version: analyzer.get_version(),
            });
        }

        let rayhunter = RuntimeMetadata::new();

        ReportMetadata {
            analyzers,
            rayhunter,
            report_version: REPORT_VERSION,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_analysis_row_deserialize_old_format() {
        let row: AnalysisRow = serde_json::from_value(json!({
            "packet_timestamp": "2023-01-01T00:00:00+00:00",
            "skipped_message_reason": null,
            "events": [
                {
                    "event_type": { "type": "QualitativeWarning", "severity": "High" },
                    "message": "Test warning"
                },
                {
                    "event_type": { "type": "Informational" },
                    "message": "Test info"
                },
                null
            ]
        }))
        .unwrap();

        assert_eq!(row.events[0].as_ref().unwrap().event_type, EventType::High);
        assert_eq!(
            row.events[1].as_ref().unwrap().event_type,
            EventType::Informational
        );
        assert!(row.events[2].is_none());
    }

    #[test]
    fn test_analysis_row_deserialize_new_format() {
        let row: AnalysisRow = serde_json::from_value(json!({
            "packet_timestamp": "2023-01-01T00:00:00+00:00",
            "skipped_message_reason": null,
            "events": [
                { "event_type": "High", "message": "Test warning" },
                { "event_type": "Informational", "message": "Test info" },
                null
            ]
        }))
        .unwrap();

        assert_eq!(row.events[0].as_ref().unwrap().event_type, EventType::High);
        assert_eq!(
            row.events[1].as_ref().unwrap().event_type,
            EventType::Informational
        );
        assert!(row.events[2].is_none());
    }

    #[test]
    fn test_analysis_row_position_roundtrip() {
        let row = AnalysisRow {
            packet_timestamp: None,
            skipped_message_reason: Some("skipped".to_string()),
            events: Vec::new(),
            position: Some(Position {
                lat: 37.7749,
                lon: -122.4194,
            }),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("position"));
        let back: AnalysisRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.position, row.position);
    }

    #[test]
    fn test_analysis_row_position_absent_is_omitted() {
        // A row without a fix must not serialize a `position` key, and an old
        // row lacking the key must still deserialize.
        let row = AnalysisRow {
            skipped_message_reason: Some("skipped".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(!json.contains("position"));
        let back: AnalysisRow = serde_json::from_value(
            json!({ "packet_timestamp": null, "skipped_message_reason": "x", "events": [] }),
        )
        .unwrap();
        assert!(back.position.is_none());
    }

    #[test]
    fn test_event_backcompat_missing_structured_fields() {
        // An event serialized before the structured fields existed must still
        // deserialize, leaving the new fields unset.
        let event: Event =
            serde_json::from_value(json!({ "event_type": "High", "message": "hi" })).unwrap();
        assert!(event.analyzer.is_none());
        assert!(event.confidence.is_none());
        assert!(event.cell.is_none());
    }

    #[test]
    fn test_event_roundtrip_with_structured_fields() {
        use crate::analysis::cell_info::{Plmn, ServingCellInfo};

        let event = Event {
            event_type: EventType::High,
            message: "null cipher".to_string(),
            analyzer: Some(AnalyzerId {
                name: "Null Cipher".to_string(),
                version: 2,
            }),
            confidence: Some(0.9),
            cell: Some(ServingCellInfo {
                plmn: Some(Plmn {
                    mcc: "310".to_string(),
                    mnc: "410".to_string(),
                }),
                tac: Some(0x1234),
                cell_id: Some(0x0ABCDEF),
                band: Some(2),
                ..Default::default()
            }),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.analyzer, event.analyzer);
        assert_eq!(back.confidence, event.confidence);
        assert_eq!(back.cell, event.cell);
    }

    struct AlwaysFires;
    impl Analyzer for AlwaysFires {
        fn get_name(&self) -> Cow<'_, str> {
            Cow::from("Always Fires")
        }
        fn get_description(&self) -> Cow<'_, str> {
            Cow::from("test analyzer that fires on every element")
        }
        fn analyze_information_element(
            &mut self,
            _ie: &InformationElement,
            _packet_num: usize,
        ) -> Option<Event> {
            Some(Event {
                event_type: EventType::Low,
                message: "fired".to_string(),
                ..Default::default()
            })
        }
        fn get_version(&self) -> u32 {
            7
        }
    }

    #[test]
    fn test_harness_stamps_analyzer_identity() {
        let mut harness = Harness::new();
        harness.add_analyzer(Box::new(AlwaysFires));
        // A GSM element carries no cell identity, so `cell` stays unset while
        // the analyzer identity is still stamped.
        let events = harness.analyze_information_element(&InformationElement::GSM);
        let event = events[0].as_ref().unwrap();
        let analyzer = event.analyzer.as_ref().expect("analyzer stamped");
        assert_eq!(analyzer.name, "Always Fires");
        assert_eq!(analyzer.version, 7);
        assert!(event.cell.is_none());
        // The central packet-number suffix is still appended.
        assert!(event.message.contains("packet"));
    }

    #[test]
    fn test_harness_records_physical_cell_context() {
        // A raw LTE RRC OTA log packet carries PCI/EARFCN in its header. The
        // harness records them onto the serving cell from the header, even
        // though this synthetic payload does not decode as valid RRC.
        let (_, message) = crate::diag::diaglog::test::get_test_message(&[
            0x40, 0x1, 0xee, 0xad, 0xd5, 0x4d, 0xd0,
        ]);
        let mut harness = Harness::new();
        let _ = harness.analyze_qmdl_message(Ok(message));
        let cell = harness
            .current_serving_cell()
            .expect("serving cell recorded from RRC OTA header");
        assert_eq!(cell.pci, Some(160));
        assert_eq!(cell.earfcn, Some(2050));
    }

    #[test]
    fn test_harness_records_signal_measurements() {
        use crate::diag::diaglog::{LogBody, Timestamp};
        // A version-4 0xB193 body decoding to rsrp -90, rsrq -10.
        let mut body = vec![0u8; 32];
        body[0] = 4;
        body[4..6].copy_from_slice(&2050u16.to_le_bytes());
        body[6..8].copy_from_slice(&(160u16 << 7).to_le_bytes());
        body[8..12].copy_from_slice(&1440u32.to_le_bytes());
        body[16..20].copy_from_slice(&(320u32 << 22).to_le_bytes());
        body[20..24].copy_from_slice(&(640u32 << 11).to_le_bytes());
        let message = Message::Log {
            pending_msgs: 0,
            outer_length: 0,
            inner_length: 0,
            log_type: 0xb193,
            timestamp: Timestamp { ts: 0 },
            body: LogBody::LteMl1ServingCellMeas { body },
        };
        let mut harness = Harness::new();
        let _ = harness.analyze_qmdl_message(Ok(message));
        let cell = harness.current_serving_cell().expect("cell recorded");
        assert!((cell.rsrp.expect("rsrp") - (-90.0)).abs() < 0.01);
        assert!((cell.rsrq.expect("rsrq") - (-10.0)).abs() < 0.01);
    }
}
