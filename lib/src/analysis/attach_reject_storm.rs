use std::borrow::Cow;
use std::collections::VecDeque;

use pycrate_rs::nas::NASMessage;
use pycrate_rs::nas::emm::EMMMessage;
use pycrate_rs::nas::generated::emm::emm_attach_reject::EMMCauseEMMCause as AttachRejectCause;
use pycrate_rs::nas::generated::emm::emm_tracking_area_update_reject::EMMCauseEMMCause as TauRejectCause;

use super::analyzer::{Analyzer, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};

/// The maximum number of packets between rejects to consider them part of the
/// same "storm." If rejects are spread further apart than this, older ones age
/// out of the window.
const WINDOW_SIZE: usize = 200;

/// Number of Attach/TAU Rejects within the window that triggers an alert.
const REJECT_THRESHOLD: usize = 3;

/// Unified reject cause — both Attach Reject and TAU Reject have structurally
/// identical cause enums but they're different Rust types in pycrate_rs.
#[derive(Clone, Debug, PartialEq)]
enum RejectCause {
    PLMNNotAllowed,
    EPSServicesNotAllowed,
    EPSServicesAndNonEPSServicesNotAllowed,
    EPSServicesNotAllowedInThisPLMN,
    RoamingNotAllowedInThisTrackingArea,
    NoSuitableCellsInTrackingArea,
    NetworkFailure,
    Congestion,
    Other(&'static str),
}

impl From<&AttachRejectCause> for RejectCause {
    fn from(c: &AttachRejectCause) -> Self {
        match c {
            AttachRejectCause::PLMNNotAllowed => RejectCause::PLMNNotAllowed,
            AttachRejectCause::EPSServicesNotAllowed => RejectCause::EPSServicesNotAllowed,
            AttachRejectCause::EPSServicesAndNonEPSServicesNotAllowed => {
                RejectCause::EPSServicesAndNonEPSServicesNotAllowed
            }
            AttachRejectCause::EPSServicesNotAllowedInThisPLMN => {
                RejectCause::EPSServicesNotAllowedInThisPLMN
            }
            AttachRejectCause::RoamingNotAllowedInThisTrackingArea => {
                RejectCause::RoamingNotAllowedInThisTrackingArea
            }
            AttachRejectCause::NoSuitableCellsInTrackingArea => {
                RejectCause::NoSuitableCellsInTrackingArea
            }
            AttachRejectCause::NetworkFailure => RejectCause::NetworkFailure,
            AttachRejectCause::Congestion => RejectCause::Congestion,
            AttachRejectCause::IMSIUnknownInHSS => RejectCause::Other("IMSI unknown in HSS"),
            AttachRejectCause::IllegalUE => RejectCause::Other("Illegal UE"),
            AttachRejectCause::IMEINotAccepted => RejectCause::Other("IMEI not accepted"),
            AttachRejectCause::IllegalME => RejectCause::Other("Illegal ME"),
            _ => RejectCause::Other("Other"),
        }
    }
}

impl From<&TauRejectCause> for RejectCause {
    fn from(c: &TauRejectCause) -> Self {
        match c {
            TauRejectCause::PLMNNotAllowed => RejectCause::PLMNNotAllowed,
            TauRejectCause::EPSServicesNotAllowed => RejectCause::EPSServicesNotAllowed,
            TauRejectCause::EPSServicesAndNonEPSServicesNotAllowed => {
                RejectCause::EPSServicesAndNonEPSServicesNotAllowed
            }
            TauRejectCause::EPSServicesNotAllowedInThisPLMN => {
                RejectCause::EPSServicesNotAllowedInThisPLMN
            }
            TauRejectCause::RoamingNotAllowedInThisTrackingArea => {
                RejectCause::RoamingNotAllowedInThisTrackingArea
            }
            TauRejectCause::NoSuitableCellsInTrackingArea => {
                RejectCause::NoSuitableCellsInTrackingArea
            }
            TauRejectCause::NetworkFailure => RejectCause::NetworkFailure,
            TauRejectCause::Congestion => RejectCause::Congestion,
            TauRejectCause::IMSIUnknownInHSS => RejectCause::Other("IMSI unknown in HSS"),
            TauRejectCause::IllegalUE => RejectCause::Other("Illegal UE"),
            TauRejectCause::IMEINotAccepted => RejectCause::Other("IMEI not accepted"),
            TauRejectCause::IllegalME => RejectCause::Other("Illegal ME"),
            _ => RejectCause::Other("Other"),
        }
    }
}

/// Cause codes that indicate "wrong SIM / wrong carrier" rather than an attack.
fn is_wrong_sim_cause(cause: &RejectCause) -> bool {
    matches!(
        cause,
        RejectCause::PLMNNotAllowed
            | RejectCause::EPSServicesNotAllowed
            | RejectCause::EPSServicesAndNonEPSServicesNotAllowed
            | RejectCause::EPSServicesNotAllowedInThisPLMN
            | RejectCause::RoamingNotAllowedInThisTrackingArea
    )
}

fn cause_name(cause: &RejectCause) -> &'static str {
    match cause {
        RejectCause::PLMNNotAllowed => "PLMN not allowed",
        RejectCause::EPSServicesNotAllowed => "EPS services not allowed",
        RejectCause::EPSServicesAndNonEPSServicesNotAllowed => "EPS+non-EPS services not allowed",
        RejectCause::EPSServicesNotAllowedInThisPLMN => "EPS not allowed in this PLMN",
        RejectCause::RoamingNotAllowedInThisTrackingArea => "Roaming not allowed in TA",
        RejectCause::NoSuitableCellsInTrackingArea => "No suitable cells in TA",
        RejectCause::NetworkFailure => "Network failure",
        RejectCause::Congestion => "Congestion",
        RejectCause::Other(name) => name,
    }
}

/// Detects an abnormal burst of Attach Reject or Tracking Area Update Reject
/// messages within a short packet window. Legitimate networks occasionally
/// reject a device (roaming, congestion), but multiple rapid rejects suggest
/// a fake cell that is forcing repeated attach attempts to harvest identifiers
/// (IMSI/IMEI) on each cycle.
///
/// This is a common IMSI catcher pattern: reject → phone retries on another
/// cell → that cell is also the catcher → reject again → repeat.
///
/// If all rejects use "wrong SIM" cause codes (PLMNNotAllowed, etc.), severity
/// is lowered to Informational and the message indicates a likely SIM/carrier
/// mismatch rather than an attack.
pub struct AttachRejectStormAnalyzer {
    /// Ring buffer of (packet_num, cause_code) for rejects in the window.
    reject_history: VecDeque<(usize, RejectCause)>,
    /// Whether we've already fired for the current storm (avoid spamming).
    alerted_for_current_storm: bool,
}

impl Default for AttachRejectStormAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl AttachRejectStormAnalyzer {
    pub fn new() -> Self {
        Self {
            reject_history: VecDeque::new(),
            alerted_for_current_storm: false,
        }
    }

    /// Remove rejects that are older than WINDOW_SIZE packets from current.
    fn expire_old(&mut self, current_packet: usize) {
        while let Some(&(oldest, _)) = self.reject_history.front() {
            if current_packet.saturating_sub(oldest) > WINDOW_SIZE {
                self.reject_history.pop_front();
                // If the window shrinks below threshold, reset alert state
                if self.reject_history.len() < REJECT_THRESHOLD {
                    self.alerted_for_current_storm = false;
                }
            } else {
                break;
            }
        }
    }

    /// Record a reject and return an event if it completes a storm. Split out
    /// from message parsing so the storm/severity logic is unit-testable.
    ///
    /// A single reject never alerts on its own: cause codes like "EPS services
    /// not allowed" (EMM #7/#8) are indistinguishable from a legitimately
    /// unprovisioned/wrong-carrier SIM, so we only escalate on a *burst*. A
    /// burst whose causes are all "wrong SIM" is reported Informational (a SIM
    /// mismatch, not an attack); a burst with other causes is Medium (possible
    /// forced-reattach). Actual 2G downgrade is caught by the dedicated
    /// downgrade analyzers, which inspect the redirection rather than the cause.
    fn observe_reject(&mut self, packet_num: usize, cause: RejectCause) -> Option<Event> {
        self.expire_old(packet_num);
        self.reject_history.push_back((packet_num, cause));

        if self.reject_history.len() < REJECT_THRESHOLD || self.alerted_for_current_storm {
            return None;
        }
        self.alerted_for_current_storm = true;

        let all_wrong_sim = self
            .reject_history
            .iter()
            .all(|(_, c)| is_wrong_sim_cause(c));
        let latest_cause = &self.reject_history.back().unwrap().1;
        let span = packet_num.saturating_sub(
            self.reject_history
                .front()
                .map(|(p, _)| *p)
                .unwrap_or(packet_num),
        );

        if all_wrong_sim {
            Some(Event {
                event_type: EventType::Informational,
                message: format!(
                    "SIM/carrier mismatch: {} rejects within {} packets, all cause '{}' \
                     — check that your SIM matches the device's carrier lock",
                    self.reject_history.len(),
                    span,
                    cause_name(latest_cause),
                ),
                ..Default::default()
            })
        } else {
            Some(Event {
                event_type: EventType::Medium,
                message: format!(
                    "Attach/TAU Reject storm: {} rejects within {} packets (cause: '{}') \
                     — possible forced-reattach attack",
                    self.reject_history.len(),
                    span,
                    cause_name(latest_cause),
                ),
                ..Default::default()
            })
        }
    }
}

impl Analyzer for AttachRejectStormAnalyzer {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from("Attach Reject Storm")
    }

    fn get_description(&self) -> Cow<'_, str> {
        Cow::from(
            "Detects bursts of Attach Reject or TAU Reject messages within a short window. \
             Multiple rapid rejects suggest a fake cell forcing repeated attach attempts to \
             harvest IMSI/IMEI on each cycle. If all rejects are 'PLMN not allowed' type \
             causes, reports as a likely SIM/carrier mismatch instead.",
        )
    }

    fn get_version(&self) -> u32 {
        3
    }

    fn analyze_information_element(
        &mut self,
        ie: &InformationElement,
        packet_num: usize,
    ) -> Option<Event> {
        let payload = match ie {
            InformationElement::LTE(inner) => match &**inner {
                LteInformationElement::NAS(payload) => payload,
                _ => return None,
            },
            _ => return None,
        };

        // Extract the cause code from Attach Reject or TAU Reject
        let cause: RejectCause = match payload {
            NASMessage::EMMMessage(EMMMessage::EMMAttachReject(reject)) => {
                RejectCause::from(&reject.emm_cause.inner)
            }
            NASMessage::EMMMessage(EMMMessage::EMMTrackingAreaUpdateReject(reject)) => {
                RejectCause::from(&reject.emm_cause.inner)
            }
            _ => return None,
        };

        self.observe_reject(packet_num, cause)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Drive `observe_reject` `n` times with the same cause on consecutive
    // packets and return the last event produced.
    fn run(
        analyzer: &mut AttachRejectStormAnalyzer,
        n: usize,
        cause: RejectCause,
    ) -> Option<Event> {
        let mut last = None;
        for i in 0..n {
            last = analyzer.observe_reject(i, cause.clone());
        }
        last
    }

    #[test]
    fn test_single_wrong_sim_reject_does_not_alert() {
        // Regression: a lone "EPS services not allowed" (EMM #7) is a normal
        // unprovisioned/wrong-carrier SIM outcome and must NOT fire a High
        // "cell-site simulator" alert.
        let mut analyzer = AttachRejectStormAnalyzer::new();
        assert!(
            analyzer
                .observe_reject(0, RejectCause::EPSServicesNotAllowed)
                .is_none()
        );
        assert!(
            analyzer
                .observe_reject(1, RejectCause::EPSServicesAndNonEPSServicesNotAllowed)
                .is_none()
        );
    }

    #[test]
    fn test_below_threshold_no_alert() {
        let mut analyzer = AttachRejectStormAnalyzer::new();
        assert!(
            run(
                &mut analyzer,
                REJECT_THRESHOLD - 1,
                RejectCause::NetworkFailure
            )
            .is_none()
        );
    }

    #[test]
    fn test_wrong_sim_storm_is_informational_not_high() {
        // Regression: even a *burst* of wrong-SIM causes is Informational, never
        // High.
        let mut analyzer = AttachRejectStormAnalyzer::new();
        let event = run(
            &mut analyzer,
            REJECT_THRESHOLD,
            RejectCause::EPSServicesNotAllowed,
        )
        .expect("storm should alert");
        assert_eq!(event.event_type, EventType::Informational);
    }

    #[test]
    fn test_mixed_cause_storm_is_medium() {
        let mut analyzer = AttachRejectStormAnalyzer::new();
        let event = run(&mut analyzer, REJECT_THRESHOLD, RejectCause::NetworkFailure)
            .expect("storm should alert");
        assert_eq!(event.event_type, EventType::Medium);
    }

    #[test]
    fn test_no_duplicate_alert_for_same_storm() {
        let mut analyzer = AttachRejectStormAnalyzer::new();
        assert!(run(&mut analyzer, REJECT_THRESHOLD, RejectCause::NetworkFailure).is_some());
        // Another reject in the same (unbroken) storm must not re-alert.
        assert!(
            analyzer
                .observe_reject(REJECT_THRESHOLD, RejectCause::NetworkFailure)
                .is_none()
        );
    }

    #[test]
    fn test_rejects_spread_apart_never_storm() {
        // Rejects more than WINDOW_SIZE apart age out and never accumulate.
        let mut analyzer = AttachRejectStormAnalyzer::new();
        for i in 0..10 {
            let pkt = i * (WINDOW_SIZE + 5);
            assert!(
                analyzer
                    .observe_reject(pkt, RejectCause::NetworkFailure)
                    .is_none()
            );
            assert_eq!(analyzer.reject_history.len(), 1);
        }
    }

    #[test]
    fn test_old_rejects_expire() {
        let mut analyzer = AttachRejectStormAnalyzer::new();
        analyzer
            .reject_history
            .push_back((10, RejectCause::PLMNNotAllowed));
        analyzer
            .reject_history
            .push_back((20, RejectCause::PLMNNotAllowed));
        analyzer.expire_old(10 + WINDOW_SIZE + 1);
        assert_eq!(analyzer.reject_history.len(), 1); // only packet 20 remains
    }

    #[test]
    fn test_wrong_sim_detection() {
        assert!(is_wrong_sim_cause(&RejectCause::PLMNNotAllowed));
        assert!(is_wrong_sim_cause(&RejectCause::EPSServicesNotAllowed));
        assert!(!is_wrong_sim_cause(
            &RejectCause::NoSuitableCellsInTrackingArea
        ));
        assert!(!is_wrong_sim_cause(&RejectCause::Congestion));
    }
}
