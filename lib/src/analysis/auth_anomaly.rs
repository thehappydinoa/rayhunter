use std::borrow::Cow;

use pycrate_rs::nas::NASMessage;
use pycrate_rs::nas::emm::EMMMessage;

use super::analyzer::{Analyzer, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};

use telcom_parser::lte_rrc::{DL_DCCH_MessageType, DL_DCCH_MessageType_c1};

/// Detects when the network issues a Security Mode Command (enabling ciphering
/// and integrity protection) without first sending an Authentication Request
/// in the current connection. In legitimate LTE, the MME must run EPS-AKA
/// (Authentication Request → Response) before Security Mode Command so the UE
/// can verify the network's identity. Skipping authentication means the tower
/// never proved who it is — a hallmark of IMSI catchers.
/// The messages the analyzer reacts to, classified so the state machine can be
/// unit-tested without constructing pycrate NAS / telcom RRC types by hand.
#[derive(Clone, Copy, PartialEq, Debug)]
enum NasEvent {
    /// Start of a NAS connection (Attach / TAU / Service Request).
    ConnectionStart,
    /// Network sent an Authentication Request.
    AuthRequest,
    /// Network sent a Security Mode Command.
    SecurityMode,
    /// The RRC connection was released (session end).
    ConnectionEnd,
}

pub struct AuthAnomalyAnalyzer {
    /// Whether the start of the current connection was observed in-capture. If
    /// we joined mid-connection, authentication may predate the capture, so a
    /// bare Security Mode Command must not be treated as an anomaly.
    saw_connection_start: bool,
    /// Whether we've seen an Authentication Request in the current connection.
    saw_auth_request: bool,
}

impl Default for AuthAnomalyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthAnomalyAnalyzer {
    pub fn new() -> Self {
        Self {
            saw_connection_start: false,
            saw_auth_request: false,
        }
    }

    /// Advance the state machine and return an event if a Security Mode Command
    /// arrived without prior authentication in a connection we observed from its
    /// start. Split out from message parsing so it is unit-testable.
    fn observe(&mut self, event: NasEvent) -> Option<Event> {
        match event {
            NasEvent::ConnectionStart => {
                self.saw_connection_start = true;
                self.saw_auth_request = false;
                None
            }
            NasEvent::AuthRequest => {
                self.saw_auth_request = true;
                None
            }
            NasEvent::SecurityMode => {
                if self.saw_connection_start && !self.saw_auth_request {
                    Some(Event {
                        event_type: EventType::Medium,
                        message: "Security Mode Command issued without prior authentication \
                                  — tower never proved its identity"
                            .to_string(),
                        ..Default::default()
                    })
                } else {
                    None
                }
            }
            NasEvent::ConnectionEnd => {
                self.saw_connection_start = false;
                self.saw_auth_request = false;
                None
            }
        }
    }
}

impl Analyzer for AuthAnomalyAnalyzer {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from("Missing Authentication Before Security Mode")
    }

    fn get_description(&self) -> Cow<'_, str> {
        Cow::from(
            "Detects when the network enables ciphering (Security Mode Command) without first \
             authenticating via EPS-AKA. This means the tower never proved its identity, which \
             is a strong indicator of an IMSI catcher. False positives may occur on inter-eNB \
             handovers where the target eNB reuses the existing security context.",
        )
    }

    fn get_version(&self) -> u32 {
        1
    }

    fn analyze_information_element(
        &mut self,
        ie: &InformationElement,
        _packet_num: usize,
    ) -> Option<Event> {
        let inner = match ie {
            InformationElement::LTE(inner) => inner,
            _ => return None,
        };

        let event = match &**inner {
            LteInformationElement::NAS(payload) => match payload {
                NASMessage::EMMMessage(EMMMessage::EMMAttachRequest(_))
                | NASMessage::EMMMessage(EMMMessage::EMMTrackingAreaUpdateRequest(_))
                | NASMessage::EMMMessage(EMMMessage::EMMExtServiceRequest(_)) => {
                    NasEvent::ConnectionStart
                }
                NASMessage::EMMMessage(EMMMessage::EMMAuthenticationRequest(_)) => {
                    NasEvent::AuthRequest
                }
                NASMessage::EMMMessage(EMMMessage::EMMSecurityModeCommand(_)) => {
                    NasEvent::SecurityMode
                }
                _ => return None,
            },

            // RRC Connection Release ends the session.
            LteInformationElement::DlDcch(rrc_msg) => {
                if let DL_DCCH_MessageType::C1(DL_DCCH_MessageType_c1::RrcConnectionRelease(_)) =
                    rrc_msg.message
                {
                    NasEvent::ConnectionEnd
                } else {
                    return None;
                }
            }

            _ => return None,
        };

        self.observe(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smc_after_attach_without_auth_fires() {
        // A full connection observed from its start: Attach → Security Mode
        // Command with no authentication in between is the real anomaly.
        let mut a = AuthAnomalyAnalyzer::new();
        assert!(a.observe(NasEvent::ConnectionStart).is_none());
        let event = a.observe(NasEvent::SecurityMode).expect("should fire");
        assert_eq!(event.event_type, EventType::Medium);
    }

    #[test]
    fn test_smc_after_auth_does_not_fire() {
        let mut a = AuthAnomalyAnalyzer::new();
        a.observe(NasEvent::ConnectionStart);
        a.observe(NasEvent::AuthRequest);
        assert!(a.observe(NasEvent::SecurityMode).is_none());
    }

    #[test]
    fn test_smc_without_observed_connection_start_does_not_fire() {
        // Regression: recording started mid-connection (auth already happened
        // before the capture). A bare Security Mode Command must NOT alert.
        let mut a = AuthAnomalyAnalyzer::new();
        assert!(a.observe(NasEvent::SecurityMode).is_none());
    }

    #[test]
    fn test_connection_end_requires_fresh_start_before_alerting() {
        // After a session ends, a stray SMC (without a new observed start)
        // must not alert.
        let mut a = AuthAnomalyAnalyzer::new();
        a.observe(NasEvent::ConnectionStart);
        a.observe(NasEvent::ConnectionEnd);
        assert!(a.observe(NasEvent::SecurityMode).is_none());
    }

    #[test]
    fn test_second_connection_alerts_independently() {
        // A clean authenticated connection, then a new connection that skips
        // auth: the second one must still fire.
        let mut a = AuthAnomalyAnalyzer::new();
        a.observe(NasEvent::ConnectionStart);
        a.observe(NasEvent::AuthRequest);
        assert!(a.observe(NasEvent::SecurityMode).is_none());
        a.observe(NasEvent::ConnectionEnd);
        a.observe(NasEvent::ConnectionStart);
        assert!(a.observe(NasEvent::SecurityMode).is_some());
    }
}
