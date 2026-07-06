use std::borrow::Cow;

use telcom_parser::lte_rrc::{PCCH_MessageType, PCCH_MessageType_c1, PagingUE_Identity};

use super::analyzer::{Analyzer, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};

/// Detects when the network pages a device using its raw IMSI rather than the
/// normal S-TMSI (temporary identifier). Legitimate networks assign a TMSI
/// during initial attach and use it for all subsequent paging — paging by raw
/// IMSI means either:
///
/// 1. A cell-site simulator is doing "presence testing" — checking if a target
///    IMSI is in the area by triggering a paging response.
/// 2. The network has lost track of the device's TMSI (rare, usually only
///    happens after prolonged unreachability).
///
/// In normal operation, IMSI paging should essentially never occur. Even one
/// instance is worth flagging.
pub struct ImsiPagingAnalyzer {}

impl Analyzer for ImsiPagingAnalyzer {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from("IMSI Paging (Presence Test)")
    }

    fn get_description(&self) -> Cow<'_, str> {
        Cow::from(
            "Detects when the network pages a device using its raw IMSI instead of the \
             normal S-TMSI. This is a strong indicator of a cell-site simulator performing \
             presence testing — checking if a specific subscriber is in the area. \
             Legitimate networks almost never page by IMSI.",
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
        let pcch_msg = match ie {
            InformationElement::LTE(inner) => match &**inner {
                LteInformationElement::PCCH(msg) => msg,
                _ => return None,
            },
            _ => return None,
        };

        // Navigate: PCCH_Message → c1 → Paging → paging_record_list
        let paging = match &pcch_msg.message {
            PCCH_MessageType::C1(PCCH_MessageType_c1::Paging(paging)) => paging,
            _ => return None,
        };

        let records = match &paging.paging_record_list {
            Some(list) => &list.0,
            None => return None,
        };

        // Check each paging record for IMSI-based identity
        for record in records {
            if let PagingUE_Identity::Imsi(imsi) = &record.ue_identity {
                let imsi_str: String = imsi.0.iter().map(|d| char::from(b'0' + d.0)).collect();
                return Some(Event {
                    event_type: EventType::High,
                    message: format!(
                        "Device paged by raw IMSI ({}) — possible presence testing by \
                         cell-site simulator",
                        imsi_str,
                    ),
                    ..Default::default()
                });
            }
        }

        None
    }
}
