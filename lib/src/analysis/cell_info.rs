//! Structured serving-cell context attached to analysis [`Event`](super::analyzer::Event)s.
//!
//! Downstream consumers (e.g. correlating a cellular detection with other
//! sensor observations, or looking a cell up against a known-tower database)
//! need a stable, machine-readable identity for the serving cell at the moment
//! an event fired, rather than parsing it out of free-text messages.
//!
//! The identity fields ([`Plmn`], TAC, cell id, band) are recovered from the
//! LTE RRC SIB1 broadcast, which is already decoded by the analysis pipeline.
//! The physical-layer fields (EARFCN, PCI, RSRP/RSRQ/SINR) come from Qualcomm
//! DIAG log packets that the RRC layer does not carry; they are reserved here
//! and populated by a later change.

use serde::{Deserialize, Serialize};

use deku::bitvec::*;
use telcom_parser::lte_rrc::{
    BCCH_DL_SCH_MessageType, BCCH_DL_SCH_MessageType_c1, SystemInformationBlockType1,
};

use super::information_element::{InformationElement, LteInformationElement};

/// A PLMN (Public Land Mobile Network) identity: an operator's MCC + MNC.
///
/// Stored as digit strings rather than integers so leading zeros (which are
/// significant in an MNC, e.g. MNC "01" is distinct from "1") and the MNC's
/// 2-vs-3-digit width are preserved losslessly.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct Plmn {
    /// Mobile Country Code, always 3 digits, e.g. "310".
    pub mcc: String,
    /// Mobile Network Code, 2 or 3 digits, e.g. "410" or "01".
    pub mnc: String,
}

/// Structured identity and radio context of a serving cell, as much of it as
/// is known at a given moment. Every field is optional: a fresh capture may
/// see a warning before it has observed a SIB1, and the physical-layer fields
/// are not always available.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct ServingCellInfo {
    /// Serving PLMN (operator) identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plmn: Option<Plmn>,
    /// Tracking Area Code (LTE) / Location Area Code analogue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tac: Option<u32>,
    /// 28-bit E-UTRAN cell identity (ECI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_id: Option<u32>,
    /// E-UTRA operating band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<u16>,

    // --- Physical-layer context (reserved; sourced from DIAG log packets) ---
    /// Serving E-UTRA Absolute Radio Frequency Channel Number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earfcn: Option<u32>,
    /// Physical Cell Identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci: Option<u16>,
    /// Reference Signal Received Power, in dBm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsrp: Option<f32>,
    /// Reference Signal Received Quality, in dB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsrq: Option<f32>,
    /// Signal-to-Interference-plus-Noise Ratio, in dB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sinr: Option<f32>,
}

impl ServingCellInfo {
    /// True if no field has been populated. Used to avoid attaching an empty
    /// object to events.
    pub fn is_empty(&self) -> bool {
        *self == ServingCellInfo::default()
    }

    /// Extract the RRC-derived identity fields from an LTE SIB1 broadcast.
    ///
    /// The physical-layer fields are left unset; SIB1 does not carry them.
    pub fn from_sib1(sib1: &SystemInformationBlockType1) -> Self {
        let access = &sib1.cell_access_related_info;

        let cell_id = Some(access.cell_identity.0.as_bitslice().load_be::<u32>());
        let tac = Some(access.tracking_area_code.0.as_bitslice().load_be::<u32>());
        let band = Some(sib1.freq_band_indicator.0 as u16);

        let plmn = access.plmn_identity_list.0.first().map(|info| {
            let identity = &info.plmn_identity;
            let mcc = identity
                .mcc
                .as_ref()
                .map(|mcc| digits_to_string(mcc.0.iter().map(|d| d.0)))
                .unwrap_or_default();
            let mnc = digits_to_string(identity.mnc.0.iter().map(|d| d.0));
            Plmn { mcc, mnc }
        });

        ServingCellInfo {
            plmn,
            tac,
            cell_id,
            band,
            ..Default::default()
        }
    }

    /// Extract serving-cell identity from an information element if it is a
    /// SIB1 broadcast, otherwise `None`.
    pub fn from_information_element(ie: &InformationElement) -> Option<Self> {
        if let InformationElement::LTE(lte_ie) = ie
            && let LteInformationElement::BcchDlSch(sch_msg) = &**lte_ie
            && let BCCH_DL_SCH_MessageType::C1(c1) = &sch_msg.message
            && let BCCH_DL_SCH_MessageType_c1::SystemInformationBlockType1(sib1) = c1
        {
            return Some(Self::from_sib1(sib1));
        }
        None
    }
}

/// Concatenate single decimal digits into a string, e.g. `[3, 1, 0]` -> "310".
fn digits_to_string(digits: impl Iterator<Item = u8>) -> String {
    digits.map(|d| char::from(b'0' + d)).collect()
}

/// Tracks the most recently observed serving cell across a stream of
/// information elements. The [`Harness`](super::analyzer::Harness) feeds every
/// IE through [`observe`](Self::observe) so that events can be stamped with the
/// serving cell in effect when they fired.
#[derive(Default)]
pub struct ServingCellTracker {
    current: Option<ServingCellInfo>,
}

impl ServingCellTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the tracked serving cell from an information element. A no-op for
    /// elements that do not carry cell identity.
    pub fn observe(&mut self, ie: &InformationElement) {
        if let Some(info) = ServingCellInfo::from_information_element(ie) {
            self.current = Some(info);
        }
    }

    /// The most recently observed serving cell, if any.
    pub fn current(&self) -> Option<ServingCellInfo> {
        self.current.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digits_to_string() {
        assert_eq!(digits_to_string([3, 1, 0].into_iter()), "310");
        assert_eq!(digits_to_string([0, 1].into_iter()), "01");
    }

    #[test]
    fn test_serving_cell_info_is_empty() {
        assert!(ServingCellInfo::default().is_empty());
        assert!(
            !ServingCellInfo {
                tac: Some(7),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn test_serving_cell_info_roundtrip() {
        let info = ServingCellInfo {
            plmn: Some(Plmn {
                mcc: "310".to_string(),
                mnc: "410".to_string(),
            }),
            tac: Some(0x1234),
            cell_id: Some(0x0ABCDEF),
            band: Some(2),
            ..Default::default()
        };
        let json = serde_json::to_string(&info).unwrap();
        // Reserved physical-layer fields are omitted when unset.
        assert!(!json.contains("earfcn"));
        let back: ServingCellInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }
}
