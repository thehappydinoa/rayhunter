//! Structured serving-cell context attached to analysis [`Event`](super::analyzer::Event)s.
//!
//! Downstream consumers (e.g. correlating a cellular detection with other
//! sensor observations, or looking a cell up against a known-tower database)
//! need a stable, machine-readable identity for the serving cell at the moment
//! an event fired, rather than parsing it out of free-text messages.
//!
//! The identity fields ([`Plmn`], TAC, cell id, band) are recovered from the
//! LTE RRC SIB1 broadcast, which is already decoded by the analysis pipeline.
//! The physical-layer fields come from Qualcomm DIAG log packets, not RRC:
//! EARFCN and PCI from the LTE RRC OTA log header and the LTE ML1 serving-cell
//! measurement log (see [`ServingCellTracker::observe_physical`]). RSRP/RSRQ
//! come from that same ML1 log (see [`ServingCellTracker::observe_signal`]).
//! RSRP is decoded for the v18 subpacket layout MDM9207-class devices (e.g. the
//! Orbic) emit; RSRQ and SINR are not yet decoded for v18.

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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct Plmn {
    /// Mobile Country Code, always 3 digits, e.g. "310".
    pub mcc: String,
    /// Mobile Network Code, 2 or 3 digits, e.g. "410" or "01".
    pub mnc: String,
}

impl Plmn {
    /// Resolve this PLMN to a named operator/country via the curated
    /// [`mcc_mnc`](super::mcc_mnc) table.
    pub fn carrier(&self) -> super::mcc_mnc::Carrier {
        super::mcc_mnc::lookup(&self.mcc, &self.mnc)
    }

    /// A human-readable label for this PLMN, always non-empty: the resolved
    /// operator/country if known, otherwise the raw `MCC-MNC` digits.
    pub fn display_name(&self) -> String {
        self.carrier()
            .display()
            .unwrap_or_else(|| format!("{}-{}", self.mcc, self.mnc))
    }
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

    // --- Physical-layer context (sourced from DIAG log packets, not RRC) ---
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
    /// Every distinct PLMN seen over the life of the capture, in a stable
    /// order. Used to summarize which operator(s) the run observed.
    observed_plmns: std::collections::BTreeSet<Plmn>,
}

impl ServingCellTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the tracked serving cell's identity from an information element.
    /// A no-op for elements that do not carry cell identity. Physical-layer
    /// fields (PCI/EARFCN/signal) recorded via [`observe_physical`](Self::observe_physical)
    /// are preserved rather than overwritten.
    pub fn observe(&mut self, ie: &InformationElement) {
        if let Some(info) = ServingCellInfo::from_information_element(ie) {
            if let Some(plmn) = &info.plmn {
                self.observed_plmns.insert(plmn.clone());
            }
            let current = self.current.get_or_insert_with(ServingCellInfo::default);
            current.plmn = info.plmn;
            current.tac = info.tac;
            current.cell_id = info.cell_id;
            current.band = info.band;
        }
    }

    /// Record physical-layer serving-cell context (PCI and EARFCN) recovered
    /// from a DIAG LTE RRC OTA log header. These arrive on RRC packets
    /// independently of the SIB1 that carries the cell identity, so they are
    /// merged into the current cell rather than replacing it.
    pub fn observe_physical(&mut self, pci: u16, earfcn: u32) {
        let current = self.current.get_or_insert_with(ServingCellInfo::default);
        // A change of serving carrier invalidates the previously recorded
        // signal, which was measured on the old EARFCN. Clear it so a stale
        // RSRP can't linger across a reselection until a fresh ML1 arrives.
        if current.earfcn != Some(earfcn) {
            current.rsrp = None;
            current.rsrq = None;
        }
        current.pci = Some(pci);
        current.earfcn = Some(earfcn);
    }

    /// Record serving-cell signal measurements (RSRP/RSRQ) from an LTE ML1
    /// measurement, merging whichever are present into the current cell.
    ///
    /// ML1 reports measured cells including neighbors, so the measurement is
    /// attributed to the serving cell only when its `earfcn` matches the serving
    /// cell's (established from the RRC OTA header). A no-op otherwise.
    ///
    /// Caveat: an intra-frequency neighbor shares the serving EARFCN, and the
    /// v18 layout exposes no reliable PCI to distinguish it, so a co-channel
    /// neighbor's RSRP can be attributed here. Treat this as the RSRP of a cell
    /// on the serving carrier.
    pub fn observe_signal(&mut self, earfcn: u32, rsrp: Option<f32>, rsrq: Option<f32>) {
        let Some(current) = self.current.as_mut() else {
            return;
        };
        if current.earfcn != Some(earfcn) {
            return;
        }
        if rsrp.is_some() {
            current.rsrp = rsrp;
        }
        if rsrq.is_some() {
            current.rsrq = rsrq;
        }
    }

    /// The most recently observed serving cell, if any.
    pub fn current(&self) -> Option<ServingCellInfo> {
        self.current.clone()
    }

    /// A borrow of the most recently observed serving cell. Used on the
    /// per-message analysis hot path to avoid cloning when no event fires;
    /// callers needing an owned value use [`current`](Self::current).
    pub fn current_ref(&self) -> Option<&ServingCellInfo> {
        self.current.as_ref()
    }

    /// Every distinct PLMN observed so far, in a stable order.
    pub fn observed_plmns(&self) -> impl Iterator<Item = &Plmn> {
        self.observed_plmns.iter()
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
    fn test_observe_physical_records_pci_earfcn() {
        let mut tracker = ServingCellTracker::new();
        assert!(tracker.current().is_none());
        tracker.observe_physical(160, 2050);
        let cell = tracker
            .current()
            .expect("cell created by physical observation");
        assert_eq!(cell.pci, Some(160));
        assert_eq!(cell.earfcn, Some(2050));
        // Identity fields remain unset until a SIB1 is observed.
        assert!(cell.plmn.is_none());
    }

    #[test]
    fn test_observe_signal_matches_serving_earfcn() {
        let mut tracker = ServingCellTracker::new();
        // No serving cell yet: signal is dropped.
        tracker.observe_signal(2050, Some(-95.0), None);
        assert!(tracker.current().is_none());
        // Establish the serving cell at EARFCN 2050.
        tracker.observe_physical(160, 2050);
        // A neighbor measurement (different EARFCN) must not touch the cell.
        tracker.observe_signal(5780, Some(-70.0), None);
        assert_eq!(tracker.current().unwrap().rsrp, None);
        // A measurement for the serving EARFCN is applied.
        tracker.observe_signal(2050, Some(-102.9), None);
        assert_eq!(tracker.current().unwrap().rsrp, Some(-102.9));
    }

    #[test]
    fn test_carrier_change_clears_stale_signal() {
        let mut tracker = ServingCellTracker::new();
        tracker.observe_physical(160, 2050);
        tracker.observe_signal(2050, Some(-95.0), None);
        assert_eq!(tracker.current().unwrap().rsrp, Some(-95.0));
        // Reselect to a different EARFCN: the old cell's RSRP must be cleared.
        tracker.observe_physical(200, 5780);
        let cell = tracker.current().unwrap();
        assert_eq!(cell.earfcn, Some(5780));
        assert_eq!(cell.rsrp, None);
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
