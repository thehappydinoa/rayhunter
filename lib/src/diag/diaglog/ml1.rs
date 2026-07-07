//! LTE ML1 Serving Cell Measurement Response (`0xB193`) parsing.
//!
//! `0xB193` has an outer header followed by one or more subpackets:
//!
//! ```text
//! [0]     u8   version           (outer, 1 on all observed devices)
//! [1]     u8   num_subpackets
//! [2:4]   u16  system frame number
//! [4]     u8   subpacket_id       (25 = serving cell measurement)
//! [5]     u8   subpacket_version  (the real layout discriminator)
//! [6:8]   u16  subpacket_size
//! [8:]         subpacket data
//! ```
//!
//! Note this is a *different* log from `0xB17F` ("Serving Cell Meas and Eval"),
//! which has a flat, non-subpacketed layout.
//!
//! The **subpacket version** — not the outer version — selects the field
//! layout, and layouts differ substantially between chipsets. Only versions
//! validated against a real capture are decoded; any other returns `None` so an
//! unrecognized layout fails safe rather than emitting bogus values.
//!
//! - **v18** (MDM9207; e.g. the Orbic RC400L): the serving cell is inline in the
//!   carrier header — EARFCN at `sp+0` (low 18 bits), serving PCI at `sp+4` (low
//!   9 bits). Confirmed against a real Orbic frame (EARFCN 700, PCI 64). The
//!   RSRP/RSRQ field layout for v18 is **not yet reverse-engineered** — it can't
//!   be located from a stationary capture (the field is indistinguishable from
//!   constant look-alikes without a wide RSRP sweep correlated to ground truth),
//!   so `rsrp`/`rsrq` are `None`. See the `diaggrok` project's `0xB193` notes.

/// The serving-cell measurement subpacket id within `0xB193`.
const SUBPACKET_ID_SERVING_CELL_MEAS: u8 = 25;

/// Serving-cell physical-layer measurements decoded from a `0xB193` packet.
/// `earfcn`/`pci` are populated for any known subpacket version; `rsrp`/`rsrq`
/// are `Some` only for versions whose signal-field layout has been decoded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ServingCellMeasurement {
    /// E-UTRA Absolute Radio Frequency Channel Number of the serving cell.
    pub earfcn: u32,
    /// Physical Cell Identity (0..503).
    pub pci: u16,
    /// Reference Signal Received Power, in dBm.
    pub rsrp: Option<f32>,
    /// Reference Signal Received Quality, in dB.
    pub rsrq: Option<f32>,
}

fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

impl ServingCellMeasurement {
    /// Decode from the raw `0xB193` log body (starting at the outer version
    /// byte). Returns `None` for non-serving-cell subpackets, unsupported
    /// subpacket versions, or truncated data.
    pub fn parse(body: &[u8]) -> Option<Self> {
        // Outer header is 8 bytes; subpacket data follows.
        let subpacket_id = *body.get(4)?;
        let subpacket_version = *body.get(5)?;
        let sp = body.get(8..)?;

        if subpacket_id != SUBPACKET_ID_SERVING_CELL_MEAS {
            return None;
        }

        match subpacket_version {
            18 => Self::parse_subpacket_v18(sp),
            _ => None,
        }
    }

    /// v18 (MDM9207): serving EARFCN (low 18 bits) at `sp+0`, serving PCI (low 9
    /// bits) at `sp+4`. RSRP/RSRQ not yet located for this version.
    fn parse_subpacket_v18(sp: &[u8]) -> Option<Self> {
        let earfcn = u32_le(sp, 0)? & 0x3_ffff;
        let pci = (u32_le(sp, 4)? & 0x1ff) as u16;
        Some(Self {
            earfcn,
            pci,
            rsrp: None,
            rsrq: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real 0xB193 body captured from an Orbic RC400L (MDM9207): outer version
    // 1, subpacket id 25, subpacket version 18 (0x12), EARFCN 700, PCI 64.
    fn orbic_v18_body() -> Vec<u8> {
        vec![
            0x01, 0x01, 0x4a, 0xe0, 0x19, 0x12, 0x60, 0x00, // outer header
            0xbc, 0x02, 0x00, 0x00, // sp+0: earfcn = 0x2bc = 700
            0x40, 0x10, 0x00, 0x00, // sp+4: 0x1040 -> pci low9 = 64
        ]
    }

    #[test]
    fn parses_orbic_v18() {
        let m = ServingCellMeasurement::parse(&orbic_v18_body()).expect("v18 parses");
        assert_eq!(m.earfcn, 700);
        assert_eq!(m.pci, 64);
        // v18 RSRP/RSRQ layout is not yet reverse-engineered.
        assert_eq!(m.rsrp, None);
        assert_eq!(m.rsrq, None);
    }

    #[test]
    fn unsupported_subpacket_version_is_none() {
        // A serving-cell subpacket with an unknown version must fail safe.
        let mut b = orbic_v18_body();
        b[5] = 59; // an as-yet-unimplemented version
        assert!(ServingCellMeasurement::parse(&b).is_none());
    }

    #[test]
    fn wrong_subpacket_id_is_none() {
        let mut b = orbic_v18_body();
        b[4] = 30; // not the serving-cell-measurement subpacket
        assert!(ServingCellMeasurement::parse(&b).is_none());
    }

    #[test]
    fn truncated_is_none() {
        assert!(ServingCellMeasurement::parse(&[0x01, 0x01, 0x00]).is_none());
        assert!(ServingCellMeasurement::parse(&[]).is_none());
    }
}
