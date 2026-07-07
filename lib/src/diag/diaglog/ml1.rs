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
//! This is a *different* log from `0xB17F` ("Serving Cell Meas and Eval"),
//! which has a flat, non-subpacketed layout.
//!
//! The **subpacket version** selects the field layout, and layouts differ
//! substantially between chipsets. Only versions validated against a real
//! capture are decoded; any other returns `None` so an unrecognized layout
//! fails safe rather than emitting bogus values.
//!
//! - **v18** (MDM9207; e.g. the Orbic RC400L): EARFCN at `sp+0` (low 18 bits)
//!   and RSRP at `sp+32` (low 12 bits, `-180 + raw/16` dBm). The RSRP field and
//!   scaling were reverse-engineered and validated to r=0.999 over a 28 dB range
//!   by time-aligned correlation against `0xB17F` v5 ground truth (which the
//!   same modem emits with a known, decodable layout). Each frame reports one
//!   *measured* cell (serving or neighbor), identified by its EARFCN — the
//!   caller attributes RSRP to the serving cell only on an EARFCN match. RSRQ
//!   is not yet located for v18.
//!
//!   Because the reliable per-cell discriminator here is EARFCN alone (the v18
//!   PCI field has not been located), an *intra-frequency* neighbor — which
//!   shares the serving cell's EARFCN — cannot be distinguished from the serving
//!   cell, so its RSRP can be attributed to the serving cell. On a stable/served
//!   device this is the serving cell in practice; treat the value as "RSRP of a
//!   cell on the serving carrier."

/// The serving-cell measurement subpacket id within `0xB193`.
const SUBPACKET_ID_SERVING_CELL_MEAS: u8 = 25;

/// Plausible LTE RSRP range in dBm (3GPP measurement range is roughly
/// -140..-44); values outside this are treated as padding/garbage.
const RSRP_MIN_DBM: f32 = -140.0;
const RSRP_MAX_DBM: f32 = -30.0;

/// A single measured-cell record decoded from a `0xB193` packet. `earfcn`
/// identifies which cell the measurement is for (may be a neighbor, not the
/// serving cell). `rsrp`/`rsrq` are `Some` only for versions whose signal-field
/// layout has been decoded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ServingCellMeasurement {
    /// E-UTRA Absolute Radio Frequency Channel Number the measurement is for.
    pub earfcn: u32,
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

    /// v18 (MDM9207): EARFCN (low 18 bits) at `sp+0`, RSRP (low 12 bits,
    /// `-180 + raw/16` dBm) at `sp+32`.
    fn parse_subpacket_v18(sp: &[u8]) -> Option<Self> {
        let earfcn = u32_le(sp, 0)? & 0x3_ffff;
        let rsrp = -180.0 + (u32_le(sp, 32)? & 0xfff) as f32 * 0.0625;
        // Drop physically implausible values: a zeroed/padding field decodes to
        // -180 dBm, well outside the real RSRP range, and must not be reported.
        let rsrp = (RSRP_MIN_DBM..=RSRP_MAX_DBM)
            .contains(&rsrp)
            .then_some(rsrp);
        Some(Self {
            earfcn,
            rsrp,
            rsrq: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real 0xB193 body captured from an Orbic RC400L (MDM9207): outer version
    // 1, subpacket id 25, subpacket version 18. Measured cell EARFCN 5780, RSRP
    // raw 1583 -> -81.06 dBm (cross-validated against 0xB17F).
    fn orbic_v18_body() -> Vec<u8> {
        vec![
            0x01, 0x01, 0xea, 0xe0, 0x19, 0x12, 0x60, 0x00, // outer header
            0x94, 0x16, 0x00, 0x00, // sp+0: earfcn = 0x1694 = 5780
            0x40, 0x10, 0x00, 0x00, 0xf9, 0x0c, 0x00, 0x00, 0xcc, 0xa5, 0x00, 0x00, 0xe6, 0x52,
            0xc8, 0x07, 0xf9, 0xbc, 0x18, 0x00, 0x2f, 0xf6, 0x5c, 0x00, 0xcf, 0xf5, 0x62, 0x00,
            0x2f, 0x06, 0x16, 0x58, // sp+32: 0x5816062f, low12 = 1583 = RSRP raw
        ]
    }

    #[test]
    fn parses_orbic_v18() {
        let m = ServingCellMeasurement::parse(&orbic_v18_body()).expect("v18 parses");
        assert_eq!(m.earfcn, 5780);
        // 1583 / 16 - 180 = -81.0625
        assert!((m.rsrp.expect("rsrp") - (-81.0625)).abs() < 0.01);
        assert_eq!(m.rsrq, None);
    }

    #[test]
    fn v18_zeroed_rsrp_field_is_none() {
        // A zeroed sp+32 decodes to -180 dBm, which is implausible and must be
        // reported as absent, not as a real measurement.
        let mut b = orbic_v18_body();
        b[40..44].copy_from_slice(&0u32.to_le_bytes());
        let m = ServingCellMeasurement::parse(&b).expect("still parses");
        assert_eq!(m.earfcn, 5780);
        assert_eq!(m.rsrp, None);
    }

    #[test]
    fn unsupported_subpacket_version_is_none() {
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
