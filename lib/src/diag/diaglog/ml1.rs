//! LTE ML1 measurement log packet parsing (physical-layer signal metrics).
//!
//! The `0xB193` "LTE ML1 Serving Cell Measurement Result" log packet carries
//! the serving cell's RSRP/RSRQ/RSSI, which the RRC and NAS layers do not. The
//! packet is version-tagged (its first byte) and its layout differs by version.
//!
//! Only the versions whose wire format is known are decoded; any other version
//! returns `None` so an unrecognized layout fails safe rather than producing
//! bogus signal values. Field offsets, bit packing, and dB scaling follow the
//! public Qualcomm DIAG format as implemented by QCSuper/SCAT.

/// Serving-cell physical-layer measurements decoded from a `0xB193` packet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ServingCellMeasurement {
    /// E-UTRA Absolute Radio Frequency Channel Number of the serving cell.
    pub earfcn: u32,
    /// Physical Cell Identity (0..503).
    pub pci: u16,
    /// Reference Signal Received Power, in dBm.
    pub rsrp: f32,
    /// Reference Signal Received Quality, in dB.
    pub rsrq: f32,
    /// Received Signal Strength Indicator, in dBm.
    pub rssi: f32,
}

fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
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
    /// Decode from the raw `0xB193` log body, which begins with the version
    /// byte. Returns `None` for unsupported versions or truncated data.
    pub fn parse(body: &[u8]) -> Option<Self> {
        match *body.first()? {
            4 => {
                // '<BHHHLLLLLL': version, rrc_rel(B), reserved(H), earfcn(H),
                // pci_serv_layer_prio(H), meas_rsrp(L), avg_rsrp(L), rsrq(L),
                // rssi(L), rxlev(L), s_search(L).
                let earfcn = u16_le(body, 4)? as u32;
                let pci_serv = u16_le(body, 6)?;
                let meas_rsrp = u32_le(body, 8)?;
                let rsrq_raw = u32_le(body, 16)?;
                let rssi_raw = u32_le(body, 20)?;
                Some(Self::from_raw(
                    earfcn, pci_serv, meas_rsrp, rsrq_raw, rssi_raw,
                ))
            }
            5 => {
                // '<BHLH2xLLLLLL': like v4 but earfcn is 4 bytes and 2 pad
                // bytes follow pci_serv_layer_prio.
                let earfcn = u32_le(body, 4)?;
                let pci_serv = u16_le(body, 8)?;
                let meas_rsrp = u32_le(body, 12)?;
                let rsrq_raw = u32_le(body, 20)?;
                let rssi_raw = u32_le(body, 24)?;
                Some(Self::from_raw(
                    earfcn, pci_serv, meas_rsrp, rsrq_raw, rssi_raw,
                ))
            }
            _ => None,
        }
    }

    /// Apply the shared bit-unpacking and dB scaling common to both versions.
    fn from_raw(earfcn: u32, pci_serv: u16, meas_rsrp: u32, rsrq_raw: u32, rssi_raw: u32) -> Self {
        // PCI is the high 9 bits of the packed 16-bit pci_serv_layer_prio field.
        let pci = pci_serv >> 7;
        // RSRP: low 12 bits, 1/16 dB steps, -180 dBm offset.
        let rsrp = -180.0 + (meas_rsrp & 0xfff) as f32 * 0.0625;
        // RSRQ: high 10 bits, 1/16 dB steps, -30 dB offset.
        let rsrq = -30.0 + ((rsrq_raw >> 22) & 0x3ff) as f32 * 0.0625;
        // RSSI: bits [11..21], 1/16 dB steps, -110 dBm offset.
        let rssi = -110.0 + ((rssi_raw >> 11) & 0x7ff) as f32 * 0.0625;
        Self {
            earfcn,
            pci,
            rsrp,
            rsrq,
            rssi,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A version-4 body whose raw fields are chosen to decode to round dB values:
    // earfcn 2050, pci 160, rsrp -90, rsrq -10, rssi -70.
    fn v4_body() -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[0] = 4; // version
        b[4..6].copy_from_slice(&2050u16.to_le_bytes()); // earfcn
        b[6..8].copy_from_slice(&(160u16 << 7).to_le_bytes()); // pci in high 9 bits
        b[8..12].copy_from_slice(&1440u32.to_le_bytes()); // meas_rsrp: -180 + 1440/16 = -90
        b[16..20].copy_from_slice(&(320u32 << 22).to_le_bytes()); // rsrq: -30 + 320/16 = -10
        b[20..24].copy_from_slice(&(640u32 << 11).to_le_bytes()); // rssi: -110 + 640/16 = -70
        b
    }

    #[test]
    fn parses_v4() {
        let m = ServingCellMeasurement::parse(&v4_body()).expect("v4 parses");
        assert_eq!(m.earfcn, 2050);
        assert_eq!(m.pci, 160);
        assert!((m.rsrp - (-90.0)).abs() < 0.01, "rsrp = {}", m.rsrp);
        assert!((m.rsrq - (-10.0)).abs() < 0.01, "rsrq = {}", m.rsrq);
        assert!((m.rssi - (-70.0)).abs() < 0.01, "rssi = {}", m.rssi);
    }

    #[test]
    fn parses_v5() {
        // Same values as v4 but in the v5 layout (u32 earfcn + 2 pad bytes).
        let mut b = vec![0u8; 36];
        b[0] = 5;
        b[4..8].copy_from_slice(&2050u32.to_le_bytes());
        b[8..10].copy_from_slice(&(160u16 << 7).to_le_bytes());
        b[12..16].copy_from_slice(&1440u32.to_le_bytes());
        b[20..24].copy_from_slice(&(320u32 << 22).to_le_bytes());
        b[24..28].copy_from_slice(&(640u32 << 11).to_le_bytes());
        let m = ServingCellMeasurement::parse(&b).expect("v5 parses");
        assert_eq!(m.earfcn, 2050);
        assert_eq!(m.pci, 160);
        assert!((m.rsrp - (-90.0)).abs() < 0.01);
    }

    #[test]
    fn unsupported_version_is_none() {
        // An unknown version must fail safe rather than emit bogus values.
        let mut b = vec![0u8; 64];
        b[0] = 24;
        assert!(ServingCellMeasurement::parse(&b).is_none());
    }

    #[test]
    fn truncated_is_none() {
        assert!(ServingCellMeasurement::parse(&[4, 0, 0]).is_none());
        assert!(ServingCellMeasurement::parse(&[]).is_none());
    }
}
