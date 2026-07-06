use std::borrow::Cow;

use pycrate_rs::nas::NASMessage;
use pycrate_rs::nas::emm::EMMMessage;

use super::analyzer::{Analyzer, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};

/// Detects Type-0 SMS ("silent SMS") delivered over NAS. These messages are
/// processed by the baseband but never shown to the user — no notification,
/// no storage. They are commonly used by IMSI catchers and law enforcement
/// to silently ping a device and confirm its presence on a cell, enabling
/// location tracking.
///
/// Detection: the SMS-DELIVER TPDU carried inside EMMDLNASTransport has
/// TP-Protocol-Identifier = 0x40 ("Short Message Type 0", 3GPP TS 23.040
/// §9.2.3.9).
pub struct Type0SmsAnalyzer {}

impl Analyzer for Type0SmsAnalyzer {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from("Silent SMS (Type-0) Detected")
    }

    fn get_description(&self) -> Cow<'_, str> {
        Cow::from(
            "Detects Type-0 (\"silent\") SMS messages delivered over NAS. These are invisible \
             to the user and are commonly used to track a device's location by confirming \
             its presence on a cell. Legitimate networks rarely send them to consumer devices.",
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
        let payload = match ie {
            InformationElement::LTE(inner) => match &**inner {
                LteInformationElement::NAS(payload) => payload,
                _ => return None,
            },
            _ => return None,
        };

        // SMS in LTE is carried inside Downlink NAS Transport
        let container = match payload {
            NASMessage::EMMMessage(EMMMessage::EMMDLNASTransport(transport)) => {
                &transport.nas_container.inner.buf
            }
            _ => return None,
        };

        // Parse the SMS-CP layer → SMS-RP layer → SMS-TP (TPDU) and check
        // TP-PID for Type-0.
        if is_type0_sms(container) {
            return Some(Event {
                event_type: EventType::High,
                message: "Silent SMS (Type-0) received — may be used for location tracking"
                    .to_string(),
                ..Default::default()
            });
        }
        None
    }
}

/// Parses the raw NAS container bytes from EMMDLNASTransport to determine if
/// the carried SMS is a Type-0 (silent) message.
///
/// Layer structure (3GPP TS 24.011, TS 23.040):
///   CP-Data (msg type 0x09 for MT SMS-CP) → RP-Data (msg type 0x01 for
///   network-to-MS) → TPDU (SMS-DELIVER)
///
/// In the TPDU, TP-PID is the byte immediately after the TP-OA (originating
/// address) field. TP-PID = 0x40 means "Short Message Type 0".
fn is_type0_sms(container: &[u8]) -> bool {
    // Minimum: 1 byte protocol discriminator + transaction ID,
    //          1 byte CP message type, 1 byte CP-data length, RP header...
    if container.len() < 2 {
        return false;
    }

    // The first byte is the protocol discriminator / transaction ID.
    // Protocol discriminator for SMS is 0x09 (lower nibble).
    let pd = container[0] & 0x0F;
    if pd != 0x09 {
        return false;
    }

    // Second byte: CP message type. CP-DATA = 0x01.
    let cp_msg_type = container[1];
    if cp_msg_type != 0x01 {
        return false;
    }

    // Third byte: CP-Data length
    if container.len() < 4 {
        return false;
    }
    let _cp_data_len = container[2] as usize;

    // CP-Data payload starts at byte 3. This is the RP layer.
    let rp = &container[3..];
    if rp.is_empty() {
        return false;
    }

    // RP message type: 0x01 = RP-DATA (network to MS)
    let rp_msg_type = rp[0] & 0x07;
    if rp_msg_type != 0x01 {
        return false;
    }

    // RP-DATA structure:
    //   1 byte: message type indicator
    //   1 byte: message reference
    //   1 byte: RP-OA length (in bytes of the address value, or 0)
    if rp.len() < 3 {
        return false;
    }
    let rp_oa_len = rp[2] as usize;
    // Skip past: msg type (1) + msg ref (1) + OA length byte (1) + OA value
    let rp_da_offset = 3 + rp_oa_len;
    if rp.len() <= rp_da_offset {
        return false;
    }

    // RP-DA (destination address) length
    let rp_da_len = rp[rp_da_offset] as usize;
    // Skip RP-DA length byte + DA value
    let rp_ud_offset = rp_da_offset + 1 + rp_da_len;
    if rp.len() <= rp_ud_offset {
        return false;
    }

    // RP-User-Data: length byte, then the TPDU
    let rp_ud_len = rp[rp_ud_offset] as usize;
    let tpdu_start = rp_ud_offset + 1;
    if rp.len() < tpdu_start + rp_ud_len || rp_ud_len == 0 {
        return false;
    }

    let tpdu = &rp[tpdu_start..tpdu_start + rp_ud_len];
    extract_tp_pid_from_sms_deliver(tpdu) == Some(0x40)
}

/// Extract TP-PID from an SMS-DELIVER TPDU.
///
/// SMS-DELIVER layout (3GPP TS 23.040 §9.2.2.1):
///   byte 0: TP-MTI (bits 0-1) + flags  — MTI = 0b00 for SMS-DELIVER
///   bytes 1..N: TP-OA (originating address)
///     byte 1: address length (number of useful semi-octets/digits)
///     byte 2: type-of-address
///     bytes 3..: address digits (ceil(addr_len / 2) bytes)
///   next byte: TP-PID
fn extract_tp_pid_from_sms_deliver(tpdu: &[u8]) -> Option<u8> {
    if tpdu.is_empty() {
        return None;
    }

    // Check TP-MTI: lower 2 bits should be 0b00 for SMS-DELIVER
    let tp_mti = tpdu[0] & 0x03;
    if tp_mti != 0x00 {
        return None;
    }

    // TP-OA starts at byte 1
    if tpdu.len() < 3 {
        return None;
    }
    let addr_len_digits = tpdu[1] as usize; // number of digits
    // Address value occupies ceil(digits / 2) bytes, plus 1 byte for type-of-address
    let addr_bytes = addr_len_digits.div_ceil(2);
    // TP-OA total = 1 (length) + 1 (TOA) + addr_bytes
    let tp_pid_offset = 1 + 1 + 1 + addr_bytes; // first-byte + len + TOA + digits

    if tpdu.len() <= tp_pid_offset {
        return None;
    }

    Some(tpdu[tp_pid_offset])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type0_detection() {
        // Construct a minimal DL NAS Transport container with a Type-0 SMS.
        // PD=0x09 (SMS), CP-DATA=0x01, CP-len, RP-DATA(0x01), ref=0x00,
        // RP-OA len=0, RP-DA len=0, RP-UD len=N, TPDU...
        let mut container: Vec<u8> = Vec::new();
        // Protocol discriminator (SMS = 0x09) + transaction ID in upper nibble
        container.push(0x09); // PD
        container.push(0x01); // CP-DATA

        // Build RP layer
        let mut rp: Vec<u8> = Vec::new();
        rp.push(0x01); // RP-DATA (network→MS)
        rp.push(0x00); // message reference
        rp.push(0x00); // RP-OA length = 0 (no originating address in RP)
        rp.push(0x00); // RP-DA length = 0

        // Build TPDU (SMS-DELIVER)
        let mut tpdu: Vec<u8> = Vec::new();
        tpdu.push(0x04); // TP-MTI=00 (SMS-DELIVER), other flags set
        // TP-OA: 4 digits → 2 bytes of address
        tpdu.push(0x04); // addr length = 4 digits
        tpdu.push(0x91); // type-of-address (international)
        tpdu.push(0x21); // digits 1,2
        tpdu.push(0x43); // digits 3,4
        // TP-PID = 0x40 (Type-0!)
        tpdu.push(0x40);
        // TP-DCS, TP-SCTS, TP-UDL, ... (not needed for our check)
        tpdu.push(0x00);

        // RP-UD: length + TPDU
        rp.push(tpdu.len() as u8);
        rp.extend_from_slice(&tpdu);

        // CP-Data length
        container.push(rp.len() as u8);
        container.extend_from_slice(&rp);

        assert!(is_type0_sms(&container));
    }

    #[test]
    fn test_normal_sms_does_not_fire() {
        // Same as above but with TP-PID = 0x00 (normal SMS)
        let mut container: Vec<u8> = Vec::new();
        container.push(0x09);
        container.push(0x01);

        let mut rp: Vec<u8> = Vec::new();
        rp.push(0x01);
        rp.push(0x00);
        rp.push(0x00);
        rp.push(0x00);

        let mut tpdu: Vec<u8> = Vec::new();
        tpdu.push(0x04);
        tpdu.push(0x04);
        tpdu.push(0x91);
        tpdu.push(0x21);
        tpdu.push(0x43);
        // TP-PID = 0x00 (normal)
        tpdu.push(0x00);
        tpdu.push(0x00);

        rp.push(tpdu.len() as u8);
        rp.extend_from_slice(&tpdu);

        container.push(rp.len() as u8);
        container.extend_from_slice(&rp);

        assert!(!is_type0_sms(&container));
    }

    #[test]
    fn test_empty_container() {
        assert!(!is_type0_sms(&[]));
        assert!(!is_type0_sms(&[0x09]));
    }
}
