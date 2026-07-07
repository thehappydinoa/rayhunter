//! Map a PLMN (MCC + MNC) to a human-readable operator and country.
//!
//! Rayhunter already recovers the serving cell's [`Plmn`](super::cell_info::Plmn)
//! (MCC/MNC digit strings) from the LTE SIB1 broadcast. Those raw digits are
//! hard to read; this module turns them into names for display and reporting
//! (e.g. `310-260` -> "T-Mobile US, United States").
//!
//! This is a **curated** table, not an exhaustive registry. It covers the US
//! MNOs (the primary market, and where the MNO owning a PLMN matters most for
//! spotting an unexpected operator) plus the largest global operators, and a
//! broad MCC -> country map so an unlisted operator still resolves to a country.
//! Source: the public ITU-T E.212 / MCC-MNC assignments. Extend freely; MVNOs
//! intentionally resolve to their host MNO, since a cell broadcasts the host
//! network's PLMN.

/// A resolved operator and/or country for a PLMN. Either field may be `None`
/// when only one is known (e.g. an unlisted MNC under a known MCC still yields
/// a country).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carrier {
    /// The mobile network operator, if the exact MCC+MNC is known.
    pub operator: Option<&'static str>,
    /// The country the MCC is assigned to, if known.
    pub country: Option<&'static str>,
}

impl Carrier {
    /// True when nothing could be resolved for the PLMN.
    pub fn is_unknown(&self) -> bool {
        self.operator.is_none() && self.country.is_none()
    }

    /// A compact display string, e.g. "T-Mobile US (United States)",
    /// "Unknown operator (United States)", or `None` if wholly unknown.
    pub fn display(&self) -> Option<String> {
        match (self.operator, self.country) {
            (Some(op), Some(c)) => Some(format!("{op} ({c})")),
            (Some(op), None) => Some(op.to_string()),
            (None, Some(c)) => Some(format!("Unknown operator ({c})")),
            (None, None) => None,
        }
    }
}

/// Resolve a PLMN to an operator and/or country. `mcc` must be 3 digits; `mnc`
/// is 2 or 3 digits (leading zeros significant), matching
/// [`Plmn`](super::cell_info::Plmn) field formats.
pub fn lookup(mcc: &str, mnc: &str) -> Carrier {
    Carrier {
        operator: operator_name(mcc, mnc),
        country: country_name(mcc),
    }
}

/// The operator for an exact MCC+MNC, if listed. MVNOs map to their host MNO.
pub fn operator_name(mcc: &str, mnc: &str) -> Option<&'static str> {
    let name = match (mcc, mnc) {
        // --- United States (MCC 310, 311, 312, 313, 316) ---
        // Verizon Wireless
        ("310", "004")
        | ("310", "005")
        | ("310", "006")
        | ("310", "010")
        | ("310", "012")
        | ("310", "013")
        | ("311", "110")
        | ("311", "270")
        | ("311", "271")
        | ("311", "272")
        | ("311", "273")
        | ("311", "274")
        | ("311", "275")
        | ("311", "276")
        | ("311", "277")
        | ("311", "278")
        | ("311", "279")
        | ("311", "280")
        | ("311", "281")
        | ("311", "282")
        | ("311", "283")
        | ("311", "284")
        | ("311", "285")
        | ("311", "286")
        | ("311", "287")
        | ("311", "288")
        | ("311", "289")
        | ("311", "390")
        | ("311", "480")
        | ("311", "481")
        | ("311", "482")
        | ("311", "483")
        | ("311", "484")
        | ("311", "485")
        | ("311", "486")
        | ("311", "487")
        | ("311", "488")
        | ("311", "489")
        | ("310", "590")
        | ("310", "890")
        | ("310", "910") => "Verizon Wireless",
        // AT&T Mobility
        ("310", "070")
        | ("310", "090")
        | ("310", "150")
        | ("310", "170")
        | ("310", "280")
        | ("310", "380")
        | ("310", "410")
        | ("310", "560")
        | ("310", "680")
        | ("310", "980")
        | ("311", "180")
        | ("310", "016")
        | ("310", "038") => "AT&T",
        // T-Mobile US (incl. legacy Sprint MVNO-on-network and MetroPCS)
        ("310", "026")
        | ("310", "160")
        | ("310", "200")
        | ("310", "210")
        | ("310", "220")
        | ("310", "230")
        | ("310", "240")
        | ("310", "250")
        | ("310", "260")
        | ("310", "270")
        | ("310", "300")
        | ("310", "310")
        | ("310", "490")
        | ("310", "530")
        | ("310", "580")
        | ("310", "660")
        | ("310", "800")
        | ("311", "660")
        | ("310", "031") => "T-Mobile US",
        // Sprint (now part of T-Mobile; codes still seen)
        ("310", "120")
        | ("311", "490")
        | ("311", "870")
        | ("311", "880")
        | ("312", "530")
        | ("316", "010") => "Sprint (T-Mobile)",
        // US Cellular
        ("310", "730") | ("311", "220") | ("311", "580") => "UScellular",
        // Dish Wireless / Boost
        ("313", "340") | ("310", "390") => "Dish Wireless",
        // Google Fi (data PLMN)
        ("311", "070") => "Google Fi",

        // --- Canada (302) ---
        ("302", "220") | ("302", "221") => "Telus",
        ("302", "610") | ("302", "620") => "Bell",
        ("302", "720") | ("302", "721") => "Rogers",
        ("302", "490") | ("302", "780") => "Freedom Mobile",

        // --- Mexico (334) ---
        ("334", "020") | ("334", "030") | ("334", "050") => "Telcel",
        ("334", "040") | ("334", "090") => "AT&T Mexico",
        ("334", "070") | ("334", "080") => "Movistar Mexico",

        // --- United Kingdom (234, 235) ---
        ("234", "10") | ("234", "11") | ("234", "01") => "O2 UK",
        ("234", "15") | ("234", "91") => "Vodafone UK",
        ("234", "20") | ("234", "94") => "3 UK",
        ("234", "30") | ("234", "31") | ("234", "32") | ("234", "33") | ("234", "34") => "EE",

        // --- Germany (262) ---
        ("262", "01") | ("262", "06") => "Telekom.de",
        ("262", "02") | ("262", "04") => "Vodafone.de",
        ("262", "03") | ("262", "05") | ("262", "07") | ("262", "08") => "o2.de",

        // --- France (208) ---
        ("208", "01") | ("208", "02") | ("208", "91") => "Orange France",
        ("208", "10") | ("208", "11") | ("208", "13") => "SFR",
        ("208", "20") | ("208", "21") => "Bouygues Telecom",
        ("208", "15") | ("208", "16") => "Free Mobile",

        // --- Netherlands (204) ---
        ("204", "04") | ("204", "02") => "Vodafone NL",
        ("204", "08") | ("204", "10") => "KPN",
        ("204", "16") | ("204", "20") => "T-Mobile NL",

        // --- Spain (214) ---
        ("214", "07") | ("214", "05") => "Movistar",
        ("214", "01") | ("214", "06") => "Vodafone ES",
        ("214", "03") | ("214", "09") => "Orange ES",

        // --- Italy (222) ---
        ("222", "01") => "TIM",
        ("222", "10") => "Vodafone IT",
        ("222", "88") => "WindTre",
        ("222", "50") => "Iliad",

        // --- Australia (505) ---
        ("505", "01") => "Telstra",
        ("505", "02") | ("505", "03") => "Optus",
        ("505", "06") => "Vodafone AU",

        _ => return None,
    };
    Some(name)
}

/// The country an MCC is assigned to. Covers the countries most relevant to
/// Rayhunter users plus a broad set of common ones. Some MCCs share a country
/// (e.g. US uses 310-316); each is listed.
pub fn country_name(mcc: &str) -> Option<&'static str> {
    let name = match mcc {
        "310" | "311" | "312" | "313" | "314" | "315" | "316" => "United States",
        "302" => "Canada",
        "334" => "Mexico",
        "234" | "235" => "United Kingdom",
        "262" => "Germany",
        "208" => "France",
        "204" => "Netherlands",
        "214" => "Spain",
        "222" => "Italy",
        "232" => "Austria",
        "206" => "Belgium",
        "228" => "Switzerland",
        "238" => "Denmark",
        "240" => "Sweden",
        "242" => "Norway",
        "244" => "Finland",
        "268" => "Portugal",
        "272" => "Ireland",
        "202" => "Greece",
        "260" => "Poland",
        "230" => "Czech Republic",
        "216" => "Hungary",
        "226" => "Romania",
        "255" => "Ukraine",
        "250" => "Russia",
        "286" => "Turkey",
        "425" => "Israel",
        "460" => "China",
        "440" | "441" => "Japan",
        "450" => "South Korea",
        "404" | "405" | "406" => "India",
        "505" => "Australia",
        "530" => "New Zealand",
        "525" => "Singapore",
        "454" => "Hong Kong",
        "466" => "Taiwan",
        "502" => "Malaysia",
        "510" => "Indonesia",
        "515" => "Philippines",
        "520" => "Thailand",
        "452" => "Vietnam",
        "724" | "722" => "Brazil",
        "730" => "Chile",
        "732" => "Colombia",
        "716" => "Peru",
        "655" => "South Africa",
        "621" => "Nigeria",
        "639" => "Kenya",
        "602" => "Egypt",
        "424" => "United Arab Emirates",
        "420" => "Saudi Arabia",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_us_mnos() {
        // The SIM we investigated: T-Mobile US.
        assert_eq!(operator_name("310", "260"), Some("T-Mobile US"));
        assert_eq!(operator_name("311", "480"), Some("Verizon Wireless"));
        assert_eq!(operator_name("310", "410"), Some("AT&T"));
    }

    #[test]
    fn mnc_leading_zero_is_significant() {
        // A 2-digit MNC must not be confused with a 3-digit one.
        assert_eq!(operator_name("234", "10"), Some("O2 UK"));
        assert_eq!(operator_name("234", "010"), None);
    }

    #[test]
    fn unknown_mnc_still_yields_country() {
        let c = lookup("310", "999");
        assert_eq!(c.operator, None);
        assert_eq!(c.country, Some("United States"));
        assert_eq!(
            c.display().as_deref(),
            Some("Unknown operator (United States)")
        );
    }

    #[test]
    fn fully_unknown_is_unknown() {
        let c = lookup("001", "01");
        assert!(c.is_unknown());
        assert_eq!(c.display(), None);
    }

    #[test]
    fn display_formats() {
        assert_eq!(
            lookup("310", "260").display().as_deref(),
            Some("T-Mobile US (United States)")
        );
    }
}
