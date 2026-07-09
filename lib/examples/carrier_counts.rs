//! Diagnostic: count serving-cell PLMN (carrier) observations in a QMDL, so we
//! can see how the recording's SIB1 sightings are distributed across operators.
//!
//! Usage: cargo run -p rayhunter --example carrier_counts -- <path-to.qmdl[.gz]>

use std::collections::BTreeMap;

use rayhunter::analysis::cell_info::ServingCellInfo;
use rayhunter::analysis::information_element::InformationElement;
use rayhunter::gsmtap::parser as gsmtap_parser;
use rayhunter::qmdl::QmdlMessageReader;
use tokio::fs::File;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: carrier_counts <path-to.qmdl[.gz]>");
    let file = File::open(&path).await.expect("open");
    let mut reader = QmdlMessageReader::new(file).await.expect("reader");

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = 0usize;
    while let Some(msg) = reader.get_next_message().await.expect("read") {
        let Ok(msg) = msg else { continue };
        let Ok(Some((_ts, gsmtap))) = gsmtap_parser::parse(msg) else {
            continue;
        };
        let Ok(ie) = InformationElement::try_from(&gsmtap) else {
            continue;
        };
        if let Some(info) = ServingCellInfo::from_information_element(&ie)
            && let Some(plmn) = info.plmn
        {
            total += 1;
            *counts
                .entry(format!("{}-{} {}", plmn.mcc, plmn.mnc, plmn.display_name()))
                .or_default() += 1;
        }
    }

    println!("SIB1-with-PLMN observations: {total}");
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    for (k, c) in v {
        let pct = 100.0 * c as f64 / total.max(1) as f64;
        println!("  {c:6} ({pct:5.1}%)  {k}");
    }
}
