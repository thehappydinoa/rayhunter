//! Diagnostic: replay a QMDL and detect HDLC frames whose parse leaves trailing
//! ("leftover") bytes — the source of the `N leftover bytes when parsing
//! Message` warning — and classify each as a real dropped message (data loss)
//! or benign padding.
//!
//! It reproduces exactly what `Message::from_hdlc` does (HDLC-decapsulate, then
//! `Message::from_bytes`) but keeps the leftover slice instead of discarding it,
//! then tries to parse that leftover as another message. A leftover that parses
//! as a `Log` with a plausible log code is a dropped record; anything else
//! (the catch-all `Response`, or an unparseable remainder) is padding/CRC noise.
//!
//! Usage: cargo run -p rayhunter --example leftover_probe -- <path-to.qmdl[.gz]>

use std::collections::BTreeMap;

use deku::DekuContainerRead;
use rayhunter::diag::{CRC_CCITT, Message};
use rayhunter::hdlc::hdlc_decapsulate;
use rayhunter::qmdl::QmdlMessageReader;
use tokio::fs::File;

fn describe(m: &Message) -> String {
    match m {
        Message::Log { log_type, .. } => format!("log 0x{log_type:04x}"),
        Message::Response { .. } => "response".to_string(),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        panic!("usage: leftover_probe <path-to.qmdl[.gz]> [more.qmdl ...]");
    }

    let mut frames = 0usize;
    let mut parse_errors = 0usize;
    let mut leftover_frames = 0usize;
    let mut leftover_bytes_total = 0usize;
    let mut first_msg_types: BTreeMap<String, usize> = BTreeMap::new();
    let mut tail_is_log: BTreeMap<String, usize> = BTreeMap::new();
    let mut tail_is_response = 0usize;
    let mut tail_unparseable = 0usize;
    let mut matches_outer_inner_gap = 0usize;
    let mut samples: Vec<String> = Vec::new();

    for path in &paths {
        let file = match File::open(path).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skip {path}: {e}");
                continue;
            }
        };
        let mut reader = match QmdlMessageReader::new(file).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {path}: {e}");
                continue;
            }
        };
        while let Some((buf, _)) = reader
            .get_next_message_with_bytes()
            .await
            .expect("read error")
        {
            frames += 1;
            let data = match hdlc_decapsulate(&buf, &CRC_CCITT) {
                Ok(d) => d,
                Err(_) => continue, // HDLC error is a different warning
            };
            let ((leftover, _), msg) = match Message::from_bytes((&data, 0)) {
                Ok(v) => v,
                Err(_) => {
                    parse_errors += 1;
                    continue;
                }
            };
            if leftover.is_empty() {
                continue;
            }
            leftover_frames += 1;
            leftover_bytes_total += leftover.len();
            *first_msg_types.entry(describe(&msg)).or_default() += 1;

            // Does the leftover exactly equal the outer_length vs inner_length gap?
            // (The parser sizes the body from inner_length and ignores outer_length,
            // so a mismatch shows up as leftover.)
            if let Message::Log {
                outer_length,
                inner_length,
                ..
            } = &msg
            {
                let consumed = *inner_length as usize + 4; // opcode+pending+outer+inner+ts + (inner-12)
                if data.len().saturating_sub(consumed) == leftover.len()
                    && outer_length != inner_length
                {
                    matches_outer_inner_gap += 1;
                }
            }

            match Message::from_bytes((leftover, 0)) {
                Ok((_, tail @ Message::Log { .. })) => {
                    *tail_is_log.entry(describe(&tail)).or_default() += 1;
                }
                Ok((_, Message::Response { .. })) => tail_is_response += 1,
                Err(_) => tail_unparseable += 1,
            }

            if samples.len() < 8 {
                let head: Vec<String> = leftover
                    .iter()
                    .take(12)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let (ol, il) = match &msg {
                    Message::Log {
                        outer_length,
                        inner_length,
                        ..
                    } => (*outer_length, *inner_length),
                    _ => (0, 0),
                };
                samples.push(format!(
                    "{} | data_len={} outer={ol} inner={il} leftover={}B: {}",
                    describe(&msg),
                    data.len(),
                    leftover.len(),
                    head.join(" ")
                ));
            }
        }
    }

    let pct = 100.0 * leftover_frames as f64 / frames.max(1) as f64;
    println!("=== QMDL leftover-bytes probe: {} file(s) ===", paths.len());
    println!("frames parsed:              {frames}");
    println!("frame parse errors:        {parse_errors}");
    println!("frames with leftover:      {leftover_frames} ({pct:.2}%)");
    println!("total leftover bytes:      {leftover_bytes_total}");
    println!("first-msg type of leftover frames: {first_msg_types:?}");
    println!("--- leftover classification ---");
    println!("  parses as Log (POSSIBLE DATA LOSS): {tail_is_log:?}");
    println!("  parses as Response (catch-all, benign): {tail_is_response}");
    println!("  unparseable (padding/CRC, benign):      {tail_unparseable}");
    println!("  leftover == outer/inner length gap:     {matches_outer_inner_gap}");
    println!("--- samples ---");
    for s in &samples {
        println!("  {s}");
    }
}
