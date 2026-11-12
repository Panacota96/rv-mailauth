//! Writes a minimal synthetic Outlook .msg for the sample set (called by tests/make_samples.py).
//!
//! Usage: `cargo run -q -p rv-mailauth-core --example make_msg -- <out.msg> < spec.json`
//!
//! spec.json: {"subject": "...", "sender_name": "...", "sender_email": "...", "body": "...",
//!             "message_id": "...", "submit_time": <unix s>, "delivery_time": <unix s>,
//!             "transport_headers": "..." | null,
//!             "attachments": [{"name": "...", "mime": "...", "data_b64": "...", "modified": <unix s>}]}
//! All content is synthetic (example.org / example.net); nothing secret is involved.

use rv_mailauth_core::msg::write::{Prop, PropValue, message};
use rv_mailauth_core::msg::*;
use std::io::Read;

fn b64(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let Some(v) = T.iter().position(|&x| x == c) else {
            continue;
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: make_msg <out.msg> < spec.json");
    let mut spec = String::new();
    std::io::stdin().read_to_string(&mut spec).expect("stdin");
    let v: serde_json::Value = serde_json::from_str(&spec).expect("spec JSON");
    let text = |k: &str| v[k].as_str().map(String::from);
    let (subject, sname, semail, body, mid, th) = (
        text("subject"),
        text("sender_name"),
        text("sender_email"),
        text("body"),
        text("message_id"),
        text("transport_headers"),
    );
    let mut props = Vec::new();
    for (id, val) in [
        (PR_SUBJECT, &subject),
        (PR_SENDER_NAME, &sname),
        (PR_SENDER_EMAIL, &semail),
        (PR_SENT_REPRESENTING_NAME, &sname),
        (PR_SENT_REPRESENTING_EMAIL, &semail),
        (PR_BODY, &body),
        (PR_INTERNET_MESSAGE_ID, &mid),
        (PR_TRANSPORT_MESSAGE_HEADERS, &th),
    ] {
        if let Some(s) = val {
            props.push(Prop {
                id,
                value: PropValue::Unicode(s),
            });
        }
    }
    for (id, k) in [
        (PR_CLIENT_SUBMIT_TIME, "submit_time"),
        (PR_MESSAGE_DELIVERY_TIME, "delivery_time"),
    ] {
        if let Some(t) = v[k].as_i64() {
            props.push(Prop {
                id,
                value: PropValue::Time(t),
            });
        }
    }
    let atts: Vec<(String, String, Vec<u8>, Option<i64>)> = v["attachments"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|a| {
            (
                a["name"].as_str().unwrap_or("attachment").to_string(),
                a["mime"]
                    .as_str()
                    .unwrap_or("application/octet-stream")
                    .to_string(),
                b64(a["data_b64"].as_str().unwrap_or("")),
                a["modified"].as_i64(),
            )
        })
        .collect();
    let att_props: Vec<Vec<Prop>> = atts
        .iter()
        .map(|(name, mime, data, modified)| {
            let mut p = vec![
                Prop {
                    id: PR_ATTACH_LONG_FILENAME,
                    value: PropValue::Unicode(name),
                },
                Prop {
                    id: PR_ATTACH_MIME_TAG,
                    value: PropValue::Unicode(mime),
                },
                Prop {
                    id: PR_ATTACH_DATA_BIN,
                    value: PropValue::Binary(data),
                },
            ];
            if let Some(t) = modified {
                p.push(Prop {
                    id: PR_LAST_MODIFICATION_TIME,
                    value: PropValue::Time(*t),
                });
            }
            p
        })
        .collect();
    let bytes = message(&props, &att_props).expect("compound file");
    std::fs::write(&out, bytes).expect("write .msg");
}
