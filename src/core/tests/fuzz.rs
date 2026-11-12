//! Fuzz-style robustness of the parser path (stable-toolchain fallback for a cargo-fuzz target): thousands of
//! deterministic mutations of the sample evidence go through the message analysis (MIME, .msg compound file,
//! DKIM/ARC verification with the sample keys, BEC checks) and the mbox split. No mutation may panic, and none
//! may take long (a hang would stop a bulk run that has no worker isolation).
//!
//! RV_FUZZ_ITERATIONS overrides the number of mutations per sample (default 400 → 6 400 cases).

use rv_mailauth_core::mail::analyze_bytes;
use rv_mailauth_core::model::{DomainOptions, ItemKind, MessageLocator};
use std::path::Path;
use std::time::{Duration, Instant};

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const SPECIAL: &[u8] = b"\r\n:;=<>\"'()[]@.\\\t \0\xff\xfe=?-_/+";

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut b = input.to_vec();
    for _ in 0..=rng.below(4) {
        let len = b.len().max(1);
        match rng.below(8) {
            0 => {
                // flip a few bits
                for _ in 0..=rng.below(8) {
                    let i = rng.below(len);
                    if let Some(x) = b.get_mut(i) {
                        *x ^= 1 << rng.below(8);
                    }
                }
            }
            1 => b.truncate(rng.below(len)),
            2 => {
                let i = rng.below(len);
                let c = SPECIAL[rng.below(SPECIAL.len())];
                b.insert(i.min(b.len()), c);
            }
            3 => {
                // duplicate a slice (repeated headers, boundaries, MIME parts)
                let s = rng.below(len);
                let e = (s + rng.below(512)).min(b.len());
                let chunk = b[s.min(b.len())..e].to_vec();
                let at = rng.below(b.len().max(1)).min(b.len());
                for _ in 0..=rng.below(3) {
                    b.splice(at..at, chunk.iter().copied());
                }
            }
            4 => {
                // remove a slice
                let s = rng.below(len).min(b.len());
                let e = (s + rng.below(256)).min(b.len());
                b.drain(s..e);
            }
            5 => {
                let i = rng.below(len);
                if let Some(x) = b.get_mut(i) {
                    *x = SPECIAL[rng.below(SPECIAL.len())];
                }
            }
            6 => {
                // random bytes overwrite (compound-file sectors, base64, DKIM tags)
                let i = rng.below(len);
                for k in 0..rng.below(64) {
                    if let Some(x) = b.get_mut(i + k) {
                        *x = rng.next() as u8;
                    }
                }
            }
            _ => {
                // a hostile header line on top
                let lines: &[&[u8]] = &[
                    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=s2026; l=99999999; h=from; bh=; b=\r\n",
                    b"ARC-Seal: i=50; cv=pass; d=example.org; s=s2026; b=AA==\r\n",
                    b"Content-Type: multipart/mixed; boundary=\"\"\r\n",
                    b"Received: from a by b; Mon, 99 Foo 9999 99:99:99 +9999\r\n",
                    b"From: \"=?utf-8?B?////?=\" <@@@>\r\n",
                ];
                let l = lines[rng.below(lines.len())];
                b.splice(0..0, l.iter().copied());
            }
        }
    }
    b
}

#[test]
fn mutated_samples_never_panic_or_hang() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (keys, _, _) =
        rv_mailauth_core::dkim::load_key_file(&root.join("examples/sample/dkim-keys.txt")).unwrap();
    let opts = DomainOptions {
        own_domains: vec!["acme.example".into()],
        ..DomainOptions::default()
    };
    let per_sample: usize = std::env::var("RV_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    let mut samples: Vec<_> = std::fs::read_dir(root.join("examples/sample/evidence"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    samples.sort();
    let mut rng = Rng(0x5EED_2026_1111_0001);
    let mut cases = 0usize;
    let mut slowest = Duration::ZERO;
    let started = Instant::now();
    for p in &samples {
        let original = std::fs::read(p).unwrap();
        let is_msg = p.extension().is_some_and(|e| e == "msg");
        let is_mbox = p.extension().is_some_and(|e| e == "mbox");
        for _ in 0..per_sample {
            let data = mutate(&mut rng, &original);
            let t = Instant::now();
            if is_mbox {
                let s = rv_mailauth_core::mbox::scan(&data[..], "fuzz", 1000).unwrap();
                for m in s.messages.iter().take(20) {
                    let start = (m.message_offset as usize).min(data.len());
                    let end = (start + m.length as usize).min(data.len());
                    let msg = rv_mailauth_core::mbox::unescape(&data[start..end], "mboxrd");
                    analyze_bytes(&msg, ItemKind::Eml, MessageLocator::default(), &keys, &opts);
                }
            } else {
                let kind = if is_msg { ItemKind::Msg } else { ItemKind::Eml };
                analyze_bytes(&data, kind, MessageLocator::default(), &keys, &opts);
                // The other parser on the same bytes too: classification can be fooled by a renamed file.
                let other = if is_msg { ItemKind::Eml } else { ItemKind::Msg };
                analyze_bytes(&data, other, MessageLocator::default(), &keys, &opts);
            }
            let el = t.elapsed();
            slowest = slowest.max(el);
            assert!(
                el < Duration::from_secs(20),
                "{}: one mutation took {:?} (possible hang)",
                p.display(),
                el
            );
            cases += 1;
        }
    }
    eprintln!(
        "fuzz: {} mutations of {} samples in {:?}, slowest case {:?}",
        cases,
        samples.len(),
        started.elapsed(),
        slowest
    );
    assert!(cases >= samples.len() * per_sample);
}

#[test]
fn pathological_inputs() {
    let opts = DomainOptions::default();
    let deep: Vec<u8> = (0..2000)
        .flat_map(|i| {
            format!("Content-Type: multipart/mixed; boundary=\"b{i}\"\r\n\r\n--b{i}\r\n")
                .into_bytes()
        })
        .collect();
    let many_hops: Vec<u8> = (0..5000)
        .flat_map(|i| {
            format!("Received: from h{i} by h{i}; Tue, 10 Nov 2026 10:00:00 +0000\r\n").into_bytes()
        })
        .chain(b"From: a@example.org\r\n\r\nx".iter().copied())
        .collect();
    let long_line = vec![b'A'; 4 << 20];
    for input in [
        &deep[..],
        &many_hops[..],
        &long_line[..],
        b"",
        b"\r\n\r\n",
        b"From:",
    ] {
        let t = Instant::now();
        let o = analyze_bytes(input, ItemKind::Eml, MessageLocator::default(), &[], &opts);
        assert!(t.elapsed() < Duration::from_secs(20));
        assert!(o.analysis.headers.hops.len() <= rv_mailauth_core::model::MAX_HOPS);
        let _ = analyze_bytes(input, ItemKind::Msg, MessageLocator::default(), &[], &opts);
    }
}
