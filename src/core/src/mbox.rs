//! mbox containers: splitting into messages (a streaming byte scan in the parent, no parsing) and reading
//! one message back with its "From " escaping undone.
//!
//! A message starts at a line beginning with `From ` that is the first line of the file or follows an empty
//! line. The stored message is everything after that separator line up to the next separator, minus the empty
//! line in front of it. Each message gets the stable id `<path>#<n>@<offset>`.
//!
//! Escaping: writers protect body lines that begin with "From " by prefixing `>`. mboxrd also prefixes lines
//! that already begin with `>…From `, so reading strips one `>` from every `^>+From ` line; mboxo strips it
//! only from `^>From ` (and cannot tell an escaped line from an original ">From " line — a limitation of the
//! format, not of the tool). The variant is `DomainOptions::mbox_variant` (default mboxrd).

#![forbid(unsafe_code)]

use crate::analyzer::{Analysis, AnalyzeCtx, OutputFile, TYPE_MBOX};
use crate::model::{MboxMessageRef, finding};
use serde_json::json;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const CHUNK: usize = 1 << 20;
const FROM_LINE_CAP: usize = 200;

/// Result of scanning an mbox file.
#[derive(Debug, Default)]
pub struct Scan {
    pub messages: Vec<MboxMessageRef>,
    /// Messages beyond `max` (counted, not listed).
    pub not_listed: u64,
    /// Bytes before the first separator (0 for a well-formed mbox).
    pub leading_bytes: u64,
    pub bytes: u64,
}

struct Scanner {
    /// (separator offset, offset after the separator line, from line, length of the blank line before it)
    seps: Vec<(u64, u64, String, u64)>,
    not_listed: u64,
    max: u64,
    /// Some(length incl. terminator) when the previous line was empty
    prev_blank_len: Option<u64>,
}

impl Scanner {
    fn line(&mut self, line_start: u64, line_end: u64, prefix: &[u8]) {
        let content: &[u8] = prefix.strip_suffix(b"\r").unwrap_or(prefix);
        let len = line_end - line_start;
        if content.starts_with(b"From ") && (line_start == 0 || self.prev_blank_len.is_some()) {
            if (self.seps.len() as u64) < self.max {
                let blank = if line_start == 0 {
                    0
                } else {
                    self.prev_blank_len.unwrap_or(0)
                };
                let fl = String::from_utf8_lossy(content).into_owned();
                self.seps.push((line_start, line_end, fl, blank));
            } else {
                self.not_listed += 1;
            }
        }
        // An empty line: LF or CR LF only (len counts the terminator).
        self.prev_blank_len = (content.is_empty() && (1..=2).contains(&len)).then_some(len);
    }
}

/// Finds the message boundaries in one streaming pass (constant memory, 1 MiB chunks).
pub fn scan<R: Read>(mut r: R, path_id: &str, max: u64) -> std::io::Result<Scan> {
    let mut sc = Scanner {
        seps: Vec::new(),
        not_listed: 0,
        max,
        prev_blank_len: None,
    };
    let mut pos: u64 = 0;
    let mut line_start: u64 = 0;
    let mut prefix: Vec<u8> = Vec::with_capacity(FROM_LINE_CAP);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        for &b in &buf[..n] {
            if b == b'\n' {
                sc.line(line_start, pos + 1, &prefix);
                prefix.clear();
                line_start = pos + 1;
            } else if prefix.len() < FROM_LINE_CAP {
                // Only the start of a line matters; a long line keeps a capped prefix.
                prefix.push(b);
            }
            pos += 1;
        }
    }
    if pos > line_start {
        sc.line(line_start, pos, &prefix);
    }
    let total = pos;
    let seps = &sc.seps;
    let mut messages = Vec::with_capacity(seps.len());
    for (i, (off, body_start, fl, _)) in seps.iter().enumerate() {
        let end = match seps.get(i + 1) {
            Some((next, _, _, blank)) => next.saturating_sub(*blank),
            None => total,
        };
        messages.push(MboxMessageRef {
            n: i as u64 + 1,
            offset: *off,
            message_offset: *body_start,
            length: end.saturating_sub(*body_start),
            from_line: fl.chars().take(FROM_LINE_CAP).collect(),
            id: format!("{}#{}@{}", path_id, i + 1, off),
        });
    }
    Ok(Scan {
        leading_bytes: messages.first().map(|m| m.offset).unwrap_or(total),
        messages,
        not_listed: sc.not_listed,
        bytes: total,
    })
}

/// Undoes the "From " escaping of one stored message.
pub fn unescape(stored: &[u8], variant: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(stored.len());
    for line in stored.split_inclusive(|&b| b == b'\n') {
        let gts = line.iter().take_while(|&&b| b == b'>').count();
        let escaped =
            gts > 0 && line[gts..].starts_with(b"From ") && (variant != "mboxo" || gts == 1);
        if escaped {
            out.extend_from_slice(&line[1..]);
        } else {
            out.extend_from_slice(line);
        }
    }
    out
}

/// Reads one message of the mbox at `path` (un-escaped). `max` caps the bytes read.
pub fn read_message(
    path: &Path,
    m: &MboxMessageRef,
    variant: &str,
    max: u64,
) -> Result<Vec<u8>, String> {
    if m.length > max {
        return Err(format!("too_large: {} bytes (limit {})", m.length, max));
    }
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    f.seek(SeekFrom::Start(m.message_offset))
        .map_err(|e| e.to_string())?;
    let mut stored = Vec::with_capacity(m.length as usize);
    f.take(m.length)
        .read_to_end(&mut stored)
        .map_err(|e| e.to_string())?;
    if (stored.len() as u64) < m.length {
        return Err(format!(
            "truncated: {} of {} bytes readable",
            stored.len(),
            m.length
        ));
    }
    Ok(unescape(&stored, variant))
}

/// The container analysis: list the messages, write `mbox_index.json`, flag a damaged structure.
pub fn analyze_container(ctx: &AnalyzeCtx) -> Analysis {
    let ext = Path::new(ctx.file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    let id = ctx.path.display().to_string();
    let scanned =
        std::fs::File::open(ctx.path).and_then(|f| scan(f, &id, ctx.opts.max_mbox_messages.max(1)));
    let mut a = Analysis {
        detected_type: Some(TYPE_MBOX.into()),
        extension: ext,
        ..Analysis::default()
    };
    let s = match scanned {
        Ok(s) => s,
        Err(e) => {
            a.findings.push(
                finding("FILE_STRUCTURE_DAMAGED")
                    .with("format", "mbox")
                    .with("problems", format!("read_error: {e}")),
            );
            a.details = json!({"kind": "mbox", "mbox": {"count": 0, "messages": [], "variant": ctx.opts.mbox_variant, "not_analysed": 0}});
            return a;
        }
    };
    let mut problems = Vec::new();
    if s.messages.is_empty() {
        problems.push("no_message_separator".to_string());
    } else if s.leading_bytes > 0 {
        problems.push(format!("{}_bytes_before_first_separator", s.leading_bytes));
    }
    if let Some(last) = s.messages.last()
        && last.length == 0
    {
        problems.push(format!("message_{}_empty", last.n));
    }
    if !problems.is_empty() {
        a.findings.push(
            finding("FILE_STRUCTURE_DAMAGED")
                .with("format", "mbox")
                .with("problems", problems.join(", ")),
        );
    }
    let index = json!({
        "schema": "rv-mailauth.mbox-index/1",
        "mbox": id, "bytes": s.bytes, "variant": ctx.opts.mbox_variant,
        "count": s.messages.len() as u64 + s.not_listed,
        "not_analysed": s.not_listed,
        "messages": s.messages,
    });
    if std::fs::write(
        ctx.item_dir.join("mbox_index.json"),
        crate::report::pretty(&index),
    )
    .is_ok()
    {
        a.outputs.push(OutputFile {
            rel_path: "mbox_index.json".into(),
            kind: "mbox_index".into(),
        });
    }
    a.details = json!({
        "kind": "mbox",
        "mbox": {"count": s.messages.len() as u64 + s.not_listed, "listed": s.messages.len(),
                 "not_analysed": s.not_listed, "variant": ctx.opts.mbox_variant,
                 "leading_bytes": s.leading_bytes, "problems": problems, "messages": s.messages},
    });
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOX: &[u8] = b"From a@example.org Tue Nov 10 10:00:00 2026\r\nFrom: a@example.org\r\n\r\nhello\r\n>From the start\r\n\r\nFrom b@example.org Tue Nov 10 11:00:00 2026\r\nFrom: b@example.org\r\n\r\nFrom inside is not a separator (no blank line before)? no: preceded by blank\r\n";

    #[test]
    fn splits_on_from_lines_after_blank_lines() {
        let s = scan(BOX, "box", 100).unwrap();
        assert_eq!(s.messages.len(), 3);
        let m1 = &s.messages[0];
        assert_eq!(m1.offset, 0);
        assert_eq!(m1.id, "box#1@0");
        let stored = &BOX[m1.message_offset as usize..(m1.message_offset + m1.length) as usize];
        assert_eq!(
            stored,
            b"From: a@example.org\r\n\r\nhello\r\n>From the start\r\n"
        );
        assert_eq!(
            unescape(stored, "mboxrd"),
            b"From: a@example.org\r\n\r\nhello\r\nFrom the start\r\n"
        );
        assert!(s.messages[1].from_line.starts_with("From b@example.org"));
        assert_eq!(s.leading_bytes, 0);
    }

    #[test]
    fn mboxo_and_mboxrd_unescaping() {
        let x = b">>From x\n>From y\n>Fromage\n";
        assert_eq!(unescape(x, "mboxrd"), b">From x\nFrom y\n>Fromage\n");
        assert_eq!(unescape(x, "mboxo"), b">>From x\nFrom y\n>Fromage\n");
    }

    #[test]
    fn caps_and_garbage() {
        let s = scan(BOX, "box", 1).unwrap();
        assert_eq!(s.messages.len(), 1);
        assert_eq!(s.not_listed, 2);
        let g = scan(&b"no separator here\nat all"[..], "g", 10).unwrap();
        assert!(g.messages.is_empty());
        assert_eq!(g.leading_bytes, 24);
        // A long line without newline does not buffer the whole line.
        let long = vec![b'x'; 3 * CHUNK];
        assert!(scan(&long[..], "l", 10).unwrap().messages.is_empty());
    }
}
