//! Domain entry point — where the email analysis plugs into the forensic pipeline.
//!
//! `run.rs` calls [`analyze_item`] once per readable evidence file (after hashing) and once per message of an
//! mbox (after the container was split). The routing:
//!
//! ```text
//! classify(name, first 4 KiB)
//!   Eml  ──► message analysis (worker process with Isolation::Subprocess)
//!   Msg  ──► message analysis of the Outlook compound file (worker)
//!   Mbox ──► container: split into MboxMessageRef (in process, a byte scan), mbox_index.json
//!            each message: message analysis of its bytes (worker per message)
//!   Other ──► reference inventory logic (`analyze`): type from the signature, extension mismatch …
//! ```
//!
//! The analysis never touches the audit log: it returns findings, `details` (JSON for the technical report
//! and the audit summary) and the files it wrote; the pipeline hashes and audits every one of them.

pub use crate::model::{
    DomainOptions, Finding, Isolation, ItemKind, MboxMessageRef, MessageAnalysis, Severity,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Also the payload a worker process prints on stdout (see `worker.rs`), hence Deserialize.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Analysis {
    pub detected_type: Option<String>,
    pub extension: Option<String>,
    pub findings: Vec<Finding>,
    /// Domain data for the technical report: `kind`, `message` (a [`MessageAnalysis`]), `mbox` (container),
    /// `worker`. Null if none.
    pub details: Value,
    /// Files the analysis wrote under the item folder; the pipeline hashes and audits every one.
    pub outputs: Vec<OutputFile>,
}

/// One file written by the analysis, relative to the item report folder (forward slashes).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct OutputFile {
    pub rel_path: String,
    /// headers | dkim | attachment | mbox_index | partial_output | unlisted_output
    pub kind: String,
}

/// Everything the domain analysis gets for one item. `item_dir` exists; write outputs only there.
pub struct AnalyzeCtx<'a> {
    pub path: &'a std::path::Path,
    pub file_name: &'a str,
    pub size: u64,
    /// First 4 KiB, already read during hashing.
    pub head: &'a [u8],
    pub item_dir: &'a std::path::Path,
    pub opts: &'a DomainOptions,
    /// Set for one message inside an mbox (the file at `path` is the mbox).
    pub message: Option<&'a MboxMessageRef>,
}

pub const TYPE_EML: &str = "Email message (RFC 5322)";
pub const TYPE_MSG: &str = "Outlook message (MSG, compound file)";
pub const TYPE_MBOX: &str = "Mailbox (mbox)";
pub const TYPE_MBOX_MESSAGE: &str = "Email message in an mbox (RFC 5322)";

const OLE_MAGIC: &[u8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

fn extension_of(file_name: &str) -> Option<String> {
    std::path::Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
}

/// Header field names that mark the start of an RFC 5322 message without a known extension.
const MAIL_HEADERS: &[&str] = &[
    "received",
    "return-path",
    "from",
    "date",
    "subject",
    "message-id",
    "dkim-signature",
    "mime-version",
    "delivered-to",
    "x-mailer",
    "to",
    "arc-seal",
    "authentication-results",
];

/// True when the first bytes look like a header section: the first line is `Name: value` and at least two
/// known mail header names appear among the first lines.
fn looks_like_headers(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&head[..head.len().min(4096)]);
    let mut known = 0;
    for line in text.lines().take(60) {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((name, _)) = line.split_once(':') else {
            break; // end of the header block (or a line cut at 4 KiB)
        };
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b':' && b != b' ');
        if !valid {
            return false;
        }
        if MAIL_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            known += 1;
        }
    }
    known >= 2
}

/// What the evidence file is (signature first, then the extension).
pub fn classify(file_name: &str, head: &[u8]) -> ItemKind {
    let ext = extension_of(file_name);
    let ext = ext.as_deref().unwrap_or("");
    if head.starts_with(OLE_MAGIC) {
        return if ext == "msg" {
            ItemKind::Msg
        } else {
            ItemKind::Other
        };
    }
    if head.starts_with(b"From ") {
        return ItemKind::Mbox;
    }
    match ext {
        "msg" => ItemKind::Msg,
        "mbox" | "mbx" => ItemKind::Mbox,
        "eml" => ItemKind::Eml,
        _ if looks_like_headers(head) => ItemKind::Eml,
        _ => ItemKind::Other,
    }
}

/// FROZEN entry point called by run.rs for every readable item and for every message of an mbox.
/// Emails go to the message analysis — in a worker process with [`Isolation::Subprocess`], so a crash,
/// hang or memory blow-up becomes a `PARSER_FAILED` finding instead of ending the run. An mbox container
/// is split in process (a byte scan, no parsing). Everything else keeps the reference inventory logic.
pub fn analyze_item(ctx: &AnalyzeCtx) -> Analysis {
    let kind = classify(ctx.file_name, ctx.head);
    if ctx.message.is_none() {
        match kind {
            ItemKind::Other => return analyze(ctx.file_name, ctx.size, ctx.head),
            ItemKind::Mbox => return crate::mbox::analyze_container(ctx),
            ItemKind::Eml | ItemKind::Msg => {}
        }
    }
    match &ctx.opts.isolation {
        Isolation::InProcess => crate::mail::analyze_message(ctx, kind),
        Isolation::Subprocess { exe } => crate::worker::analyze_in_worker(exe, ctx),
    }
}

/// The messages of an mbox container, as found by [`analyze_item`] (empty for other items).
pub fn mbox_messages(a: &Analysis) -> Vec<MboxMessageRef> {
    a.details
        .get("mbox")
        .and_then(|m| m.get("messages"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// The message analysis in `details` (None when the item is not a message or the worker failed).
pub fn message_of(a: &Analysis) -> Option<MessageAnalysis> {
    a.details
        .get("message")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// DNS names ("selector._domainkey.domain") of the DKIM signatures whose key was not available offline.
/// Online mode fetches exactly these in the parent, then repeats the analysis with them.
pub fn missing_dns_keys(a: &Analysis) -> Vec<String> {
    let mut names: Vec<String> = message_of(a)
        .map(|m| {
            m.dkim
                .signatures
                .iter()
                .filter(|s| s.key_source == "none" && s.result == "key_not_available")
                .filter(|s| !s.selector.is_empty() && !s.domain.is_empty())
                .map(|s| crate::dkim::key_name(&s.selector, &s.domain))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.dedup();
    names
}

/// The part of `Analysis::details` that `run.rs` writes into the `item_analyzed` audit entry: kind, the
/// message identity and DKIM results in brief, how the worker ended. Small and float-free, so the audit
/// chain stays canonical.
pub fn audit_summary(details: &Value) -> Value {
    if !details.is_object() {
        return Value::Null;
    }
    let mut m = serde_json::Map::new();
    if let Some(k) = details.get("kind") {
        m.insert("kind".into(), k.clone());
    }
    if let Some(w) = details.get("worker") {
        let mut w = w.clone();
        if let Some(o) = w.as_object_mut() {
            o.remove("stderr_tail");
        }
        m.insert("worker".into(), w);
    }
    if let Some(msg) = details.get("message") {
        m.insert(
            "message".into(),
            json!({
                "bytes": msg["bytes"], "sha256": msg["sha256"],
                "message_id": msg["headers"]["message_id"],
                "hops": msg["headers"]["hops_total"],
                "attachments": msg["attachments_total"],
                "dkim": msg["dkim"]["signatures"].as_array().map(|a| a.iter().map(|s| json!({
                    "d": s["domain"], "s": s["selector"], "a": s["algorithm"], "result": s["result"],
                    "key_source": s["key_source"]})).collect::<Vec<_>>()).unwrap_or_default(),
                "arc": msg["dkim"]["arc"]["result"],
            }),
        );
    }
    if let Some(mb) = details.get("mbox") {
        m.insert(
            "mbox".into(),
            json!({"messages": mb["count"], "variant": mb["variant"], "not_analysed": mb["not_analysed"]}),
        );
    }
    if m.is_empty() { Value::Null } else { m.into() }
}

struct Signature {
    name: &'static str,
    offset: usize,
    magic: &'static [u8],
    extensions: &'static [&'static str],
    executable: bool,
}

const SIGNATURES: &[Signature] = &[
    Signature {
        name: "PDF document",
        offset: 0,
        magic: b"%PDF-",
        extensions: &["pdf"],
        executable: false,
    },
    Signature {
        name: "PNG image",
        offset: 0,
        magic: b"\x89PNG\r\n\x1a\n",
        extensions: &["png"],
        executable: false,
    },
    Signature {
        name: "JPEG image",
        offset: 0,
        magic: b"\xFF\xD8\xFF",
        extensions: &["jpg", "jpeg", "jpe", "jfif"],
        executable: false,
    },
    Signature {
        name: "GIF image",
        offset: 0,
        magic: b"GIF8",
        extensions: &["gif"],
        executable: false,
    },
    Signature {
        name: "ZIP / Office Open XML",
        offset: 0,
        magic: b"PK\x03\x04",
        extensions: &[
            "zip", "docx", "xlsx", "pptx", "odt", "ods", "jar", "apk", "epub",
        ],
        executable: false,
    },
    Signature {
        name: "OLE2 (legacy Office, MSG)",
        offset: 0,
        magic: OLE_MAGIC,
        extensions: &["doc", "xls", "ppt", "msg"],
        executable: false,
    },
    Signature {
        name: "Windows executable (PE)",
        offset: 0,
        magic: b"MZ",
        extensions: &["exe", "dll", "sys", "scr", "com", "efi"],
        executable: true,
    },
    Signature {
        name: "Linux executable (ELF)",
        offset: 0,
        magic: b"\x7fELF",
        extensions: &["so", "bin", "elf", "o"],
        executable: true,
    },
    Signature {
        name: "SQLite database",
        offset: 0,
        magic: b"SQLite format 3\0",
        extensions: &["db", "sqlite", "sqlite3"],
        executable: false,
    },
    Signature {
        name: "7-Zip archive",
        offset: 0,
        magic: b"7z\xBC\xAF\x27\x1C",
        extensions: &["7z"],
        executable: false,
    },
    Signature {
        name: "RAR archive",
        offset: 0,
        magic: b"Rar!\x1A\x07",
        extensions: &["rar"],
        executable: false,
    },
    Signature {
        name: "GZIP archive",
        offset: 0,
        magic: b"\x1F\x8B",
        extensions: &["gz", "tgz"],
        executable: false,
    },
    Signature {
        name: "Windows event log (EVTX)",
        offset: 0,
        magic: b"ElfFile\0",
        extensions: &["evtx"],
        executable: false,
    },
    Signature {
        name: "Windows registry hive",
        offset: 0,
        magic: b"regf",
        extensions: &["dat", "hve"],
        executable: false,
    },
    Signature {
        name: "MP4 / QuickTime video",
        offset: 4,
        magic: b"ftyp",
        extensions: &["mp4", "m4v", "mov", "m4a", "3gp", "heic"],
        executable: false,
    },
];

fn detect(head: &[u8]) -> Option<&'static Signature> {
    SIGNATURES.iter().find(|s| {
        head.len() >= s.offset + s.magic.len()
            && &head[s.offset..s.offset + s.magic.len()] == s.magic
    })
}

fn known_extension(ext: &str) -> bool {
    SIGNATURES.iter().any(|s| s.extensions.contains(&ext))
}

/// Reference inventory analysis of a non-email item, from its name, size and first bytes (no second read).
pub fn analyze(file_name: &str, size: u64, head: &[u8]) -> Analysis {
    let extension = extension_of(file_name);
    let sig = detect(head);
    let mut findings = Vec::new();
    if size == 0 {
        findings.push(Finding::new("EMPTY_FILE", Severity::Info));
    }
    if let (Some(s), Some(ext)) = (sig, extension.as_deref())
        && !s.extensions.contains(&ext)
    {
        if s.executable {
            findings.push(
                Finding::new("EXECUTABLE_CONTENT", Severity::High)
                    .with("detected", s.name)
                    .with("extension", ext),
            );
        } else if known_extension(ext)
            || matches!(
                ext,
                "txt" | "csv" | "log" | "xml" | "json" | "html" | "eml" | "mbox"
            )
        {
            findings.push(
                Finding::new("EXTENSION_MISMATCH", Severity::Medium)
                    .with("detected", s.name)
                    .with("extension", ext),
            );
        }
    }
    Analysis {
        detected_type: sig.map(|s| s.name.to_string()),
        extension,
        findings,
        details: json!({"kind": "other"}),
        outputs: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_types_and_mismatches() {
        let a = analyze("report.pdf", 10, b"%PDF-1.7\n");
        assert_eq!(a.detected_type.as_deref(), Some("PDF document"));
        assert!(a.findings.is_empty());

        let b = analyze("holiday.jpg", 10, b"%PDF-1.7\n");
        assert_eq!(b.findings[0].code, "EXTENSION_MISMATCH");

        let c = analyze("invoice.pdf", 10, b"MZ\x90\x00");
        assert_eq!(c.findings[0].code, "EXECUTABLE_CONTENT");
        assert_eq!(c.findings[0].severity, Severity::High);

        let d = analyze("empty.txt", 0, b"");
        assert_eq!(d.findings[0].code, "EMPTY_FILE");

        let e = analyze("notes.md", 10, b"hello");
        assert!(e.detected_type.is_none() && e.findings.is_empty());

        let f = analyze("clip.mov", 12, b"\0\0\0\x18ftypqt  ");
        assert!(f.findings.is_empty());
    }

    #[test]
    fn classifies_mail_containers() {
        assert_eq!(classify("a.eml", b"anything"), ItemKind::Eml);
        assert_eq!(
            classify(
                "export.txt",
                b"Received: from x\r\n by y; Tue, 10 Nov 2026 10:00:00 +0000\r\nFrom: a@example.org\r\n\r\nhi"
            ),
            ItemKind::Eml
        );
        assert_eq!(
            classify("notes.txt", b"Hello: world\nplain text"),
            ItemKind::Other
        );
        assert_eq!(
            classify("box", b"From a@example.org Tue Nov 10 10:00:00 2026\n"),
            ItemKind::Mbox
        );
        assert_eq!(classify("inbox.mbox", b"garbage"), ItemKind::Mbox);
        assert_eq!(classify("m.msg", OLE_MAGIC), ItemKind::Msg);
        assert_eq!(classify("legacy.doc", OLE_MAGIC), ItemKind::Other);
        assert_eq!(classify("broken.msg", b"not ole"), ItemKind::Msg);
    }

    #[test]
    fn every_code_has_a_severity_and_wording() {
        for lang in ["en", "es", "fr"] {
            let c = crate::i18n::catalog(lang);
            for (code, _) in crate::model::FINDING_CODES {
                let (t, s, d) = c.finding(code, &Default::default());
                assert!(
                    !t.is_empty() && !s.is_empty() && !d.is_empty() && t != *code,
                    "{lang}: {code} not worded"
                );
                for w in ["proves", "prueba que", "prouve que", "demuestra que"] {
                    assert!(
                        !s.to_lowercase().contains(w),
                        "{lang}: {code} 'shows' claims proof"
                    );
                }
            }
        }
    }
}
