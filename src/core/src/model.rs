//! Data model of the email analysis — FROZEN for v0.1.
//!
//! Field names here are the contract between the core, the worker process (they travel as JSON), the
//! per-message outputs (`headers.json`, `dkim.json`), the CLI flags and the GUI settings
//! ([`DomainOptions`] maps 1:1 onto them). Later work may add fields (with `#[serde(default)]`), never
//! rename or remove one.
//!
//! ```text
//! evidence file ──► ItemKind (eml | msg | mbox | other)
//!   eml / msg ──► one MessageAnalysis (worker process)
//!   mbox      ──► MboxMessageRef × n (split in the parent) ──► one MessageAnalysis per message (worker each)
//! MessageAnalysis = HeaderSummary (addresses, hops, dates, Authentication-Results)
//!                 + DkimReport (per signature: d=, s=, algorithm, result, key source; ARC)
//!                 + attachments (SHA-256, MIME dates) + BEC signals → Findings
//! ```
//!
//! No floats anywhere: the audit chain is canonical JSON with integers and strings only.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn key(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// One finding: a stable code (worded in i18n/*.json: title, shows, does_not_prove), a severity and named
/// string parameters. A finding is a signal for the examiner, never a verdict.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub params: BTreeMap<String, String>,
}

impl Finding {
    pub fn new(code: &str, severity: Severity) -> Finding {
        Finding {
            code: code.into(),
            severity,
            params: BTreeMap::new(),
        }
    }
    pub fn with(mut self, k: &str, v: impl Into<String>) -> Finding {
        self.params.insert(k.into(), v.into());
        self
    }
}

/// Every finding code this tool emits, with its severity (the i18n catalogues word each one).
pub const FINDING_CODES: &[(&str, Severity)] = &[
    ("DKIM_BODY_HASH_MISMATCH", Severity::High),
    // Medium, not high: with a matching body hash the failure can also come from a rotated or wrong key.
    ("DKIM_SIGNATURE_INVALID", Severity::Medium),
    ("DKIM_KEY_FROM_CURRENT_DNS", Severity::Medium),
    ("DKIM_DOMAIN_NOT_ALIGNED", Severity::Medium),
    ("ARC_CHAIN_INVALID", Severity::Medium),
    ("RECEIVED_TIME_NOT_MONOTONIC", Severity::Medium),
    ("DATE_AFTER_FIRST_HOP", Severity::Medium),
    ("MSG_TRANSPORT_HEADERS_MISSING", Severity::Medium),
    ("ATTACHMENT_DATE_AFTER_SENT", Severity::Medium),
    ("LOOKALIKE_DOMAIN", Severity::Medium),
    ("REPLY_TO_DIFFERS", Severity::Medium),
    ("DISPLAY_NAME_SPOOF", Severity::Medium),
    ("FILE_STRUCTURE_DAMAGED", Severity::Medium),
    ("PARSER_FAILED", Severity::Medium),
    ("DKIM_NOT_SIGNED", Severity::Low),
    ("DKIM_SIGNATURE_NOT_EVALUATED", Severity::Low),
    ("TIMEZONE_INCONSISTENT", Severity::Low),
    ("MESSAGE_ID_DOMAIN_MISMATCH", Severity::Low),
    ("DKIM_KEY_NOT_AVAILABLE", Severity::Info),
    ("PAYMENT_DETAILS_MENTIONED", Severity::Info),
    ("DKIM_SIGNATURE_VALID", Severity::Info),
    ("AUTH_RESULTS_RECORDED", Severity::Info),
];

/// Codes of the shared forensic pipeline (inventory of non-email files, read errors, duplicates, case folder),
/// with the severity `analyzer.rs` and `run.rs` give them. Together with [`FINDING_CODES`] this is every code
/// of the i18n catalogues; `docs/reports.md` lists both (tests/docs_catalogue.rs keeps it in step).
/// REGISTRY_PATH_CONTENT_CHANGED is emitted by intake tools only, never by this analysis tool.
pub const PIPELINE_FINDING_CODES: &[(&str, Severity)] = &[
    ("EVIDENCE_HASH_MISMATCH_WITH_CASE", Severity::High),
    ("EXECUTABLE_CONTENT", Severity::High),
    ("UNREADABLE", Severity::High),
    ("EVIDENCE_NOT_IN_CASE_REGISTRY", Severity::Medium),
    ("EXTENSION_MISMATCH", Severity::Medium),
    ("REGISTRY_PATH_CONTENT_CHANGED", Severity::Medium),
    ("DUPLICATE", Severity::Info),
    ("EMPTY_FILE", Severity::Info),
];

/// Severity of a known code (panics in debug builds on an unknown code, so a typo cannot ship).
pub fn severity_of(code: &str) -> Severity {
    match FINDING_CODES.iter().find(|(c, _)| *c == code) {
        Some((_, s)) => *s,
        None => {
            debug_assert!(false, "unknown finding code {code}");
            Severity::Medium
        }
    }
}

/// A finding of a known code with its catalogue severity.
pub fn finding(code: &str) -> Finding {
    Finding::new(code, severity_of(code))
}

/// What an evidence file is, from its signature and name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    /// RFC 5322 message (.eml, or a text file that starts with header fields)
    Eml,
    /// Outlook message (OLE / Compound File Binary, .msg)
    Msg,
    /// Mailbox of several RFC 5322 messages, each starting with a "From " line
    Mbox,
    /// Anything else: inventoried only (type from its signature), no email analysis
    #[default]
    Other,
}

impl ItemKind {
    pub fn name(&self) -> &'static str {
        match self {
            ItemKind::Eml => "eml",
            ItemKind::Msg => "msg",
            ItemKind::Mbox => "mbox",
            ItemKind::Other => "other",
        }
    }
}

/// One message inside an mbox file. `id` is stable for the same file content:
/// `<absolute path of the mbox>#<n>@<offset>` (n from 1, offset in bytes of the "From " line).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MboxMessageRef {
    pub n: u64,
    /// Byte offset of the "From " separator line in the mbox file.
    pub offset: u64,
    /// Byte offset of the first header line (after the separator line).
    pub message_offset: u64,
    /// Bytes of the stored message (separator line and the blank line before the next one excluded,
    /// escaping still in place).
    pub length: u64,
    /// The separator line itself, without line ending (capped at 200 characters).
    pub from_line: String,
    pub id: String,
    /// The mbox the message comes from (the registered evidence) and its digests from this run's hashing
    /// pass, so every derived message item cites its source: mbox hash + index + byte offset. Empty (and
    /// left out of the JSON) in `mbox_index.json`, which is written before the messages are hashed and names
    /// the mbox once at its top.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub container_path: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub container_hashes: BTreeMap<String, String>,
}

/// Which bytes of the evidence the worker analyses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MessageLocator {
    pub kind: ItemKind,
    /// For an mbox message: the message inside the mbox (bytes are un-escaped before parsing).
    pub mbox: Option<MboxMessageRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MailAddress {
    pub name: Option<String>,
    pub address: String,
    /// Lower-case domain part ("" when the address has none).
    pub domain: String,
}

/// One Received header. `position` 1 is the first hop (closest to the sender, the bottom-most header);
/// `header_index` 0 is the top-most header (added last, by the final receiving server).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Hop {
    pub position: u64,
    pub header_index: u64,
    pub from: Option<String>,
    pub by: Option<String>,
    pub with: Option<String>,
    pub id: Option<String>,
    pub for_addr: Option<String>,
    /// Text after the last ';' (the date the receiving server wrote).
    pub date_raw: Option<String>,
    /// That date in UTC, RFC 3339 ("2026-11-10T10:00:00Z"); None when it cannot be parsed.
    pub date_utc: Option<String>,
    /// Seconds since 1970-01-01 UTC.
    pub timestamp: Option<i64>,
    /// Zone offset written by the server, minutes east of UTC.
    pub tz_offset_min: Option<i64>,
    /// The header value, unfolded (capped at 998 characters).
    pub raw: String,
}

/// One Authentication-Results header: what the receiving server SAYS it checked. Recorded as stated
/// evidence; never re-interpreted as a verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuthResultsHeader {
    /// 0 = top-most Authentication-Results header.
    pub header_index: u64,
    pub authserv_id: String,
    /// method=result pairs as written ("dkim" → "pass", "spf" → "fail", …), in order.
    pub methods: Vec<(String, String)>,
    /// The header value, unfolded (capped at 998 characters).
    pub raw: String,
}

/// Outlook .msg properties read from the compound file (MAPI property streams).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MsgProperties {
    /// PR_TRANSPORT_MESSAGE_HEADERS (0x007D) present and not empty.
    pub transport_headers: bool,
    pub transport_headers_bytes: u64,
    pub subject: Option<String>,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub sent_representing_name: Option<String>,
    pub sent_representing_email: Option<String>,
    pub internet_message_id: Option<String>,
    /// PR_CLIENT_SUBMIT_TIME (0x0039), UTC RFC 3339.
    pub client_submit_time: Option<String>,
    /// PR_MESSAGE_DELIVERY_TIME (0x0E06), UTC RFC 3339.
    pub delivery_time: Option<String>,
    pub body_bytes: u64,
    pub attachment_count: u64,
    pub recipient_count: u64,
    /// Compound-file streams read (names), capped.
    pub streams: Vec<String>,
}

/// headers.json: everything read from the header section (and, for .msg, the MAPI properties).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HeaderSummary {
    pub kind: ItemKind,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub date_raw: Option<String>,
    pub date_utc: Option<String>,
    pub date_timestamp: Option<i64>,
    pub date_tz_offset_min: Option<i64>,
    pub from: Vec<MailAddress>,
    pub sender: Option<MailAddress>,
    pub reply_to: Vec<MailAddress>,
    pub return_path: Option<String>,
    /// To + Cc, capped (see `recipients_total`).
    pub recipients: Vec<MailAddress>,
    pub recipients_total: u64,
    /// Received hops, top-most header first, capped (see `hops_total`).
    pub hops: Vec<Hop>,
    pub hops_total: u64,
    pub auth_results: Vec<AuthResultsHeader>,
    pub header_count: u64,
    /// MIME structure problems reported by the parser ("unterminated", "no_blank_line", …).
    pub structure_problems: Vec<String>,
    pub mime_parts: u64,
    pub msg: Option<MsgProperties>,
}

/// One DKIM-Signature header and its offline verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DkimSignatureCheck {
    /// 1 = top-most DKIM-Signature header.
    pub index: u64,
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    /// "relaxed/relaxed", "simple/simple", …
    pub canonicalization: String,
    pub signed_headers: Vec<String>,
    pub identity: String,
    /// l= (0 = whole body signed)
    pub body_length: u64,
    /// t= (seconds since 1970, 0 = absent)
    pub signed_at: u64,
    /// x= (0 = absent)
    pub expires_at: u64,
    /// pass | body_hash_mismatch | signature_invalid | key_not_available | not_evaluated
    pub result: String,
    /// The verifier's reason when not "pass".
    pub reason: Option<String>,
    /// key_file | current_dns | none
    pub key_source: String,
    /// Line of the key file the key came from.
    pub key_line: Option<u64>,
    /// d= is the From domain or shares its organisational domain (relaxed alignment).
    pub aligned_with_from: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ArcCheck {
    /// Number of ARC-Seal headers.
    pub instances: u64,
    /// none (no ARC headers) | pass | invalid | key_not_available | not_evaluated
    pub result: String,
    pub reason: Option<String>,
}

/// dkim.json: the offline DKIM and ARC verification of one message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DkimReport {
    /// offline (keys only from the examiner's key file) | online (key file, then today's DNS)
    pub mode: String,
    pub key_file: Option<String>,
    pub key_file_sha256: Option<String>,
    pub keys_loaded: u64,
    /// Lines of the key file that could not be used (line number and reason), capped.
    pub key_file_problems: Vec<String>,
    /// False when DKIM was not attempted (e.g. .msg: the original MIME body is not stored).
    pub evaluated: bool,
    pub not_evaluated_reason: Option<String>,
    pub signatures: Vec<DkimSignatureCheck>,
    pub arc: ArcCheck,
}

/// One MIME attachment (or .msg attachment).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AttachmentInfo {
    /// 1-based, in MIME order.
    pub index: u64,
    pub file_name: Option<String>,
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: u64,
    /// SHA-256 of the decoded content.
    pub sha256: String,
    /// Content-Disposition creation-date / modification-date as written, and in UTC.
    pub creation_date_raw: Option<String>,
    pub creation_date_utc: Option<String>,
    pub modification_date_raw: Option<String>,
    pub modification_date_utc: Option<String>,
    /// Path of the extracted copy relative to the message folder, when extraction was requested.
    pub extracted: Option<String>,
}

/// Everything the analysis of one message produced (`Analysis::details["message"]`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MessageAnalysis {
    pub locator: MessageLocator,
    /// Bytes analysed (after mbox un-escaping) and their SHA-256.
    pub bytes: u64,
    pub sha256: String,
    pub headers: HeaderSummary,
    pub dkim: DkimReport,
    /// Capped list (see `attachments_total`).
    pub attachments: Vec<AttachmentInfo>,
    pub attachments_total: u64,
    /// Payment-related terms found in the subject and text (lower case, capped).
    pub payment_terms: Vec<String>,
}

/// One DKIM public key the examiner supplied (or, in online mode, fetched from today's DNS).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct KeyRecord {
    /// "selector._domainkey.domain", lower case, no trailing dot.
    pub name: String,
    /// The TXT value ("v=DKIM1; k=rsa; p=…"), quoted strings already joined.
    pub txt: String,
    /// key_file | current_dns
    pub source: String,
    /// Line in the key file (0 for DNS).
    pub line: u64,
}

/// How heavy analysis runs. A worker process (`<exe> worker …`) per message is the DEFAULT, so a crash, a
/// hostile MIME tree or a hang cannot stop a bulk run or corrupt the audit log.
///
/// - `Worker` (default): a worker process of the running front-end executable. The CLI and GUI register
///   themselves at start-up (`worker::register_frontend_executable`); a program that did not register (a
///   unit-test binary, a library user) cannot serve as a worker, so the run falls back to `InProcess` and
///   records that fallback in `analysis_configured`.
/// - `Subprocess { exe }`: a worker process of the given executable.
/// - `InProcess`: no isolation (explicit opt-in, for tests; parser panics are still caught).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    #[default]
    Worker,
    InProcess,
    Subprocess {
        exe: PathBuf,
    },
}

/// Domain options (FROZEN names; the CLI flags and GUI settings map 1:1 onto them).
/// Serialisable: the parent passes them to a worker process as JSON (`--opts`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainOptions {
    /// `--dkim-keys FILE`: DKIM public keys supplied by the examiner ("selector._domainkey.domain<TAB>TXT"
    /// lines, or BIND zone-file TXT records). None = no key: every signature is DKIM_KEY_NOT_AVAILABLE.
    pub dkim_keys: Option<PathBuf>,
    /// `--online`: keys missing from the key file are fetched from today's DNS (parent process only; every
    /// fetch is an audit entry and adds DKIM_KEY_FROM_CURRENT_DNS). Off by default.
    pub online_dns: bool,
    /// Keys fetched in online mode, handed to the worker by the parent (not a user option).
    pub fetched_keys: Vec<KeyRecord>,
    /// `--own-domain`: the organisation's own domains, for lookalike and display-name checks.
    pub own_domains: Vec<String>,
    /// `--extract-attachments`: write each attachment under `<message folder>/attachments/`. Off by default.
    pub extract_attachments: bool,
    /// Tolerated clock difference between servers, in seconds, before a date/hop order is a finding.
    pub clock_skew_s: u64,
    /// mbox flavour for un-escaping body lines: "mboxrd" (strip one '>' from ">…From " lines) or "mboxo"
    /// (strip it only from ">From " lines).
    pub mbox_variant: String,
    /// Messages larger than this are not parsed (PARSER_FAILED, reason too_large).
    pub max_message_bytes: u64,
    /// An mbox with more messages than this: the rest is not analysed (recorded on the container).
    pub max_mbox_messages: u64,
    pub worker_timeout_s: u64,
    pub worker_memory_mb: u64,
    /// Write item reports only for items with findings above info.
    pub item_reports_flagged_only: bool,
    pub isolation: Isolation,
}

impl Default for DomainOptions {
    fn default() -> Self {
        DomainOptions {
            dkim_keys: None,
            online_dns: false,
            fetched_keys: Vec::new(),
            own_domains: Vec::new(),
            extract_attachments: false,
            clock_skew_s: 300,
            mbox_variant: "mboxrd".into(),
            max_message_bytes: 200 * 1024 * 1024,
            max_mbox_messages: 50_000,
            worker_timeout_s: 120,
            worker_memory_mb: 1024,
            item_reports_flagged_only: false,
            isolation: Isolation::Worker,
        }
    }
}

/// Lists that grow with hostile input are capped in the per-message outputs (the totals are kept).
pub const MAX_HOPS: usize = 100;
pub const MAX_RECIPIENTS: usize = 50;
pub const MAX_ATTACHMENTS: usize = 200;
pub const MAX_SIGNATURES: usize = 20;
pub const MAX_AUTH_RESULTS: usize = 20;
pub const MAX_RAW_CHARS: usize = 998;
