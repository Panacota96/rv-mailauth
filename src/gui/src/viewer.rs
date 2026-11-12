//! The finished run as the window shows it, read back ONLY from the run's audited outputs:
//!
//! ```text
//! logs/<RUN>/audit.jsonl (chain verified) ──► item_analyzed   → results table (status, findings)
//!                                         ├─► message_started → mbox message n @ offset
//!                                         └─► output_written  → file + digests
//! reports/<RUN>/items/<item>/headers.json, dkim.json ──► digest == audit digest? ──► MessageView
//!                                                                 └─ no ──► refused (not shown)
//! ```
//!
//! No drawing code here: everything is unit-tested headless.

use rv_mailauth_core::model::{
    AttachmentInfo, DkimReport, Finding, HeaderSummary, MailAddress, Severity,
};
use rv_mailauth_core::{HashAlgo, audit, hash, psl};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// A delay between two hops above this is highlighted as a gap (one hour).
pub const GAP_S: i64 = 3_600;

/// A file the analysis wrote, as the audit log records it (`output_written`).
#[derive(Clone, Debug, PartialEq)]
pub struct AuditedFile {
    /// Relative to the run's report folder ("items/00003-x.eml/headers.json").
    pub file: String,
    pub kind: String,
    /// algorithm name -> hex digest
    pub hashes: BTreeMap<String, String>,
}

/// One row of the results table: an evidence file, or one message of an mbox (`message` = Some(n)).
#[derive(Clone, Debug, PartialEq)]
pub struct ItemRow {
    pub index: u64,
    pub message: Option<u64>,
    /// Byte offset of the message's "From " line in its mbox.
    pub offset: Option<u64>,
    /// The audit entries' `item` (path, or `<mbox path>#n@offset`).
    pub item: String,
    pub name: String,
    pub detected_type: String,
    /// ok | attention | problem
    pub status: String,
    pub findings: Vec<Finding>,
    pub outputs: Vec<AuditedFile>,
}

impl ItemRow {
    /// Findings per severity: [high, medium, low, info].
    pub fn counts(&self) -> [usize; 4] {
        let n = |s: Severity| self.findings.iter().filter(|f| f.severity == s).count();
        [
            n(Severity::High),
            n(Severity::Medium),
            n(Severity::Low),
            n(Severity::Info),
        ]
    }

    pub fn output(&self, kind: &str) -> Option<&AuditedFile> {
        self.outputs.iter().find(|o| o.kind == kind)
    }

    /// A message with its headers.json and dkim.json can be opened in the viewer.
    pub fn viewable(&self) -> bool {
        self.output("headers").is_some() && self.output("dkim").is_some()
    }

    /// "12" for a file, "12.3" for the third message of mbox item 12.
    pub fn label(&self) -> String {
        match self.message {
            Some(n) => format!("{}.{}", self.index, n),
            None => self.index.to_string(),
        }
    }
}

/// The run read back from its audit log.
#[derive(Clone, Debug, PartialEq)]
pub struct RunView {
    pub run_id: String,
    pub report_dir: PathBuf,
    pub log_dir: PathBuf,
    /// Clock skew the run used (analysis_configured), for the hop timeline.
    pub clock_skew_s: u64,
    /// Files first, each mbox followed by its messages.
    pub rows: Vec<ItemRow>,
}

fn file_name(item: &str) -> String {
    Path::new(item)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| item.to_string())
}

impl RunView {
    /// Reads `<log_dir>/audit.jsonl` (refused unless its hash chain verifies) into the results table.
    pub fn load(report_dir: &Path, log_dir: &Path) -> Result<RunView, String> {
        let audit_path = log_dir.join("audit.jsonl");
        audit::verify(&audit_path)
            .map_err(|p| format!("{} does not verify: {}", audit_path.display(), p.join("; ")))?;
        let text = std::fs::read_to_string(&audit_path)
            .map_err(|e| format!("cannot read {}: {}", audit_path.display(), e))?;
        let mut run_id = String::new();
        let mut clock_skew_s = rv_mailauth_core::model::DomainOptions::default().clock_skew_s;
        let mut offsets: BTreeMap<String, u64> = BTreeMap::new();
        let mut outputs: BTreeMap<String, Vec<AuditedFile>> = BTreeMap::new();
        let mut rows = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let e: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
            if run_id.is_empty() {
                run_id = e["run_id"].as_str().unwrap_or_default().to_string();
            }
            let item = e["item"].as_str().unwrap_or_default().to_string();
            let d = &e["details"];
            match e["action"].as_str().unwrap_or_default() {
                "analysis_configured" => {
                    if let Some(s) = d["clock_skew_s"].as_u64() {
                        clock_skew_s = s;
                    }
                }
                "message_started" => {
                    if let Some(o) = d["offset"].as_u64() {
                        offsets.insert(item, o);
                    }
                }
                "output_written" => outputs.entry(item).or_default().push(AuditedFile {
                    file: d["file"].as_str().unwrap_or_default().to_string(),
                    kind: d["kind"].as_str().unwrap_or_default().to_string(),
                    hashes: serde_json::from_value(d["hashes"].clone()).unwrap_or_default(),
                }),
                "item_analyzed" => {
                    let message = d["message"].as_u64();
                    rows.push(ItemRow {
                        index: d["index"].as_u64().unwrap_or(0),
                        message,
                        offset: None,
                        name: file_name(&item),
                        item,
                        detected_type: d["detected_type"].as_str().unwrap_or("-").to_string(),
                        status: d["status"].as_str().unwrap_or("ok").to_string(),
                        findings: serde_json::from_value(d["findings"].clone()).unwrap_or_default(),
                        outputs: vec![],
                    })
                }
                _ => {}
            }
        }
        for r in &mut rows {
            r.outputs = outputs.remove(&r.item).unwrap_or_default();
            r.offset = offsets.get(&r.item).copied();
            if let Some(n) = r.message {
                // "<mbox name> #n" (the item id "<mbox>#n@offset" names the bytes, the offset is shown apart).
                let base = r.item.rsplit_once('#').map_or(r.item.as_str(), |(b, _)| b);
                r.name = format!("{} #{}", file_name(base), n);
            }
        }
        rows.sort_by_key(|r| (r.index, r.message.unwrap_or(0)));
        Ok(RunView {
            run_id,
            report_dir: report_dir.to_path_buf(),
            log_dir: log_dir.to_path_buf(),
            clock_skew_s,
            rows,
        })
    }

    /// Reads one audited output and checks it against EVERY digest the audit log recorded for it. Refused when
    /// the path leaves the report folder, the file is missing, no digest is recorded or one does not match.
    pub fn read_audited(&self, f: &AuditedFile) -> Result<Vec<u8>, String> {
        let rel = Path::new(&f.file);
        if f.file.is_empty() || rel.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(format!("{}: not a path inside the report folder", f.file));
        }
        let bytes = std::fs::read(self.report_dir.join(rel))
            .map_err(|e| format!("{}: cannot read ({})", f.file, e))?;
        let mut checked = 0;
        for (algo, want) in &f.hashes {
            let Some(a) = HashAlgo::parse(algo) else {
                continue;
            };
            if !hash::hash_bytes(&bytes, a).eq_ignore_ascii_case(want) {
                return Err(format!(
                    "{}: {} does not match the digest recorded in the audit log (changed after the run)",
                    f.file,
                    a.name()
                ));
            }
            checked += 1;
        }
        if checked == 0 {
            return Err(format!("{}: no digest recorded in the audit log", f.file));
        }
        Ok(bytes)
    }
}

/// One Received hop in the timeline (first hop = closest to the sender).
#[derive(Clone, Debug, PartialEq)]
pub struct HopView {
    pub position: u64,
    pub from: String,
    pub by: String,
    pub with: String,
    pub date_utc: Option<String>,
    pub date_raw: Option<String>,
    pub tz_offset_min: Option<i64>,
    /// Seconds since the previous dated hop.
    pub delta_s: Option<i64>,
    /// Dated earlier than the previous dated hop by more than the run's clock skew.
    pub out_of_order: bool,
    /// More than [`GAP_S`] after the previous dated hop.
    pub gap: bool,
    /// No date could be read.
    pub undated: bool,
}

/// One address line (From / Sender / Reply-To / Return-Path).
#[derive(Clone, Debug, PartialEq)]
pub struct AddrRow {
    /// ui key of the role: addr_from | addr_sender | addr_reply_to | addr_return_path
    pub role: &'static str,
    pub value: String,
    pub domain: String,
    /// Its organisational domain differs from the From address's.
    pub mismatch: bool,
}

/// The message open in the viewer: built only from digest-checked headers.json and dkim.json.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageView {
    pub row: usize,
    pub title: String,
    pub headers: HeaderSummary,
    pub dkim: DkimReport,
    pub attachments: Vec<AttachmentInfo>,
    pub attachments_total: u64,
    pub message_bytes: u64,
    pub message_sha256: String,
    pub hops: Vec<HopView>,
    pub addresses: Vec<AddrRow>,
    pub findings: Vec<Finding>,
    /// (file, sha256) of the outputs shown, as checked against the audit log.
    pub files: Vec<(String, String)>,
}

fn addr_text(a: &MailAddress) -> String {
    match &a.name {
        Some(n) if !n.is_empty() => format!("{} <{}>", n, a.address),
        _ => a.address.clone(),
    }
}

fn domain_of(address: &str) -> String {
    address
        .trim()
        .trim_matches(['<', '>'])
        .rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('>').to_lowercase())
        .unwrap_or_default()
}

/// The Received hops in sending order with their delays, out-of-order and gap marks.
pub fn hop_timeline(h: &HeaderSummary, clock_skew_s: u64) -> Vec<HopView> {
    let mut hops: Vec<_> = h.hops.iter().collect();
    hops.sort_by_key(|x| x.position);
    let mut prev: Option<i64> = None;
    hops.into_iter()
        .map(|x| {
            let delta = match (prev, x.timestamp) {
                (Some(p), Some(t)) => Some(t - p),
                _ => None,
            };
            if x.timestamp.is_some() {
                prev = x.timestamp;
            }
            HopView {
                position: x.position,
                from: x.from.clone().unwrap_or_else(|| "-".into()),
                by: x.by.clone().unwrap_or_else(|| "-".into()),
                with: x.with.clone().unwrap_or_default(),
                date_utc: x.date_utc.clone(),
                date_raw: x.date_raw.clone(),
                tz_offset_min: x.tz_offset_min,
                delta_s: delta,
                out_of_order: delta.is_some_and(|d| d < -(clock_skew_s as i64)),
                gap: delta.is_some_and(|d| d > GAP_S),
                undated: x.timestamp.is_none(),
            }
        })
        .collect()
}

/// From, Sender, Reply-To and Return-Path, each compared with the From domain (organisational domain).
pub fn address_rows(h: &HeaderSummary) -> Vec<AddrRow> {
    let from_org = h
        .from
        .first()
        .map(|a| psl::org_domain(&a.domain))
        .unwrap_or_default();
    let row = |role, value: String, domain: String| {
        let mismatch =
            !from_org.is_empty() && !domain.is_empty() && psl::org_domain(&domain) != from_org;
        AddrRow {
            role,
            value,
            domain,
            mismatch,
        }
    };
    let mut out: Vec<AddrRow> = h
        .from
        .iter()
        .map(|a| row("addr_from", addr_text(a), a.domain.clone()))
        .collect();
    if let Some(s) = &h.sender {
        out.push(row("addr_sender", addr_text(s), s.domain.clone()));
    }
    for a in &h.reply_to {
        out.push(row("addr_reply_to", addr_text(a), a.domain.clone()));
    }
    if let Some(rp) = &h.return_path {
        out.push(row("addr_return_path", rp.clone(), domain_of(rp)));
    }
    out
}

impl MessageView {
    /// Opens row `row` of `run`: headers.json and dkim.json are read and checked against the audit log's
    /// digests first; any mismatch refuses the whole message.
    pub fn open(run: &RunView, row: usize) -> Result<MessageView, String> {
        let r = run
            .rows
            .get(row)
            .ok_or_else(|| format!("no item at row {row}"))?;
        let (Some(hf), Some(df)) = (r.output("headers"), r.output("dkim")) else {
            return Err(format!(
                "{}: no headers.json / dkim.json in the audit log",
                r.name
            ));
        };
        let hb = run.read_audited(hf)?;
        let db = run.read_audited(df)?;
        let hv: Value = serde_json::from_slice(&hb).map_err(|e| format!("{}: {}", hf.file, e))?;
        let dv: Value = serde_json::from_slice(&db).map_err(|e| format!("{}: {}", df.file, e))?;
        let headers: HeaderSummary = serde_json::from_value(hv["headers"].clone())
            .map_err(|e| format!("{}: {}", hf.file, e))?;
        let dkim: DkimReport = serde_json::from_value(dv["dkim"].clone())
            .map_err(|e| format!("{}: {}", df.file, e))?;
        let attachments: Vec<AttachmentInfo> =
            serde_json::from_value(hv["attachments"].clone()).unwrap_or_default();
        let sha =
            |f: &AuditedFile, b: &[u8]| (f.file.clone(), hash::hash_bytes(b, HashAlgo::Sha256));
        Ok(MessageView {
            row,
            title: match r.offset {
                Some(o) => format!("#{}  {}  @{}", r.label(), r.name, o),
                None => format!("#{}  {}", r.label(), r.name),
            },
            hops: hop_timeline(&headers, run.clock_skew_s),
            addresses: address_rows(&headers),
            attachments_total: hv["attachments_total"]
                .as_u64()
                .unwrap_or(attachments.len() as u64),
            attachments,
            message_bytes: hv["bytes"].as_u64().unwrap_or(0),
            message_sha256: hv["sha256"].as_str().unwrap_or_default().to_string(),
            findings: r.findings.clone(),
            files: vec![sha(hf, &hb), sha(df, &db)],
            headers,
            dkim,
        })
    }

    /// Header table rows (label key, value): identity, dates, counts, structure and what servers stated.
    pub fn header_rows(&self) -> Vec<(String, String)> {
        let h = &self.headers;
        let o = |v: &Option<String>| v.clone().unwrap_or_else(|| "\u{2014}".into());
        let mut rows = vec![
            ("hdr_message_id".to_string(), o(&h.message_id)),
            ("hdr_subject".to_string(), o(&h.subject)),
            ("hdr_date".to_string(), o(&h.date_raw)),
            ("hdr_date_utc".to_string(), o(&h.date_utc)),
            (
                "hdr_recipients".to_string(),
                format!(
                    "{}{}",
                    h.recipients
                        .iter()
                        .map(addr_text)
                        .collect::<Vec<_>>()
                        .join(", "),
                    if h.recipients_total > h.recipients.len() as u64 {
                        format!(" (+{})", h.recipients_total - h.recipients.len() as u64)
                    } else {
                        String::new()
                    }
                ),
            ),
            (
                "hdr_counts".to_string(),
                format!(
                    "{} headers \u{00B7} {} MIME parts \u{00B7} {} hops",
                    h.header_count, h.mime_parts, h.hops_total
                ),
            ),
            (
                "hdr_message".to_string(),
                format!(
                    "{} B \u{00B7} SHA-256 {}",
                    self.message_bytes, self.message_sha256
                ),
            ),
        ];
        if !h.structure_problems.is_empty() {
            rows.push(("hdr_structure".to_string(), h.structure_problems.join(", ")));
        }
        for a in &h.auth_results {
            rows.push((
                "hdr_auth_results".to_string(),
                format!(
                    "{}: {}",
                    a.authserv_id,
                    a.methods
                        .iter()
                        .map(|(m, r)| format!("{m}={r}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        if let Some(m) = &h.msg {
            rows.push((
                "hdr_msg_transport".to_string(),
                format!("{} ({} B)", m.transport_headers, m.transport_headers_bytes),
            ));
            if let Some(t) = &m.client_submit_time {
                rows.push(("hdr_msg_submit".to_string(), t.clone()));
            }
        }
        rows
    }

    /// Seconds between the Date header and the first dated hop (positive = hop after Date).
    pub fn date_to_first_hop_s(&self) -> Option<i64> {
        let first = self.hops.iter().find_map(|h| {
            self.headers
                .hops
                .iter()
                .find(|x| x.position == h.position)
                .and_then(|x| x.timestamp)
        })?;
        Some(first - self.headers.date_timestamp?)
    }
}

/// "+3 d 04 h" / "-2 h 05 min" / "+12 s"; "—" when unknown.
pub fn delta_text(secs: Option<i64>) -> String {
    let Some(s) = secs else {
        return "\u{2014}".into();
    };
    let a = s.unsigned_abs();
    let body = match a {
        0..=59 => format!("{} s", a),
        60..=3599 => format!("{} min {:02} s", a / 60, a % 60),
        3600..=86_399 => format!("{} h {:02} min", a / 3600, (a % 3600) / 60),
        _ => format!("{} d {:02} h", a / 86_400, (a % 86_400) / 3600),
    };
    format!("{}{}", if s < 0 { "-" } else { "+" }, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_mailauth_core::model::Hop;

    fn hop(position: u64, ts: Option<i64>) -> Hop {
        Hop {
            position,
            header_index: 10 - position,
            from: Some(format!("h{position}")),
            by: Some(format!("h{}", position + 1)),
            timestamp: ts,
            date_utc: ts.map(|t| t.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn timeline_marks_out_of_order_gaps_and_missing_dates() {
        let h = HeaderSummary {
            // Stored top-most first; the timeline is in sending order.
            hops: vec![
                hop(5, Some(10_000)),
                hop(4, None),
                hop(3, Some(1_000)),
                hop(2, Some(1_400)),
                hop(1, Some(1_000)),
            ],
            ..Default::default()
        };
        let t = hop_timeline(&h, 300);
        assert_eq!(
            t.iter().map(|x| x.position).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5]
        );
        assert_eq!(t[1].delta_s, Some(400));
        assert!(!t[1].out_of_order && !t[1].gap);
        assert_eq!(t[2].delta_s, Some(-400));
        assert!(t[2].out_of_order, "400 s back, skew 300");
        assert!(t[3].undated && t[3].delta_s.is_none());
        assert_eq!(
            t[4].delta_s,
            Some(9_000),
            "measured from the last dated hop"
        );
        assert!(t[4].gap);
        assert!(!hop_timeline(&h, 600)[2].out_of_order, "within the skew");
        assert_eq!(delta_text(Some(-400)), "-6 min 40 s");
        assert_eq!(delta_text(None), "\u{2014}");
    }

    #[test]
    fn addresses_are_compared_on_the_organisational_domain() {
        let a = |addr: &str| MailAddress {
            name: None,
            address: addr.into(),
            domain: addr.rsplit_once('@').unwrap().1.into(),
        };
        let h = HeaderSummary {
            from: vec![a("ceo@mail.example.org")],
            reply_to: vec![a("ceo@examp1e.org")],
            sender: Some(a("relay@example.org")),
            return_path: Some("<bounce@lists.example.org>".into()),
            ..Default::default()
        };
        let rows = address_rows(&h);
        let by = |r: &str| rows.iter().find(|x| x.role == r).unwrap();
        assert!(!by("addr_from").mismatch);
        assert!(!by("addr_sender").mismatch, "same organisational domain");
        assert!(by("addr_reply_to").mismatch);
        assert_eq!(by("addr_return_path").domain, "lists.example.org");
        assert!(!by("addr_return_path").mismatch);
    }
}
