//! The analysis of ONE message (an .eml, an .msg, or one message of an mbox): header section, Received hops,
//! dates, Authentication-Results as stated evidence, offline DKIM/ARC, attachments, BEC signals.
//!
//! [`analyze_message`] reads the bytes, runs [`analyze_bytes`] (pure: no file system, no network — the part
//! the fuzz test drives) and writes `headers.json`, `dkim.json` and, when asked, the attachments. It runs
//! inside the worker process with `Isolation::Subprocess`; in process it is guarded by `catch_unwind`.

#![forbid(unsafe_code)]

use crate::analyzer::{Analysis, AnalyzeCtx, OutputFile, TYPE_EML, TYPE_MBOX_MESSAGE, TYPE_MSG};
use crate::dkim::org_domain;
use crate::model::{
    AttachmentInfo, AuthResultsHeader, DkimReport, DomainOptions, Finding, HeaderSummary, Hop,
    ItemKind, KeyRecord, MAX_ATTACHMENTS, MAX_AUTH_RESULTS, MAX_HOPS, MAX_RAW_CHARS,
    MAX_RECIPIENTS, MailAddress, MessageAnalysis, MessageLocator, finding,
};
use mail_parser::{DateTime, MessageParser};
use serde_json::json;
use std::io::Read;

/// Seconds since 1970 → "2026-11-10T10:00:00Z".
pub fn rfc3339(ts: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(ts, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn cap(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n).collect();
        t.push('…');
        t
    }
}

/// Header value with folding removed (CRLF + whitespace → one space), lossy UTF-8.
fn unfold(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    let mut last_space = false;
    for c in s.chars() {
        if c == '\r' || c == '\n' {
            continue;
        }
        if c == '\t' || c == ' ' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(c);
            last_space = false;
        }
    }
    out.trim().to_string()
}

fn tz_minutes(d: &DateTime) -> i64 {
    let m = d.tz_hour as i64 * 60 + d.tz_minute as i64;
    if d.tz_before_gmt { -m } else { m }
}

struct ParsedDate {
    utc: Option<String>,
    ts: Option<i64>,
    tz: Option<i64>,
}

fn parse_date(raw: &str) -> ParsedDate {
    match DateTime::parse_rfc822(raw).filter(|d| d.is_valid()) {
        Some(d) => {
            let ts = d.to_timestamp();
            ParsedDate {
                utc: rfc3339(ts),
                ts: Some(ts),
                tz: Some(tz_minutes(&d)),
            }
        }
        None => ParsedDate {
            utc: None,
            ts: None,
            tz: None,
        },
    }
}

/// Splits "from a (x) by b with ESMTPS id c for <d>; date" into its clauses (comments dropped).
fn parse_received(value: &str, header_index: u64) -> Hop {
    let (clauses, date) = match value.rfind(';') {
        Some(p) => (&value[..p], Some(value[p + 1..].trim().to_string())),
        None => (value, None),
    };
    // Drop (comments), keeping nesting simple.
    let mut plain = String::new();
    let mut depth = 0usize;
    for c in clauses.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => plain.push(c),
            _ => {}
        }
    }
    let toks: Vec<&str> = plain.split_whitespace().collect();
    let mut hop = Hop {
        header_index,
        raw: cap(value, MAX_RAW_CHARS),
        ..Hop::default()
    };
    let mut i = 0;
    while i + 1 < toks.len() {
        let v = Some(toks[i + 1].trim_matches(['<', '>']).to_string());
        match toks[i].to_ascii_lowercase().as_str() {
            "from" if hop.from.is_none() => hop.from = v,
            "by" if hop.by.is_none() => hop.by = v,
            "with" if hop.with.is_none() => hop.with = v,
            "id" if hop.id.is_none() => hop.id = v,
            "for" if hop.for_addr.is_none() => hop.for_addr = v,
            _ => {
                i += 1;
                continue;
            }
        }
        i += 2;
    }
    if let Some(d) = date.filter(|d| !d.is_empty()) {
        let p = parse_date(&d);
        hop.date_raw = Some(cap(&d, 200));
        hop.date_utc = p.utc;
        hop.timestamp = p.ts;
        hop.tz_offset_min = p.tz;
    }
    hop
}

fn parse_auth_results(value: &str, header_index: u64) -> AuthResultsHeader {
    let mut parts = value.split(';');
    let authserv_id = parts
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    let methods = parts
        .filter_map(|p| {
            let tok = p.split_whitespace().next()?;
            let (m, r) = tok.split_once('=')?;
            Some((m.to_ascii_lowercase(), r.to_ascii_lowercase()))
        })
        .take(32)
        .collect();
    AuthResultsHeader {
        header_index,
        authserv_id,
        methods,
        raw: cap(value, MAX_RAW_CHARS),
    }
}

fn address(name: Option<&str>, addr: Option<&str>) -> Option<MailAddress> {
    let address = addr?.trim().to_string();
    if address.is_empty() {
        return None;
    }
    let domain = address
        .rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default();
    Some(MailAddress {
        name: name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()),
        address,
        domain,
    })
}

fn mailboxes(list: Option<mail_parser::AddressList>) -> Vec<MailAddress> {
    list.map(|l| {
        l.mailboxes()
            .filter_map(|m| address(m.name(), m.address()))
            .collect()
    })
    .unwrap_or_default()
}

/// Header summary of a parsed message (root headers).
fn summarize(m: &mail_parser::Message, kind: ItemKind) -> HeaderSummary {
    let mut h = HeaderSummary {
        kind,
        ..HeaderSummary::default()
    };
    let headers = m.headers();
    h.header_count = headers.len() as u64;
    let mut received_index = 0u64;
    let mut ar_index = 0u64;
    let mut hops = Vec::new();
    for hd in headers.iter() {
        let name = hd.raw_name().to_ascii_lowercase();
        match name.as_str() {
            "received" => {
                if hops.len() < MAX_HOPS {
                    hops.push(parse_received(&unfold(hd.raw_value()), received_index));
                }
                received_index += 1;
            }
            "authentication-results" => {
                if h.auth_results.len() < MAX_AUTH_RESULTS {
                    h.auth_results
                        .push(parse_auth_results(&unfold(hd.raw_value()), ar_index));
                }
                ar_index += 1;
            }
            "date" if h.date_raw.is_none() => {
                let raw = unfold(hd.raw_value());
                let p = parse_date(&raw);
                h.date_raw = Some(cap(&raw, 200));
                h.date_utc = p.utc;
                h.date_timestamp = p.ts;
                h.date_tz_offset_min = p.tz;
            }
            "return-path" if h.return_path.is_none() => {
                let v = unfold(hd.raw_value());
                let v = v
                    .trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .trim();
                if !v.is_empty() {
                    h.return_path = Some(cap(v, 320));
                }
            }
            _ => {}
        }
    }
    h.hops_total = received_index;
    // Positions: the bottom-most Received header is hop 1 (first server).
    let total = received_index;
    for hop in &mut hops {
        hop.position = total - hop.header_index;
    }
    h.hops = hops;
    h.message_id = m.message_id().map(|s| cap(s, 320));
    h.subject = m.subject().map(|s| cap(s, 500));
    h.from = mailboxes(m.from());
    h.sender = mailboxes(m.sender()).into_iter().next();
    h.reply_to = mailboxes(m.reply_to());
    let mut rcpt = mailboxes(m.to());
    rcpt.extend(mailboxes(m.cc()));
    h.recipients_total = rcpt.len() as u64;
    rcpt.truncate(MAX_RECIPIENTS);
    h.recipients = rcpt;
    let mut problems: Vec<String> = Vec::new();
    let mut parts = 0u64;
    for p in m.parts() {
        parts += 1;
        for n in p.flags().names() {
            if matches!(n, "unterminated" | "no_blank_line" | "missing_delimiter") {
                let n = n.to_string();
                if !problems.contains(&n) {
                    problems.push(n);
                }
            }
        }
    }
    h.mime_parts = parts;
    h.structure_problems = problems;
    h
}

fn is_message_like(h: &HeaderSummary) -> bool {
    !h.from.is_empty()
        || h.date_raw.is_some()
        || h.message_id.is_some()
        || h.hops_total > 0
        || h.subject.is_some()
}

fn safe_name(n: &str) -> String {
    let s: String = n
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(60)
        .collect();
    let s = s.trim_matches('.').to_string();
    if s.is_empty() { "attachment".into() } else { s }
}

/// Result of [`analyze_bytes`].
pub struct MessageOutcome {
    pub analysis: MessageAnalysis,
    pub findings: Vec<Finding>,
    /// Decoded attachment contents (same order as `analysis.attachments`), for extraction.
    pub blobs: Vec<Vec<u8>>,
}

fn attachment_info(
    index: u64,
    name: Option<&str>,
    ctype: String,
    data: &[u8],
    created: Option<(String, Option<i64>)>,
    modified: Option<(String, Option<i64>)>,
) -> AttachmentInfo {
    AttachmentInfo {
        index,
        file_name: name.map(|n| cap(n, 255)),
        content_type: ctype,
        size: data.len() as u64,
        sha256: crate::hash::hash_bytes(data, crate::hash::HashAlgo::Sha256),
        creation_date_raw: created.as_ref().map(|c| c.0.clone()),
        creation_date_utc: created.and_then(|c| c.1).and_then(rfc3339),
        modification_date_raw: modified.as_ref().map(|c| c.0.clone()),
        modification_date_utc: modified.and_then(|c| c.1).and_then(rfc3339),
        extracted: None,
    }
}

/// The whole analysis of one message held in memory. `keys`: the examiner's keys (and DNS keys in online
/// mode). Pure: never reads or writes a file and never uses the network.
pub fn analyze_bytes(
    bytes: &[u8],
    kind: ItemKind,
    locator: MessageLocator,
    keys: &[KeyRecord],
    opts: &DomainOptions,
) -> MessageOutcome {
    let mut findings: Vec<Finding> = Vec::new();
    let mut ma = MessageAnalysis {
        locator,
        bytes: bytes.len() as u64,
        sha256: crate::hash::hash_bytes(bytes, crate::hash::HashAlgo::Sha256),
        ..MessageAnalysis::default()
    };
    let mut blobs = Vec::new();
    let mut text = String::new();
    let parser = MessageParser::new();
    let mut attach_dates: Vec<(u64, String, &'static str, i64)> = Vec::new();

    match kind {
        ItemKind::Msg => {
            let d = match crate::msg::read(bytes, opts.max_message_bytes) {
                Ok(d) => d,
                Err(e) => {
                    findings.push(
                        finding("FILE_STRUCTURE_DAMAGED")
                            .with("format", "msg")
                            .with("problems", cap(&e, 300)),
                    );
                    ma.headers.kind = kind;
                    ma.dkim = DkimReport {
                        mode: mode(opts),
                        evaluated: false,
                        not_evaluated_reason: Some("file_structure_damaged".into()),
                        ..DkimReport::default()
                    };
                    return MessageOutcome {
                        analysis: ma,
                        findings,
                        blobs,
                    };
                }
            };
            let mut h = match &d.transport_headers {
                Some(th) => {
                    let mut raw = th.replace("\r\n", "\n").replace('\n', "\r\n");
                    if !raw.ends_with("\r\n") {
                        raw.push_str("\r\n");
                    }
                    raw.push_str("\r\n");
                    match parser.parse_headers(raw.as_bytes()) {
                        Some(m) => summarize(&m, kind),
                        None => HeaderSummary::default(),
                    }
                }
                None => HeaderSummary::default(),
            };
            h.kind = kind;
            if d.transport_headers.is_none() {
                findings.push(finding("MSG_TRANSPORT_HEADERS_MISSING"));
                // What Outlook stored instead: subject, sender, submit time.
                h.subject = d.props.subject.clone();
                h.message_id = d.props.internet_message_id.clone();
                let sender = d
                    .props
                    .sent_representing_email
                    .as_deref()
                    .or(d.props.sender_email.as_deref());
                let sname = d
                    .props
                    .sent_representing_name
                    .as_deref()
                    .or(d.props.sender_name.as_deref());
                h.from = address(sname, sender).into_iter().collect();
                h.date_utc = d.props.client_submit_time.clone();
                h.date_timestamp = d.submit_ts;
            }
            text.push_str(d.props.subject.as_deref().unwrap_or_default());
            text.push('\n');
            text.push_str(&cap(d.body.as_deref().unwrap_or_default(), 1 << 20));
            for (i, a) in d.attachments.iter().enumerate() {
                let idx = i as u64 + 1;
                let c = a.created.map(|t| (rfc3339(t).unwrap_or_default(), Some(t)));
                let m = a
                    .modified
                    .map(|t| (rfc3339(t).unwrap_or_default(), Some(t)));
                if let Some(t) = a.created {
                    attach_dates.push((idx, a.name.clone().unwrap_or_default(), "creation", t));
                }
                if let Some(t) = a.modified {
                    attach_dates.push((idx, a.name.clone().unwrap_or_default(), "modification", t));
                }
                if ma.attachments.len() < MAX_ATTACHMENTS {
                    ma.attachments.push(attachment_info(
                        idx,
                        a.name.as_deref(),
                        a.mime
                            .clone()
                            .unwrap_or_else(|| "application/octet-stream".into()),
                        &a.data,
                        c,
                        m,
                    ));
                    blobs.push(a.data.clone());
                }
            }
            ma.attachments_total = d.attachments.len() as u64;
            ma.dkim = DkimReport {
                mode: mode(opts),
                evaluated: false,
                ..DkimReport::default()
            };
            ma.dkim.arc.result = "not_evaluated".into();
            match &d.transport_headers {
                None => {
                    ma.dkim.not_evaluated_reason = Some("msg_transport_headers_missing".into());
                }
                Some(th) => {
                    let reason = "msg_body_not_original";
                    ma.dkim.not_evaluated_reason = Some(reason.into());
                    ma.dkim.signatures = crate::dkim::list_signatures(th.as_bytes(), reason);
                    if ma.dkim.signatures.is_empty() {
                        findings.push(finding("DKIM_NOT_SIGNED"));
                    }
                    for s in &ma.dkim.signatures {
                        findings.push(
                            finding("DKIM_SIGNATURE_NOT_EVALUATED")
                                .with("d", s.domain.clone())
                                .with("s", s.selector.clone())
                                .with("reason", reason),
                        );
                    }
                }
            }
            h.msg = Some(d.props.clone());
            ma.headers = h;
        }
        _ => {
            let Some(m) = parser.parse(bytes) else {
                findings.push(
                    finding("FILE_STRUCTURE_DAMAGED")
                        .with("format", "rfc5322")
                        .with("problems", "no_header_section"),
                );
                ma.headers.kind = kind;
                ma.dkim.mode = mode(opts);
                ma.dkim.not_evaluated_reason = Some("file_structure_damaged".into());
                return MessageOutcome {
                    analysis: ma,
                    findings,
                    blobs,
                };
            };
            let h = summarize(&m, kind);
            if !is_message_like(&h) {
                findings.push(
                    finding("FILE_STRUCTURE_DAMAGED")
                        .with("format", "rfc5322")
                        .with("problems", "no_message_header_fields"),
                );
            } else if !h.structure_problems.is_empty() {
                findings.push(
                    finding("FILE_STRUCTURE_DAMAGED")
                        .with("format", "mime")
                        .with("problems", h.structure_problems.join(", ")),
                );
            }
            text.push_str(h.subject.as_deref().unwrap_or_default());
            text.push('\n');
            for b in m.text_bodies() {
                if text.len() > 1 << 20 {
                    break;
                }
                text.push_str(&cap(&b, 1 << 20));
                text.push('\n');
            }
            let mut n = 0u64;
            for p in m.attachments() {
                n += 1;
                let data = p.decoded();
                let disp = p.content_disposition();
                let date_attr = |attr: &str| {
                    disp.as_ref().and_then(|d| d.attribute(attr)).map(|v| {
                        let v = cap(v, 200);
                        let ts = parse_date(&v).ts;
                        (v, ts)
                    })
                };
                let created = date_attr("creation-date");
                let modified = date_attr("modification-date");
                let name = p.attachment_name().map(String::from);
                for (field, d) in [("creation", &created), ("modification", &modified)] {
                    if let Some((_, Some(t))) = d {
                        attach_dates.push((n, name.clone().unwrap_or_default(), field, *t));
                    }
                }
                if ma.attachments.len() < MAX_ATTACHMENTS {
                    let ct = p
                        .content_type()
                        .map(|c| match c.subtype() {
                            Some(s) => format!("{}/{}", c.ctype(), s),
                            None => c.ctype().to_string(),
                        })
                        .unwrap_or_else(|| "application/octet-stream".into());
                    ma.attachments.push(attachment_info(
                        n,
                        name.as_deref(),
                        ct.to_ascii_lowercase(),
                        &data,
                        created,
                        modified,
                    ));
                    blobs.push(data.into_owned());
                }
            }
            ma.attachments_total = n;
            let from_domain = h.from.first().map(|a| a.domain.clone()).unwrap_or_default();
            ma.dkim = crate::dkim::verify(bytes, keys, &from_domain);
            ma.dkim.mode = mode(opts);
            ma.headers = h;
            dkim_findings(&ma, &from_domain, &mut findings);
        }
    }

    // Stated evidence: what the receiving servers wrote.
    if let Some(top) = ma.headers.auth_results.first() {
        let methods: Vec<String> = top
            .methods
            .iter()
            .map(|(m, r)| format!("{m}={r}"))
            .collect();
        findings.push(
            finding("AUTH_RESULTS_RECORDED")
                .with("count", ma.headers.auth_results.len().to_string())
                .with("authserv_id", top.authserv_id.clone())
                .with("results", crate::report::capped_list(&methods, 10)),
        );
    }
    date_findings(&ma.headers, opts.clock_skew_s as i64, &mut findings);
    if let Some(date) = ma.headers.date_timestamp {
        let mut n = 0;
        for (idx, name, field, t) in &attach_dates {
            if *t > date + opts.clock_skew_s as i64 && n < 10 {
                n += 1;
                findings.push(
                    finding("ATTACHMENT_DATE_AFTER_SENT")
                        .with(
                            "attachment",
                            if name.is_empty() {
                                format!("#{idx}")
                            } else {
                                name.clone()
                            },
                        )
                        .with("field", *field)
                        .with("attachment_date", rfc3339(*t).unwrap_or_default())
                        .with("date", ma.headers.date_utc.clone().unwrap_or_default()),
                );
            }
        }
    }
    message_id_finding(&ma.headers, &mut findings);
    findings.extend(crate::bec::header_signals(&ma.headers, &opts.own_domains));
    let terms = crate::bec::payment_terms(&text);
    if !terms.is_empty() {
        findings.push(
            finding("PAYMENT_DETAILS_MENTIONED")
                .with("terms", crate::report::capped_list(&terms, 10)),
        );
    }
    ma.payment_terms = terms.into_iter().take(20).collect();
    MessageOutcome {
        analysis: ma,
        findings,
        blobs,
    }
}

fn mode(opts: &DomainOptions) -> String {
    if opts.online_dns { "online" } else { "offline" }.into()
}

fn dkim_findings(ma: &MessageAnalysis, from_domain: &str, out: &mut Vec<Finding>) {
    let d = &ma.dkim;
    if !d.evaluated {
        return;
    }
    if d.signatures.is_empty() {
        out.push(finding("DKIM_NOT_SIGNED"));
    }
    for s in &d.signatures {
        let base = |code: &str| {
            finding(code)
                .with("d", s.domain.clone())
                .with("s", s.selector.clone())
        };
        match s.result.as_str() {
            "pass" => {
                out.push(
                    base("DKIM_SIGNATURE_VALID")
                        .with("a", s.algorithm.clone())
                        .with("key_source", s.key_source.clone()),
                );
                if s.key_source == "current_dns" {
                    out.push(base("DKIM_KEY_FROM_CURRENT_DNS"));
                }
            }
            "body_hash_mismatch" => out.push(base("DKIM_BODY_HASH_MISMATCH")),
            "signature_invalid" => out.push(
                base("DKIM_SIGNATURE_INVALID")
                    .with("reason", s.reason.clone().unwrap_or_default())
                    .with("key_source", s.key_source.clone()),
            ),
            "key_not_available" => out.push(
                base("DKIM_KEY_NOT_AVAILABLE")
                    .with("name", crate::dkim::key_name(&s.selector, &s.domain)),
            ),
            _ => out.push(
                base("DKIM_SIGNATURE_NOT_EVALUATED")
                    .with("reason", s.reason.clone().unwrap_or_default()),
            ),
        }
    }
    let passing: Vec<&str> = d
        .signatures
        .iter()
        .filter(|s| s.result == "pass")
        .map(|s| s.domain.as_str())
        .collect();
    if !passing.is_empty()
        && !from_domain.is_empty()
        && !d
            .signatures
            .iter()
            .any(|s| s.result == "pass" && s.aligned_with_from)
    {
        out.push(
            finding("DKIM_DOMAIN_NOT_ALIGNED")
                .with("d", passing.join(", "))
                .with("from_domain", from_domain),
        );
    }
    if d.arc.result == "invalid" {
        out.push(
            finding("ARC_CHAIN_INVALID")
                .with("instances", d.arc.instances.to_string())
                .with("reason", d.arc.reason.clone().unwrap_or_default()),
        );
    }
}

fn zone(m: i64) -> String {
    let sign = if m < 0 { '-' } else { '+' };
    format!("{}{:02}{:02}", sign, m.abs() / 60, m.abs() % 60)
}

fn date_findings(h: &HeaderSummary, skew: i64, out: &mut Vec<Finding>) {
    // Hops from the first server (position 1) to the last.
    let mut timed: Vec<&Hop> = h.hops.iter().filter(|x| x.timestamp.is_some()).collect();
    timed.sort_by_key(|x| x.position);
    let mut backwards = Vec::new();
    for w in timed.windows(2) {
        let (a, b) = (w[0], w[1]);
        if let (Some(ta), Some(tb)) = (a.timestamp, b.timestamp)
            && tb + skew < ta
        {
            backwards.push((a, b, ta - tb));
        }
    }
    if let Some((a, b, by)) = backwards.first() {
        out.push(
            finding("RECEIVED_TIME_NOT_MONOTONIC")
                .with("hop", b.position.to_string())
                .with("hop_date", b.date_utc.clone().unwrap_or_default())
                .with("previous_hop", a.position.to_string())
                .with("previous_date", a.date_utc.clone().unwrap_or_default())
                .with("earlier_by_s", by.to_string())
                .with("count", backwards.len().to_string()),
        );
    }
    let first = timed.first();
    if let (Some(d), Some(f)) = (h.date_timestamp, first)
        && let Some(ft) = f.timestamp
        && d > ft + skew
    {
        out.push(
            finding("DATE_AFTER_FIRST_HOP")
                .with("date", h.date_utc.clone().unwrap_or_default())
                .with("first_hop_date", f.date_utc.clone().unwrap_or_default())
                .with("later_by_s", (d - ft).to_string()),
        );
    }
    if let Some(tz) = h.date_tz_offset_min {
        let invalid = tz.abs() > 14 * 60 || tz % 15 != 0;
        let from_org = h
            .from
            .first()
            .map(|a| org_domain(&a.domain))
            .unwrap_or_default();
        // The first hop stamped by the sender's own organisation (its submission server).
        let own_first = first.filter(|f| {
            !from_org.is_empty() && f.by.as_deref().is_some_and(|b| org_domain(b) == from_org)
        });
        if invalid {
            out.push(
                finding("TIMEZONE_INCONSISTENT")
                    .with("date_zone", zone(tz))
                    .with("hop_zone", "-")
                    .with("reason", "invalid_offset"),
            );
        } else if let Some(f) = own_first
            && let Some(hz) = f.tz_offset_min
            && hz != tz
        {
            out.push(
                finding("TIMEZONE_INCONSISTENT")
                    .with("date_zone", zone(tz))
                    .with("hop_zone", zone(hz))
                    .with("reason", "sender_server_zone_differs"),
            );
        }
    }
}

fn message_id_finding(h: &HeaderSummary, out: &mut Vec<Finding>) {
    let Some(mid) = h.message_id.as_deref() else {
        return;
    };
    let Some(from) = h.from.first().filter(|a| !a.domain.is_empty()) else {
        return;
    };
    let Some((_, d)) = mid.trim_matches(['<', '>']).rsplit_once('@') else {
        return;
    };
    let d = d.trim().to_ascii_lowercase();
    if !d.contains('.') {
        return;
    }
    if org_domain(&d) != org_domain(&from.domain) {
        out.push(
            finding("MESSAGE_ID_DOMAIN_MISMATCH")
                .with("message_id_domain", d)
                .with("from_domain", from.domain.clone()),
        );
    }
}

/// (path, SHA-256 — empty when unreadable —, problems) of the examiner's key file.
type KeyFileInfo = (String, String, Vec<String>);

/// Keys for this analysis: the examiner's key file, then keys the parent fetched (online mode).
pub fn keys_for(opts: &DomainOptions) -> (Vec<KeyRecord>, Option<KeyFileInfo>) {
    let mut keys = Vec::new();
    let mut file = None;
    if let Some(p) = &opts.dkim_keys {
        match crate::dkim::load_key_file(p) {
            Ok((k, problems, digest)) => {
                keys.extend(k);
                file = Some((p.display().to_string(), digest, problems));
            }
            Err(e) => file = Some((p.display().to_string(), String::new(), vec![e])),
        }
    }
    keys.extend(opts.fetched_keys.iter().cloned());
    (keys, file)
}

fn read_capped(path: &std::path::Path, max: u64) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    if size > max {
        return Err(format!("too_large: {size} bytes (limit {max})"));
    }
    let mut b = Vec::with_capacity(size as usize);
    f.take(max).read_to_end(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}

fn not_completed(ctx: &AnalyzeCtx, kind: ItemKind, reason: &str, detail: String) -> Analysis {
    let ext = std::path::Path::new(ctx.file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    Analysis {
        detected_type: Some(type_name(kind, ctx.message.is_some()).into()),
        extension: ext,
        findings: vec![
            finding("PARSER_FAILED")
                .with("reason", reason)
                .with("exit_code", "-"),
        ],
        details: json!({"kind": kind.name(), "message_analysis": "not_completed", "reason": reason, "detail": detail}),
        outputs: vec![],
    }
}

fn type_name(kind: ItemKind, in_mbox: bool) -> &'static str {
    match (kind, in_mbox) {
        (_, true) => TYPE_MBOX_MESSAGE,
        (ItemKind::Msg, _) => TYPE_MSG,
        _ => TYPE_EML,
    }
}

/// The message analysis with file I/O: read the bytes, analyse, write headers.json, dkim.json and the
/// attachments (when asked). Panics in the parsers become PARSER_FAILED (reason panic).
pub fn analyze_message(ctx: &AnalyzeCtx, kind: ItemKind) -> Analysis {
    let max = ctx.opts.max_message_bytes;
    let bytes = match ctx.message {
        Some(m) => crate::mbox::read_message(ctx.path, m, &ctx.opts.mbox_variant, max),
        None => read_capped(ctx.path, max),
    };
    let bytes = match bytes {
        Ok(b) => b,
        Err(e) if e.starts_with("too_large") => return not_completed(ctx, kind, "too_large", e),
        Err(e) => return not_completed(ctx, kind, "read_error", e),
    };
    let (keys, key_file) = keys_for(ctx.opts);
    let locator = MessageLocator {
        kind: if ctx.message.is_some() {
            ItemKind::Mbox
        } else {
            kind
        },
        mbox: ctx.message.cloned(),
    };
    let msg_kind = if ctx.message.is_some() {
        ItemKind::Eml
    } else {
        kind
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        analyze_bytes(&bytes, msg_kind, locator, &keys, ctx.opts)
    }));
    let Ok(mut out) = outcome else {
        return not_completed(ctx, kind, "panic", "the parser panicked".into());
    };
    if let Some((path, digest, problems)) = key_file {
        out.analysis.dkim.key_file = Some(path);
        out.analysis.dkim.key_file_sha256 = Some(digest).filter(|d| !d.is_empty());
        out.analysis.dkim.key_file_problems = problems.into_iter().take(50).collect();
    }
    out.analysis.dkim.keys_loaded = keys.len() as u64;
    let mut outputs = Vec::new();
    if ctx.opts.extract_attachments && !out.blobs.is_empty() {
        let dir = ctx.item_dir.join("attachments");
        if std::fs::create_dir_all(&dir).is_ok() {
            for (a, blob) in out.analysis.attachments.iter_mut().zip(&out.blobs) {
                let rel = format!(
                    "attachments/{:03}-{}",
                    a.index,
                    safe_name(a.file_name.as_deref().unwrap_or("attachment"))
                );
                if std::fs::write(ctx.item_dir.join(&rel), blob).is_ok() {
                    a.extracted = Some(rel.clone());
                    outputs.push(OutputFile {
                        rel_path: rel,
                        kind: "attachment".into(),
                    });
                }
            }
        }
    }
    let mut write = |name: &str, kind: &str, v: serde_json::Value| {
        if std::fs::write(ctx.item_dir.join(name), crate::report::pretty(&v)).is_ok() {
            outputs.insert(
                0,
                OutputFile {
                    rel_path: name.into(),
                    kind: kind.into(),
                },
            );
        }
    };
    write(
        "dkim.json",
        "dkim",
        json!({"schema": "rv-mailauth.dkim/1", "dkim": out.analysis.dkim}),
    );
    write(
        "headers.json",
        "headers",
        json!({"schema": "rv-mailauth.headers/1", "bytes": out.analysis.bytes, "sha256": out.analysis.sha256,
               "locator": out.analysis.locator, "headers": out.analysis.headers,
               "attachments": out.analysis.attachments, "attachments_total": out.analysis.attachments_total}),
    );
    let ext = std::path::Path::new(ctx.file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    Analysis {
        detected_type: Some(type_name(kind, ctx.message.is_some()).into()),
        extension: ext,
        findings: out.findings,
        details: json!({"kind": kind.name(), "message_analysis": "completed", "message": out.analysis}),
        outputs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(msg: &str, opts: &DomainOptions) -> MessageOutcome {
        analyze_bytes(
            msg.as_bytes(),
            ItemKind::Eml,
            MessageLocator::default(),
            &[],
            opts,
        )
    }

    fn codes(o: &MessageOutcome) -> Vec<String> {
        let mut c: Vec<String> = o.findings.iter().map(|f| f.code.clone()).collect();
        c.sort();
        c
    }

    const CLEAN: &str = "Received: from mx.example.net by mx.acme.example with ESMTPS id 2; Tue, 10 Nov 2026 10:00:05 +0000\r\n\
Received: from [192.0.2.1] (client) by smtp.example.net with ESMTPSA id 1 for <ana@acme.example>; Tue, 10 Nov 2026 10:00:02 +0000\r\n\
From: Bruno <bruno@example.net>\r\nTo: Ana <ana@acme.example>\r\nSubject: Minutes\r\n\
Date: Tue, 10 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@example.net>\r\n\r\nSee you.\r\n";

    #[test]
    fn clean_unsigned_message() {
        let o = run(CLEAN, &DomainOptions::default());
        assert_eq!(codes(&o), ["DKIM_NOT_SIGNED"]);
        let h = &o.analysis.headers;
        assert_eq!(h.hops_total, 2);
        assert_eq!(h.hops[1].position, 1);
        assert_eq!(h.hops[1].by.as_deref(), Some("smtp.example.net"));
        assert_eq!(h.hops[1].for_addr.as_deref(), Some("ana@acme.example"));
        assert_eq!(h.hops[0].date_utc.as_deref(), Some("2026-11-10T10:00:05Z"));
        assert_eq!(h.date_tz_offset_min, Some(0));
        assert_eq!(h.from[0].domain, "example.net");
    }

    #[test]
    fn dates_and_hops() {
        let m = CLEAN.replace("10:00:05 +0000", "09:30:00 +0000").replace(
            "Date: Tue, 10 Nov 2026 10:00:00 +0000",
            "Date: Tue, 10 Nov 2026 12:00:00 +0200",
        );
        let o = run(&m, &DomainOptions::default());
        assert!(codes(&o).contains(&"RECEIVED_TIME_NOT_MONOTONIC".to_string()));
        let m = CLEAN.replace(
            "Date: Tue, 10 Nov 2026 10:00:00",
            "Date: Tue, 10 Nov 2026 11:00:00",
        );
        let o = run(&m, &DomainOptions::default());
        let f = o
            .findings
            .iter()
            .find(|f| f.code == "DATE_AFTER_FIRST_HOP")
            .unwrap();
        assert_eq!(f.params["later_by_s"], "3598");
        let m = CLEAN.replace("10:00:00 +0000", "15:00:00 +0500");
        let o = run(&m, &DomainOptions::default());
        let f = o
            .findings
            .iter()
            .find(|f| f.code == "TIMEZONE_INCONSISTENT")
            .unwrap();
        assert_eq!(f.params["reason"], "sender_server_zone_differs");
        let m = CLEAN.replace(
            "Message-ID: <1@example.net>",
            "Message-ID: <1@mailer.example.com>",
        );
        assert!(
            codes(&run(&m, &DomainOptions::default()))
                .contains(&"MESSAGE_ID_DOMAIN_MISMATCH".into())
        );
    }

    #[test]
    fn auth_results_and_attachment_dates() {
        let m = format!(
            "Authentication-Results: mx.acme.example; dkim=pass header.d=example.net; spf=fail smtp.mailfrom=example.net\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n{}",
            CLEAN.replace("\r\n\r\nSee you.\r\n", "\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee you.\r\n--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Disposition: attachment; filename=\"a.pdf\"; modification-date=\"Wed, 11 Nov 2026 09:00:00 +0000\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--b--\r\n")
        );
        let o = run(&m, &DomainOptions::default());
        let c = codes(&o);
        assert!(c.contains(&"AUTH_RESULTS_RECORDED".into()), "{c:?}");
        assert!(c.contains(&"ATTACHMENT_DATE_AFTER_SENT".into()), "{c:?}");
        let ar = &o.analysis.headers.auth_results[0];
        assert_eq!(ar.authserv_id, "mx.acme.example");
        assert_eq!(ar.methods[0], ("dkim".to_string(), "pass".to_string()));
        assert_eq!(o.analysis.attachments[0].size, 9);
        assert_eq!(
            o.analysis.attachments[0].file_name.as_deref(),
            Some("a.pdf")
        );
        // Truncated multipart: structure damaged.
        let cut = &m[..m.len() - 8];
        assert!(
            codes(&run(cut, &DomainOptions::default())).contains(&"FILE_STRUCTURE_DAMAGED".into())
        );
    }

    #[test]
    fn garbage_is_damaged_not_a_panic() {
        let o = run(
            "\u{0}\u{1}binary junk without headers",
            &DomainOptions::default(),
        );
        assert!(codes(&o).contains(&"FILE_STRUCTURE_DAMAGED".to_string()));
    }
}
