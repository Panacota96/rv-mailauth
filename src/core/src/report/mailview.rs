//! The email part of the technical report: one view model (sections of label/value rows) rendered the same
//! way by technical.html and the PDF writer, built from `ItemResult::details` and `outputs`.

use super::ItemResult;
use crate::i18n::Catalog;
use crate::model::{MailAddress, MessageAnalysis};
use serde_json::{Value, json};

const MAX_ROWS: usize = 30;

fn addr(a: &MailAddress) -> String {
    match &a.name {
        Some(n) => format!("{} <{}>", n, a.address),
        None => a.address.clone(),
    }
}

fn rows_capped(mut rows: Vec<(String, String)>, c: &Catalog) -> Vec<Value> {
    let total = rows.len();
    rows.truncate(MAX_ROWS);
    let mut out: Vec<Value> = rows
        .into_iter()
        .map(|(k, v)| json!({"k": k, "v": v}))
        .collect();
    if total > MAX_ROWS {
        out.push(json!({"k": "…", "v": format!("(+{}) — {}", total - MAX_ROWS, c.label("mail_outputs"))}));
    }
    out
}

fn section(title: String, rows: Vec<Value>) -> Value {
    json!({"title": title, "rows": rows})
}

fn opt(v: &Option<String>, c: &Catalog) -> String {
    v.clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| c.label("mail_none"))
}

/// Sections for one item; empty when the item is not an email.
pub fn mail_view(c: &Catalog, it: &ItemResult) -> Value {
    let mut sections = Vec::new();
    let d = &it.details;
    if let Some(mb) = d.get("mbox") {
        let msgs = mb["messages"].as_array().cloned().unwrap_or_default();
        let rows: Vec<(String, String)> = msgs
            .iter()
            .map(|m| {
                (
                    format!("#{} @{}", m["n"], m["offset"]),
                    format!(
                        "{} ({} B) · {}",
                        m["id"].as_str().unwrap_or_default(),
                        m["length"],
                        m["from_line"].as_str().unwrap_or_default()
                    ),
                )
            })
            .collect();
        let mut head =
            vec![json!({"k": c.label("mail_mbox_messages"), "v": format!("{}", mb["count"])})];
        head.extend(rows_capped(rows, c));
        sections.push(section(c.label("mail_section"), head));
    }
    let Some(m) = d
        .get("message")
        .and_then(|v| serde_json::from_value::<MessageAnalysis>(v.clone()).ok())
    else {
        if d.get("message_analysis").and_then(Value::as_str) == Some("not_completed") {
            sections.push(section(
                c.label("mail_section"),
                vec![json!({"k": c.label("status"), "v": c.label("mail_not_completed")})],
            ));
        }
        return json!({"sections": sections});
    };
    let h = &m.headers;
    let mut facts: Vec<(String, String)> = Vec::new();
    if let Some(r) = &m.locator.mbox {
        facts.push((
            c.label("mail_mbox_message"),
            format!("#{} @{} ({} B): {}", r.n, r.offset, r.length, r.from_line),
        ));
    }
    facts.push((c.label("mail_message_id"), opt(&h.message_id, c)));
    facts.push((
        c.label("mail_from"),
        if h.from.is_empty() {
            c.label("mail_none")
        } else {
            h.from.iter().map(addr).collect::<Vec<_>>().join(", ")
        },
    ));
    if !h.reply_to.is_empty() {
        facts.push((
            c.label("mail_reply_to"),
            h.reply_to.iter().map(addr).collect::<Vec<_>>().join(", "),
        ));
    }
    if h.return_path.is_some() {
        facts.push((c.label("mail_return_path"), opt(&h.return_path, c)));
    }
    facts.push((c.label("mail_subject"), opt(&h.subject, c)));
    facts.push((
        c.label("mail_date"),
        format!(
            "{} ({})",
            opt(&h.date_raw, c),
            h.date_utc.clone().unwrap_or_else(|| "-".into())
        ),
    ));
    facts.push((
        c.label("mail_dkim_mode"),
        format!(
            "{} · {} · {} key(s)",
            m.dkim.mode,
            m.dkim
                .key_file
                .clone()
                .unwrap_or_else(|| c.label("mail_none")),
            m.dkim.keys_loaded
        ),
    ));
    if !m.dkim.evaluated {
        facts.push((
            c.label("mail_dkim_not_evaluated"),
            opt(&m.dkim.not_evaluated_reason, c),
        ));
    }
    sections.push(section(
        c.label("mail_section"),
        facts
            .into_iter()
            .map(|(k, v)| json!({"k": k, "v": v}))
            .collect(),
    ));

    let mut hops: Vec<&crate::model::Hop> = h.hops.iter().collect();
    hops.sort_by_key(|x| x.position);
    let hop_rows: Vec<(String, String)> = hops
        .iter()
        .map(|x| {
            (
                format!("{} {}", c.label("mail_hop"), x.position),
                format!(
                    "{}: {} · {}: {} · {}: {}",
                    c.label("mail_hop_from"),
                    x.from.clone().unwrap_or_else(|| "-".into()),
                    c.label("mail_hop_by"),
                    x.by.clone().unwrap_or_else(|| "-".into()),
                    c.label("mail_hop_date"),
                    x.date_utc
                        .clone()
                        .or_else(|| x.date_raw.clone())
                        .unwrap_or_else(|| "-".into())
                ),
            )
        })
        .collect();
    if !hop_rows.is_empty() {
        sections.push(section(c.label("mail_hops"), rows_capped(hop_rows, c)));
    }

    let mut dk: Vec<(String, String)> = m
        .dkim
        .signatures
        .iter()
        .map(|s| {
            (
                format!("#{} d={} s={}", s.index, s.domain, s.selector),
                format!(
                    "{}: {} · {}: {} · {}: {}{}{}",
                    c.label("mail_dkim_result"),
                    s.result,
                    c.label("mail_dkim_algorithm"),
                    s.algorithm,
                    c.label("mail_key_source"),
                    s.key_source,
                    s.key_line
                        .map(|l| format!(" (line {l})"))
                        .unwrap_or_default(),
                    s.reason
                        .as_ref()
                        .map(|r| format!(" · {r}"))
                        .unwrap_or_default()
                ),
            )
        })
        .collect();
    dk.push((
        c.label("mail_arc"),
        format!(
            "{} ({}){}",
            m.dkim.arc.result,
            m.dkim.arc.instances,
            m.dkim
                .arc
                .reason
                .as_ref()
                .map(|r| format!(" · {r}"))
                .unwrap_or_default()
        ),
    ));
    sections.push(section(c.label("mail_dkim"), rows_capped(dk, c)));

    if !h.auth_results.is_empty() {
        let rows = h
            .auth_results
            .iter()
            .map(|a| {
                (
                    a.authserv_id.clone(),
                    a.methods
                        .iter()
                        .map(|(m, r)| format!("{m}={r}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            })
            .collect();
        sections.push(section(c.label("mail_auth_results"), rows_capped(rows, c)));
    }
    if !m.attachments.is_empty() {
        let rows = m
            .attachments
            .iter()
            .map(|a| {
                (
                    format!(
                        "#{} {}",
                        a.index,
                        a.file_name.clone().unwrap_or_else(|| "-".into())
                    ),
                    format!(
                        "{}: {} · {}: {} · SHA-256 {}{}{}",
                        c.label("mail_attachment_type"),
                        a.content_type,
                        c.label("mail_attachment_size"),
                        a.size,
                        a.sha256,
                        a.creation_date_utc
                            .as_ref()
                            .map(|d| format!(" · creation-date {d}"))
                            .unwrap_or_default(),
                        a.modification_date_utc
                            .as_ref()
                            .map(|d| format!(" · modification-date {d}"))
                            .unwrap_or_default()
                    ),
                )
            })
            .collect();
        sections.push(section(c.label("mail_attachments"), rows_capped(rows, c)));
    }
    if !it.outputs.is_empty() {
        let rows = it
            .outputs
            .iter()
            .map(|o| {
                (
                    format!("{} ({})", o.rel_path, o.kind),
                    o.hashes
                        .iter()
                        .map(|(a, h)| format!("{a} {h}"))
                        .collect::<Vec<_>>()
                        .join(" · "),
                )
            })
            .collect();
        sections.push(section(c.label("mail_outputs"), rows_capped(rows, c)));
    }
    json!({"sections": sections})
}

/// The email data of the technical JSON report (language-neutral): the message analysis, the mbox container
/// summary and the files the analysis wrote with their digests.
pub fn mail_json(it: &ItemResult) -> Value {
    let d = &it.details;
    json!({
        "kind": d.get("kind"),
        "message_analysis": d.get("message_analysis"),
        "message": d.get("message"),
        "mbox": d.get("mbox").map(|m| json!({"count": m["count"], "variant": m["variant"], "not_analysed": m["not_analysed"],
                                              "problems": m["problems"], "index_file": "mbox_index.json"})),
        "worker": d.get("worker"),
        "outputs": it.outputs,
    })
}
