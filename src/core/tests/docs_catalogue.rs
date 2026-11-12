//! docs/reports.md lists every finding code with its severity and the exact English wording of
//! i18n/en.json (title, what it shows, what it does not prove), and every limitation printed in the reports.
//! This test regenerates both tables and fails when the page differs;
//! `RV_UPDATE_DOCS=1 cargo test -p rv-mailauth-core --test docs_catalogue` rewrites them.

use rv_mailauth_core::model::{FINDING_CODES, PIPELINE_FINDING_CODES, Severity};
use serde_json::Value;
use std::path::{Path, PathBuf};

const START: &str = "<!-- findings-catalogue:start (generated from i18n/en.json by src/core/tests/docs_catalogue.rs; do not edit by hand) -->";
const END: &str = "<!-- findings-catalogue:end -->";
const LIM_START: &str = "<!-- limitations:start (generated from i18n/en.json by src/core/tests/docs_catalogue.rs; do not edit by hand) -->";
const LIM_END: &str = "<!-- limitations:end -->";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn table(codes: &[(&str, Severity)], findings: &Value, severity: &Value) -> String {
    let mut out = String::from(
        "| Code | Severity | Title | What it shows | What it does not prove |\n| --- | --- | --- | --- | --- |\n",
    );
    for (code, sev) in codes {
        let f = &findings[*code];
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            code,
            severity[sev.key()].as_str().unwrap_or_default(),
            cell(f["title"].as_str().unwrap_or_default()),
            cell(f["shows"].as_str().unwrap_or_default()),
            cell(f["does_not_prove"].as_str().unwrap_or_default()),
        ));
    }
    out
}

fn en() -> Value {
    serde_json::from_str(&std::fs::read_to_string(root().join("i18n/en.json")).unwrap()).unwrap()
}

fn limitations() -> String {
    let en = en();
    let mut out = format!("{LIM_START}\n\n| Code | Text (en.json) |\n| --- | --- |\n");
    for (code, text) in en["limitations"].as_object().unwrap() {
        let text = cell(text.as_str().unwrap_or_default());
        out.push_str(&format!("| `{code}` | {text} |\n"));
    }
    out.push_str(&format!("\n{LIM_END}"));
    out
}

fn generated() -> String {
    let en = en();
    format!(
        "{START}\n\n### Email findings\n\n{}\n### Pipeline findings (non-email files, read errors, duplicates, case folder)\n\n{}\n{END}",
        table(FINDING_CODES, &en["findings"], &en["severity"]),
        table(PIPELINE_FINDING_CODES, &en["findings"], &en["severity"]),
    )
}

#[test]
fn every_catalogue_code_has_a_severity_and_no_other() {
    let en = en();
    let mut catalogue: Vec<&str> = en["findings"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut known: Vec<&str> = FINDING_CODES
        .iter()
        .chain(PIPELINE_FINDING_CODES)
        .map(|(c, _)| *c)
        .collect();
    catalogue.sort();
    known.sort();
    assert_eq!(catalogue, known);
}

#[test]
fn pipeline_severities_are_the_ones_the_code_emits() {
    let src: String = ["analyzer.rs", "run.rs"]
        .iter()
        .map(|f| std::fs::read_to_string(root().join("src/core/src").join(f)).unwrap())
        .collect();
    for (code, sev) in PIPELINE_FINDING_CODES {
        let variant = match sev {
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        };
        let emitted = format!("Finding::new(\"{code}\", Severity::{variant})");
        assert!(src.contains(&emitted), "{code}: not emitted as {emitted}");
    }
}

/// Replaces the block between `start` and `end` with `fresh` (RV_UPDATE_DOCS=1) or fails when it differs.
fn check_block(start: &str, end: &str, fresh: &str) {
    // Both blocks live in one file: one test at a time reads and (with RV_UPDATE_DOCS=1) rewrites it.
    static PAGE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = PAGE.lock().unwrap_or_else(|e| e.into_inner());
    let page_path = root().join("docs/reports.md");
    let page = std::fs::read_to_string(&page_path)
        .unwrap()
        .replace("\r\n", "\n");
    let (Some(a), Some(b)) = (page.find(start), page.find(end)) else {
        panic!("docs/reports.md has no generated block {start}");
    };
    let current = &page[a..b + end.len()];
    if current != fresh {
        if std::env::var("RV_UPDATE_DOCS").as_deref() == Ok("1") {
            let updated = format!("{}{}{}", &page[..a], fresh, &page[b + end.len()..]);
            std::fs::write(&page_path, updated).unwrap();
        } else {
            panic!(
                "docs/reports.md differs from i18n/en.json ({start}): run \
                 RV_UPDATE_DOCS=1 cargo test -p rv-mailauth-core --test docs_catalogue"
            );
        }
    }
}

#[test]
fn reports_page_lists_the_catalogue_exactly() {
    check_block(START, END, &generated());
}

#[test]
fn reports_page_lists_the_limitations_exactly() {
    check_block(LIM_START, LIM_END, &limitations());
}
