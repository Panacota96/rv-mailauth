//! The email options of `rv-mailauth analyze` and the `keys import|show` commands, end to end.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn bin() -> Command {
    let mut c = Command::cargo_bin("rv-mailauth").unwrap();
    c.env("RV_NO_TIMESTAMP", "1");
    c
}

fn sample(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/sample")
        .join(name)
}

fn only_dir(p: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    dirs.pop().unwrap()
}

/// The audit entries of the only run under `out`.
fn audit(out: &Path) -> Vec<Value> {
    let log = only_dir(&out.join("logs")).join("audit.jsonl");
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn entry<'a>(entries: &'a [Value], action: &str) -> &'a Value {
    entries
        .iter()
        .find(|e| e["action"] == action)
        .unwrap_or_else(|| panic!("no {action} entry"))
}

fn details<'a>(entries: &'a [Value], action: &str) -> &'a Value {
    &entry(entries, action)["details"]
}

const DOMAIN_OPTIONS: [&str; 12] = [
    "--dkim-keys",
    "--online",
    "--own-domain",
    "--extract-attachments",
    "--clock-skew",
    "--mbox-variant",
    "--max-message-mb",
    "--max-mbox-messages",
    "--worker-timeout",
    "--worker-memory-mb",
    "--isolation",
    "--item-reports",
];

#[test]
fn help_documents_every_email_option_with_default_and_example() {
    let out = bin().args(["analyze", "--help"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let options = text.split("\nOptions:").nth(1).unwrap();
    let options = options.split("EXAMPLES:").next().unwrap();
    for flag in DOMAIN_OPTIONS {
        // Each option block: the flag line, then its text with a Default: and an Example: line.
        let block = options
            .split(&format!("\n      {flag}"))
            .nth(1)
            .unwrap_or_else(|| panic!("{flag} not documented"));
        let block = block.split("\n  -").next().unwrap();
        let block = block.split("\n      --").next().unwrap();
        assert!(
            block.contains("Default:") && block.contains("Example:"),
            "{flag}: {block}"
        );
    }
    assert!(text.contains("today's DNS") || text.contains("TODAY's DNS"));
    assert!(text.contains("weaker evidence"));
    for section in ["headers.json", "dkim.json", "attachments/", "_<n>_<offset>"] {
        assert!(text.contains(section), "FILES WRITTEN lacks {section}");
    }
    for w in text.lines() {
        assert!(w.chars().count() <= 100, "line wider than 100: {w}");
    }
}

#[test]
fn scan_is_a_hidden_alias_of_analyze() {
    let help = bin().arg("--help").output().unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("analyze") && !help.contains("scan"), "{help}");
    let a = bin().args(["analyze", "--help"]).output().unwrap();
    let s = bin().args(["scan", "--help"]).output().unwrap();
    assert_eq!(s.status.code(), Some(0));
    assert_eq!(a.stdout, s.stdout);
    // And it runs: same usage errors, same work.
    bin()
        .args(["scan", "-i", ".", "--hash", "md5,sha1,sha256"])
        .assert()
        .code(2);
    let out = tempfile::tempdir().unwrap();
    bin()
        .args([
            "scan",
            "--progress",
            "none",
            "--isolation",
            "in-process",
            "-i",
        ])
        .arg(sample("evidence/02-clean-ed25519.eml"))
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(0);
    assert!(
        audit(out.path())
            .iter()
            .any(|e| e["action"] == "run_finished")
    );
}

#[test]
fn every_email_option_reaches_the_run_and_the_audit_log() {
    let out = tempfile::tempdir().unwrap();
    let keys = sample("dkim-keys.txt");
    bin()
        .args(["analyze", "--progress", "none", "-i"])
        .arg(sample("evidence/01-clean-rsa.eml"))
        .arg("-i")
        .arg(sample("evidence/14-not-aligned-attachment-date.eml"))
        .arg("-i")
        .arg(sample("evidence/12-mailbox.mbox"))
        .arg("--dkim-keys")
        .arg(&keys)
        .args([
            "--own-domain",
            "ACME.example.",
            "--own-domain",
            "@acme-group.example,acme.test",
            "--extract-attachments",
            "--clock-skew",
            "900",
            "--mbox-variant",
            "mboxo",
            "--max-message-mb",
            "1",
            "--max-mbox-messages",
            "2",
            "--worker-timeout",
            "60",
            "--worker-memory-mb",
            "512",
            "--isolation",
            "in-process",
            "--item-reports",
            "flagged",
            "--lang",
            "all",
            "-o",
        ])
        .arg(out.path())
        .assert()
        .code(predicate::in_iter([0, 3]));
    let entries = audit(out.path());
    let c = details(&entries, "analysis_configured");
    assert_eq!(c["dkim_mode"], "offline");
    assert_eq!(c["dkim_key_file"]["keys"], 4, "{c}");
    let sha = rv_mailauth_core::hash::hash_bytes(
        &std::fs::read(&keys).unwrap(),
        rv_mailauth_core::HashAlgo::Sha256,
    );
    assert_eq!(c["dkim_key_file"]["sha256"], sha.as_str());
    assert_eq!(
        c["own_domains"],
        serde_json::json!(["acme.example", "acme-group.example", "acme.test"])
    );
    assert_eq!(c["extract_attachments"], true);
    assert_eq!(c["clock_skew_s"], 900);
    assert_eq!(c["mbox_variant"], "mboxo");
    assert_eq!(c["max_message_bytes"], 1024 * 1024);
    assert_eq!(c["max_mbox_messages"], 2);
    assert_eq!(c["worker_timeout_s"], 60);
    assert_eq!(c["worker_memory_mb"], 512);
    assert_eq!(c["isolation"], "in_process");
    assert_eq!(c["item_reports"], "flagged");

    let reports = only_dir(&out.path().join("reports"));
    let items = reports.join("items");
    // --extract-attachments: the attachment is copied out and audited as an output.
    let attachment_item = std::fs::read_dir(&items)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.to_string_lossy()
                .ends_with("-14-not-aligned-attachment-date.eml")
        })
        .unwrap();
    let extracted: Vec<_> = std::fs::read_dir(attachment_item.join("attachments"))
        .unwrap()
        .collect();
    assert!(!extracted.is_empty());
    assert!(entries.iter().any(|e| {
        e["action"] == "output_written"
            && e["details"]["file"]
                .as_str()
                .is_some_and(|f| f.contains("/attachments/"))
    }));
    // --max-mbox-messages 2: the mbox's third message is not analysed.
    let stats: Value =
        serde_json::from_str(&std::fs::read_to_string(reports.join("statistics.json")).unwrap())
            .unwrap();
    let messages = stats["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["path"].as_str().unwrap().contains(".mbox#"))
        .count();
    assert_eq!(messages, 2, "{stats}");
    // --item-reports flagged: the clean RSA message (status ok) has no report files; the skip is audited.
    let clean = &stats["items"][0];
    assert_eq!(clean["status"], "ok");
    assert!(!items.join("00001-01-clean-rsa.eml/technical.json").exists());
    assert!(items.join("00001-01-clean-rsa.eml/dkim.json").exists());
    assert_eq!(
        details(&entries, "item_reports_skipped")["reason"],
        "item_reports_flagged_only"
    );
    assert!(attachment_item.join("technical.json").exists());
    // The statistics reports do not link to the reports that were not written; they say why.
    assert_eq!(stats["item_reports"], "flagged");
    assert_eq!(clean["item_reports_written"], false);
    assert_eq!(clean["report_skipped"], "item_reports_flagged_only");
    let flagged = stats["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["status"] != "ok")
        .unwrap();
    assert_eq!(flagged["item_reports_written"], true);
    assert!(flagged.get("report_skipped").is_none());
    let catalogue = |lang: &str| -> Value {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../i18n/{lang}.json"));
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    };
    for lang in ["en", "es", "fr"] {
        let html = std::fs::read_to_string(reports.join(format!("statistics.{lang}.html")))
            .unwrap()
            .replace("&#x2f;", "/"); // minijinja escapes "/" in attributes
        let labels = &catalogue(lang)["labels"];
        let not_written = labels["item_report_not_written"].as_str().unwrap();
        let escaped = not_written.replace('\'', "&#x27;");
        assert!(
            !html.contains("href=\"items/00001-01-clean-rsa.eml/"),
            "{lang}: link to a report that was not written"
        );
        assert!(
            html.contains(&format!("01-clean-rsa.eml <em>({escaped})</em>")),
            "{lang}"
        );
        assert!(html.contains("--item-reports flagged"), "{lang}");
        let link = format!(
            "href=\"items/{}/technical.{lang}.html\"",
            attachment_item.file_name().unwrap().to_string_lossy()
        );
        assert!(html.contains(&link), "{lang}: flagged item keeps its link");
        let pdf = std::fs::read(reports.join(format!("statistics.{lang}.pdf"))).unwrap();
        assert!(pdf.starts_with(b"%PDF-"));
        if lang == "en" {
            let text = String::from_utf8_lossy(&pdf);
            assert!(
                text.contains("flagged-only mode"),
                "PDF says why there is no report"
            );
            assert!(
                text.contains("--item-reports flagged"),
                "PDF explains the mode"
            );
        }
    }
    // The DKIM key file did its work: the RSA message verifies.
    assert!(
        clean["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "DKIM_SIGNATURE_VALID"),
        "{clean}"
    );
}

#[test]
fn default_isolation_is_a_worker_process_and_reports_are_written_for_every_item() {
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["analyze", "--progress", "none", "-i"])
        .arg(sample("evidence/02-clean-ed25519.eml"))
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(0);
    let entries = audit(out.path());
    let c = details(&entries, "analysis_configured");
    assert_eq!(c["isolation_requested"], "worker_process_of_frontend");
    assert_eq!(c["isolation"], "worker_process");
    assert_eq!(c["item_reports"], "all");
    assert_eq!(c["dkim_mode"], "offline");
    assert_eq!(c["clock_skew_s"], 300);
    assert_eq!(c["mbox_variant"], "mboxrd");
    assert_eq!(c["max_message_bytes"], 200 * 1024 * 1024);
    assert!(c["dkim_key_file"].is_null());
    assert!(
        only_dir(&out.path().join("reports"))
            .join("items/00001-02-clean-ed25519.eml/technical.json")
            .exists()
    );
}

/// --online is not refused with --isolation in-process: DNS lookups always run in the main process (the
/// core never lets a worker use the network), so both isolation modes accept it. A message without a DKIM
/// signature needs no lookup, so this test makes no network request.
#[test]
fn online_mode_is_accepted_with_both_isolations_and_recorded() {
    for isolation in ["in-process", "worker"] {
        let out = tempfile::tempdir().unwrap();
        bin()
            .args([
                "analyze",
                "--online",
                "--progress",
                "none",
                "--isolation",
                isolation,
                "-i",
            ])
            .arg(sample("evidence/08-display-name-spoof.eml"))
            .args(["--own-domain", "acme.example", "-o"])
            .arg(out.path())
            .assert()
            .code(0);
        let entries = audit(out.path());
        assert_eq!(
            details(&entries, "analysis_configured")["dkim_mode"],
            "online"
        );
        assert!(!entries.iter().any(|e| e["action"] == "dkim_key_fetched"));
    }
}

#[test]
fn bad_email_option_values_are_usage_errors() {
    let file = sample("evidence/01-clean-rsa.eml");
    let file = file.to_str().unwrap();
    for bad in [
        vec!["--own-domain", "not a domain"],
        vec!["--own-domain", "localhost"],
        vec!["--own-domain", "-acme.example"],
        vec!["--clock-skew", "-5"],
        vec!["--clock-skew", "90000"],
        vec!["--mbox-variant", "mboxcl2"],
        vec!["--max-message-mb", "0"],
        vec!["--max-mbox-messages", "0"],
        vec!["--worker-timeout", "0"],
        vec!["--worker-memory-mb", "16"],
        vec!["--isolation", "thread"],
        vec!["--item-reports", "some"],
        vec!["--dkim-keys", "no-such-key-file.txt"],
        vec!["--dkim-keys", "."],
    ] {
        let out = tempfile::tempdir().unwrap();
        bin()
            .args(["analyze", "--progress", "none", "-i", file])
            .args(&bad)
            .arg("-o")
            .arg(out.path())
            .assert()
            .code(2);
        assert!(
            !out.path().join("logs").exists(),
            "{bad:?}: a usage error must not start a run"
        );
    }
}

// ------------------------------------------------------------------------------------------ keys

const ZONE: &str = "$ORIGIN example.org.\n\
@ 3600 IN SOA ns1.example.org. host.example.org. ( 1 7200 3600 1209600 3600 )\n\
@ IN MX 10 mx.example.org.\n\
www IN A 192.0.2.1\n\
@ IN TXT \"v=spf1 -all\"\n\
_dmarc.example.org. IN TXT \"v=DMARC1; p=reject\"\n\
old._domainkey.example.org. IN TXT \"v=DKIM1; p=\"\n";

fn zone_with_sample_keys(dir: &Path) -> PathBuf {
    let p = dir.join("archive.zone");
    let keys = std::fs::read_to_string(sample("dkim-keys.txt")).unwrap();
    std::fs::write(&p, format!("{ZONE}{keys}")).unwrap();
    p
}

#[test]
fn keys_import_writes_a_normalised_key_file_and_audits_the_import() {
    let tmp = tempfile::tempdir().unwrap();
    let zone = zone_with_sample_keys(tmp.path());
    let key_file = tmp.path().join("keys/case-keys.txt");
    let out = tmp.path().join("out");
    bin()
        .args(["keys", "import"])
        .arg(&zone)
        .arg("--key-file")
        .arg(&key_file)
        .arg("-o")
        .arg(&out)
        .args(["--case", "CASE-T", "--actor", "Tester"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("4 DKIM keys written"))
        .stdout(predicate::str::contains("6 records ignored"));
    let text = std::fs::read_to_string(&key_file).unwrap();
    let names: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split('\t').next().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "ed2026._domainkey.example.org",
            "m1._domainkey.mailer.example.com",
            "s2025._domainkey.example.org",
            "s2026._domainkey.example.org"
        ]
    );
    // The normalised file parses back without a problem, with the same keys as the original.
    let (keys, problems) = rv_mailauth_core::dkim::parse_key_file(&text);
    assert!(problems.is_empty() && keys.len() == 4, "{problems:?}");
    let sha = |b: &[u8]| rv_mailauth_core::hash::hash_bytes(b, rv_mailauth_core::HashAlgo::Sha256);
    let zone_sha = sha(&std::fs::read(&zone).unwrap());
    assert!(
        text.contains(&zone_sha),
        "the header names the source digest"
    );
    // Its own audit run: source digest, every key, every ignored record, the key file digest.
    let entries = audit(&out);
    let started = details(&entries, "keys_import_started");
    assert_eq!(started["sources"][0]["sha256"], zone_sha.as_str());
    assert_eq!(started["case_id"], "CASE-T");
    assert_eq!(entry(&entries, "keys_import_started")["actor"], "Tester");
    assert_eq!(
        entries
            .iter()
            .filter(|e| e["action"] == "key_imported")
            .count(),
        4
    );
    let ignored: Vec<&str> = entries
        .iter()
        .filter(|e| e["action"] == "record_ignored")
        .map(|e| e["details"]["reason"].as_str().unwrap())
        .collect();
    assert!(ignored.contains(&"other_record_type") && ignored.contains(&"not_a_dkim_key_name"));
    assert!(ignored.contains(&"revoked_key"), "{ignored:?}");
    let written = details(&entries, "output_written");
    assert_eq!(written["sha256"], sha(text.as_bytes()).as_str());
    let ed = entries
        .iter()
        .find(|e| e["action"] == "key_imported" && e["details"]["selector"] == "ed2026")
        .unwrap();
    assert_eq!(ed["details"]["key_type"], "ed25519");
    assert_eq!(ed["details"]["bits"], 256);
    let log_dir = only_dir(&out.join("logs"));
    assert!(log_dir.join("environment.json").is_file());
    bin().arg("verify-log").arg(&log_dir).assert().code(0);
    // The imported file is usable by analyze: the RSA sample verifies with it.
    bin()
        .args(["keys", "show"])
        .arg(&key_file)
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "4 usable keys, 0 records not usable",
        ));
    // Never overwritten.
    bin()
        .args(["keys", "import"])
        .arg(&zone)
        .arg("--key-file")
        .arg(&key_file)
        .arg("-o")
        .arg(&out)
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "already exists: choose another --key-file",
        ));
}

#[test]
fn keys_import_refuses_malformed_records_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let cases = [
        // A DKIM record whose key cannot be used.
        "bad._domainkey.example.org\tv=DKIM1; k=rsa; p=AAAA\n".to_string(),
        // A DKIM record relative to $ORIGIN: refused, not silently skipped.
        "$ORIGIN example.org.\ns1._domainkey IN TXT \"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\"\n".to_string(),
        // Two different keys under one name.
        "a._domainkey.example.org\tv=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n\
         a._domainkey.example.org\tv=DKIM1; k=ed25519; p=gLFtgEWf/adXNdiOuX1lF3mdfGWJ50NglMFoPaxwK/E=\n"
            .to_string(),
        // A line that is no DNS record at all.
        "this is not a zone file\n".to_string(),
        // Nothing to import.
        "; empty\n@ IN A 192.0.2.1\n".to_string(),
    ];
    for (i, text) in cases.iter().enumerate() {
        let src = tmp.path().join(format!("src-{i}.txt"));
        std::fs::write(&src, text).unwrap();
        let key_file = tmp.path().join(format!("keys-{i}.txt"));
        let out = tmp.path().join(format!("out-{i}"));
        bin()
            .args(["keys", "import"])
            .arg(&src)
            .arg("--key-file")
            .arg(&key_file)
            .arg("-o")
            .arg(&out)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("error:"));
        assert!(!key_file.exists() && !out.exists(), "case {i}: {text}");
    }
    // Missing source: runtime error.
    bin()
        .args(["keys", "import", "no-such-archive.zone", "--key-file"])
        .arg(tmp.path().join("k.txt"))
        .assert()
        .code(1);
    // Usage: a source and --key-file are required.
    bin()
        .args(["keys", "import", "--key-file", "k.txt"])
        .assert()
        .code(2);
    bin().args(["keys", "import", "a.zone"]).assert().code(2);
}

#[test]
fn keys_show_lists_selector_domain_type_and_bits() {
    bin()
        .args(["keys", "show"])
        .arg(sample("dkim-keys.txt"))
        .assert()
        .code(0)
        .stdout(predicate::str::is_match(r"s2026\s+example\.org\s+rsa\s+2048").unwrap())
        .stdout(predicate::str::is_match(r"ed2026\s+example\.org\s+ed25519\s+256").unwrap())
        .stdout(predicate::str::is_match(r"m1\s+mailer\.example\.com\s+rsa\s+2048").unwrap())
        .stdout(predicate::str::contains(
            "4 usable keys, 0 records not usable",
        ));
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("bad.txt");
    std::fs::write(
        &bad,
        "ok._domainkey.example.org\tv=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\nbad._domainkey.example.org\tv=DKIM1; p=AAAA\n",
    )
    .unwrap();
    bin()
        .args(["keys", "show"])
        .arg(&bad)
        .assert()
        .code(2)
        .stdout(predicate::str::contains(
            "1 usable keys, 1 records not usable",
        ))
        .stdout(predicate::str::contains("line 2"));
    bin()
        .args(["keys", "show", "no-such-file.txt"])
        .assert()
        .code(1);
    for args in [vec!["keys"], vec!["keys", "import"], vec!["keys", "show"]] {
        let help = bin().args(&args).arg("--help").output().unwrap();
        let help = String::from_utf8(help.stdout).unwrap();
        assert!(help.contains("EXAMPLES:"), "{args:?}");
    }
}
