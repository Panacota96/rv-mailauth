//! Worker-process isolation end to end, with the real executable as the worker (`<exe> worker …`): the sample
//! set gives exactly the in-process findings, and a crashing or hanging worker costs one message, never the
//! run or the audit chain. One test function on purpose: it sets the debug-only fault variables.

use rv_mailauth_core::model::{DomainOptions, Isolation};
use rv_mailauth_core::{HashAlgo, RunConfig, run};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_with(
    inputs: Vec<PathBuf>,
    out: &Path,
    domain: DomainOptions,
) -> rv_mailauth_core::RunSummary {
    let cfg = RunConfig {
        inputs,
        algorithms: vec![HashAlgo::Sha256],
        out_dir: out.to_path_buf(),
        langs: vec!["en".into()],
        actor: "worker-test".into(),
        tsa_url: None,
        domain,
        ..RunConfig::default()
    };
    run(&cfg, &mut |_| {}, &AtomicBool::new(false)).unwrap()
}

fn codes(report_dir: &Path) -> BTreeMap<String, (Vec<String>, Value)> {
    let mut m = BTreeMap::new();
    for e in std::fs::read_dir(report_dir.join("items")).unwrap() {
        let t: Value = serde_json::from_str(
            &std::fs::read_to_string(e.unwrap().path().join("technical.json")).unwrap(),
        )
        .unwrap();
        let mut c: Vec<String> = t["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["code"].as_str().unwrap().to_string())
            .collect();
        c.sort();
        let name = t["item"]["file_name"].as_str().unwrap().to_string();
        m.insert(name, (c, t["email"]["worker"].clone()));
    }
    m
}

#[test]
fn worker_processes_match_in_process_and_contain_faults() {
    let exp: Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("examples/sample/expected_findings.json")).unwrap(),
    )
    .unwrap();
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_rv-mailauth"));
    let opts = DomainOptions {
        dkim_keys: Some(root().join("examples/sample/dkim-keys.txt")),
        own_domains: vec!["acme.example".into()],
        isolation: Isolation::Subprocess { exe: exe.clone() },
        ..DomainOptions::default()
    };
    let evidence = root().join("examples/sample/evidence");

    // 1. Same findings as the in-process analysis (expected_findings.json), every message in a worker.
    let out = tempfile::tempdir().unwrap();
    let s = run_with(vec![evidence.clone()], out.path(), opts.clone());
    let got = codes(&s.report_dir);
    let want: BTreeMap<String, Vec<String>> = serde_json::from_value(exp["files"].clone()).unwrap();
    for (name, (c, worker)) in &got {
        let key = match name.rsplit_once('@') {
            Some((k, _)) if k.contains('#') => k.to_string(),
            _ => name.clone(),
        };
        assert_eq!(Some(c), want.get(&key), "{name}");
        if !name.ends_with(".mbox") {
            assert_eq!(worker["status"], "completed", "{name}: {worker}");
            assert_eq!(worker["protocol"], "rv-mailauth-worker/1");
        }
    }
    assert_eq!(got.len(), want.len());
    let audit = std::fs::read_to_string(s.log_dir.join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"isolation\":\"worker_process\""));

    // 2. A crashing worker: PARSER_FAILED for each message, its partial output audited, the run completes.
    // SAFETY: this binary has a single test; the variables only reach the worker children (debug builds).
    unsafe { std::env::set_var("RV_WORKER_TEST_FAULT", "crash") };
    let out = tempfile::tempdir().unwrap();
    let s = run_with(
        vec![
            evidence.join("01-clean-rsa.eml"),
            evidence.join("12-mailbox.mbox"),
        ],
        out.path(),
        opts.clone(),
    );
    let got = codes(&s.report_dir);
    assert_eq!(got.len(), 5, "{got:?}"); // eml + mbox + 3 messages
    for (name, (c, worker)) in &got {
        if name.ends_with(".mbox") {
            assert!(
                c.is_empty(),
                "{name}: the container is split in process: {c:?}"
            );
            continue;
        }
        assert!(c.contains(&"PARSER_FAILED".to_string()), "{name}: {c:?}");
        assert_eq!(worker["reason"], "crashed", "{name}");
    }
    let audit = std::fs::read_to_string(s.log_dir.join("audit.jsonl")).unwrap();
    assert!(audit.contains("partial-before-crash.bin"));
    assert!(audit.contains("\"action\":\"run_finished\""));

    // 3. A hanging worker is killed at the time limit.
    unsafe {
        std::env::set_var("RV_WORKER_TEST_FAULT", "hang");
        std::env::set_var("RV_WORKER_TEST_TIMEOUT_S", "1");
    }
    let out = tempfile::tempdir().unwrap();
    let s = run_with(
        vec![evidence.join("02-clean-ed25519.eml")],
        out.path(),
        opts.clone(),
    );
    let got = codes(&s.report_dir);
    let (c, worker) = &got["02-clean-ed25519.eml"];
    assert!(c.contains(&"PARSER_FAILED".to_string()));
    assert_eq!(worker["reason"], "timeout");

    // 4. A worker that exceeds its memory cap (Job Object on Windows, RLIMIT_AS on Unix).
    unsafe { std::env::set_var("RV_WORKER_TEST_FAULT", "oom") };
    let out = tempfile::tempdir().unwrap();
    let s = run_with(
        vec![evidence.join("02-clean-ed25519.eml")],
        out.path(),
        DomainOptions {
            worker_memory_mb: 256,
            ..opts
        },
    );
    let got = codes(&s.report_dir);
    let (c, worker) = &got["02-clean-ed25519.eml"];
    assert!(c.contains(&"PARSER_FAILED".to_string()));
    assert_eq!(worker["reason"], "memory_limit", "{worker}");
    unsafe {
        std::env::remove_var("RV_WORKER_TEST_FAULT");
        std::env::remove_var("RV_WORKER_TEST_TIMEOUT_S");
    }

    // 5. The CLI binary uses worker processes by default (no option given).
    let out = tempfile::tempdir().unwrap();
    let st = std::process::Command::new(&exe)
        .args([
            "analyze",
            "--hash",
            "sha256",
            "--progress",
            "none",
            "--no-timestamp",
            "-i",
        ])
        .arg(evidence.join("01-clean-rsa.eml"))
        .arg("-o")
        .arg(out.path())
        .status()
        .unwrap();
    assert!(st.code().is_some_and(|c| c <= 3), "{st:?}");
    let logs = std::fs::read_dir(out.path().join("logs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let audit = std::fs::read_to_string(logs.join("audit.jsonl")).unwrap();
    assert!(
        audit.contains("\"isolation\":\"worker_process\"")
            && audit.contains("\"isolation_requested\":\"worker_process_of_frontend\""),
        "default isolation not recorded as a worker process"
    );
}
