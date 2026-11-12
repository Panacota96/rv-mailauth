//! `rv-mailauth keys import|show`: DKIM public-key files for offline verification (`analyze --dkim-keys`).
//!
//! `import` reads archived DNS TXT records (BIND zone-file lines or "selector._domainkey.domain<TAB>TXT"),
//! keeps the DKIM key records, validates each one with the same parser `analyze` uses
//! (`rv_mailauth_core::dkim::parse_key_file`), and writes a normalised key file (one
//! `name<TAB>value` line per key, sorted). The import is its own audit run (`<OUT>/logs/<RUN-ID>/`): the
//! SHA-256 of every source file, every key imported or record ignored, and the SHA-256 of the key file
//! written. Nothing is fetched from the network.

use rv_mailauth_core::audit::AuditLog;
use rv_mailauth_core::hash::{HashAlgo, hash_bytes};
use rv_mailauth_core::model::KeyRecord;
use rv_mailauth_core::trust;
use rv_mailauth_core::{TOOL_NAME, TOOL_VERSION, dkim};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const EXIT_OK: u8 = 0;
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_USAGE: u8 = 2;

/// Resource-record types that may appear in an archived zone file and are not TXT: skipped by `import`.
const OTHER_RR_TYPES: &[&str] = &[
    "A", "AAAA", "MX", "NS", "CNAME", "SOA", "SRV", "PTR", "CAA", "DS", "DNSKEY", "RRSIG", "NSEC",
    "NSEC3", "TLSA", "HTTPS", "SVCB", "SPF", "HINFO", "NAPTR", "SSHFP", "LOC", "DNAME",
];

/// What one key looks like: (selector, domain, key type, bits).
pub struct KeyInfo {
    pub selector: String,
    pub domain: String,
    pub key_type: String,
    pub bits: Option<u64>,
}

fn sha256(b: &[u8]) -> String {
    hash_bytes(b, HashAlgo::Sha256)
}

/// Tag value of a DKIM key record ("k", "p", …); tags are case-sensitive (RFC 6376 3.2), values trimmed.
fn tag<'a>(txt: &'a str, name: &str) -> Option<&'a str> {
    txt.split(';').find_map(|t| {
        let (k, v) = t.split_once('=')?;
        (k.trim() == name).then_some(v.trim())
    })
}

/// Standard base64 (whitespace ignored, padding optional).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut n) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
        }
    }
    Some(out)
}

/// One DER element: (tag, content, rest).
fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&t, b) = b.split_first()?;
    let (&l, mut b) = b.split_first()?;
    let len = if l < 0x80 {
        l as usize
    } else {
        let n = (l & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < n {
            return None;
        }
        let v = b[..n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        b = &b[n..];
        v
    };
    (b.len() >= len).then(|| (t, &b[..len], &b[len..]))
}

fn integer_bits(n: &[u8]) -> u64 {
    let n: &[u8] = match n.iter().position(|&x| x != 0) {
        Some(i) => &n[i..],
        None => return 0,
    };
    n.len() as u64 * 8 - n[0].leading_zeros() as u64
}

/// Modulus size of an RSA key given as SubjectPublicKeyInfo (RFC 6376) or bare RSAPublicKey (PKCS#1).
fn rsa_bits(key: &[u8]) -> Option<u64> {
    let (t, seq, _) = der(key)?;
    if t != 0x30 {
        return None;
    }
    let (t, first, rest) = der(seq)?;
    if t == 0x02 {
        return Some(integer_bits(first)); // PKCS#1 RSAPublicKey: modulus first
    }
    let (t, bits, _) = der(rest)?;
    if t != 0x03 || bits.is_empty() {
        return None;
    }
    let (t, inner, _) = der(&bits[1..])?;
    if t != 0x30 {
        return None;
    }
    let (t, n, _) = der(inner)?;
    (t == 0x02).then(|| integer_bits(n))
}

pub fn key_info(k: &KeyRecord) -> KeyInfo {
    let (selector, domain) = k
        .name
        .split_once("._domainkey.")
        .map(|(s, d)| (s.to_string(), d.to_string()))
        .unwrap_or_else(|| (String::new(), k.name.clone()));
    let key_type = tag(&k.txt, "k").unwrap_or("rsa").to_ascii_lowercase();
    let raw = tag(&k.txt, "p").and_then(base64_decode).unwrap_or_default();
    let bits = match key_type.as_str() {
        "ed25519" => (raw.len() == 32).then_some(256),
        "rsa" => rsa_bits(&raw),
        _ => None,
    };
    KeyInfo {
        selector,
        domain,
        key_type,
        bits,
    }
}

/// Why `import` skipped a record ("other_record_type", "not_a_dkim_key_name") or refused it (None).
fn ignorable(problem: &str, lines: &[&str]) -> Option<&'static str> {
    if problem.contains("is not selector._domainkey.domain") {
        // TXT records of other names (SPF, DMARC, verification tokens) in an archived zone. A name with
        // "_domainkey" in it is a DKIM record written relative to $ORIGIN: refused, never skipped silently.
        let name = problem.split('"').nth(1).unwrap_or_default();
        return (!name.contains("_domainkey")).then_some("not_a_dkim_key_name");
    }
    if problem.ends_with(": no TXT record") {
        let n: usize = problem
            .strip_prefix("line ")?
            .split(':')
            .next()?
            .parse()
            .ok()?;
        let line = lines.get(n.checked_sub(1)?)?;
        // name [ttl] [class] TYPE …: the first token after the optional TTL and class is the type.
        let rr_type = line.split_whitespace().skip(1).find(|t| {
            !(t.bytes().all(|b| b.is_ascii_digit())
                || ["IN", "CH", "HS"].iter().any(|c| t.eq_ignore_ascii_case(c)))
        })?;
        let other = OTHER_RR_TYPES
            .iter()
            .any(|r| rr_type.eq_ignore_ascii_case(r));
        return other.then_some("other_record_type");
    }
    None
}

/// Revoked keys (`p=` empty, RFC 6376 3.6.1) are history, not keys: skipped with a note.
fn revoked(problem: &str, lines: &[&str]) -> bool {
    let n: Option<usize> = problem
        .strip_prefix("line ")
        .and_then(|p| p.split(':').next())
        .and_then(|p| p.parse().ok());
    let Some(line) = n.and_then(|n| lines.get(n.wrapping_sub(1))) else {
        return false;
    };
    problem.ends_with("not a usable DKIM key record")
        && line
            .replace(['"', ' ', '\t'], "")
            .split(';')
            .any(|t| t == "p=" || t == "p=)" || t.starts_with("p=)"))
}

pub struct ImportArgs {
    pub sources: Vec<PathBuf>,
    pub output: PathBuf,
    pub out_dir: PathBuf,
    pub actor: String,
    pub case_id: Option<String>,
    pub tsa_url: Option<String>,
    pub command_line: Vec<String>,
}

struct Source {
    path: PathBuf,
    bytes: u64,
    sha256: String,
    keys: Vec<KeyRecord>,
    ignored: Vec<(String, &'static str)>,
}

fn new_run_id() -> String {
    let seed = format!(
        "{:?}-{}-{}",
        std::time::SystemTime::now(),
        std::process::id(),
        rv_mailauth_core::env::hostname()
    );
    format!(
        "{}-{}",
        rv_mailauth_core::time::utc_compact(),
        &sha256(seed.as_bytes())[..6]
    )
}

/// `keys import`. Every record is validated before anything is written: one malformed DKIM record (or two
/// different keys under the same name) refuses the whole import with exit 2 and writes nothing.
pub fn import(a: ImportArgs) -> u8 {
    let mut sources = Vec::new();
    let mut refused = Vec::new();
    for p in &a.sources {
        let bytes = match std::fs::read(p) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: cannot read {}: {}", p.display(), e);
                return EXIT_ERROR;
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        let lines: Vec<&str> = text.lines().collect();
        let (keys, problems) = dkim::parse_key_file(&text);
        let mut ignored = Vec::new();
        for pr in problems {
            if let Some(why) = ignorable(&pr, &lines) {
                ignored.push((pr, why));
            } else if revoked(&pr, &lines) {
                ignored.push((pr, "revoked_key"));
            } else {
                refused.push(format!("{}: {}", p.display(), pr));
            }
        }
        sources.push(Source {
            path: p.clone(),
            bytes: bytes.len() as u64,
            sha256: sha256(&bytes),
            keys,
            ignored,
        });
    }
    // One key per name: identical duplicates are merged, different ones refused.
    let mut by_name: BTreeMap<String, (KeyRecord, String)> = BTreeMap::new();
    for s in &sources {
        for k in &s.keys {
            let at = format!("{}:{}", s.path.display(), k.line);
            match by_name.get(&k.name) {
                Some((old, old_at)) if old.txt != k.txt => refused.push(format!(
                    "{at}: {} has a different key than {old_at}: import one key per selector (archive the other separately)",
                    k.name
                )),
                Some(_) => {}
                None => {
                    by_name.insert(k.name.clone(), (k.clone(), at));
                }
            }
        }
    }
    if !refused.is_empty() {
        eprintln!("error: not imported (nothing written): records that are not usable DKIM keys:");
        for r in &refused {
            eprintln!("  - {}", r);
        }
        return EXIT_USAGE;
    }
    if by_name.is_empty() {
        eprintln!(
            "error: no DKIM key record (selector._domainkey.domain TXT \"v=DKIM1; ...\") found"
        );
        return EXIT_USAGE;
    }
    if a.output.exists() {
        eprintln!(
            "error: {} already exists: choose another --output (an imported key file is never overwritten)",
            a.output.display()
        );
        return EXIT_ERROR;
    }

    // The normalised file, checked by re-parsing it before it is written.
    let mut text = format!(
        "# DKIM public keys normalised by {TOOL_NAME} {TOOL_VERSION} `keys import` ({}).\n# Use with: {TOOL_NAME} analyze --dkim-keys <this file>\n",
        rv_mailauth_core::time::utc_now()
    );
    for s in &sources {
        text.push_str(&format!(
            "# source: {} ({} bytes, sha256 {})\n",
            s.path.display(),
            s.bytes,
            s.sha256
        ));
    }
    for (name, (k, _)) in &by_name {
        text.push_str(&format!("{}\t{}\n", name, k.txt.trim()));
    }
    let (check, problems) = dkim::parse_key_file(&text);
    if !problems.is_empty() || check.len() != by_name.len() {
        eprintln!(
            "error: internal check failed: the normalised file does not parse back ({problems:?})"
        );
        return EXIT_ERROR;
    }

    let run_id = new_run_id();
    let log_dir = a.out_dir.join("logs").join(&run_id);
    let mut log = match AuditLog::create(&log_dir, &run_id, &a.actor) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "error: cannot create the audit log in {}: {}",
                log_dir.display(),
                e
            );
            return EXIT_ERROR;
        }
    };
    let env = rv_mailauth_core::env::describe(TOOL_NAME, TOOL_VERSION, "cli", &a.command_line);
    let result = (|| -> std::io::Result<()> {
        std::fs::write(
            log_dir.join("environment.json"),
            serde_json::to_vec_pretty(&env).unwrap_or_default(),
        )?;
        log.record(
            "keys_import_started",
            None,
            json!({"run_id": run_id, "tool": TOOL_NAME, "version": TOOL_VERSION, "case_id": a.case_id,
                   "output": a.output.display().to_string(),
                   "sources": sources.iter().map(|s| json!({"path": s.path.display().to_string(), "bytes": s.bytes, "sha256": s.sha256})).collect::<Vec<_>>()}),
        )?;
        for s in &sources {
            let p = s.path.display().to_string();
            for (problem, why) in &s.ignored {
                log.record(
                    "record_ignored",
                    Some(&p),
                    json!({"reason": why, "detail": problem}),
                )?;
            }
        }
        for (name, (k, at)) in &by_name {
            let i = key_info(k);
            log.record(
                "key_imported",
                Some(at),
                json!({"name": name, "selector": i.selector, "domain": i.domain, "key_type": i.key_type,
                       "bits": i.bits, "txt_sha256": sha256(k.txt.trim().as_bytes())}),
            )?;
        }
        if let Some(parent) = a.output.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&a.output)
            .and_then(|mut f| f.write_all(text.as_bytes()))?;
        log.record(
            "output_written",
            Some(&a.output.display().to_string()),
            json!({"kind": "dkim_key_file", "bytes": text.len(), "sha256": sha256(text.as_bytes()), "keys": by_name.len()}),
        )?;
        log.record(
            "keys_import_finished",
            None,
            json!({"keys": by_name.len(), "ignored": sources.iter().map(|s| s.ignored.len()).sum::<usize>()}),
        )?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = log.record("run_failed", None, json!({"error": e.to_string()}));
        eprintln!("error: {}", e);
        return EXIT_ERROR;
    }
    let ts = match &a.tsa_url {
        None => "off".to_string(),
        Some(url) => match trust::timestamp_head(&log_dir, log.entries(), log.head(), url) {
            Ok(t) => match log.record("timestamp_obtained", Some(&t.file), t.to_json()) {
                Ok(_) => format!("ok {}", t.gen_time),
                Err(e) => {
                    eprintln!("error: {}", e);
                    return EXIT_ERROR;
                }
            },
            Err(e) => {
                let (seq, head) = (log.entries(), log.head().to_string());
                let _ = log.record(
                    "timestamp_pending",
                    None,
                    json!({"tsa": url, "reason": e, "covers_seq": seq, "head": head}),
                );
                format!(
                    "pending ({e}); run `{TOOL_NAME} timestamp {}` later",
                    log_dir.display()
                )
            }
        },
    };
    let ignored: usize = sources.iter().map(|s| s.ignored.len()).sum();
    println!(
        "OK  {} DKIM keys written to {} (sha256 {})",
        by_name.len(),
        a.output.display(),
        sha256(text.as_bytes())
    );
    for s in &sources {
        println!("    source {} sha256 {}", s.path.display(), s.sha256);
    }
    if ignored > 0 {
        println!(
            "    {ignored} records ignored (other record types, other TXT names, revoked keys): see the audit log"
        );
    }
    println!("    timestamp: {ts}");
    println!("    logs: {}", log_dir.display());
    EXIT_OK
}

/// `keys show`: one line per key; records that cannot be used are listed and give exit 2.
pub fn show(path: &Path) -> u8 {
    let (keys, problems, digest) = match dkim::load_key_file(path) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    println!("{}  sha256 {}", path.display(), digest);
    println!(
        "{:<5} {:<24} {:<32} {:<8} {:>5}",
        "LINE", "SELECTOR", "DOMAIN", "TYPE", "BITS"
    );
    for k in &keys {
        let i = key_info(k);
        println!(
            "{:<5} {:<24} {:<32} {:<8} {:>5}",
            k.line,
            i.selector,
            i.domain,
            i.key_type,
            i.bits.map(|b| b.to_string()).unwrap_or_else(|| "?".into())
        );
    }
    println!(
        "{} usable keys, {} records not usable",
        keys.len(),
        problems.len()
    );
    for p in &problems {
        println!("  - {}", p);
    }
    if problems.is_empty() {
        EXIT_OK
    } else {
        EXIT_USAGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_bits() {
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
        assert_eq!(integer_bits(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(integer_bits(&[0x01]), 1);
        let ed = KeyRecord {
            name: "ed._domainkey.example.org".into(),
            txt: "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into(),
            ..Default::default()
        };
        let i = key_info(&ed);
        assert_eq!(
            (
                i.selector.as_str(),
                i.domain.as_str(),
                i.key_type.as_str(),
                i.bits
            ),
            ("ed", "example.org", "ed25519", Some(256))
        );
    }
}
