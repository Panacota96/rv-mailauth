//! DKIM and ARC verification OFFLINE, with public keys the examiner supplies.
//!
//! The verifier is mail-auth's (`MessageAuthenticator`), built with a resolver that has **no name server at
//! all** (`ResolverConfig::from_parts(None, vec![], vec![])`): a key that is not in the injected cache fails at
//! once ("no connections available") and becomes `key_not_available` — no query can leave the machine. Keys
//! come from the examiner's key file (`--dkim-keys`) and, in online mode, from records the PARENT process
//! fetched (`DomainOptions::fetched_keys`, fetched by the parent); this module itself has no network code.
//!
//! Key file format (one key per record; `#` comments and blank lines ignored):
//!
//! ```text
//! s2026._domainkey.example.org<TAB>v=DKIM1; k=rsa; p=MIIBIjANBgkq…
//! ed._domainkey.example.org.  3600  IN  TXT  ( "v=DKIM1; k=ed25519; "
//!                                              "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" )
//! ```
//!
//! The second form is a BIND zone-file record (TTL and class optional, quoted strings joined, `;` comments
//! outside quotes ignored, parentheses may span lines).

use crate::model::{ArcCheck, DkimReport, DkimSignatureCheck, KeyRecord, MAX_SIGNATURES};
use mail_auth::dkim::DomainKey;
use mail_auth::dns::TxtRecordParser;
use mail_auth::hickory_resolver::config::{ResolverConfig, ResolverOpts};
use mail_auth::{
    AuthenticatedMessage, DkimResult, DnsCache, Error, MessageAuthenticator, Negative, RecordSet,
    ResolverCache, TxtRecord,
};
use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

/// "selector._domainkey.domain", lower case, without a trailing dot.
pub fn key_name(selector: &str, domain: &str) -> String {
    format!(
        "{}._domainkey.{}",
        selector.trim().to_ascii_lowercase(),
        domain.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}

/// Joins the quoted strings of a TXT value (`"a" "b"` → `ab`); an unquoted value is returned trimmed.
fn join_quoted(v: &str) -> String {
    let v = v.trim();
    if !v.contains('"') {
        return v.to_string();
    }
    let mut out = String::new();
    let mut inside = false;
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => inside = !inside,
            '\\' if inside => {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            _ if inside => out.push(c),
            _ => {}
        }
    }
    out
}

/// Removes a `;` comment outside quotes (BIND).
fn strip_zone_comment(line: &str) -> &str {
    let mut inside = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => inside = !inside,
            ';' if !inside => return &line[..i],
            _ => {}
        }
    }
    line
}

/// The text after the TXT token of "[ttl] [class] TXT value" (a zone-file record), or None.
fn after_txt_token(v: &str) -> Option<&str> {
    let mut rest = v.trim_start();
    for _ in 0..3 {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let tok = &rest[..end];
        let next = rest[end..].trim_start();
        if tok.eq_ignore_ascii_case("TXT") {
            return Some(next);
        }
        let ttl = !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_digit());
        if !(ttl || tok.eq_ignore_ascii_case("IN")) {
            return None;
        }
        rest = next;
    }
    None
}

/// Parses a key file. Returns the usable keys and one problem line per record that cannot be used.
pub fn parse_key_file(text: &str) -> (Vec<KeyRecord>, Vec<String>) {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut keys = Vec::new();
    let mut problems = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line_no = i as u64 + 1;
        let raw = lines[i];
        i += 1;
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with(';') || t.starts_with('$') {
            continue;
        }
        let simple = raw.split_once('\t').filter(|(n, v)| {
            let n = n.trim();
            !n.is_empty() && !n.contains(char::is_whitespace) && after_txt_token(v).is_none()
        });
        let (name, value) = if let Some((n, v)) = simple {
            // Simple format: name<TAB>value
            (n.trim().to_string(), join_quoted(v))
        } else {
            // BIND: name [ttl] [class] TXT ( "…" "…" ) possibly over several lines.
            let mut rec = strip_zone_comment(raw).to_string();
            if rec.contains('(') {
                while !rec.contains(')') && i < lines.len() {
                    rec.push(' ');
                    rec.push_str(strip_zone_comment(lines[i]));
                    i += 1;
                }
            }
            let rec = rec.replace(['(', ')'], " ");
            let parsed = rec
                .trim()
                .split_once(char::is_whitespace)
                .and_then(|(n, rest)| Some((n, after_txt_token(rest)?)));
            let Some((name, value)) = parsed else {
                problems.push(format!("line {line_no}: no TXT record"));
                continue;
            };
            (name.to_string(), join_quoted(value))
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if !name.contains("._domainkey.") {
            problems.push(format!(
                "line {line_no}: name {name:?} is not selector._domainkey.domain"
            ));
            continue;
        }
        if DomainKey::parse(value.as_bytes()).is_err() {
            problems.push(format!(
                "line {line_no}: {name}: not a usable DKIM key record"
            ));
            continue;
        }
        keys.push(KeyRecord {
            name,
            txt: value,
            source: "key_file".into(),
            line: line_no,
        });
    }
    (keys, problems)
}

/// Reads and parses the key file: (keys, problems, SHA-256 of the file).
pub fn load_key_file(
    path: &std::path::Path,
) -> Result<(Vec<KeyRecord>, Vec<String>, String), String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read DKIM key file {}: {}", path.display(), e))?;
    let digest = crate::hash::hash_bytes(&bytes, crate::hash::HashAlgo::Sha256);
    let text = String::from_utf8_lossy(&bytes);
    let (k, p) = parse_key_file(&text);
    Ok((k, p, digest))
}

// ---------------------------------------------------------------- injected DNS cache

struct Map<K, V>(Mutex<HashMap<K, V>>);

impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for Map<K, V> {
    fn get<Q>(&self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().ok()?.get(k).cloned()
    }
    fn remove<Q>(&self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().ok()?.remove(k)
    }
    fn insert(&self, k: K, v: V, _: Instant) {
        if let Ok(mut m) = self.0.lock() {
            m.insert(k, v);
        }
    }
}

fn map<K, V>() -> Map<K, V> {
    Map(Mutex::new(HashMap::new()))
}

type Answer<T> = Result<RecordSet<T>, Negative>;

/// The only "DNS" the verifier sees: the keys put here.
struct OfflineDns {
    txt: Map<Box<str>, TxtRecord>,
    mx: Map<Box<str>, Answer<mail_auth::Mx>>,
    v4: Map<Box<str>, Answer<std::net::Ipv4Addr>>,
    v6: Map<Box<str>, Answer<std::net::Ipv6Addr>>,
    ptr: Map<std::net::IpAddr, Answer<Box<str>>>,
}

impl DnsCache for OfflineDns {
    type Txt = Map<Box<str>, TxtRecord>;
    type Mx = Map<Box<str>, Answer<mail_auth::Mx>>;
    type Ipv4 = Map<Box<str>, Answer<std::net::Ipv4Addr>>;
    type Ipv6 = Map<Box<str>, Answer<std::net::Ipv6Addr>>;
    type Ptr = Map<std::net::IpAddr, Answer<Box<str>>>;
    fn txt(&self) -> Option<&Self::Txt> {
        Some(&self.txt)
    }
    fn mx(&self) -> Option<&Self::Mx> {
        Some(&self.mx)
    }
    fn ipv4(&self) -> Option<&Self::Ipv4> {
        Some(&self.v4)
    }
    fn ipv6(&self) -> Option<&Self::Ipv6> {
        Some(&self.v6)
    }
    fn ptr(&self) -> Option<&Self::Ptr> {
        Some(&self.ptr)
    }
}

/// An authenticator that cannot reach any name server.
fn offline_authenticator() -> Option<MessageAuthenticator> {
    MessageAuthenticator::new(
        ResolverConfig::from_parts(None, vec![], vec![]),
        ResolverOpts::default(),
    )
    .ok()
}

fn algorithm_name(a: mail_auth::crypto::Algorithm) -> &'static str {
    use mail_auth::crypto::Algorithm;
    #[allow(unreachable_patterns)]
    match a {
        Algorithm::RsaSha256 => "rsa-sha256",
        Algorithm::RsaSha1 => "rsa-sha1",
        Algorithm::Ed25519Sha256 => "ed25519-sha256",
        _ => "other",
    }
}

fn canon_name(c: mail_auth::dkim::Canonicalization) -> &'static str {
    match c {
        mail_auth::dkim::Canonicalization::Relaxed => "relaxed",
        mail_auth::dkim::Canonicalization::Simple => "simple",
    }
}

fn is_dns(e: &Error) -> bool {
    matches!(e, Error::Dns(_))
}

/// (result, reason) of one DKIM output.
fn classify(r: &DkimResult) -> (&'static str, Option<String>) {
    match r {
        DkimResult::Pass => ("pass", None),
        DkimResult::Neutral(Error::Dkim(mail_auth::dkim::DkimError::BodyHashMismatch)) => (
            "body_hash_mismatch",
            Some("computed body hash differs from bh=".into()),
        ),
        DkimResult::Neutral(e) => ("not_evaluated", Some(e.to_string())),
        DkimResult::Fail(e) if is_dns(e) => ("key_not_available", Some(e.to_string())),
        DkimResult::Fail(e) => ("signature_invalid", Some(e.to_string())),
        DkimResult::TempError(e) | DkimResult::PermError(e) => {
            ("key_not_available", Some(e.to_string()))
        }
        DkimResult::None => ("not_evaluated", Some("no signature evaluated".into())),
    }
}

/// Organisational domain (relaxed DMARC-style alignment): the registrable domain under the bundled Public
/// Suffix List (see `psl.rs`).
pub fn org_domain(domain: &str) -> String {
    crate::psl::org_domain(domain)
}

/// Verifies every DKIM signature and the ARC chain of `raw` with `keys` only.
/// `from_domain` is the RFC 5322 From domain (for alignment).
pub fn verify(raw: &[u8], keys: &[KeyRecord], from_domain: &str) -> DkimReport {
    let mut report = DkimReport {
        mode: "offline".into(),
        evaluated: true,
        ..DkimReport::default()
    };
    let Some(msg) = AuthenticatedMessage::parse(raw) else {
        report.evaluated = false;
        report.not_evaluated_reason = Some("the header section could not be read".into());
        report.arc.result = "not_evaluated".into();
        return report;
    };
    let by_name: BTreeMap<&str, &KeyRecord> = keys
        .iter()
        .rev() // first record of a name wins (key file before DNS)
        .map(|k| (k.name.as_str(), k))
        .collect();
    let cache = OfflineDns {
        txt: map(),
        mx: map(),
        v4: map(),
        v6: map(),
        ptr: map(),
    };
    let mut wanted: Vec<String> = msg
        .dkim_signatures()
        .iter()
        .map(|h| key_name(&h.header.s, &h.header.d))
        .collect();
    wanted.extend(
        msg.arc_message_signatures()
            .iter()
            .map(|h| key_name(&h.header.s, &h.header.d)),
    );
    wanted.extend(
        msg.arc_seals()
            .iter()
            .map(|h| key_name(&h.header.s, &h.header.d)),
    );
    for name in &wanted {
        if let Some(k) = by_name.get(name.as_str())
            && let Ok(dk) = DomainKey::parse(k.txt.as_bytes())
        {
            cache.txt.insert(
                format!("{name}.").into_boxed_str(),
                dk.into(),
                Instant::now(),
            );
        }
    }
    let Some(auth) = offline_authenticator() else {
        report.evaluated = false;
        report.not_evaluated_reason = Some("verifier could not be initialised".into());
        return report;
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() else {
        report.evaluated = false;
        report.not_evaluated_reason = Some("async runtime could not be initialised".into());
        return report;
    };
    let from_org = org_domain(from_domain);
    let outputs =
        rt.block_on(auth.verify_dkim(mail_auth::Parameters::new(&msg).with_cache(&cache)));
    let mut sigs = Vec::new();
    for (i, o) in outputs.iter().enumerate() {
        let (result, reason) = classify(o.result());
        let mut c = DkimSignatureCheck {
            index: i as u64 + 1,
            result: result.into(),
            reason,
            key_source: "none".into(),
            ..DkimSignatureCheck::default()
        };
        if let Some(s) = o.signature() {
            c.domain = s.d.clone();
            c.selector = s.s.clone();
            c.algorithm = algorithm_name(s.a).into();
            c.canonicalization = format!("{}/{}", canon_name(s.ch), canon_name(s.cb));
            c.signed_headers = s.h.iter().take(64).cloned().collect();
            c.identity = s.i.clone();
            c.body_length = s.l;
            c.signed_at = s.t;
            c.expires_at = s.x;
            c.aligned_with_from = !from_org.is_empty() && org_domain(&s.d) == from_org;
            if let Some(k) = by_name.get(key_name(&s.s, &s.d).as_str()) {
                c.key_source = k.source.clone();
                c.key_line = (k.line > 0).then_some(k.line);
            }
        }
        if c.result == "key_not_available" {
            c.key_source = "none".into();
            c.key_line = None;
        }
        sigs.push(c);
    }
    sigs.truncate(MAX_SIGNATURES);
    report.signatures = sigs;
    let arc_instances = msg.arc_seals().len() as u64;
    report.arc = if arc_instances == 0 && msg.arc_message_signatures().is_empty() {
        ArcCheck {
            instances: 0,
            result: "none".into(),
            reason: None,
        }
    } else {
        let out = rt.block_on(auth.verify_arc(mail_auth::Parameters::new(&msg).with_cache(&cache)));
        let (result, reason) = match out.result() {
            DkimResult::Pass => ("pass", None),
            DkimResult::None => ("none", None),
            DkimResult::Fail(e) | DkimResult::TempError(e) | DkimResult::PermError(e)
                if is_dns(e) =>
            {
                ("key_not_available", Some(e.to_string()))
            }
            DkimResult::Fail(e)
            | DkimResult::Neutral(e)
            | DkimResult::PermError(e)
            | DkimResult::TempError(e) => ("invalid", Some(e.to_string())),
        };
        ArcCheck {
            instances: arc_instances,
            result: result.into(),
            reason,
        }
    };
    report
}

/// The DKIM-Signature headers of a header block, read without verification (for .msg, whose original
/// MIME body is not stored, so no signature can be evaluated).
pub fn list_signatures(raw_headers: &[u8], reason: &str) -> Vec<DkimSignatureCheck> {
    let mut with_body = raw_headers.to_vec();
    if !with_body.ends_with(b"\r\n\r\n") && !with_body.ends_with(b"\n\n") {
        with_body.extend_from_slice(b"\r\n\r\n");
    }
    let Some(msg) = AuthenticatedMessage::parse(&with_body) else {
        return vec![];
    };
    msg.dkim_signatures()
        .iter()
        .take(MAX_SIGNATURES)
        .enumerate()
        .map(|(i, h)| {
            let s = &h.header;
            DkimSignatureCheck {
                index: i as u64 + 1,
                domain: s.d.clone(),
                selector: s.s.clone(),
                algorithm: algorithm_name(s.a).into(),
                canonicalization: format!("{}/{}", canon_name(s.ch), canon_name(s.cb)),
                signed_headers: s.h.iter().take(64).cloned().collect(),
                identity: s.i.clone(),
                body_length: s.l,
                signed_at: s.t,
                expires_at: s.x,
                result: "not_evaluated".into(),
                reason: Some(reason.into()),
                key_source: "none".into(),
                key_line: None,
                aligned_with_from: false,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_simple_and_bind_forms() {
        // A syntactically valid Ed25519 key record (32 zero-free bytes, base64): parse-only test.
        let p = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        let text = format!(
            "# examiner keys\n\
             s1._domainkey.Example.org\tv=DKIM1; k=ed25519; p={p}\n\
             ed._domainkey.example.net. 3600 IN TXT ( \"v=DKIM1; k=ed25519; \"\n   \"p={p}\" ) ; comment\n\
             bad._domainkey.example.org\tv=DKIM1; k=rsa; p=@@@\n\
             notakey.example.org\tv=DKIM1; p={p}\n"
        );
        let (keys, problems) = parse_key_file(&text);
        let names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(
            names,
            ["s1._domainkey.example.org", "ed._domainkey.example.net"]
        );
        assert_eq!(keys[1].txt, format!("v=DKIM1; k=ed25519; p={p}"));
        assert_eq!(keys[0].line, 2);
        assert_eq!(problems.len(), 2, "{problems:?}");
    }

    #[test]
    fn org_domain_uses_the_public_suffix_list() {
        assert_eq!(org_domain("mail.example.org"), "example.org");
        assert_eq!(org_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(org_domain("smtp.empresa.com.co"), "empresa.com.co");
        assert_eq!(org_domain("mail.impots.gouv.fr"), "impots.gouv.fr");
        assert_eq!(org_domain("Example.ORG."), "example.org");
    }

    /// DKIM alignment under .com.co, .gouv.fr and .co.uk: same registrable domain aligns, a sibling under the
    /// same public suffix does not.
    #[test]
    fn alignment_under_multi_label_suffixes() {
        let sig = |d: &str| {
            format!(
                "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={d}; s=s1; h=from; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGVzdA==\r\nFrom: a@x\r\n\r\n"
            )
        };
        for (d, from, aligned) in [
            ("mail.empresa.com.co", "empresa.com.co", true),
            ("otra.com.co", "empresa.com.co", false),
            ("notif.impots.gouv.fr", "impots.gouv.fr", true),
            ("douane.gouv.fr", "impots.gouv.fr", false),
            ("bounce.example.co.uk", "example.co.uk", true),
            ("other.co.uk", "example.co.uk", false),
        ] {
            let r = verify(sig(d).as_bytes(), &[], from);
            assert_eq!(r.signatures[0].aligned_with_from, aligned, "{d} vs {from}");
        }
    }

    #[test]
    fn unsigned_and_unknown_key_messages() {
        let r = verify(
            b"From: a@example.org\r\nSubject: x\r\n\r\nbody\r\n",
            &[],
            "example.org",
        );
        assert!(r.evaluated && r.signatures.is_empty());
        assert_eq!(r.arc.result, "none");
        // A signature whose key is not supplied: key_not_available, quickly, without any network.
        let msg = b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=s1;\r\n h=from:subject; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n b=dGVzdA==\r\nFrom: a@example.org\r\nSubject: x\r\n\r\n";
        let t = Instant::now();
        let r = verify(msg, &[], "example.org");
        assert!(t.elapsed().as_secs() < 5);
        assert_eq!(r.signatures.len(), 1);
        assert_eq!(
            r.signatures[0].result, "key_not_available",
            "{:?}",
            r.signatures[0]
        );
        assert_eq!(r.signatures[0].domain, "example.org");
        assert_eq!(r.signatures[0].key_source, "none");
        assert!(r.signatures[0].aligned_with_from);
    }

    #[test]
    fn broken_arc_chain_is_invalid() {
        // An ARC set without its ARC-Authentication-Results header: a broken chain.
        let msg = b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.net; s=arc; t=1; b=dGVzdA==\r\nARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.net; s=arc; h=from; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGVzdA==\r\nFrom: a@example.org\r\n\r\nx\r\n";
        let r = verify(msg, &[], "example.org");
        assert_eq!(r.arc.result, "invalid", "{:?}", r.arc);
        assert_eq!(r.arc.instances, 1);
    }
}
