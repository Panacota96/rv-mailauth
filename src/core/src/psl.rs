//! Organisational (registrable) domains from the bundled Public Suffix List (MPL-2.0, unmodified copy in
//! `src/core/data/public_suffix_list.dat`; version and SHA-256 in `PSL_VERSION.txt`).
//!
//! The standard algorithm (https://publicsuffix.org/list/): the longest matching rule wins, an exception rule
//! (`!x.y`) beats a wildcard (`*.y`), and an unlisted top-level label is a public suffix (implicit `*`).
//! The registrable domain is the public suffix plus one label; a domain that IS a public suffix is its own
//! organisational domain. Both the ICANN and the PRIVATE sections are used. Matching is done on the Unicode
//! form (punycode labels decoded), so `xn--` and Unicode spellings give the same result.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::OnceLock;

pub const DATA: &str = include_str!("../data/public_suffix_list.dat");
const VERSION_FILE: &str = include_str!("../data/PSL_VERSION.txt");

struct Rules {
    exact: HashSet<String>,
    /// "*.parent" stored as "parent"
    wildcard: HashSet<String>,
    /// "!x.parent" stored as "x.parent"
    exception: HashSet<String>,
}

fn rules() -> &'static Rules {
    static R: OnceLock<Rules> = OnceLock::new();
    R.get_or_init(|| parse(DATA))
}

fn parse(text: &str) -> Rules {
    let mut r = Rules {
        exact: HashSet::new(),
        wildcard: HashSet::new(),
        exception: HashSet::new(),
    };
    for line in text.lines() {
        let Some(rule) = line.split_whitespace().next() else {
            continue;
        };
        if rule.starts_with("//") {
            continue;
        }
        let rule = rule.to_lowercase();
        if let Some(x) = rule.strip_prefix('!') {
            r.exception.insert(x.to_string());
        } else if let Some(p) = rule.strip_prefix("*.") {
            r.wildcard.insert(p.to_string());
        } else {
            r.exact.insert(rule);
        }
    }
    r
}

/// Unicode, lower case, without the trailing dot.
fn normalise(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('.').to_lowercase();
    if d.split('.').any(|l| l.starts_with("xn--")) {
        idna::domain_to_unicode(&d).0.to_lowercase()
    } else {
        d
    }
}

/// Number of labels of the public suffix of `labels`.
fn suffix_len(r: &Rules, labels: &[&str]) -> usize {
    let n = labels.len();
    for i in 0..n {
        let cand = labels[i..].join(".");
        if r.exception.contains(&cand) {
            return n - i - 1;
        }
        if r.exact.contains(&cand) {
            return n - i;
        }
        if i + 1 < n && r.wildcard.contains(&labels[i + 1..].join(".")) {
            return n - i;
        }
    }
    1 // implicit "*" rule
}

/// The public suffix of `domain` ("co.uk" for "mail.example.co.uk").
pub fn public_suffix(domain: &str) -> String {
    let d = normalise(domain);
    let labels: Vec<&str> = d.split('.').filter(|l| !l.is_empty()).collect();
    if labels.is_empty() {
        return String::new();
    }
    let k = suffix_len(rules(), &labels).min(labels.len());
    labels[labels.len() - k..].join(".")
}

/// The organisational (registrable) domain: public suffix plus one label ("example.co.uk").
pub fn org_domain(domain: &str) -> String {
    let d = normalise(domain);
    let labels: Vec<&str> = d.split('.').filter(|l| !l.is_empty()).collect();
    if labels.is_empty() {
        return String::new();
    }
    let k = (suffix_len(rules(), &labels) + 1).min(labels.len());
    labels[labels.len() - k..].join(".")
}

fn field(name: &str) -> String {
    VERSION_FILE
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}:")))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

/// {file, version, commit, downloaded, sha256 (recorded), sha256_actual} for environment.json and the audit log.
pub fn describe() -> serde_json::Value {
    serde_json::json!({
        "name": "Public Suffix List", "file": "public_suffix_list.dat", "source": field("source"),
        "version": field("version"), "commit": field("commit"), "downloaded": field("downloaded"),
        "sha256": crate::hash::hash_bytes(DATA.as_bytes(), crate::hash::HashAlgo::Sha256),
        "licence": "MPL-2.0", "rules": rules().exact.len() + rules().wildcard.len() + rules().exception.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_list_matches_its_pinned_digest() {
        let actual = crate::hash::hash_bytes(DATA.as_bytes(), crate::hash::HashAlgo::Sha256);
        assert_eq!(
            actual,
            field("sha256"),
            "PSL_VERSION.txt sha256 does not match the bundled file"
        );
        assert!(DATA.contains(&format!("// VERSION: {}", field("version"))));
        assert!(describe()["rules"].as_u64().unwrap() > 5000);
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(org_domain("mail.example.co.uk"), "example.co.uk");
        assert_eq!(org_domain("a.b.empresa.com.co"), "empresa.com.co");
        assert_eq!(org_domain("impots.gouv.fr"), "impots.gouv.fr");
        assert_eq!(org_domain("www.service.impots.gouv.fr"), "impots.gouv.fr");
        assert_eq!(org_domain("gouv.fr"), "gouv.fr");
        assert_eq!(public_suffix("gouv.fr"), "gouv.fr");
        assert_eq!(org_domain("Mail.Example.ORG."), "example.org");
        assert_eq!(org_domain("acme.example"), "acme.example"); // unlisted TLD: implicit "*"
        assert_eq!(public_suffix("x.y.co.uk"), "co.uk");
        // Wildcard and exception rules (*.kawasaki.jp, !city.kawasaki.jp).
        assert_eq!(org_domain("a.b.kawasaki.jp"), "a.b.kawasaki.jp");
        assert_eq!(org_domain("www.city.kawasaki.jp"), "city.kawasaki.jp");
        // Punycode and Unicode spellings agree.
        assert_eq!(
            org_domain("xn--bcher-kva.example"),
            org_domain("bücher.example")
        );
    }
}
