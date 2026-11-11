//! Business-email-compromise (BEC) heuristics: lookalike domains, Reply-To / Return-Path pointing elsewhere,
//! display-name spoofing and payment-details wording. Every result is a signal with known false positives
//! (stated in the limitations and in each finding's "does not prove").

#![forbid(unsafe_code)]

use crate::dkim::org_domain;
use crate::model::{Finding, HeaderSummary, MailAddress, finding};

/// Confusable skeleton (Unicode TR39), lower case.
pub fn skeleton(s: &str) -> String {
    unicode_security::skeleton(&s.to_lowercase())
        .collect::<String>()
        .to_lowercase()
}

/// Domain in Unicode form (punycode `xn--` labels decoded), lower case.
pub fn to_unicode(domain: &str) -> String {
    let (u, _) = idna::domain_to_unicode(domain.trim().trim_end_matches('.'));
    u.to_lowercase()
}

/// Levenshtein distance over characters (small strings only: domain labels are capped at 63).
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().take(64).collect();
    let b: Vec<char> = b.chars().take(64).collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// (registrable label, suffix) of a domain: "mail.acme.example" → ("acme", "example").
fn label_and_suffix(domain: &str) -> (String, String) {
    let org = org_domain(domain);
    match org.split_once('.') {
        Some((l, s)) => (l.to_string(), s.to_string()),
        None => (org, String::new()),
    }
}

/// How `domain` imitates `own`, or None. Own domains and their subdomains never match.
pub fn lookalike(domain: &str, own: &str) -> Option<&'static str> {
    let d = domain.trim().trim_end_matches('.').to_lowercase();
    let o = own.trim().trim_end_matches('.').to_lowercase();
    if d.is_empty() || o.is_empty() || org_domain(&d) == org_domain(&o) {
        return None;
    }
    let du = to_unicode(&d);
    let ou = to_unicode(&o);
    let puny = d.split('.').any(|l| l.starts_with("xn--"));
    let (dl, _) = label_and_suffix(&du);
    let (ol, _) = label_and_suffix(&ou);
    if org_domain(&du) == org_domain(&ou) {
        return Some("punycode");
    }
    if dl == ol {
        return Some("same_name_other_suffix");
    }
    if skeleton(&dl) == skeleton(&ol) {
        return Some(if puny {
            "punycode_confusable"
        } else {
            "confusable"
        });
    }
    if ol.chars().count() >= 4 {
        let dist = edit_distance(&dl, &ol);
        if dist <= 2 {
            return Some(if dist <= 1 {
                "edit_distance_1"
            } else {
                "edit_distance_2"
            });
        }
    }
    None
}

fn is_own(domain: &str, own: &[String]) -> bool {
    let org = org_domain(domain);
    own.iter().any(|o| org_domain(o) == org)
}

/// Finds something that looks like an email address inside a display name.
fn address_in(name: &str) -> Option<String> {
    name.split(|c: char| {
        c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | '"' | '\'' | ',' | ';')
    })
    .find(|t| {
        t.split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.ends_with('.'))
    })
    .map(|t| {
        t.trim_matches(|c: char| c == '.' || c == ':')
            .to_lowercase()
    })
}

fn contains_word(hay: &str, word: &str) -> bool {
    let hay = hay.to_lowercase();
    let word = word.to_lowercase();
    if word.is_empty() {
        return false;
    }
    hay.match_indices(&word).any(|(i, _)| {
        let before = hay[..i].chars().next_back();
        let after = hay[i + word.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('>').to_lowercase())
        .unwrap_or_default()
}

/// Lookalike, Reply-To / Return-Path and display-name findings for one message.
pub fn header_signals(h: &HeaderSummary, own: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    let from = h.from.first();
    let from_domain = from.map(|a| a.domain.clone()).unwrap_or_default();

    // Lookalike domains in the sender-side headers.
    let mut seen: Vec<String> = Vec::new();
    let mut check = |header: &str, domain: &str, out: &mut Vec<Finding>| {
        if domain.is_empty() || seen.iter().any(|s| s == domain) || is_own(domain, own) {
            return;
        }
        for o in own {
            if let Some(method) = lookalike(domain, o) {
                seen.push(domain.to_string());
                out.push(
                    finding("LOOKALIKE_DOMAIN")
                        .with("header", header)
                        .with("domain", domain)
                        .with("domain_unicode", to_unicode(domain))
                        .with("own_domain", o.to_lowercase())
                        .with("method", method),
                );
                return;
            }
        }
    };
    for a in &h.from {
        check("From", &a.domain, &mut out);
    }
    if let Some(s) = &h.sender {
        check("Sender", &s.domain, &mut out);
    }
    for a in &h.reply_to {
        check("Reply-To", &a.domain, &mut out);
    }
    if let Some(rp) = &h.return_path {
        check("Return-Path", &domain_of(rp), &mut out);
    }

    // Reply-To / Return-Path pointing to another organisation than From.
    if !from_domain.is_empty() {
        let from_org = org_domain(&from_domain);
        if let Some(rt) = h
            .reply_to
            .iter()
            .find(|a| !a.domain.is_empty() && org_domain(&a.domain) != from_org)
        {
            out.push(
                finding("REPLY_TO_DIFFERS")
                    .with("header", "Reply-To")
                    .with("address", rt.address.clone())
                    .with("from_domain", from_domain.clone()),
            );
        }
        if let Some(rp) = &h.return_path {
            let d = domain_of(rp);
            if !d.is_empty() && org_domain(&d) != from_org {
                out.push(
                    finding("REPLY_TO_DIFFERS")
                        .with("header", "Return-Path")
                        .with("address", rp.clone())
                        .with("from_domain", from_domain.clone()),
                );
            }
        }
    }

    // Display-name spoofing.
    for a in h.from.iter().chain(h.sender.iter()) {
        if let Some(f) = display_name_spoof(a, own) {
            out.push(f);
            break;
        }
    }
    out
}

fn display_name_spoof(a: &MailAddress, own: &[String]) -> Option<Finding> {
    let name = a.name.as_deref()?.trim();
    if name.is_empty() {
        return None;
    }
    if let Some(inner) = address_in(name)
        && inner != a.address.to_lowercase()
    {
        return Some(
            finding("DISPLAY_NAME_SPOOF")
                .with("display_name", name)
                .with("address", a.address.clone())
                .with("reason", "address_in_name")
                .with("name_address", inner),
        );
    }
    if is_own(&a.domain, own) {
        return None;
    }
    for o in own {
        let (label, _) = label_and_suffix(&to_unicode(o));
        if contains_word(name, o) || (label.chars().count() >= 4 && contains_word(name, &label)) {
            return Some(
                finding("DISPLAY_NAME_SPOOF")
                    .with("display_name", name)
                    .with("address", a.address.clone())
                    .with("reason", "own_name_external_address")
                    .with("own_domain", o.to_lowercase()),
            );
        }
    }
    None
}

/// Payment-related wording (EN/ES/FR), matched as whole words in lower case.
const PAYMENT_TERMS: &[&str] = &[
    // English
    "iban",
    "swift code",
    "bic code",
    "bank details",
    "banking details",
    "bank account",
    "account number",
    "routing number",
    "sort code",
    "wire transfer",
    "new account",
    "changed our bank",
    "change of bank",
    "updated bank",
    "payment details",
    // Español
    "datos bancarios",
    "cuenta bancaria",
    "número de cuenta",
    "numero de cuenta",
    "nueva cuenta",
    "transferencia bancaria",
    "cambio de cuenta",
    "cambiamos de banco",
    "cambio de banco",
    "clabe",
    // Français
    "coordonnées bancaires",
    "rib",
    "nouveau compte",
    "numéro de compte",
    "virement",
    "changement de banque",
    "changement de rib",
    "nouvelles coordonnées",
];

/// True for an IBAN-shaped token with a valid ISO 13616 check (mod 97 = 1).
pub fn is_iban(candidate: &str) -> bool {
    let s: String = candidate.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&s.len()) || !s.is_ascii() {
        return false;
    }
    let b = s.as_bytes();
    if !(b[0].is_ascii_uppercase()
        && b[1].is_ascii_uppercase()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit())
        || !s
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let v = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else {
            c as u32 - 'A' as u32 + 10
        };
        for d in v.to_string().chars() {
            rem = (rem * 10 + (d as u32 - '0' as u32)) % 97;
        }
    }
    rem == 1
}

/// IBAN-shaped sequences: a country code + 2 digits, then groups of letters/digits separated by single spaces.
fn find_ibans(text: &str) -> usize {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut n = 0;
    let mut i = 0;
    while i < words.len() {
        let w = words[i].trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if w.len() >= 4 && w.as_bytes()[..2].iter().all(u8::is_ascii_uppercase) {
            let mut cand = String::new();
            let mut j = i;
            let mut found = false;
            while j < words.len() && cand.len() <= 34 {
                cand.push_str(words[j].trim_matches(|c: char| !c.is_ascii_alphanumeric()));
                if is_iban(&cand) {
                    found = true;
                    break;
                }
                j += 1;
            }
            if found {
                n += 1;
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    n
}

/// Payment-related terms in `text` (lower case, sorted, unique); "iban_number" for a checksum-valid IBAN.
pub fn payment_terms(text: &str) -> Vec<String> {
    let mut out: Vec<String> = PAYMENT_TERMS
        .iter()
        .filter(|t| contains_word(text, t))
        .map(|t| t.to_string())
        .collect();
    if find_ibans(text) > 0 {
        out.push("iban_number".into());
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(name: Option<&str>, a: &str) -> MailAddress {
        MailAddress {
            name: name.map(String::from),
            address: a.into(),
            domain: domain_of(a),
        }
    }

    #[test]
    fn lookalikes() {
        let own = "acme.example";
        assert_eq!(lookalike("acrne.example", own), Some("confusable"));
        assert_eq!(lookalike("acme-pay.example", own), None);
        assert_eq!(lookalike("acmee.example", own), Some("edit_distance_1"));
        assert_eq!(lookalike("acme.example.net", own), None);
        assert_eq!(lookalike("mail.acme.example", own), None);
        assert_eq!(lookalike("acme.test", own), Some("same_name_other_suffix"));
        // Cyrillic "а" (U+0430) in punycode.
        let puny = idna::domain_to_ascii("\u{0430}cme.example").unwrap();
        assert!(puny.starts_with("xn--"));
        assert_eq!(lookalike(&puny, own), Some("punycode_confusable"));
        assert_eq!(lookalike("example.net", own), None);
    }

    #[test]
    fn display_name_and_reply_to() {
        let own = vec!["acme.example".to_string()];
        let h = HeaderSummary {
            from: vec![addr(Some("ACME Finance"), "finance@example.net")],
            reply_to: vec![addr(None, "pay@example.org")],
            ..HeaderSummary::default()
        };
        let f = header_signals(&h, &own);
        let codes: Vec<&str> = f.iter().map(|f| f.code.as_str()).collect();
        assert_eq!(codes, ["REPLY_TO_DIFFERS", "DISPLAY_NAME_SPOOF"]);
        assert_eq!(f[1].params["reason"], "own_name_external_address");
        let h = HeaderSummary {
            from: vec![addr(Some("ceo@acme.example"), "x@example.net")],
            ..HeaderSummary::default()
        };
        let f = header_signals(&h, &own);
        assert_eq!(f[0].params["reason"], "address_in_name");
        let h = HeaderSummary {
            from: vec![addr(Some("ACME Finance"), "finance@acme.example")],
            ..HeaderSummary::default()
        };
        assert!(header_signals(&h, &own).is_empty());
    }

    #[test]
    fn payment_wording_and_ibans() {
        assert!(is_iban("GB82 WEST 1234 5698 7654 32"));
        assert!(is_iban("DE89370400440532013000"));
        assert!(!is_iban("DE89370400440532013001"));
        let t =
            payment_terms("Please note our new bank details: IBAN DE89 3704 0044 0532 0130 00.");
        assert_eq!(t, ["bank details", "iban", "iban_number"]);
        assert_eq!(payment_terms("Nuevos datos bancarios"), ["datos bancarios"]);
        assert_eq!(payment_terms("Voici notre nouveau RIB"), ["rib"]);
        assert!(payment_terms("Tribute and fibre").is_empty());
    }

    #[test]
    fn edit_distance_basics() {
        assert_eq!(edit_distance("acme", "acme"), 0);
        assert_eq!(edit_distance("acme", "acne"), 1);
        assert_eq!(edit_distance("acme", "amce"), 2);
    }
}
