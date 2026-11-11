//! Online mode only (`DomainOptions::online_dns`, CLI `--online`): fetches TODAY's DKIM key records from the
//! system's DNS resolver. Called by the PARENT process (`run.rs`), one audit entry per fetch; never by a worker.
//!
//! A key published today may not be the key that signed the message (keys are rotated and old selectors are
//! removed), so every signature verified with such a key also carries DKIM_KEY_FROM_CURRENT_DNS.

use crate::model::KeyRecord;

/// Result of one TXT lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetch {
    pub name: String,
    /// The TXT value when found and usable as a DKIM key record.
    pub txt: Result<String, String>,
    pub elapsed_ms: u64,
}

/// Looks up `selector._domainkey.domain` TXT records with the system resolver configuration.
pub fn fetch_key(name: &str) -> Fetch {
    let started = std::time::Instant::now();
    let txt = (|| -> Result<String, String> {
        let auth = mail_auth::MessageAuthenticator::new_system_conf()
            .map_err(|e| format!("no system DNS configuration: {e}"))?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let raw = rt
            .block_on(auth.txt_raw_lookup(format!("{name}.")))
            .map_err(|e| e.to_string())?;
        let txt = String::from_utf8_lossy(&raw).into_owned();
        let (keys, problems) = crate::dkim::parse_key_file(&format!("{name}\t{txt}"));
        if keys.is_empty() {
            return Err(problems
                .first()
                .cloned()
                .unwrap_or_else(|| "not a DKIM key record".into()));
        }
        Ok(txt)
    })();
    Fetch {
        name: name.to_string(),
        txt,
        elapsed_ms: started.elapsed().as_millis() as u64,
    }
}

impl Fetch {
    pub fn record(&self) -> Option<KeyRecord> {
        self.txt.as_ref().ok().map(|t| KeyRecord {
            name: self.name.clone(),
            txt: t.clone(),
            source: "current_dns".into(),
            line: 0,
        })
    }
}
