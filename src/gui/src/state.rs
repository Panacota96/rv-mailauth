//! Everything the window shows and every rule it enforces, without any drawing code.
//! Kept separate from `app.rs` so it can be unit-tested headless (CI has no display).

use crate::viewer::{MessageView, RunView};
use rv_mailauth_core::model::{DomainOptions, Severity};
use rv_mailauth_core::{
    CASE_ROLE, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, case, hash, i18n,
    time::human_duration,
};
use serde_json::{Value, json};
use std::ops::RangeInclusive;
use std::path::PathBuf;

/// Accepted ranges of the numeric options (a value outside is clamped, and the clamped value audited).
pub const CLOCK_SKEW_RANGE: RangeInclusive<u64> = 0..=86_400;
pub const TIMEOUT_RANGE: RangeInclusive<u64> = 5..=3_600;
pub const MEMORY_RANGE: RangeInclusive<u64> = 128..=16_384;
pub const MAX_MESSAGE_MB_RANGE: RangeInclusive<u64> = 1..=2_048;
pub const MAX_MBOX_MESSAGES_RANGE: RangeInclusive<u64> = 1..=1_000_000;
pub const MBOX_VARIANTS: [&str; 2] = ["mboxrd", "mboxo"];

/// One change in section "3. Options"; each maps 1:1 onto a [`DomainOptions`] field and is audited under
/// [`OptionChange::audit_name`] (with `at_utc`).
#[derive(Clone, Debug, PartialEq)]
pub enum OptionChange {
    /// DKIM key file given by the examiner; empty = none.
    DkimKeys(String),
    /// Fetch keys missing from the key file from today's DNS (weaker evidence).
    OnlineDns(bool),
    AddOwnDomain(String),
    RemoveOwnDomain(String),
    ExtractAttachments(bool),
    ClockSkew(u64),
    MboxVariant(String),
    /// true = item reports only for flagged items, false = for every item.
    ItemReportsFlaggedOnly(bool),
    WorkerTimeout(u64),
    WorkerMemory(u64),
    /// In MiB (the core option is in bytes).
    MaxMessageMb(u64),
    MaxMboxMessages(u64),
}

impl OptionChange {
    pub fn audit_name(&self) -> &'static str {
        match self {
            OptionChange::DkimKeys(_) => "ui_dkim_keys_changed",
            OptionChange::OnlineDns(_) => "ui_online_dns_changed",
            OptionChange::AddOwnDomain(_) => "ui_own_domain_added",
            OptionChange::RemoveOwnDomain(_) => "ui_own_domain_removed",
            OptionChange::ExtractAttachments(_) => "ui_extract_attachments_changed",
            OptionChange::ClockSkew(_) => "ui_clock_skew_changed",
            OptionChange::MboxVariant(_) => "ui_mbox_variant_changed",
            OptionChange::ItemReportsFlaggedOnly(_) => "ui_item_reports_changed",
            OptionChange::WorkerTimeout(_) => "ui_worker_timeout_changed",
            OptionChange::WorkerMemory(_) => "ui_worker_memory_changed",
            OptionChange::MaxMessageMb(_) => "ui_max_message_size_changed",
            OptionChange::MaxMboxMessages(_) => "ui_max_mbox_messages_changed",
        }
    }
}

/// Normalises a typed own domain ("  @Example.ORG. " -> "example.org"); Err when it is not a domain name.
pub fn normalize_domain(raw: &str) -> Result<String, String> {
    let d = raw
        .trim()
        .trim_start_matches('@')
        .trim_end_matches('.')
        .to_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_alphanumeric() || c == '-')
    };
    if d.len() > 253 || !d.contains('.') || !d.split('.').all(label_ok) {
        return Err(format!("Not a domain name: {}", raw.trim()));
    }
    Ok(d)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    Idle,
    Running,
    Finished,
    Cancelled,
    Failed(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub elapsed_ms: u64,
    pub eta_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Outcome {
    pub items: u64,
    pub errors: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub report: PathBuf,
    pub report_dir: PathBuf,
    pub log_dir: PathBuf,
}

/// One item's link to the case registry, shown in the result panel.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceLink {
    pub index: u64,
    pub path: String,
    pub evidence_id: Option<String>,
    /// registered | already_registered | verified | mismatch | not_in_registry
    pub status: String,
}

pub const LANG_CHOICES: [(&str, &str); 4] = [
    ("en", "English"),
    ("es", "Español"),
    ("fr", "Français"),
    ("all", "All three (EN + ES + FR)"),
];

#[derive(Clone, Debug)]
pub struct GuiState {
    pub inputs: Vec<PathBuf>,
    pub path_entry: String,
    pub recursive: bool,
    pub selected: Vec<HashAlgo>,
    pub lang: String,
    pub out_dir: String,
    pub actor: String,
    pub case_id: String,
    pub phase: Phase,
    pub progress: Progress,
    pub current_item: String,
    pub warnings: Vec<String>,
    pub outcome: Option<Outcome>,
    /// User actions recorded before the run; handed to the core as audit preamble entries.
    pub ui_actions: Vec<(String, Value)>,
    /// Interface language (en/es/fr), independent from the report language.
    pub ui_lang: String,
    pub jurisdiction: String,
    pub timestamp: bool,
    pub tsa_url: String,
    pub sign_cert: String,
    /// Kept in memory only; never logged.
    pub sign_password: String,
    /// Shared case folder; when set, the output folder is derived from it and locked.
    pub case_dir: String,
    /// Evidence ids reported by the last run (case folder only).
    pub evidence: Vec<EvidenceLink>,
    /// Section "3. Options": the analysis options (core defaults; isolation = worker process).
    pub options: DomainOptions,
    /// Own domain being typed (added with [`OptionChange::AddOwnDomain`]).
    pub own_domain_entry: String,
    /// The finished run as read back from its audit log (results table + message viewer).
    pub run_view: Option<RunView>,
    /// Why the finished run could not be read back (shown instead of the results table).
    pub run_view_error: Option<String>,
    /// The message open in the viewer.
    pub message: Option<MessageView>,
    /// Why the last message could not be opened (digest mismatch, missing file, …).
    pub message_error: Option<String>,
    /// Last failure to write the reviewed run's review log (the view was then noted for the next run).
    pub review_error: Option<String>,
}

impl Default for GuiState {
    fn default() -> Self {
        GuiState {
            inputs: vec![],
            path_entry: String::new(),
            recursive: true,
            selected: vec![HashAlgo::Sha256],
            lang: "en".into(),
            out_dir: "rakvor-out".into(),
            actor: rv_mailauth_core::env::os_user(),
            case_id: String::new(),
            phase: Phase::Idle,
            progress: Progress::default(),
            current_item: String::new(),
            warnings: vec![],
            outcome: None,
            ui_actions: vec![],
            ui_lang: "en".into(),
            jurisdiction: "co".into(),
            timestamp: true,
            tsa_url: rv_mailauth_core::trust::DEFAULT_TSA.into(),
            sign_cert: String::new(),
            sign_password: String::new(),
            case_dir: String::new(),
            evidence: vec![],
            options: DomainOptions::default(),
            own_domain_entry: String::new(),
            run_view: None,
            run_view_error: None,
            message: None,
            message_error: None,
            review_error: None,
        }
    }
}

impl GuiState {
    /// Records a user action with the time it happened (written to the audit log when the run starts).
    fn note(&mut self, action: &str, mut details: Value) {
        if let Some(o) = details.as_object_mut() {
            o.insert("at_utc".into(), json!(rv_mailauth_core::time::utc_now()));
        }
        self.ui_actions.push((action.to_string(), details));
    }

    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }

    /// A checkbox is clickable if it can be unticked (more than one ticked) or ticked (fewer than two ticked).
    pub fn can_toggle(&self, a: HashAlgo) -> bool {
        if self.selected.contains(&a) {
            self.selected.len() > 1
        } else {
            self.selected.len() < HashAlgo::MAX_SELECTED
        }
    }

    pub fn toggle_algo(&mut self, a: HashAlgo) -> Result<(), String> {
        if !self.can_toggle(a) {
            return Err(if self.selected.contains(&a) {
                "At least one hash algorithm is required.".into()
            } else {
                format!(
                    "At most {} hash algorithms can be selected.",
                    HashAlgo::MAX_SELECTED
                )
            });
        }
        if let Some(i) = self.selected.iter().position(|x| *x == a) {
            self.selected.remove(i);
        } else {
            self.selected.push(a);
        }
        self.note(
            "ui_hash_selection_changed",
            json!({"algorithms": self.selected}),
        );
        Ok(())
    }

    pub fn add_input(&mut self, p: PathBuf) {
        if !self.inputs.contains(&p) {
            self.note("ui_input_added", json!({"path": p.display().to_string()}));
            self.inputs.push(p);
        }
    }

    pub fn add_typed_path(&mut self) {
        let t = self.path_entry.trim().trim_matches('"').to_string();
        if !t.is_empty() {
            self.add_input(PathBuf::from(t));
            self.path_entry.clear();
        }
    }

    pub fn remove_input(&mut self, i: usize) {
        if i < self.inputs.len() {
            let p = self.inputs.remove(i);
            self.note("ui_input_removed", json!({"path": p.display().to_string()}));
        }
    }

    pub fn set_lang(&mut self, l: &str) {
        if self.lang != l {
            self.lang = l.to_string();
            self.note("ui_language_changed", json!({"lang": l}));
        }
    }

    pub fn set_recursive(&mut self, r: bool) {
        if self.recursive != r {
            self.recursive = r;
            self.note("ui_recursive_changed", json!({"recursive": r}));
        }
    }

    /// GUI text in the interface language.
    pub fn tr(&self, key: &str) -> String {
        i18n::catalog(&self.ui_lang).ui(key)
    }

    pub fn set_ui_lang(&mut self, l: &str) {
        if self.ui_lang != l && ["en", "es", "fr"].contains(&l) {
            self.ui_lang = l.to_string();
            self.note("ui_interface_language_changed", json!({"ui_lang": l}));
        }
    }

    pub fn set_jurisdiction(&mut self, j: &str) {
        if self.jurisdiction != j && (j == "co" || j == "fr") {
            self.jurisdiction = j.to_string();
            self.note("ui_jurisdiction_changed", json!({"jurisdiction": j}));
        }
    }

    pub fn set_timestamp(&mut self, on: bool, url: &str) {
        let url = url.trim().to_string();
        if self.timestamp != on || self.tsa_url != url {
            self.timestamp = on;
            self.tsa_url = url.clone();
            self.note(
                "ui_timestamp_changed",
                json!({"enabled": on, "tsa_url": url}),
            );
        }
    }

    pub fn set_sign_cert(&mut self, path: &str) {
        let path = path.trim().trim_matches('"').to_string();
        if self.sign_cert != path {
            self.sign_cert = path.clone();
            self.note(
                "ui_signing_certificate_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }}),
            );
        }
    }

    /// Applies one option change (numbers clamped to their range, domains normalised) and audits it when
    /// the value changed. Ok(false) = nothing changed; Err = refused (e.g. not a domain name), nothing audited.
    pub fn set_option(&mut self, c: OptionChange) -> Result<bool, String> {
        fn put<T: PartialEq>(slot: &mut T, v: T) -> bool {
            let changed = *slot != v;
            *slot = v;
            changed
        }
        let o = &mut self.options;
        let (changed, value): (bool, Value) = match &c {
            OptionChange::DkimKeys(p) => {
                let p = p.trim().trim_matches('"').to_string();
                let new = (!p.is_empty()).then(|| PathBuf::from(&p));
                (
                    put(&mut o.dkim_keys, new),
                    if p.is_empty() { Value::Null } else { json!(p) },
                )
            }
            OptionChange::OnlineDns(v) => (put(&mut o.online_dns, *v), json!(v)),
            OptionChange::AddOwnDomain(raw) => {
                let d = normalize_domain(raw)?;
                let added = !o.own_domains.contains(&d);
                if added {
                    o.own_domains.push(d.clone());
                }
                self.own_domain_entry.clear();
                (added, json!(d))
            }
            OptionChange::RemoveOwnDomain(d) => {
                let before = o.own_domains.len();
                o.own_domains.retain(|x| x != d);
                (o.own_domains.len() != before, json!(d))
            }
            OptionChange::ExtractAttachments(v) => (put(&mut o.extract_attachments, *v), json!(v)),
            OptionChange::ClockSkew(v) => {
                let v = (*v).clamp(*CLOCK_SKEW_RANGE.start(), *CLOCK_SKEW_RANGE.end());
                (put(&mut o.clock_skew_s, v), json!(v))
            }
            OptionChange::MboxVariant(v) => {
                if !MBOX_VARIANTS.contains(&v.as_str()) {
                    return Err(format!("Unknown mbox variant: {v}"));
                }
                (put(&mut o.mbox_variant, v.clone()), json!(v))
            }
            OptionChange::ItemReportsFlaggedOnly(v) => (
                put(&mut o.item_reports_flagged_only, *v),
                json!(if *v { "flagged" } else { "all" }),
            ),
            OptionChange::WorkerTimeout(v) => {
                let v = (*v).clamp(*TIMEOUT_RANGE.start(), *TIMEOUT_RANGE.end());
                (put(&mut o.worker_timeout_s, v), json!(v))
            }
            OptionChange::WorkerMemory(v) => {
                let v = (*v).clamp(*MEMORY_RANGE.start(), *MEMORY_RANGE.end());
                (put(&mut o.worker_memory_mb, v), json!(v))
            }
            OptionChange::MaxMessageMb(v) => {
                let v = (*v).clamp(*MAX_MESSAGE_MB_RANGE.start(), *MAX_MESSAGE_MB_RANGE.end());
                (put(&mut o.max_message_bytes, v * 1024 * 1024), json!(v))
            }
            OptionChange::MaxMboxMessages(v) => {
                let v = (*v).clamp(
                    *MAX_MBOX_MESSAGES_RANGE.start(),
                    *MAX_MBOX_MESSAGES_RANGE.end(),
                );
                (put(&mut o.max_mbox_messages, v), json!(v))
            }
        };
        if changed {
            self.note(c.audit_name(), json!({"value": value}));
        }
        Ok(changed)
    }

    /// The configured maximum message size in MiB (as shown in the options).
    pub fn max_message_mb(&self) -> u64 {
        self.options.max_message_bytes / (1024 * 1024)
    }

    /// Short form of the options, for the settings line in environment.json and `ui_start_clicked`.
    pub fn options_json(&self) -> Value {
        let o = &self.options;
        json!({"dkim_keys": o.dkim_keys.as_ref().map(|p| p.display().to_string()), "online_dns": o.online_dns,
            "own_domains": o.own_domains, "extract_attachments": o.extract_attachments,
            "clock_skew_s": o.clock_skew_s, "mbox_variant": o.mbox_variant,
            "item_reports": if o.item_reports_flagged_only { "flagged" } else { "all" },
            "worker_timeout_s": o.worker_timeout_s, "worker_memory_mb": o.worker_memory_mb,
            "max_message_bytes": o.max_message_bytes, "max_mbox_messages": o.max_mbox_messages})
    }

    /// Rule: with a case folder the output folder is `<case>/runs/<tool>/<RUN-ID>` and cannot be edited.
    pub fn set_case_dir(&mut self, path: &str) {
        let path = path.trim().trim_matches('"').to_string();
        if self.case_dir != path {
            self.case_dir = path.clone();
            self.note(
                "ui_case_dir_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }, "role": CASE_ROLE.name()}),
            );
        }
    }

    /// The case folder given by RV Hub (`--case-dir`): preset like a typed folder (`ui_case_dir_changed`) and
    /// recorded as `ui_case_dir_from_launcher`, so the audit log shows the folder was not chosen in the GUI.
    pub fn set_case_dir_from_launcher(&mut self, path: &std::path::Path) {
        let shown = path.display().to_string();
        self.note("ui_case_dir_from_launcher", json!({"path": shown}));
        self.set_case_dir(&shown);
    }

    /// A launch argument that was ignored (e.g. `--case-dir` without a folder), recorded in the audit log.
    pub fn note_launch_problem(&mut self, problem: &str) {
        self.note("ui_launch_argument_ignored", json!({"problem": problem}));
    }

    pub fn out_locked(&self) -> bool {
        !self.case_dir.trim().is_empty()
    }

    /// What the output-folder field shows: the derived run folder when a case folder is set.
    pub fn out_dir_display(&self) -> String {
        if self.out_locked() {
            PathBuf::from(self.case_dir.trim())
                .join("runs")
                .join(TOOL_NAME)
                .join("<RUN-ID>")
                .display()
                .to_string()
        } else {
            self.out_dir.clone()
        }
    }

    /// Result-panel lines: "E0001  acta.txt  — Verified: identical to the registered evidence".
    pub fn evidence_lines(&self) -> Vec<String> {
        let c = i18n::catalog(&self.ui_lang);
        self.evidence
            .iter()
            .map(|e| {
                let name = std::path::Path::new(&e.path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| e.path.clone());
                format!(
                    "{}  {}  \u{2014} {}",
                    e.evidence_id.as_deref().unwrap_or("\u{2014}"),
                    name,
                    c.label(&format!("case_status_{}", e.status))
                )
            })
            .collect()
    }

    pub fn can_start(&self) -> bool {
        !self.is_running()
            && (!self.inputs.is_empty() || self.out_locked())
            && (self.out_locked() || !self.out_dir.trim().is_empty())
    }

    /// Builds the run configuration; the recorded UI actions become audit preamble entries.
    pub fn to_config(&self) -> Result<RunConfig, String> {
        if self.inputs.is_empty() && !self.out_locked() {
            return Err("Add at least one file or folder.".into());
        }
        hash::validate_selection(&self.selected)?;
        let case_id = Some(self.case_id.trim().to_string()).filter(|s| !s.is_empty());
        if self.out_locked() {
            case::preflight(
                std::path::Path::new(self.case_dir.trim()),
                case_id.as_deref(),
                &[],
            )
            .map_err(|e| e.message)?;
        }
        let langs = i18n::parse_langs(&self.lang)?;
        if !self.sign_cert.is_empty() && !std::path::Path::new(&self.sign_cert).is_file() {
            return Err(format!("Signing certificate not found: {}", self.sign_cert));
        }
        if let Some(k) = &self.options.dkim_keys
            && !k.is_file()
        {
            return Err(format!("DKIM key file not found: {}", k.display()));
        }
        let mut preamble = self.ui_actions.clone();
        preamble.push(("ui_start_clicked".into(), json!({"algorithms": self.selected, "lang": self.lang, "recursive": self.recursive,
            "inputs": self.inputs.len(), "jurisdiction": self.jurisdiction, "timestamp": self.timestamp,
            "pdf_signing": !self.sign_cert.is_empty(), "options": self.options_json(), "case_dir": if self.out_locked() { json!(self.case_dir.trim()) } else { Value::Null },
            "at_utc": rv_mailauth_core::time::utc_now()})));
        let settings = vec![
            format!("{} (gui)", TOOL_NAME),
            format!(
                "inputs={}",
                self.inputs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(";")
            ),
            format!(
                "hash={}",
                self.selected
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            format!("lang={}", self.lang),
            format!("recursive={}", self.recursive),
            format!("out={}", self.out_dir_display().trim()),
            format!(
                "case_dir={}",
                if self.out_locked() {
                    self.case_dir.trim()
                } else {
                    "none"
                }
            ),
            format!("jurisdiction={}", self.jurisdiction),
            format!("options={}", self.options_json()),
            format!(
                "tsa={}",
                if self.timestamp {
                    self.tsa_url.as_str()
                } else {
                    "off"
                }
            ),
            format!(
                "sign_cert={}",
                if self.sign_cert.is_empty() {
                    "none"
                } else {
                    self.sign_cert.as_str()
                }
            ),
        ];
        Ok(RunConfig {
            inputs: self.inputs.clone(),
            input_list: None,
            recursive: self.recursive,
            algorithms: self.selected.clone(),
            out_dir: PathBuf::from(self.out_dir.trim()),
            langs,
            actor: if self.actor.trim().is_empty() {
                rv_mailauth_core::env::os_user()
            } else {
                self.actor.trim().to_string()
            },
            case_id,
            frontend: "gui".into(),
            preamble,
            command_line: settings,
            tool_name: TOOL_NAME.into(),
            tool_version: TOOL_VERSION.into(),
            jurisdiction: self.jurisdiction.clone(),
            tsa_url: if self.timestamp {
                Some(self.tsa_url.clone())
            } else {
                None
            },
            sign_cert: if self.sign_cert.is_empty() {
                None
            } else {
                Some(PathBuf::from(&self.sign_cert))
            },
            sign_password: if self.sign_password.is_empty() {
                None
            } else {
                Some(self.sign_password.clone())
            },
            case_dir: if self.out_locked() {
                Some(PathBuf::from(self.case_dir.trim()))
            } else {
                None
            },
            evidence_ids: vec![],
            case_role: CASE_ROLE,
            domain: DomainOptions {
                fetched_keys: vec![],
                ..self.options.clone()
            },
        })
    }

    pub fn start(&mut self) {
        self.phase = Phase::Running;
        self.progress = Progress::default();
        self.current_item.clear();
        self.warnings.clear();
        self.outcome = None;
        self.evidence.clear();
        self.run_view = None;
        self.run_view_error = None;
        self.message = None;
        self.message_error = None;
        self.review_error = None;
        // Recorded actions now belong to this run's audit log.
        self.ui_actions.clear();
    }

    pub fn apply(&mut self, e: &Event) {
        match e {
            Event::RunStarted {
                total_items,
                total_bytes,
                ..
            } => {
                self.progress.total = *total_items;
                self.progress.bytes_total = *total_bytes;
            }
            Event::ItemStarted { path, .. } => self.current_item = path.clone(),
            Event::EvidenceLinked {
                index,
                path,
                evidence_id,
                status,
            } => self.evidence.push(EvidenceLink {
                index: *index,
                path: path.clone(),
                evidence_id: evidence_id.clone(),
                status: status.clone(),
            }),
            Event::Progress {
                done,
                total,
                bytes_done,
                bytes_total,
                elapsed_ms,
                eta_ms,
            } => {
                self.progress = Progress {
                    done: *done,
                    total: *total,
                    bytes_done: *bytes_done,
                    bytes_total: *bytes_total,
                    elapsed_ms: *elapsed_ms,
                    eta_ms: *eta_ms,
                };
            }
            Event::Error { path, message } => {
                self.warnings
                    .push(format!("{}: {}", path.as_deref().unwrap_or("-"), message))
            }
            Event::RunFinished {
                items,
                errors,
                high,
                medium,
                low,
                info,
                report_dir,
                log_dir,
                cancelled,
                elapsed_ms,
                ..
            } => {
                self.progress.elapsed_ms = *elapsed_ms;
                self.progress.eta_ms = None;
                let lang = if self.lang == "all" {
                    "en".to_string()
                } else {
                    self.lang.clone()
                };
                self.outcome = Some(Outcome {
                    items: *items,
                    errors: *errors,
                    high: *high,
                    medium: *medium,
                    low: *low,
                    info: *info,
                    report: PathBuf::from(report_dir).join(format!("statistics.{}.html", lang)),
                    report_dir: PathBuf::from(report_dir),
                    log_dir: PathBuf::from(log_dir),
                });
                self.phase = if *cancelled {
                    Phase::Cancelled
                } else {
                    Phase::Finished
                };
                self.current_item.clear();
            }
            _ => {}
        }
    }

    /// Reads the finished run back from its audit log (results table); called once the run is over.
    pub fn load_results(&mut self) {
        let Some(o) = &self.outcome else { return };
        match RunView::load(&o.report_dir, &o.log_dir) {
            Ok(v) => {
                self.run_view = Some(v);
                self.run_view_error = None;
            }
            Err(e) => {
                self.run_view = None;
                self.run_view_error = Some(e);
            }
        }
        self.message = None;
        self.message_error = None;
    }

    /// "Open" on a results row: the message is shown only when headers.json and dkim.json match the digests in
    /// the audit log. Both outcomes go to the run's review log (`ui_message_viewed` / `ui_message_refused`).
    pub fn open_message(&mut self, row: usize) -> bool {
        let Some(run) = &self.run_view else {
            return false;
        };
        let Some(r) = run.rows.get(row).cloned() else {
            return false;
        };
        let run_id = run.run_id.clone();
        let mut details = json!({"item": r.item, "index": r.index, "message": r.message, "run_id": run_id,
                                 "at_utc": rv_mailauth_core::time::utc_now()});
        let opened = MessageView::open(run, row);
        let ok = opened.is_ok();
        match opened {
            Ok(v) => {
                details["files"] = json!(
                    v.files
                        .iter()
                        .map(|(f, h)| json!({"file": f, "sha256": h}))
                        .collect::<Vec<_>>()
                );
                details["digest_ok"] = json!(true);
                self.message = Some(v);
                self.message_error = None;
                self.record_review("ui_message_viewed", details);
            }
            Err(e) => {
                details["digest_ok"] = json!(false);
                details["reason"] = json!(e);
                self.message = None;
                self.message_error = Some(e);
                self.record_review("ui_message_refused", details);
            }
        }
        ok
    }

    pub fn close_message(&mut self) {
        self.message = None;
        self.message_error = None;
    }

    /// Writes one entry to the reviewed run's hash-chained review log (`review.jsonl`, anchored to its
    /// `run_finished`). If that fails, the entry falls back to the next run's audit preamble and the error is
    /// kept for the status line.
    fn record_review(&mut self, action: &str, details: Value) {
        let actor = if self.actor.trim().is_empty() {
            rv_mailauth_core::env::os_user()
        } else {
            self.actor.trim().to_string()
        };
        let written = match self.outcome.as_ref().map(|o| o.log_dir.clone()) {
            Some(dir) => rv_mailauth_core::review::append(&dir, &actor, action, details.clone())
                .map(|_| ())
                .map_err(|e| format!("{}: {}", dir.display(), e)),
            None => Err("no finished run in this window".to_string()),
        };
        match written {
            Ok(()) => self.review_error = None,
            Err(e) => {
                self.review_error = Some(e);
                self.note(action, details);
            }
        }
    }

    /// Findings of the open message in the interface language, most severe first.
    pub fn message_findings(&self) -> Vec<FindingText> {
        let cat = i18n::catalog(&self.ui_lang);
        let mut out: Vec<FindingText> = self
            .message
            .as_ref()
            .map(|m| m.findings.as_slice())
            .unwrap_or_default()
            .iter()
            .map(|f| {
                let (title, shows, not_proves) = cat.finding(&f.code, &f.params);
                FindingText {
                    severity: f.severity,
                    code: f.code.clone(),
                    title,
                    shows,
                    not_proves,
                }
            })
            .collect();
        out.sort_by_key(|f| std::cmp::Reverse(f.severity));
        out
    }

    pub fn severity_name(&self, s: Severity) -> String {
        i18n::catalog(&self.ui_lang).severity(s.key())
    }

    /// Results-table status in the interface language (ok / attention / problem).
    pub fn status_name(&self, status: &str) -> String {
        self.tr(&format!("status_{status}"))
    }

    pub fn fail(&mut self, msg: String) {
        self.phase = Phase::Failed(msg);
    }

    /// 0.0..=1.0, by bytes (or by files when every file is empty).
    pub fn fraction(&self) -> f32 {
        let p = &self.progress;
        if p.bytes_total > 0 {
            (p.bytes_done as f64 / p.bytes_total as f64).clamp(0.0, 1.0) as f32
        } else if p.total > 0 {
            (p.done as f64 / p.total as f64) as f32
        } else if matches!(self.phase, Phase::Finished) {
            1.0
        } else {
            0.0
        }
    }

    /// `live_elapsed_ms` is measured by the window clock so the timer keeps moving between events.
    pub fn timing_text(&self, live_elapsed_ms: Option<u64>) -> String {
        let elapsed = live_elapsed_ms
            .unwrap_or(self.progress.elapsed_ms)
            .max(self.progress.elapsed_ms);
        let eta = match self.progress.eta_ms {
            Some(ms) if self.is_running() => human_duration(ms),
            _ => "\u{2014}".into(),
        };
        format!(
            "{}: {}   \u{00B7}   {}: {}",
            self.tr("elapsed"),
            human_duration(elapsed),
            self.tr("remaining"),
            eta
        )
    }

    pub fn progress_text(&self) -> String {
        format!(
            "{} / {} {}  \u{00B7}  {:.0}%",
            self.progress.done,
            self.progress.total,
            self.tr("files"),
            self.fraction() * 100.0
        )
    }
}

/// One finding as the viewer lists it: what it shows and what it does not prove.
#[derive(Clone, Debug, PartialEq)]
pub struct FindingText {
    pub severity: Severity,
    pub code: String,
    pub title: String,
    pub shows: String,
    pub not_proves: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_most_two_and_at_least_one_algorithm() {
        let mut s = GuiState::default();
        assert_eq!(s.selected, vec![HashAlgo::Sha256]);
        assert!(
            !s.can_toggle(HashAlgo::Sha256),
            "cannot untick the last one"
        );
        assert!(s.toggle_algo(HashAlgo::Sha256).is_err());
        s.toggle_algo(HashAlgo::Md5).unwrap();
        assert!(
            !s.can_toggle(HashAlgo::Blake3),
            "third checkbox is disabled"
        );
        assert!(s.toggle_algo(HashAlgo::Blake3).is_err());
        assert!(s.can_toggle(HashAlgo::Sha256));
        s.toggle_algo(HashAlgo::Sha256).unwrap();
        assert_eq!(s.selected, vec![HashAlgo::Md5]);
    }

    #[test]
    fn settings_changes_become_audit_preamble() {
        let mut s = GuiState::default();
        assert!(s.to_config().is_err(), "no input yet");
        s.path_entry = "\"C:\\evidence\"".into();
        s.add_typed_path();
        s.toggle_algo(HashAlgo::Blake3).unwrap();
        s.set_lang("es");
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.inputs, vec![PathBuf::from("C:\\evidence")]);
        assert_eq!(cfg.frontend, "gui");
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "ui_input_added",
                "ui_hash_selection_changed",
                "ui_language_changed",
                "ui_start_clicked"
            ]
        );
        s.start();
        assert!(s.ui_actions.is_empty());
    }

    #[test]
    fn events_drive_progress_and_outcome() {
        let mut s = GuiState::default();
        s.start();
        s.apply(&Event::RunStarted {
            run_id: "R".into(),
            tool: "t".into(),
            version: "v".into(),
            frontend: "gui".into(),
            algorithms: vec![HashAlgo::Sha256],
            langs: vec!["en".into()],
            total_items: 4,
            total_bytes: 400,
        });
        s.apply(&Event::Progress {
            done: 1,
            total: 4,
            bytes_done: 100,
            bytes_total: 400,
            elapsed_ms: 2000,
            eta_ms: Some(6000),
        });
        assert!((s.fraction() - 0.25).abs() < 1e-6);
        assert!(s.timing_text(Some(2500)).contains("6.0 s"));
        assert!(s.progress_text().starts_with("1 / 4"));
        s.apply(&Event::RunFinished {
            items: 4,
            bytes: 400,
            errors: 0,
            elapsed_ms: 8000,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
            report_dir: "out/reports/R".into(),
            log_dir: "out/logs/R".into(),
            cancelled: false,
        });
        assert_eq!(s.phase, Phase::Finished);
        assert_eq!(
            s.outcome.as_ref().unwrap().report,
            PathBuf::from("out/reports/R/statistics.en.html")
        );
    }

    #[test]
    fn interface_language_and_trust_settings_are_audited() {
        let mut s = GuiState::default();
        s.set_ui_lang("fr");
        assert_eq!(s.tr("start"), "Lancer l'analyse");
        s.set_ui_lang("es");
        assert_eq!(s.tr("start"), "Iniciar revisión");
        s.set_jurisdiction("fr");
        s.set_timestamp(false, "http://tsa.example");
        s.set_sign_cert("missing.p12");
        s.add_input(PathBuf::from("."));
        assert!(s.to_config().is_err(), "missing certificate refused");
        s.set_sign_cert("");
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.jurisdiction, "fr");
        assert!(cfg.tsa_url.is_none());
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert!(
            actions.contains(&"ui_interface_language_changed")
                && actions.contains(&"ui_timestamp_changed")
        );
        assert!(
            cfg.preamble
                .iter()
                .all(|(_, d)| !d.to_string().contains("password"))
        );
    }

    #[test]
    fn case_folder_locks_the_output_folder_and_shows_evidence_ids() {
        let tmp = std::env::temp_dir().join(format!("rv-gui-case-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("ev")).unwrap();
        std::fs::write(tmp.join("ev/a.txt"), "a").unwrap();
        std::fs::write(tmp.join("ev/b.txt"), "b").unwrap();
        let mut s = GuiState {
            timestamp: false,
            ..Default::default()
        };
        assert!(!s.can_start());
        let case_dir = tmp.join("CASE-G");
        s.set_case_dir(&format!("\"{}\"", case_dir.display()));
        assert!(
            s.out_locked() && s.can_start(),
            "a case folder alone can start (registered items)"
        );
        assert!(s.out_dir_display().contains("runs") && s.out_dir_display().ends_with("<RUN-ID>"));
        assert!(s.to_config().is_err(), "creating a case needs a case id");
        s.case_id = "CASE-G".into();
        s.add_input(tmp.join("ev"));
        if CASE_ROLE == rv_mailauth_core::CaseRole::Analysis {
            // An analysis tool verifies against a registry: create it with an explicit intake run first.
            let seed = RunConfig {
                inputs: vec![tmp.join("ev")],
                case_id: Some("CASE-G".into()),
                case_dir: Some(case_dir.clone()),
                case_role: rv_mailauth_core::CaseRole::Intake,
                ..Default::default()
            };
            let off = std::sync::atomic::AtomicBool::new(false);
            rv_mailauth_core::run(&seed, &mut |_| {}, &off).unwrap();
        }
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.case_dir.as_deref(), Some(case_dir.as_path()));
        assert_eq!(cfg.case_role, CASE_ROLE);
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(actions[0], "ui_case_dir_changed");
        s.start();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let summary = rv_mailauth_core::run(&cfg, &mut |e| s.apply(e), &cancel).unwrap();
        assert_eq!(s.phase, Phase::Finished);
        assert!(summary.log_dir.starts_with(&case_dir));
        let ids: Vec<Option<&str>> = s
            .evidence
            .iter()
            .map(|e| e.evidence_id.as_deref())
            .collect();
        assert_eq!(ids, vec![Some("E0001"), Some("E0002")]);
        assert!(s.evidence_lines()[0].starts_with("E0001  a.txt"));
        let log = std::fs::read_to_string(summary.log_dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("\"ui_case_dir_changed\"") && log.contains("\"case_linked\""));
        s.set_case_dir("");
        assert!(!s.out_locked() && s.out_dir_display() == "rakvor-out");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_real_run_from_gui_settings_is_audited() {
        let ev = std::env::temp_dir().join(format!("rv-gui-test-{}", std::process::id()));
        std::fs::create_dir_all(&ev).unwrap();
        std::fs::write(ev.join("a.txt"), "x").unwrap();
        let mut s = GuiState {
            timestamp: false, // tests stay offline
            ..Default::default()
        };
        s.add_input(ev.clone());
        s.out_dir = ev.join("out").display().to_string();
        let cfg = s.to_config().unwrap();
        s.start();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let summary = rv_mailauth_core::run(&cfg, &mut |e| s.apply(e), &cancel).unwrap();
        assert_eq!(s.phase, Phase::Finished);
        let log = std::fs::read_to_string(summary.log_dir.join("audit.jsonl")).unwrap();
        assert!(
            log.contains("\"ui_input_added\"")
                && log.contains("\"ui_start_clicked\"")
                && log.contains("\"frontend\":\"gui\"")
        );
        let _ = std::fs::remove_dir_all(&ev);
    }

    #[test]
    fn option_defaults_are_the_core_defaults() {
        let s = GuiState::default();
        assert_eq!(s.options, DomainOptions::default());
        assert_eq!(
            s.options.isolation,
            rv_mailauth_core::model::Isolation::Worker
        );
        assert!(!s.options.online_dns && s.options.dkim_keys.is_none());
        assert_eq!(s.max_message_mb(), 200);
        let mut s = s;
        s.add_input(PathBuf::from("."));
        assert_eq!(s.to_config().unwrap().domain, DomainOptions::default());
    }

    #[test]
    fn every_option_change_is_audited_with_its_time() {
        let mut s = GuiState::default();
        let keys = std::env::temp_dir().join(format!("rv-gui-keys-{}.txt", std::process::id()));
        std::fs::write(&keys, "# none\n").unwrap();
        let changes = [
            OptionChange::DkimKeys(format!("\"{}\"", keys.display())),
            OptionChange::OnlineDns(true),
            OptionChange::AddOwnDomain("  @Example.ORG. ".into()),
            OptionChange::AddOwnDomain("acme.example".into()),
            OptionChange::RemoveOwnDomain("acme.example".into()),
            OptionChange::ExtractAttachments(true),
            OptionChange::ClockSkew(999_999),
            OptionChange::MboxVariant("mboxo".into()),
            OptionChange::ItemReportsFlaggedOnly(true),
            OptionChange::WorkerTimeout(1),
            OptionChange::WorkerMemory(2048),
            OptionChange::MaxMessageMb(50),
            OptionChange::MaxMboxMessages(0),
        ];
        for c in &changes {
            assert_eq!(s.set_option(c.clone()), Ok(true), "{c:?}");
        }
        let names: Vec<&str> = s.ui_actions.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            names,
            changes.iter().map(|c| c.audit_name()).collect::<Vec<_>>()
        );
        assert!(
            s.ui_actions
                .iter()
                .all(|(_, d)| d["at_utc"].as_str().is_some_and(|t| t.ends_with('Z')))
        );
        let o = &s.options;
        assert_eq!(o.dkim_keys.as_deref(), Some(keys.as_path()));
        assert_eq!(o.own_domains, vec!["example.org".to_string()]);
        assert_eq!(o.clock_skew_s, 86_400, "clamped");
        assert_eq!(o.worker_timeout_s, 5, "clamped");
        assert_eq!(o.max_message_bytes, 50 * 1024 * 1024);
        assert_eq!(o.max_mbox_messages, 1, "clamped");
        assert_eq!(s.ui_actions[2].1["value"], "example.org");
        assert_eq!(s.ui_actions[6].1["value"], 86_400);
        assert_eq!(s.ui_actions[8].1["value"], "flagged");

        // No change, a duplicate and refused values are not audited.
        let n = s.ui_actions.len();
        assert_eq!(s.set_option(OptionChange::OnlineDns(true)), Ok(false));
        assert_eq!(
            s.set_option(OptionChange::AddOwnDomain("EXAMPLE.org".into())),
            Ok(false)
        );
        assert!(
            s.set_option(OptionChange::AddOwnDomain("not a domain".into()))
                .is_err()
        );
        assert!(
            s.set_option(OptionChange::AddOwnDomain("localhost".into()))
                .is_err()
        );
        assert!(
            s.set_option(OptionChange::MboxVariant("mboxcl2".into()))
                .is_err()
        );
        assert_eq!(s.ui_actions.len(), n);

        // The run gets exactly these options, and ui_start_clicked records them.
        s.add_input(PathBuf::from("."));
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.domain, s.options);
        let (_, start) = cfg.preamble.last().unwrap();
        assert_eq!(start["options"]["online_dns"], true);
        assert_eq!(start["options"]["own_domains"][0], "example.org");
        assert!(cfg.command_line.iter().any(|l| l.starts_with("options=")));

        // A key file that is gone is refused before the run.
        std::fs::remove_file(&keys).unwrap();
        assert!(
            s.to_config()
                .unwrap_err()
                .contains("DKIM key file not found")
        );
        assert_eq!(
            s.set_option(OptionChange::DkimKeys(String::new())),
            Ok(true)
        );
        assert!(s.options.dkim_keys.is_none() && s.to_config().is_ok());
        assert_eq!(s.ui_actions.last().unwrap().1["value"], Value::Null);
    }

    /// The sample evidence with its key file and own domain example.org, analysed from GUI settings.
    pub(crate) fn sample_run(tag: &str) -> (GuiState, PathBuf) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let out = std::env::temp_dir().join(format!("rv-gui-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let mut s = GuiState {
            timestamp: false,
            ..Default::default()
        };
        s.add_input(root.join("examples/sample/evidence"));
        s.set_option(OptionChange::DkimKeys(
            root.join("examples/sample/dkim-keys.txt")
                .display()
                .to_string(),
        ))
        .unwrap();
        s.set_option(OptionChange::AddOwnDomain("example.org".into()))
            .unwrap();
        s.out_dir = out.display().to_string();
        let cfg = s.to_config().unwrap();
        s.start();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        rv_mailauth_core::run(&cfg, &mut |e| s.apply(e), &cancel).unwrap();
        s.load_results();
        (s, out)
    }

    #[test]
    fn results_table_and_message_viewer_from_a_sample_run() {
        let (mut s, out) = sample_run("viewer");
        assert_eq!(s.phase, Phase::Finished);
        let run = s
            .run_view
            .clone()
            .expect("run read back from the audit log");
        assert!(s.run_view_error.is_none());
        let labels: Vec<String> = run.rows.iter().map(|r| r.label()).collect();
        // The mbox (item 12) is followed by its three messages.
        let at = labels.iter().position(|l| l == "12").unwrap();
        assert_eq!(&labels[at..at + 4], ["12", "12.1", "12.2", "12.3"]);
        assert_eq!(run.rows[at + 1].name, "12-mailbox.mbox #1");
        assert_eq!(run.rows[at + 1].offset, Some(0));
        assert!(!run.rows[at].viewable() && run.rows[at + 1].viewable());

        let body = run
            .rows
            .iter()
            .position(|r| r.name == "03-body-edited.eml")
            .unwrap();
        assert_eq!(run.rows[body].status, "problem");
        assert_eq!(run.rows[body].counts(), [1, 0, 0, 0]);
        assert!(s.open_message(body));
        let m = s.message.clone().unwrap();
        assert_eq!(m.dkim.signatures[0].result, "body_hash_mismatch");
        assert_eq!(m.dkim.signatures[0].key_source, "key_file");
        assert!(!m.hops.is_empty() && m.addresses[0].role == "addr_from");
        let f = s.message_findings();
        assert_eq!(f[0].code, "DKIM_BODY_HASH_MISMATCH");
        assert!(!f[0].shows.is_empty() && !f[0].not_proves.is_empty());
        assert_ne!(f[0].shows, f[0].not_proves);

        // Opening is recorded in the run's review log, chained to run_finished.
        let log_dir = s.outcome.as_ref().unwrap().log_dir.clone();
        assert_eq!(rv_mailauth_core::review::verify(&log_dir), Ok(Some(1)));
        let review = std::fs::read_to_string(log_dir.join("review.jsonl")).unwrap();
        assert!(review.contains("\"ui_message_viewed\"") && review.contains("headers.json"));
        assert!(s.review_error.is_none() && s.ui_actions.is_empty());

        // The reply-to trap highlights the Reply-To address.
        let trap = run
            .rows
            .iter()
            .position(|r| r.name == "07-reply-to-trap.eml")
            .unwrap();
        assert!(s.open_message(trap));
        let m = s.message.as_ref().unwrap();
        assert!(
            m.addresses
                .iter()
                .any(|a| a.role == "addr_reply_to" && a.mismatch)
        );
        assert_eq!(rv_mailauth_core::review::verify(&log_dir), Ok(Some(2)));
        let _ = std::fs::remove_dir_all(&out);
    }
}
