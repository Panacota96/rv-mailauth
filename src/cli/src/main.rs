//! rv-mailauth command-line interface. All work happens in `rv_mailauth_core`; this file only
//! parses arguments, renders events (progress bar or JSON Lines) and maps results to exit codes.

mod keys;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rv_mailauth_core::model::{DomainOptions, Isolation};
use rv_mailauth_core::trust::{self, DEFAULT_TSA};
use rv_mailauth_core::{
    CASE_ROLE, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, audit, case, hash, i18n, run,
    verify,
};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_FINDINGS: u8 = 3;
const EXIT_CANCELLED: u8 = 130;

const ABOUT: &str = "Look for signals that an email (.eml, .msg, .mbox) was altered or is not what it claims: offline DKIM/ARC, Received hops, dates, attachments and BEC signals, with court-ready reports and a tamper-evident audit log.";

const LONG_ABOUT: &str = "\
DESCRIPTION:
  rv-mailauth looks for signals that an email was altered after it was sent or is not what it
  claims to be. It reads .eml (RFC 5322), Outlook .msg and .mbox files (every message of an mbox
  is an item of its own): a single file, a whole folder (bulk) or a list of files. For each one:
    1. opens the file read-only and hashes it in one pass with one or two algorithms;
    2. parses the headers: From, Sender, Reply-To, Return-Path, Message-ID, Date, every Received
       hop and Authentication-Results (headers.json); for .msg, the stored transport headers;
    3. verifies every DKIM signature and the ARC chain OFFLINE with the public keys you supply
       (--dkim-keys); nothing is looked up on the network unless you add --online (dkim.json);
    4. checks the Received hops against each other and against Date (order, time zones,
       --clock-skew), the Message-ID domain and the MIME structure;
    5. lists the attachments with their SHA-256 and embedded dates (--extract-attachments also
       copies them out);
    6. flags business-email-compromise (BEC) signals: lookalike domains and display names that
       imitate --own-domain, Reply-To/Return-Path at another organisation, payment-details wording;
    7. writes a technical review and a customer summary (HTML, PDF and JSON).
  Each message is parsed in a separate worker process with a time and memory limit (--isolation),
  so a hostile message cannot stop a bulk run. Each run also writes a statistics report and an
  audit trail under <OUT>/logs/<RUN-ID>/; every action is appended to a hash-chained log that
  `rv-mailauth verify-log` can check later. The result is a set of signals for an examiner, never
  a verdict that a message is authentic or forged.

  CASE FOLDER (--case-dir): Rakvor tools share one folder per case. rv-hashinv, the intake tool,
  registers each evidence file once (evidence ids E0001, E0002, ...). rv-mailauth is an analysis
  tool: before analysing a file it re-hashes it and verifies it against that registry, so the
  reports prove the examined file is bit-identical to the registered one. `rv-mailauth
  verify-case <CASE>` checks the whole case.";

const ANALYZE_AFTER_HELP: &str = "\
EXAMPLES:
  Review one message offline with the sender's archived DKIM key (SHA-256, English reports):
    rv-mailauth analyze --input evidence/invoice.eml --dkim-keys keys/example-org-2026.txt
  Review a folder and its subfolders with SHA-256 + MD5, Spanish reports, our own domain:
    rv-mailauth analyze -i D:\\evidence -r --hash sha256,md5 --lang es --case CASE-2026-014 \\
      --dkim-keys case-keys.txt --own-domain acme.example
  Review the files listed in a text file, reports in the three languages, machine-readable progress:
    rv-mailauth analyze --input-list files.txt --lang all --progress jsonl > events.jsonl
  Large mbox: copy the attachments out, reports only for flagged messages:
    rv-mailauth analyze -i E:\\export\\inbox.mbox --extract-attachments --item-reports flagged
  Turn archived DNS records into a key file first; verify the audit log afterwards:
    rv-mailauth keys import dns-archive-2026-03.zone --key-file case-keys.txt
    rv-mailauth verify-log rakvor-out/logs/<RUN-ID>/audit.jsonl
  Analyse every item registered in a case folder (after rv-hashinv intake), then verify the case:
    rv-mailauth analyze --case-dir E:\\CASE-014 --dkim-keys E:\\CASE-014\\keys.txt
    rv-mailauth verify-case E:\\CASE-014
  Analyse two registered items of the case only:
    rv-mailauth analyze --case-dir E:\\CASE-014 --evidence E0001,E0002

EXIT CODES:
  0    Completed; no high-severity finding.
  1    Runtime error (input not found, output not writable, case log locked, ...).
       See the audit log.
  2    Usage error (unknown option, more than two hash algorithms, unsupported language, a
       --dkim-keys file that cannot be read, an invalid --own-domain). With --case-dir: folder
       of another case or schema, --case missing when creating the case, unknown evidence id.
  3    Completed with at least one high-severity finding (e.g. a DKIM body hash that no longer
       matches the body, evidence that differs from the case registry), or the case folder
       fails verification (nothing is written to it).
  130  Cancelled with Ctrl+C. Partial reports and the cancellation are written to the audit log.

FILES WRITTEN:
  <OUT>/logs/<RUN-ID>/audit.jsonl          Hash-chained log of every action (one JSON object/line).
  <OUT>/logs/<RUN-ID>/audit.log            The same actions, human-readable.
  <OUT>/logs/<RUN-ID>/hashes.csv           Hash register: index, path, size, digests, status; the
                                           messages of an mbox as <MBOX>#<n>@<offset>.
  <OUT>/logs/<RUN-ID>/environment.json     Tool and dependency versions, OS, host, user, arguments.
  <OUT>/logs/<RUN-ID>/timestamp-<SEQ>.tsr  RFC 3161 token for the audit chain head (+ .json).
  <OUT>/reports/<RUN-ID>/statistics.json   Run statistics (+ statistics.<LANG>.html and .pdf).
  <ITEM> = <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>; message n of an mbox, found at byte
           <offset>, is the item <NNNNN>-<NAME>_<n>_<offset> (a folder of its own):
  <ITEM>/headers.json                      Parsed headers, Received hops, Authentication-Results,
                                           .msg properties.
  <ITEM>/dkim.json                         Every DKIM signature and the ARC chain: result, key
                                           source (key file line or current DNS), alignment.
  <ITEM>/attachments/NNN-<NAME>            --extract-attachments: each attachment, decoded.
  <ITEM>/mbox_index.json                   mbox only: every message with its offset and length.
  <ITEM>/technical.json|.<LANG>.html|.pdf  Technical review (findings, headers, DKIM, attachments).
  <ITEM>/summary.json|.<LANG>.html|.pdf    Customer summary.
  <ITEM>/custody.json|.<es|fr|en>.html|.pdf  Chain-of-custody form.
  Every file under <ITEM> is hashed with the selected algorithms and recorded in the audit log.
  With --item-reports flagged, items without findings above info get no technical, summary or
  custody files (each skip is audited).
  With --case-dir <CASE>, logs/ and reports/ go to <CASE>/runs/rv-mailauth/<RUN-ID>/, and:
  <CASE>/case-log.jsonl                    Hash-chained case log of every tool: run_started and
                                           run_finished of this run are appended to it.
  <CASE>/case.json                         Case id and jurisdiction (only if the folder is new).
  The evidence registry (<CASE>/evidence/registry.json) is read, never written, by rv-mailauth.

FORENSIC NOTES:
  - Evidence is opened read-only and never modified; modification times are compared before and
    after. Work on a verified copy (write-blocked image or export), not on original media.
  - Findings are signals, not a verdict: a message without findings is not proven authentic, and
    a finding does not prove forgery. Read \"What it does not prove\" and the Limitations section.
  - DKIM shows that the signed headers and body are unchanged since a holder of the domain's
    signing key signed them. It does not show who wrote the message, that the display name is
    truthful, that unsigned headers are original, or when the message was sent. A message that
    passes can still be fraud sent from a real (compromised or lookalike) account.
  - Key at send time: a result is only as good as the key. Use the key published when the
    message was sent (archived DNS, the provider, passive DNS) and import it with `keys import`.
    Keys are rotated: today's key may not verify an old genuine message (DKIM_SIGNATURE_INVALID),
    and a key fetched today with --online is weaker evidence (DKIM_KEY_FROM_CURRENT_DNS).
  - DKIM_BODY_HASH_MISMATCH (high): the body differs from what was signed, whatever the key.
    DKIM_SIGNATURE_INVALID (medium) can come from edited signed headers or from a key that is not
    the one that signed; the tool cannot tell which.
  - Outlook .msg files keep the original transport headers only when Outlook stored them
    (PR_TRANSPORT_MESSAGE_HEADERS); without them (MSG_TRANSPORT_HEADERS_MISSING) there is
    nothing to verify. Outlook rebuilds the body, so DKIM over a .msg is reported as not
    evaluated, never as failed.
  - Received hops are written by each server: only the hops added by servers you trust (usually
    the recipient's own) are reliable. Times are compared with the --clock-skew tolerance.
  - BEC heuristics (lookalike domains, display-name imitation, Reply-To or Return-Path elsewhere,
    payment-details wording) are signals for review, never proof of fraud.
  - Each message is parsed in a worker process (without network on Linux) limited by
    --worker-timeout and --worker-memory-mb; a crash or limit is PARSER_FAILED for that item only.
  - Each audit entry stores the SHA-256 of the previous one; editing, deleting or re-ordering any
    line is detected by `verify-log`. The --dkim-keys file's SHA-256 and every --online lookup
    are in the audit log. Keep the log folder with the reports.
  - MD5 and SHA-1 are accepted for compatibility with older case files; pair them with SHA-256 or
    BLAKE3.
  - The chain head is timestamped by an RFC 3161 authority (proves when the log existed). Offline?
    The run finishes with `timestamp_pending`; run `rv-mailauth timestamp <LOG>` later.
  - With --sign-cert every PDF is signed with the examiner's certificate; the password is never
    logged.
  - Case folder: every item is compared with the registry (by --evidence id, else by path, else
    by content) before it is analysed; a different hash is the high finding
    EVIDENCE_HASH_MISMATCH_WITH_CASE (the analysis still runs), a file not in the registry is
    EVIDENCE_NOT_IN_CASE_REGISTRY (medium). The case log and registry digest are re-verified
    before every write; a broken case is refused (exit 3). Appends happen under case-log.lock.
  - Each run's audit.jsonl records case_linked (the case-log entry it started from); the case
    log records the run's final audit head, so the two chains vouch for each other.";

const KEYS_AFTER_HELP: &str = "\
DESCRIPTION:
  DKIM public keys for offline verification (`analyze --dkim-keys FILE`). A key file has one key
  per record: \"selector._domainkey.domain<TAB>v=DKIM1; k=rsa; p=...\" or a BIND zone-file TXT
  record. `keys import` turns archived DNS records into such a file and audits the import;
  `keys show` lists what a key file holds. Nothing is ever fetched from the network.

EXAMPLES:
  rv-mailauth keys import dns-archive-2026-03.zone --key-file case-keys.txt
  rv-mailauth keys show case-keys.txt";

const KEYS_IMPORT_AFTER_HELP: &str = "\
DESCRIPTION:
  Reads archived DNS TXT records (BIND zone-file lines, or \"selector._domainkey.domain<TAB>TXT
  value\" lines), keeps the records under selector._domainkey.domain and validates each one as a
  DKIM key record (v=DKIM1, k=rsa|ed25519, a usable p= key) with the parser `analyze` uses. Other
  record types (A, MX, SOA, ...), other TXT names (SPF, DMARC) and revoked keys (empty p=) are
  skipped and listed in the audit log. Identical duplicates are merged. The keys are written,
  sorted by name, to a new normalised key file whose header names every source and its SHA-256.
  Nothing is written if any DKIM record is malformed, has a name relative to $ORIGIN (write
  selector._domainkey.domain in full), or two different keys share one name.

FILES WRITTEN:
  <KEY-FILE>                            The normalised key file (never overwritten).
  <OUT>/logs/<RUN-ID>/audit.jsonl|.log  Hash-chained log of the import: keys_import_started
                                        (each source's path, size and SHA-256), key_imported
                                        (name, key type, bits, SHA-256 of the record),
                                        record_ignored, output_written (key file SHA-256).
  <OUT>/logs/<RUN-ID>/environment.json  Tool and dependency versions, OS, host, user, arguments.
  <OUT>/logs/<RUN-ID>/timestamp-<SEQ>.tsr  RFC 3161 token for the chain head (+ .json).

FORENSIC NOTES:
  - Record where each archive comes from (zone backup, provider export, passive DNS) and when it
    was valid: DKIM results are only as good as the key at send time.
  - The key file's SHA-256 printed here appears in the audit log of every `analyze` run that uses
    it. `rv-mailauth verify-log <LOG>` checks the import log later.

EXAMPLES:
  rv-mailauth keys import dns-archive-2026-03.zone --key-file case-keys.txt
  rv-mailauth keys import example-org.txt mailer-example-com.zone --key-file keys.txt -o E:\\lab \\
    --case CASE-014 --actor \"Ana Ruiz\"

EXIT CODES:
  0  The key file was written and the import logged.
  1  A source cannot be read, the key file already exists or cannot be written, or the audit log
     cannot be created.
  2  Usage error, or a DKIM record is malformed, two different keys share one name, or no DKIM
     key record was found (nothing is written).";

const KEYS_SHOW_AFTER_HELP: &str = "\
DESCRIPTION:
  Lists every usable key of a key file (line, selector, domain, key type, bits) with the file's
  SHA-256, then every record `analyze` could not use. Nothing is written.

EXAMPLES:
  rv-mailauth keys show case-keys.txt
  rv-mailauth keys show examples/sample/dkim-keys.txt

EXIT CODES:
  0  Every record of the file is a usable DKIM key.
  1  The file cannot be read.
  2  At least one record is not a usable DKIM key (listed).";

#[derive(Parser)]
#[command(name = TOOL_NAME, version = TOOL_VERSION, about = ABOUT, long_about = LONG_ABOUT, max_term_width = 100,
          after_long_help = "Run `rv-mailauth <COMMAND> --help` for the options, examples and exit codes of each command.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Look for signals of alteration and BEC in emails: a file, a folder or a list of files.
    // `scan` is accepted as a hidden alias for one release so existing scripts keep working.
    #[command(long_about = LONG_ABOUT, after_long_help = ANALYZE_AFTER_HELP, alias = "scan")]
    Analyze(Box<AnalyzeArgs>),
    /// DKIM key files: import archived DNS TXT records, show what a key file holds.
    #[command(subcommand, after_long_help = KEYS_AFTER_HELP)]
    Keys(KeysCmd),
    /// Verify an audit log (audit.jsonl): edited, deleted or re-ordered entries, and truncation.
    #[command(after_long_help = "\
CHECKS:
  - every entry links to the previous one (hash chain): an edited, deleted or re-ordered entry
    breaks it;
  - every timestamp token the log records (timestamp_obtained) is still next to it with its
    metadata (timestamp-<SEQ>.tsr with the recorded SHA-256, timestamp-<SEQ>.json agreeing): a
    missing file is a problem, never a skipped check; a token file no entry records is checked
    too. Every token covers the hash of the entry it names;
  - the TSA's CMS signature of every token: signer certificate in the token, ESS
    signing-certificate binding, message digest over TSTInfo, RSA signature, and an extended key
    usage that is critical and only timeStamping (RFC 3161). With --tsa-ca, also the TSA
    certificate path up to that CA bundle at the token's genTime (every candidate issuer tried;
    CA flag, keyCertSign, pathLenConstraint, directoryName name constraints, no unsupported
    critical extension); without it the output says \"chain not checked\". Revocation is
    never checked: establish it from CRL/OCSP evidence covering genTime;
  - truncation: a chain alone cannot show that entries were removed from its end. The log must
    still contain the entry covered by its RFC 3161 timestamp (covers_seq) and, for a run inside
    a case folder (<CASE>/runs/<TOOL>/<RUN-ID>/logs), end with the audit head that the case log
    recorded at run_finished (only timestamp_obtained may follow). Entries after the last
    anchored one are listed as not provable; with neither record the output says
    \"truncation not detectable without a timestamp or case record\";
  - the review log: review.jsonl in the same folder (messages opened in the GUI viewer after the
    run) is checked when present: an intact hash chain whose first entry links to the run's
    run_finished entry, every entry naming this run. The output adds \"review entries: N\"; an
    edited review log, or one copied from another run, is a failure.

EXAMPLES:
  rv-mailauth verify-log rakvor-out/logs/20261019T101500Z-a1b2c3/audit.jsonl
  rv-mailauth verify-log rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-mailauth verify-log E:\\CASE-014\\runs\\rv-mailauth\\20261019T101500Z-a1b2c3\\logs
  rv-mailauth verify-log rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-ca digicert-tsa-roots.pem

EXIT CODES:
  0  The chain is intact and agrees with its timestamps and case record (if any).
  1  The log or the --tsa-ca file cannot be read.
  3  The chain is broken (an entry was edited, deleted or re-ordered), a timestamp does not
     match or does not verify (altered token, invalid TSA signature, chain not trusted by
     --tsa-ca), the log is shorter than its timestamp or case record says (truncated), or
     review.jsonl is broken or anchored to another run.")]
    VerifyLog {
        /// Path to audit.jsonl, or to the run's log folder that contains it.
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
        /// CA bundle (PEM with one or more certificates, or one DER certificate) that the TSA
        /// certificate of every timestamp token must chain to, at the token's genTime.
        ///
        /// Default: none (the TSA signature is checked, the chain is not).
        /// Example: --tsa-ca C:\certs\tsa-roots.pem
        #[arg(long, value_name = "PEM", verbatim_doc_comment)]
        tsa_ca: Option<PathBuf>,
    },
    /// Check every hash algorithm against known-answer test vectors.
    #[command(after_long_help = "\
EXAMPLES:
  rv-mailauth self-test

EXIT CODES:
  0  All algorithms give the published answer for the input \"abc\".
  1  At least one algorithm failed: do not use this build for evidence.")]
    SelfTest,
    /// Add an RFC 3161 timestamp to a finished run (e.g. after working offline).
    #[command(after_long_help = "\
EXAMPLES:
  rv-mailauth timestamp rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-mailauth timestamp rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-url https://freetsa.org/tsr

EXIT CODES:
  0  Timestamp obtained and logged.
  1  The TSA could not be reached (nothing changed; try again).
  3  The log is missing or broken: no timestamp is added.")]
    Timestamp {
        /// The run's log folder (or its audit.jsonl).
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
        /// RFC 3161 time-stamping authority.
        /// Default: http://timestamp.digicert.com
        /// Example: --tsa-url https://freetsa.org/tsr
        #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
        tsa_url: String,
        /// Name written in the new audit entry.
        /// Default: the operating-system user name
        /// Example: --actor "Ana Ruiz"
        #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
        actor: Option<String>,
    },
    /// Verify a whole case folder: case log, evidence registry and every run's audit log.
    #[command(after_long_help = "\
CHECKS:
  - case-log.jsonl is an intact hash chain starting with case_created; case.json is unchanged;
  - evidence/registry.json has the SHA-256 recorded at the last registry change;
  - every run announced in the case log has an intact audit.jsonl (and valid timestamp
    tokens: imprint and TSA signature; the TSA chain is not checked, use verify-log
    --tsa-ca), its case_linked entry points to its run_started entry, and the audit head
    recorded at run_finished is its final entry (only timestamp_obtained may follow);
  - every run's review.jsonl (messages opened in the GUI viewer after the run), when present,
    is an intact chain anchored to that run's run_finished entry (\"review entries: N\");
  - with --rehash: every registered item still reachable at its registered path is read again
    and its digests are compared with the registry (the latest registration of a path).

EXAMPLES:
  rv-mailauth verify-case E:\\CASE-014
  rv-mailauth verify-case E:\\CASE-014 --rehash

EXIT CODES:
  0  The case folder is intact (warnings, e.g. a run still in progress or an item not
     reachable for --rehash, are printed).
  1  The folder is not a case folder (no case.json).
  3  At least one check failed: the case was edited, truncated or re-ordered, or (--rehash)
     an evidence file differs from the registry.")]
    VerifyCase {
        /// The case folder (the one that holds case.json).
        ///
        /// Example: E:\CASE-014
        case: PathBuf,
        /// Also re-hash every registered item still reachable and compare it with the registry.
        /// Default: off (only the registry's digest is checked)
        /// Example: --rehash
        #[arg(long, verbatim_doc_comment)]
        rehash: bool,
    },
    /// Print the full help of every command as Markdown (used to generate docs/usage-cli.md).
    #[command(hide = true)]
    DocsCli,
    /// Describe this tool as JSON (schema rakvor.describe/1) for RV Hub and scripts.
    #[command(hide = true, after_long_help = DESCRIBE_AFTER_HELP)]
    Describe {
        /// Print JSON: one pretty-printed object with sorted keys.
        /// Default: on (JSON is the only format)
        /// Example: --json
        #[arg(long, verbatim_doc_comment)]
        json: bool,
    },
}

const DESCRIBE_AFTER_HELP: &str = "\
DESCRIPTION:
  Prints what this tool is, what it accepts and how to launch it, validated by
  schemas/describe.schema.json. RV Hub reads it to list the tool, start its GUI on a case
  folder (rv-mailauth-gui.exe --case-dir <CASE> [FILES...]) and suggest the tool for a file.
  Fields: schema, tool, title, version, role (analysis), main_verb (analyze), accepts
  (extensions eml, mbox, msg; signatures of .msg and mbox), case_formats, log_formats, cli_exe,
  gui_exe, exit_codes. Nothing is read or written; no audit log is created.

EXAMPLES:
  rv-mailauth describe --json

EXIT CODES:
  0  The description was printed.";

#[derive(Subcommand)]
enum KeysCmd {
    /// Turn archived DNS TXT records into a normalised DKIM key file; the import is audited.
    #[command(after_long_help = KEYS_IMPORT_AFTER_HELP)]
    Import {
        /// Archived DNS records: BIND zone files or "selector._domainkey.domain<TAB>TXT" lists.
        /// Read-only; their SHA-256 goes into the audit log and the key file header.
        /// Default: none (at least one is required)
        /// Example: dns-archive-2026-03.zone
        #[arg(value_name = "FILE", required = true, verbatim_doc_comment)]
        sources: Vec<PathBuf>,
        /// The normalised key file to write (refused if it already exists).
        /// Default: none (required)
        /// Example: --key-file case-keys.txt
        #[arg(long, value_name = "FILE", verbatim_doc_comment)]
        key_file: PathBuf,
        /// Folder where logs/<RUN-ID>/ of the import is created. Created if missing.
        /// Default: ./rakvor-out
        /// Example: --out E:\case-014\rv-mailauth
        #[arg(
            short,
            long,
            value_name = "DIR",
            default_value = "rakvor-out",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        out: PathBuf,
        /// Name of the examiner, written in every audit entry.
        /// Default: the operating-system user name
        /// Example: --actor "Ana Ruiz"
        #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
        actor: Option<String>,
        /// Case or engagement identifier recorded in the audit log.
        /// Default: none
        /// Example: --case CASE-2026-014
        #[arg(short, long = "case", value_name = "ID", verbatim_doc_comment)]
        case_id: Option<String>,
        /// RFC 3161 time-stamping authority for the audit chain head.
        /// Default: http://timestamp.digicert.com
        /// Example: --tsa-url https://freetsa.org/tsr
        #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
        tsa_url: String,
        /// Do not request a trusted timestamp (offline labs). Also set by RV_NO_TIMESTAMP=1.
        /// Default: off (a timestamp is requested)
        /// Example: --no-timestamp
        #[arg(long, env = "RV_NO_TIMESTAMP", value_parser = clap::builder::FalseyValueParser::new(), verbatim_doc_comment, hide_env = true)]
        no_timestamp: bool,
    },
    /// List the keys of a key file: selector, domain, key type and bits.
    #[command(after_long_help = KEYS_SHOW_AFTER_HELP)]
    Show {
        /// Key file (as written by `keys import`, or by hand in the same format).
        /// Default: none (required)
        /// Example: case-keys.txt
        #[arg(value_name = "FILE", verbatim_doc_comment)]
        file: PathBuf,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MboxVariant {
    /// Strip one '>' from every ">...From " body line (most current software).
    Mboxrd,
    /// Strip it only from ">From " lines (older software).
    Mboxo,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum IsolationMode {
    /// A worker process per message (time and memory limits; no network on Linux).
    Worker,
    /// In the main process (debugging only; a hang stops the run).
    InProcess,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ItemReports {
    All,
    Flagged,
}

/// `--own-domain`: a domain name, lower case, without a leading "@" or trailing dot.
fn parse_domain(v: &str) -> Result<String, String> {
    let d = v
        .trim()
        .trim_start_matches('@')
        .trim_end_matches('.')
        .to_lowercase();
    let ok = d.contains('.')
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_alphanumeric() || c == '-')
        });
    if ok {
        Ok(d)
    } else {
        Err(format!("'{v}' is not a domain name (e.g. acme.example)"))
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ProgressMode {
    /// Progress bar with elapsed time, throughput and ETA on stderr.
    Bar,
    /// One JSON event per line on stdout (for scripts and other tools).
    Jsonl,
    /// No progress output; only the final summary.
    None,
}

#[derive(Args)]
struct AnalyzeArgs {
    /// File or folder to review. Repeat for several.
    ///
    /// Folders are reviewed one level deep unless --recursive is given. Symbolic links are not followed.
    /// Default: none (required unless --input-list, --case-dir or --evidence is given).
    /// Example: --input D:\evidence --input E:\export\invoice.eml
    #[arg(
        short,
        long = "input",
        value_name = "PATH",
        required_unless_present_any = ["input_list", "case_dir", "evidence"],
        verbatim_doc_comment
    )]
    inputs: Vec<PathBuf>,

    /// Text file with one path per line (bulk review). Lines starting with # are ignored.
    ///
    /// Relative paths are resolved from the list file's folder.
    /// Default: none. Example: --input-list case-014-files.txt
    #[arg(short = 'L', long, value_name = "FILE", verbatim_doc_comment)]
    input_list: Option<PathBuf>,

    /// Also review files in subfolders.
    ///
    /// Default: off (only the first level of each folder). Example: -i D:\evidence --recursive
    #[arg(short, long, verbatim_doc_comment)]
    recursive: bool,

    /// Hash algorithm(s): one or two of md5, sha1, sha256, sha512, sha3-256, blake3.
    ///
    /// Both are computed in the same read of each file. More than two is refused (exit code 2).
    /// Default: sha256. Example: --hash sha256,md5   or   --hash sha256 --hash blake3
    #[arg(
        short = 'H',
        long = "hash",
        value_name = "ALGO",
        value_delimiter = ',',
        default_value = "sha256",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    hashes: Vec<String>,

    /// Folder where logs/ and reports/ are created. Created if missing. Ignored with --case-dir.
    ///
    /// Default: ./rakvor-out. Example: --out E:\case-014\rv-mailauth
    #[arg(
        short,
        long,
        value_name = "DIR",
        default_value = "rakvor-out",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    out: PathBuf,

    /// Report language: en, es, fr, or all (one HTML and PDF per language). JSON is language-neutral.
    ///
    /// Default: en. Example: --lang es   or   --lang all
    #[arg(
        short,
        long,
        value_name = "LANG",
        default_value = "en",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    lang: String,

    /// Name of the examiner, written in every audit entry and report.
    ///
    /// Default: the operating-system user name. Example: --actor "Ana Ruiz"
    #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
    actor: Option<String>,

    /// Case or engagement identifier printed on the reports. With --case-dir it names the case
    /// when the folder is created, and must match case.json afterwards (it can be left out).
    /// Default: none. Example: --case CASE-2026-014
    #[arg(short, long = "case", value_name = "ID", verbatim_doc_comment)]
    case_id: Option<String>,

    /// How progress is shown: bar, jsonl or none.
    ///
    /// Default: bar (hidden automatically when stderr is not a terminal).
    /// Example: --progress jsonl
    #[arg(
        short,
        long,
        value_enum,
        value_name = "MODE",
        default_value = "bar",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    progress: ProgressMode,

    /// Chain-of-custody form per item: co (Colombia, Fiscalía style, Spanish) or fr (France, scellés, French).
    /// An English copy is always added. With --case-dir the case's jurisdiction applies.
    /// Default: co
    /// Example: --jurisdiction fr
    #[arg(short, long, value_name = "CC", default_value = "co", value_parser = ["co", "fr"], verbatim_doc_comment, hide_default_value = true, hide_possible_values = true)]
    jurisdiction: String,

    /// RFC 3161 time-stamping authority for the audit chain head.
    /// Default: http://timestamp.digicert.com
    /// Example: --tsa-url https://freetsa.org/tsr
    #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
    tsa_url: String,

    /// Do not request a trusted timestamp (offline labs). Also set by RV_NO_TIMESTAMP=1.
    /// Default: off (a timestamp is requested)
    /// Example: --no-timestamp
    #[arg(long, env = "RV_NO_TIMESTAMP", value_parser = clap::builder::FalseyValueParser::new(), verbatim_doc_comment, hide_env = true)]
    no_timestamp: bool,

    /// Examiner's certificate (.p12/.pfx, RSA) used to sign every PDF report. The password is read from
    /// the environment variable named by --sign-pass-env, or asked for interactively.
    /// Default: none (PDFs are not signed)
    /// Example: --sign-cert C:\certs\ana-ruiz.p12
    #[arg(long, value_name = "P12", verbatim_doc_comment)]
    sign_cert: Option<PathBuf>,

    /// Environment variable holding the certificate password.
    /// Default: RV_SIGN_PASSWORD
    /// Example: --sign-pass-env CERT_PASS
    #[arg(
        long,
        value_name = "VAR",
        default_value = "RV_SIGN_PASSWORD",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    sign_pass_env: String,

    /// Shared case folder that links the Rakvor tools of one case (created with --case if missing).
    /// Outputs go to <DIR>/runs/rv-mailauth/<RUN-ID>/; every hashed file is registered in
    /// <DIR>/evidence/registry.json; the run is recorded in <DIR>/case-log.jsonl.
    /// With no --input, every registered item is examined again.
    /// Default: none (standalone run in --out)
    /// Example: --case-dir E:\CASE-014 --case CASE-014
    #[arg(long, value_name = "DIR", verbatim_doc_comment)]
    case_dir: Option<PathBuf>,

    /// Registered evidence ids to examine (needs --case-dir), comma-separated or repeated.
    /// Default: none (the --input files, or every registered item)
    /// Example: --evidence E0001,E0007
    #[arg(
        short = 'E',
        long = "evidence",
        value_name = "IDS",
        requires = "case_dir",
        verbatim_doc_comment
    )]
    evidence: Vec<String>,

    /// DKIM public keys to verify signatures with, OFFLINE: one record per key,
    /// "selector._domainkey.domain<TAB>v=DKIM1; k=rsa; p=..." or a BIND zone-file TXT record
    /// (see `keys import`). Use the keys published when the messages were sent. The file's
    /// SHA-256 and the keys it holds go into the audit log.
    /// Default: none (every signature is DKIM_KEY_NOT_AVAILABLE)
    /// Example: --dkim-keys E:\CASE-014\keys.txt
    #[arg(long, value_name = "FILE", verbatim_doc_comment)]
    dkim_keys: Option<PathBuf>,

    /// Fetch the keys missing from --dkim-keys from TODAY's DNS (the system resolver). This is
    /// weaker evidence: the key published today may not be the one that signed the message
    /// (rotated, revoked, or re-published by whoever controls the domain now). Every lookup is
    /// an audit entry, and each result based on it carries DKIM_KEY_FROM_CURRENT_DNS (medium).
    /// Lookups run in the main process; worker processes never use the network.
    /// Default: off (no network access for DKIM)
    /// Example: --online
    #[arg(long, verbatim_doc_comment)]
    online: bool,

    /// Your organisation's own domain, for the lookalike-domain and display-name checks.
    /// Repeat (or separate with commas) for several.
    /// Default: none (the lookalike and display-name checks have nothing to compare with)
    /// Example: --own-domain acme.example --own-domain acme-group.example
    #[arg(long, value_name = "DOMAIN", value_delimiter = ',', value_parser = parse_domain, verbatim_doc_comment)]
    own_domain: Vec<String>,

    /// Copy every attachment, decoded, to <ITEM>/attachments/ (hashed and audited like every
    /// output). Attachments are always listed with their SHA-256, even without this option.
    /// Default: off
    /// Example: --extract-attachments
    #[arg(long, verbatim_doc_comment)]
    extract_attachments: bool,

    /// Clock difference tolerated between servers, in seconds (0 to 86400), before the order of
    /// the Received hops or a Date after the first hop is a finding.
    /// Default: 300
    /// Example: --clock-skew 900
    #[arg(long, value_name = "SECONDS", default_value_t = 300, value_parser = clap::value_parser!(u64).range(0..=86400), verbatim_doc_comment, hide_default_value = true)]
    clock_skew: u64,

    /// mbox flavour for un-escaping ">From " body lines: mboxrd or mboxo. The wrong flavour can
    /// change the body bytes, and so the DKIM body hash, of a message that quotes "From " lines.
    /// Default: mboxrd
    /// Example: --mbox-variant mboxo
    #[arg(
        long,
        value_enum,
        value_name = "VARIANT",
        default_value = "mboxrd",
        verbatim_doc_comment,
        hide_default_value = true,
        hide_possible_values = true
    )]
    mbox_variant: MboxVariant,

    /// Largest message parsed, in MiB (1 to 4096); a larger one is PARSER_FAILED (too_large).
    /// Default: 200
    /// Example: --max-message-mb 1024
    #[arg(long, value_name = "MB", default_value_t = 200, value_parser = clap::value_parser!(u64).range(1..=4096), verbatim_doc_comment, hide_default_value = true)]
    max_message_mb: u64,

    /// Messages analysed per mbox (1 to 10000000); the rest is listed as not analysed.
    /// Default: 50000
    /// Example: --max-mbox-messages 200000
    #[arg(long, value_name = "N", default_value_t = 50_000, value_parser = clap::value_parser!(u64).range(1..=10_000_000), verbatim_doc_comment, hide_default_value = true)]
    max_mbox_messages: u64,

    /// Seconds a worker process may spend on one message (1 to 86400) before it is stopped
    /// (PARSER_FAILED, timeout).
    /// Default: 120
    /// Example: --worker-timeout 600
    #[arg(long, value_name = "SECONDS", default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=86400), verbatim_doc_comment, hide_default_value = true)]
    worker_timeout: u64,

    /// Memory limit of one worker process in MiB (128 to 1048576): a job object on Windows, the
    /// address space on Linux/macOS. Exceeding it is PARSER_FAILED (memory_limit).
    /// Default: 1024
    /// Example: --worker-memory-mb 4096
    #[arg(long, value_name = "MB", default_value_t = 1024, value_parser = clap::value_parser!(u64).range(128..=1_048_576), verbatim_doc_comment, hide_default_value = true)]
    worker_memory_mb: u64,

    /// Where messages are parsed: worker (a separate process per message, with the limits
    /// above) or in-process (no isolation; for debugging). The choice is in the audit log.
    /// Default: worker
    /// Example: --isolation in-process
    #[arg(
        long,
        value_enum,
        value_name = "MODE",
        default_value = "worker",
        verbatim_doc_comment,
        hide_default_value = true,
        hide_possible_values = true
    )]
    isolation: IsolationMode,

    /// Per-item report files for every item (all) or only for items with findings above info
    /// (flagged). Skipped items are still listed in the statistics report; each skip is audited.
    /// Default: all
    /// Example: --item-reports flagged
    #[arg(
        long,
        value_enum,
        value_name = "WHICH",
        default_value = "all",
        verbatim_doc_comment,
        hide_default_value = true,
        hide_possible_values = true
    )]
    item_reports: ItemReports,
}

fn main() -> ExitCode {
    // `<exe> worker …`: one message analysed in an isolated child process (see core worker.rs).
    if std::env::args_os().nth(1).is_some_and(|a| a == "worker") {
        std::process::exit(rv_mailauth_core::worker::worker_main());
    }
    // This executable serves as the worker of the default isolation.
    rv_mailauth_core::worker::register_frontend_executable();
    let cli = Cli::parse();
    ExitCode::from(match cli.command {
        Command::Analyze(a) => analyze(*a),
        Command::Keys(KeysCmd::Show { file }) => keys::show(&file),
        Command::Keys(KeysCmd::Import {
            sources,
            key_file,
            out,
            actor,
            case_id,
            tsa_url,
            no_timestamp,
        }) => keys::import(keys::ImportArgs {
            sources,
            output: key_file,
            out_dir: out,
            actor: actor.unwrap_or_else(rv_mailauth_core::env::os_user),
            case_id,
            tsa_url: (!no_timestamp).then_some(tsa_url),
            command_line: std::env::args().collect(),
        }),
        Command::VerifyLog { log, tsa_ca } => verify_log(log, tsa_ca),
        Command::VerifyCase { case, rehash } => verify_case(case, rehash),
        Command::SelfTest => self_test(),
        Command::Timestamp {
            log,
            tsa_url,
            actor,
        } => timestamp(log, tsa_url, actor),
        Command::DocsCli => {
            print!("{}", docs_cli());
            EXIT_OK
        }
        Command::Describe { json: _ } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&describe()).expect("describe is valid JSON")
            );
            EXIT_OK
        }
    })
}

fn usage_error(msg: &str) -> u8 {
    eprintln!(
        "error: {}\n\nFor more information, try 'rv-mailauth analyze --help'.",
        msg
    );
    EXIT_USAGE
}

fn analyze(a: AnalyzeArgs) -> u8 {
    let mut algos = Vec::new();
    for h in &a.hashes {
        match HashAlgo::parse(h) {
            Some(x) => algos.push(x),
            None => {
                return usage_error(&format!(
                    "unknown hash algorithm '{}': use md5, sha1, sha256, sha512, sha3-256 or blake3",
                    h
                ));
            }
        }
    }
    if let Err(e) = hash::validate_selection(&algos) {
        return usage_error(&e);
    }
    let langs = match i18n::parse_langs(&a.lang) {
        Ok(l) => l,
        Err(e) => return usage_error(&e),
    };
    let evidence_ids = match case::parse_evidence_ids(&a.evidence) {
        Ok(ids) => ids,
        Err(e) => return usage_error(&e.message),
    };
    if let Some(k) = &a.dkim_keys {
        // A key file that cannot be read would silently turn every signature into "key not available".
        let readable = std::fs::metadata(k).map(|m| m.is_file()).unwrap_or(false)
            && std::fs::File::open(k).is_ok();
        if !readable {
            return usage_error(&format!("--dkim-keys {}: not a readable file", k.display()));
        }
    }
    if let Some(dir) = &a.case_dir {
        // Case problems found before the run map to their own exit codes (2 usage, 3 broken case).
        if let Err(e) = case::preflight(dir, a.case_id.as_deref(), &evidence_ids) {
            return match e.exit_code() {
                EXIT_USAGE => usage_error(&e.message),
                code => {
                    eprintln!("error: {}", e.message);
                    code
                }
            };
        }
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    let _ = ctrlc::set_handler(move || c.store(true, Ordering::SeqCst));

    let cfg = RunConfig {
        inputs: a.inputs,
        input_list: a.input_list,
        recursive: a.recursive,
        algorithms: algos,
        out_dir: a.out,
        langs,
        actor: a.actor.unwrap_or_else(rv_mailauth_core::env::os_user),
        case_id: a.case_id,
        frontend: "cli".into(),
        preamble: vec![],
        command_line: std::env::args().collect(),
        tool_name: TOOL_NAME.into(),
        tool_version: TOOL_VERSION.into(),
        jurisdiction: a.jurisdiction.clone(),
        tsa_url: if a.no_timestamp {
            None
        } else {
            Some(a.tsa_url.clone())
        },
        sign_password: a
            .sign_cert
            .as_ref()
            .and_then(|_| password(&a.sign_pass_env)),
        sign_cert: a.sign_cert.clone(),
        case_dir: a.case_dir.clone(),
        evidence_ids,
        case_role: CASE_ROLE,
        domain: DomainOptions {
            dkim_keys: a.dkim_keys.clone(),
            online_dns: a.online,
            fetched_keys: Vec::new(),
            own_domains: a.own_domain.clone(),
            extract_attachments: a.extract_attachments,
            clock_skew_s: a.clock_skew,
            mbox_variant: match a.mbox_variant {
                MboxVariant::Mboxrd => "mboxrd",
                MboxVariant::Mboxo => "mboxo",
            }
            .into(),
            max_message_bytes: a.max_message_mb * 1024 * 1024,
            max_mbox_messages: a.max_mbox_messages,
            worker_timeout_s: a.worker_timeout,
            worker_memory_mb: a.worker_memory_mb,
            item_reports_flagged_only: a.item_reports == ItemReports::Flagged,
            isolation: match a.isolation {
                IsolationMode::Worker => Isolation::Worker,
                IsolationMode::InProcess => Isolation::InProcess,
            },
        },
    };

    let bar = match a.progress {
        ProgressMode::Bar => {
            let b = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr_with_hz(8));
            b.set_style(
                ProgressStyle::with_template("{spinner} [{elapsed_precise}] {wide_bar} {binary_bytes}/{binary_total_bytes} {binary_bytes_per_sec} ETA {eta} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
            Some(b)
        }
        _ => None,
    };
    let jsonl = matches!(a.progress, ProgressMode::Jsonl);
    // A closed stdout (e.g. `| head`) must never abort a forensic run half-way: stop printing, keep working.
    let mut stdout_open = true;
    let mut sink = |e: &Event| {
        if jsonl && stdout_open {
            let mut out = std::io::stdout().lock();
            stdout_open = writeln!(out, "{}", serde_json::to_string(e).unwrap_or_default())
                .and_then(|_| out.flush())
                .is_ok();
        }
        if let Some(b) = &bar {
            match e {
                Event::RunStarted {
                    total_bytes,
                    total_items,
                    ..
                } => {
                    b.set_length(*total_bytes);
                    b.set_message(format!("0/{} files", total_items));
                }
                Event::Progress {
                    done,
                    total,
                    bytes_done,
                    ..
                } => {
                    b.set_position(*bytes_done);
                    b.set_message(format!("{}/{} files", done, total));
                }
                Event::Error { path, message } => b.println(format!(
                    "warning: {}: {}",
                    path.as_deref().unwrap_or("-"),
                    message
                )),
                Event::Cancelled { .. } => b.println("cancelled: writing partial reports..."),
                Event::Timestamp { status, reason, .. } if status != "ok" => b.println(format!(
                    "warning: timestamp pending ({}); run `rv-mailauth timestamp` later",
                    reason.as_deref().unwrap_or("-")
                )),
                _ => {}
            }
        }
    };
    let result = run(&cfg, &mut sink, &cancel);
    if let Some(b) = &bar {
        b.finish_and_clear();
    }
    match result {
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
        Ok(s) => {
            if !jsonl {
                let out = format!(
                    "{status}  run {id}\n  items: {items}  bytes: {bytes}  errors: {errors}  elapsed: {elapsed}\n  findings: high {h}, medium {m}, low {l}, info {i}\n  timestamp: {ts}\n  report: {report}\n  logs:   {logs}",
                    status = if s.cancelled {
                        "CANCELLED"
                    } else if s.high > 0 {
                        "DONE (high-severity findings)"
                    } else {
                        "DONE"
                    },
                    id = s.run_id,
                    items = s.items,
                    bytes = s.bytes,
                    errors = s.errors,
                    elapsed = rv_mailauth_core::time::human_duration(s.elapsed_ms),
                    h = s.high,
                    m = s.medium,
                    l = s.low,
                    i = s.info,
                    ts = format!(
                        "{} {}",
                        s.timestamp["status"].as_str().unwrap_or("off"),
                        s.timestamp["gen_time"].as_str().unwrap_or("")
                    )
                    .trim(),
                    report = s
                        .report_dir
                        .join(format!("statistics.{}.html", cfg.langs[0]))
                        .display(),
                    logs = s.log_dir.display()
                );
                let _ = writeln!(std::io::stdout(), "{}", out);
                if let Some(c) = &s.case {
                    let t = &c.tally;
                    let _ = writeln!(
                        std::io::stdout(),
                        "  case:   {} ({}) registered {} (new {}), verified {}, mismatched {}, not in registry {}",
                        c.case_id,
                        c.role,
                        t.registered,
                        t.added,
                        t.verified,
                        t.mismatched,
                        t.unregistered
                    );
                }
            }
            if s.cancelled {
                EXIT_CANCELLED
            } else if s.high > 0 {
                EXIT_FINDINGS
            } else {
                EXIT_OK
            }
        }
    }
}

fn password(env: &str) -> Option<String> {
    if let Ok(p) = std::env::var(env) {
        return Some(p);
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        // No echo: the password never appears on screen or in a terminal recording.
        return rpassword::prompt_password("Certificate password: ").ok();
    }
    None
}

fn timestamp(log: PathBuf, tsa_url: String, actor: Option<String>) -> u8 {
    let dir = if log.is_file() {
        log.parent().map(|p| p.to_path_buf()).unwrap_or_default()
    } else {
        log
    };
    if !dir.join("audit.jsonl").is_file() {
        eprintln!(
            "error: no audit log at {}: nothing to timestamp",
            dir.join("audit.jsonl").display()
        );
        return EXIT_FINDINGS;
    }
    let mut audit_log = match audit::AuditLog::resume(
        &dir,
        &actor.unwrap_or_else(rv_mailauth_core::env::os_user),
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_FINDINGS;
        }
    };
    match trust::timestamp_head(&dir, audit_log.entries(), audit_log.head(), &tsa_url) {
        Ok(ts) => {
            if let Err(e) = audit_log.record("timestamp_obtained", Some(&ts.file), ts.to_json()) {
                eprintln!("error: {}", e);
                return EXIT_ERROR;
            }
            println!(
                "OK  timestamp {} by {} covers entry #{}",
                ts.gen_time, ts.tsa, ts.covers_seq
            );
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
    }
}

fn verify_log(log: PathBuf, tsa_ca: Option<PathBuf>) -> u8 {
    let path = if log.is_dir() {
        log.join("audit.jsonl")
    } else {
        log
    };
    let anchors = match tsa_ca.as_deref().map(trust::load_ca_bundle).transpose() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    let v = match verify::verify_log_with(&path, anchors.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    if v.problems.is_empty() {
        println!(
            "OK  {} entries, chain intact: {}",
            v.entries,
            path.display()
        );
        for t in &v.timestamps {
            println!("    {}", t);
        }
        println!("    {}", v.truncation);
        if let Some(r) = v.review_entries {
            println!("    review entries: {r} (review.jsonl, anchored to run_finished)");
        }
    } else {
        println!("BROKEN  {}", path.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
    }
    for w in &v.warnings {
        println!("  warning: {}", w);
    }
    if v.problems.is_empty() {
        EXIT_OK
    } else {
        EXIT_FINDINGS
    }
}

fn verify_case(dir: PathBuf, rehash: bool) -> u8 {
    if !dir.join(case::CASE_FILE).is_file() {
        eprintln!(
            "error: {} is not a case folder (no {})",
            dir.display(),
            case::CASE_FILE
        );
        return EXIT_ERROR;
    }
    let mut v = case::verify_case(&dir);
    let rehashed = rehash.then(|| case::rehash_registry(&dir, &mut v));
    if v.problems.is_empty() {
        println!(
            "OK  case {}: {} case-log entries, {} registered items, {} runs verified: {}",
            v.case_id,
            v.entries,
            v.registry_items,
            v.runs,
            dir.display()
        );
        if v.review_entries > 0 {
            println!("    review entries: {}", v.review_entries);
        }
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_OK
    } else {
        println!("BROKEN  case {}: {}", v.case_id, dir.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_FINDINGS
    }
}

fn self_test() -> u8 {
    let failed = hash::self_test();
    for (algo, _) in hash::KNOWN_ANSWERS {
        println!(
            "{:<9} {}",
            algo.name(),
            if failed.contains(&algo) {
                "FAIL"
            } else {
                "PASS"
            }
        );
    }
    if failed.is_empty() {
        EXIT_OK
    } else {
        EXIT_ERROR
    }
}

/// The tool's self-description (`describe --json`, schema rakvor.describe/1; see schemas/describe.schema.json).
/// serde_json sorts the keys (no preserve_order feature), so the output is stable.
fn describe() -> serde_json::Value {
    serde_json::json!({
        "schema": "rakvor.describe/1",
        "tool": TOOL_NAME,
        "title": "RV MailAuth",
        "version": TOOL_VERSION,
        "role": CASE_ROLE.name(),
        "main_verb": "analyze",
        // .eml has no fixed signature (recognised by extension and header sniffing).
        "accepts": {"extensions": ["eml", "mbox", "msg"], "signatures": [
            {"format": "msg", "match": [{"offset": 0, "hex": "d0cf11e0a1b11ae1"}]},
            {"format": "mbox", "match": [{"offset": 0, "hex": "46726f6d20"}]}
        ]},
        "case_formats": [case::SCHEMA_CASE],
        "log_formats": ["rakvor.audit/1", "rakvor.review/1"],
        "cli_exe": format!("{}.exe", TOOL_NAME),
        "gui_exe": format!("{}-gui.exe", TOOL_NAME),
        "exit_codes": {
            "0": "Completed; no high-severity finding.",
            "1": "Runtime error (input not found, output not writable, case log locked, ...).",
            "2": "Usage error (unknown option, bad value, case folder of another case or schema).",
            "3": "Completed with at least one high-severity finding, or the case folder fails verification.",
            "130": "Cancelled with Ctrl+C; partial reports and the cancellation are in the audit log."
        }
    })
}

/// Markdown of every command's long help, so docs/usage-cli.md can never drift from the binary.
fn docs_cli() -> String {
    let mut root = Cli::command().term_width(100);
    root.build();
    let mut out = String::from(
        "# Command-line reference\n\n<!-- Generated by `rv-mailauth docs-cli`. Do not edit by hand: CI fails if this file differs. -->\n\n",
    );
    out.push_str("```mermaid\nflowchart LR\n  A[rv-mailauth] --> B[analyze]\n  A --> KI[keys import]\n  A --> KS[keys show]\n  KI --> KF[(key file)]\n  KI --> E\n  KF -. --dkim-keys .-> B\n  A --> C[verify-log]\n  A --> D[self-test]\n  A --> T[timestamp]\n  A --> V[verify-case]\n  T --> E\n  B --> E[(logs/RUN-ID)]\n  B --> F[(reports/RUN-ID)]\n  B -. --case-dir .-> K[(CASE folder)]\n  V --> K\n  C --> E\n```\n\n");
    out.push_str(&format!(
        "## rv-mailauth\n\n```text\n{}\n```\n\n",
        root.render_long_help().to_string().trim_end()
    ));
    let names: Vec<String> = root
        .get_subcommands()
        // `describe` is hidden from the command list but documented (RV Hub reads it).
        .filter(|c| (!c.is_hide_set() || c.get_name() == "describe") && c.get_name() != "help")
        .map(|c| c.get_name().to_string())
        .collect();
    for name in names {
        let sub = root.find_subcommand_mut(&name).expect("subcommand").clone();
        let mut cmd = sub.clone().bin_name(format!("rv-mailauth {}", name));
        out.push_str(&format!(
            "## rv-mailauth {}\n\n```text\n{}\n```\n\n",
            name,
            cmd.render_long_help().to_string().trim_end()
        ));
        // Nested commands (`keys import`, `keys show`).
        for nested in sub.get_subcommands().filter(|c| c.get_name() != "help") {
            let full = format!("{} {}", name, nested.get_name());
            let mut n = nested.clone().bin_name(format!("rv-mailauth {}", full));
            out.push_str(&format!(
                "## rv-mailauth {}\n\n```text\n{}\n```\n\n",
                full,
                n.render_long_help().to_string().trim_end()
            ));
        }
    }
    out
}
