# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [0.2.0](https://github.com/Panacota96/rv-mailauth/compare/v0.1.0...v0.2.0) (2026-11-12)


### Features

* RV MailAuth v0.1 — email authenticity signals (core, CLI, GUI, docs) ([#3](https://github.com/Panacota96/rv-mailauth/issues/3)) ([639abbb](https://github.com/Panacota96/rv-mailauth/commit/639abbb01a54dc13163af3468c1fca74cb49f534))

## [Unreleased]

### Added
- Project scaffolded with rakvor-tool-forge (rust profile) on 2026-11-11.
- Email analysis of `.eml`, Outlook `.msg` and `.mbox` (each mbox message a derived item citing the mbox digest,
  its number and byte offset): DKIM and ARC verified offline with examiner-supplied keys (`--dkim-keys`), optional
  audited `--online` key lookup flagged as weaker evidence, Received hops, dates and time zones, Message-ID,
  attachments with SHA-256 and embedded dates (`--extract-attachments`), BEC signals (lookalike domains with a
  pinned Public Suffix List, Reply-To / Return-Path, display-name spoofing, payment-details wording).
- `keys import` and `keys show`: DKIM key files from archived DNS records, with an audited import.
- One worker process per message with time and memory limits (`--isolation`, `--worker-timeout`,
  `--worker-memory-mb`); `--item-reports flagged`; size limits for messages and mboxes.
- Desktop app with a message viewer that checks `headers.json` and `dkim.json` against the audit log and records
  each viewing in a hash-chained `review.jsonl`.
- Documentation written from the code: theory (plain-language and expert parts), reports with the findings
  catalogue generated from the English catalogue, admissibility (draft pending a lawyer's review), usage, GUI,
  installation, development, architecture, case folder, HANDOFF and ADRs 0002–0004.

### Fixed
- `verify-log` verifies the run's `review.jsonl` (chain, link to the run's `run_finished`, entry count); an edited
  or misplaced review log fails. `verify-case` prints the review entries it verified.
- With `--item-reports flagged`, the statistics reports (HTML, PDF, JSON, every language) no longer link to item
  reports that were not written; they show the item's status and finding counts and say why.
- `headers.json` of an mbox message cites the mbox path and digests.
- The `--dkim-keys` help no longer says that every signature is unchecked without a key (a body-hash mismatch is
  found anyway); `keys import` names `--key-file` in its error; the installer ships the sample key file.
