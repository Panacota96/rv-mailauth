# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [0.3.0](https://github.com/Panacota96/rv-mailauth/compare/v0.2.2...v0.3.0) (2026-11-21)


### Features

* **update:** check for a newer release (update-check, start-up banner) ([#11](https://github.com/Panacota96/rv-mailauth/issues/11)) ([9b826d4](https://github.com/Panacota96/rv-mailauth/commit/9b826d4374be23893b4a1f511e01cd787b7c2e5c))

## [0.2.2](https://github.com/Panacota96/rv-mailauth/compare/v0.2.1...v0.2.2) (2026-11-19)


### Bug Fixes

* **deps:** drop the unmaintained chrono dependency (RUSTSEC-2026-0543); every date written or read is golden-tested byte-identical ([37e4df7](https://github.com/Panacota96/rv-mailauth/commit/37e4df73f7932e4a057cf5696e5efbe23f7b4e6a))

## [0.2.1](https://github.com/Panacota96/rv-mailauth/compare/v0.2.0...v0.2.1) (2026-11-14)


### Bug Fixes

* **core:** late audit entries and redirected run folders cannot hide an edited output ([9539338](https://github.com/Panacota96/rv-mailauth/commit/953933800b667ca633e9ad3e2202f35164b43234))
* **core:** re-hash the outputs a run's audit log records in verify-log and verify-case ([51c089c](https://github.com/Panacota96/rv-mailauth/commit/51c089ce449b403a3dc1622fbc3ab3debc93941d))
* verify-log and verify-case re-hash the outputs the audit log records ([2e1c6f4](https://github.com/Panacota96/rv-mailauth/commit/2e1c6f4e8ccd7cfd1a66cd7fec4b937c9d74f118))

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
