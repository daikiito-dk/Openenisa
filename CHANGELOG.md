# Changelog

All notable changes to openenisa are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-11

Initial public release.

### Added

- **SBOM ingestion** with format auto-detection: CycloneDX 1.4/1.5/1.6 (JSON and XML), SPDX 2.3 (JSON and XML), SPDX 3.0 (JSON-LD).
- **OSV feed matching**: JSONL/NDJSON, array, and bundle containers; purl identity with name+ecosystem fallback; SEMVER and ECOSYSTEM range evaluation (`introduced`/`fixed`/`last_affected`); GIT ranges recorded as unevaluable; `matched_by` audit field on every finding.
- **VEX triage**: OpenVEX, CSAF VEX, and CycloneDX embedded VEX parsers; severity-ordered status resolution; status-transition audit; CSAF justification labels propagated into flags.
- **CSAF 2.0 builder**: deterministic tracking IDs (SHA-256 of sorted evidence), product tree with purl/cpe identification helpers, product-status groups with product-level inheritance, remediations from feed fix versions, exploit-status threats under `--exploited`.
- **Offline validation**: embedded OASIS CSAF 2.0 JSON Schema (errata 01) with FIRST CVSS 2.0/3.0/3.1 bundled inline via `scripts/bundle_csaf.py`, plus strict conformance checks (date ordering, revision sync, product-id resolution, purl well-formedness, RFC 3339 timestamps, category convention).
- **ENISA module**: CRA Article 14 deadline math (24 h early warning / 72 h notification / 14-day final report), typed envelopes embedding validated CSAF plus evidence hashes, timeline verdicts (ON TRACK / CRITICAL / OVERDUE), and an offline `enisa submit` dry-run with dispatch template (the ENISA SRP has no public machine API yet; transport is pluggable).
- **CLI**: `parse`, `match`, `triage`, `csaf`, `validate`, `enisa deadlines|report|submit`, and the `pipeline` one-shot; `--json` on every command; `--fail-on affected` release gate with exit code 2.
- **openenisa findings interchange schema** (`schemas/openenisa/findings/v0.1.0`) and **ENISA envelope schema** (`schemas/enisa/envelope/v0.1.0`).
- Runnable example corpus (`examples/`) with pinned-timestamp reference outputs, end-to-end CLI test suite (52 tests), Makefile targets, GitHub Actions CI and release workflows, and a composite GitHub Action (`action.yml`).
