# openenisa

[![CI](https://github.com/daikiito-dk/Openenisa/actions/workflows/ci.yml/badge.svg)](https://github.com/daikiito-dk/Openenisa/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)

**English** | [日本語 (Japanese)](README.ja.md)

**Docs:** [daikiito-dk.github.io/Openenisa](https://daikiito-dk.github.io/Openenisa/)

> The open-source CSAF 2.0 & ENISA reporting engine for DevOps.

Turn a pile of SBOMs, vulnerability feeds, and VEX statements into a **schema-valid CSAF 2.0 document** and an **ENISA-ready early-warning envelope**, on the Cyber Resilience Act's 24-hour clock. One static binary, 100% offline, designed for CI pipelines and incident response automation.

## Why

Since **11 September 2026**, every manufacturer placing products with digital elements on the EU market must report actively-exploited vulnerabilities to ENISA:

| Stage | Deadline | Clock starts at | Article |
|---|---|---|---|
| Early warning | 24 hours | awareness | 14(2)(a) / 14(4)(a) |
| Notification | 72 hours | awareness | 14(2)(b) / 14(4)(b) |
| Final report (vulnerability) | 14 days | a corrective or mitigating measure is available | 14(2)(c) |
| Final report (severe incident) | 1 month | the 72 h notification | 14(4)(c) |

Your monitoring feed just told you CVE-2023-48795 is being exploited and it's in your firmware. What do you send ENISA, in what format, by when? Today the answer involves manually copying CVE IDs into a web portal while the clock burns. `openenisa` answers it in one command: **SBOM in, validated submission-ready documents out**.

Note: ENISA's Single Reporting Platform is live at [portal.cra-srp.enisa.europa.eu](https://portal.cra-srp.enisa.europa.eu) but has no public machine API yet. `openenisa` therefore produces **dispatch-ready envelopes and tracks the statutory clock**, leaving transport pluggable (portal upload now, API when published).

## 30-second demo

```console
$ openenisa pipeline \
    --sbom examples/sbom/mx2400-firmware.cyclonedx-1.5.json \
    --feed examples/vulns/osv-feed.jsonl \
    --vex examples/vex/mx2400-openssl.openvex.json \
    --vex examples/vex/mx2400-busybox.csaf-vex.json \
    --out-dir openenisa-out \
    --vendor-name "Meridian Systems" \
    --vendor-namespace "https://meridian.example" \
    --exploited

== 1/4 SBOM ==
  Format      CycloneDX 1.5 (JSON)
  Components  4
  Product     MX-2400 Server Firmware 2.4.1

== 2/4 MATCH ==
3 finding(s) from 4 feed record(s) across 1 feed(s).

== 3/4 VEX TRIAGE ==
2 VEX statement(s) applied (2 matched, 0 unmatched).
  affected -> not_affected (CVE-2024-0727)
  affected -> fixed (CVE-2023-42366)

== 4/4 DOCUMENTS ==
ENISA early-warning envelope: due 2026-10-11T09:00:00Z [ON TRACK] (envelope valid: true)
```

The whole story in four stages: your SBOM names 4 components, the OSV feed matches 3 CVEs, VEX statements suppress 2 of them (openssl isn't affected by CVE-2024-0727 in your build; busybox CVE-2023-42366 is already fixed), and **only the real one — CVE-2023-48795, Terrapin in libssh2 — lands in the ENISA envelope** with a full audit trail. In `openenisa-out/`:

- `findings.json` — triaged intermediate findings with per-component evidence
- `csaf.json` — CSAF 2.0 VEX document, valid against the embedded OASIS schema
- `enisa-early-warning.json` — ENISA envelope with deadline math and embedded evidence

## Install

**Prerequisite:** Rust 1.85+.

```console
$ cargo install --git https://github.com/daikiito-dk/Openenisa openenisa
```

Or build from source:

```console
$ git clone https://github.com/daikiito-dk/Openenisa
$ cd Openenisa
$ make install
```

Prebuilt static binaries for Linux (amd64/arm64), macOS (arm64), and Windows are attached to every [release](https://github.com/daikiito-dk/Openenisa/releases).

## Commands

| Command | What it does |
|---|---|
| `parse <sbom>` | Normalize any supported SBOM; `--json` for machine output |
| `match --sbom ... --feed ...` | Match components against OSV feeds (purl identity, SEMVER/ECOSYSTEM ranges) |
| `triage --findings ... --vex ...` | Apply OpenVEX / CSAF VEX / CycloneDX VEX statements to findings |
| `csaf --findings ... --vendor-name ... --vendor-namespace ...` | Build a CSAF 2.0 VEX document |
| `validate <file>` | Validate a CSAF document, findings, or envelope against embedded schemas |
| `enisa deadlines --aware-at ... [--measure-available-at ...]` | Print the statutory deadlines; the final report stays PENDING until its clock starts |
| `enisa report --findings ... --type early-warning ...` | Build an ENISA envelope with embedded CSAF + evidence |
| `enisa submit <envelope> [--now ...]` | Dry-run: readiness check + clock + dispatch template |
| `pipeline` | All of the above, one command, exit codes for CI |

Exit codes: `0` clean, `1` error, `2` threshold breached (`--fail-on affected` fails when known-affected findings remain after triage — the CI gate for "stop the ship"). `--json` on every command.

## Validation is not a checkbox

`validate` embeds the **official OASIS CSAF 2.0 JSON Schema** (errata 01, with FIRST CVSS 2.0/3.0/3.1 schemas bundled inline) and adds conformance checks that JSON Schema alone cannot express:

- release dates ordered (`initial_release_date` ≤ `current_release_date`)
- `revision_history` in sync with the tracking `version`
- every product id in `product_status` resolves in `product_tree`
- all `purl` identification helpers are well-formed
- all timestamps are RFC 3339
- document category follows the `csaf_*` convention

And it validates openenisa's own formats too: the findings intermediate and the ENISA envelope. Offline. No network, no vendor phone-home, no excuses.

## Reproducible

The same inputs and the same `--at` timestamp produce byte-identical documents: tracking IDs derive from a SHA-256 of the evidence, not wall-clock time. Incident response is audited later; audits demand reproducibility.

## Supported formats

| Input | Formats |
|---|---|
| SBOM | CycloneDX 1.4 / 1.5 / 1.6 (JSON + XML), SPDX 2.3 (JSON + XML), SPDX 3.0 (JSON-LD) |
| Vulnerability feed | OSV (JSONL / NDJSON / array / bundle) |
| VEX | OpenVEX, CSAF VEX, CycloneDX embedded VEX |
| Output | CSAF 2.0 VEX, ENISA envelope, openenisa findings |

## CI/CD

Use the bundled [GitHub Action](action.yml):

```yaml
- uses: daikiito-dk/Openenisa@main
  with:
    sbom: dist/bom.json
    feeds: |
      advisories/osv-feed.jsonl
    vendor-name: "Meridian Systems"
    vendor-namespace: "https://meridian.example"
    fail-on: affected   # fail the workflow if a known-affected finding survives triage
```

GitLab CI and Jenkins recipes in [docs/ci-cd.md](docs/ci-cd.md).

## Repository layout

```
src/
  model/        normalized SBOM/finding model (purl parsing, semver)
  ingest/       CycloneDX + SPDX parsers (JSON and XML)
  feed/         OSV feed loading + matching engine
  vex/          OpenVEX / CSAF VEX / CycloneDX VEX correlator
  csaf/         CSAF 2.0 builder + embedded-schema validator
  enisa/        CRA Article 14 clock, envelopes, readiness checks
  cli/          command surface (clap)
schemas/
  csaf/2.0/     vendored OASIS schema (errata 01) + FIRST CVSS schemas + offline bundle
  openenisa/    openenisa findings intermediate schema
  enisa/        ENISA envelope schema
examples/       runnable corpus: 4 SBOMs, VEX docs, OSV feed, expected outputs
scripts/        bundle_csaf.py — regenerates the offline schema bundle
tests/          end-to-end CLI tests
docs/           specification, CRA reporting guide, CI/CD recipes
```

## Status and honest limitations

- **Not legal advice.** openenisa automates document assembly and deadline math; compliance responsibility stays with the manufacturer. Read [docs/cra-reporting.md](docs/cra-reporting.md).
- **"Actively exploited" is a human decision.** `--exploited` records your determination with evidence; it does not detect exploitation.
- **ENISA SRP has no public API yet.** `enisa submit` is an offline dry-run; it prints a dispatch template and tracks readiness. When the API lands, transport becomes a plugin.
- **XML support is practical-subset:** CycloneDX XML 1.4–1.6 and SPDX 2.3 XML are parsed with streaming readers; exotic constructs may normalize imperfectly.
- **No CVE/OSV downloading built in.** Bring your own feed (OSV.dev publishes per-ecosystem dumps). Deterministic, air-gapped-friendly.

## Phase 2: PassportX Platform

openenisa is the open core. **PassportX Platform** (planned) is the commercial companion for enterprises that need continuous fleet monitoring, multi-product dashboards, Digital Product Passports, and managed ENISA submission — for organizations from Dell-class OEMs down to mid-market device makers. The OSS engine keeps the protocol open; the SaaS sells operations at scale.

## Roadmap

- [ ] `enisa dispatch --transport` plugin (when the SRP API publishes)
- [ ] CSAF translation profiles (`csaf_security_incident_response`, `informational_advisory`)
- [ ] CVSS score propagation from OSV `severity` fields
- [ ] `match --offline-nvd` local NVD mirror adapter
- [ ] SBOM diffing (`openenisa diff before.json after.json`) for release gates

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The parser surface is the growth area: each new SBOM/VEX format lands in `src/ingest/` or `src/vex/` behind the normalized model, so one parser unlocks every downstream stage.

## License

Apache-2.0. This project redistributes the OASIS CSAF 2.0 JSON Schema under its Non-Assertion Mode license and FIRST CVSS schemas under their own terms; see [NOTICE](NOTICE).
