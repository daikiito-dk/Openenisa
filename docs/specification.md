# openenisa technical specification

Version 0.1.0. This document describes the architecture, data flow, intermediate formats, and validation guarantees of `openenisa`.

## Design goals

1. **Determinism.** Same inputs + same `--at` timestamp ⇒ byte-identical outputs. Audits demand reproducibility.
2. **Offline-first.** Schema validation, matching, and generation never touch the network. Feeds and SBOMs are operator-supplied files.
3. **Normalized core.** Parsers translate external formats into one internal model; every downstream stage (matching, VEX, CSAF, ENISA) only knows the model. Adding a parser unlocks every stage.
4. **Honest automation.** The tool assembles documents and computes statutory deadlines. It does not decide whether something is "actively exploited", and it does not submit to ENISA while no public API exists.

## Data flow

```
SBOM file(s)          OSV feed(s)           VEX document(s)
 CycloneDX JSON/XML     JSONL / NDJSON         OpenVEX
 SPDX 2.3 JSON/XML      array / bundle         CSAF VEX
 SPDX 3.0 JSON-LD                              CycloneDX embedded VEX
      |                      |                       |
      v                      v                       v
 +------------------------------------------------------------+
 |                     normalized model                       |
 |   Sbom { product, components[] }     Component { name,     |
 |   version, purl, cpe, supplier, licenses, hashes, scope }   |
 +------------------------------------------------------------+
      |                      |                       |
      v                      v                       v
  `parse`              `match`                  `triage`
                         |                          |
                         v                          |
                    Finding { vuln_id, component, status, matched_by, evidence }
                         |                          |
                         +----------+---------------+
                                    v
                         FindingsDoc (interchange: findings.json)
                                    |
                    +---------------+----------------+
                    v                                v
                `csaf`                          `enisa report`
          CSAF 2.0 VEX document           ENISA envelope (embeds CSAF)
                    |                                |
                    v                                v
              `validate`                     `enisa submit`
        OASIS schema + conformance        deadline math + dry-run
```

## Module map

| Module | Responsibility |
|---|---|
| `src/model` | Normalized `Sbom`/`Component`/`Finding` types, purl parser, semver comparison, findings round-trip |
| `src/ingest` | Format auto-detection; CycloneDX JSON/XML 1.4–1.6; SPDX 2.3 JSON/XML; SPDX 3.0 JSON-LD |
| `src/feed` | OSV record loading (4 container shapes), identity matching (purl → name+ecosystem fallback), SEMVER/ECOSYSTEM range evaluation |
| `src/vex` | VEX document auto-detection and application; status transition audit |
| `src/csaf` | CSAF 2.0 builder (product tree, status groups, flags, remediations, threats) + validator |
| `src/enisa` | Report types and statutory deadline math, envelope builder, readiness dry-run, dispatch template |
| `src/cli` | Command surface; exit codes: 0 ok / 1 error / 2 threshold breached |
| `src/report` | Dependency-free terminal tables |

## Matching semantics

Identity resolution, in order:

1. **purl equality.** Component purl equals the OSV record's `package.purl` (ignoring version), or
2. **purl prefix.** OSV purl is a prefix of the component purl (`pkg:generic/openssl` matches `pkg:generic/openssl@3.0.12`), or
3. **name + ecosystem.** Component name equals OSV `package.name` and the ecosystem derived from the purl type equals the OSV ecosystem (`Generic` matches everything, because unscoped feeds cannot scope themselves).

Range evaluation for SEMVER/ECOSYSTEM ranges:

- `introduced` event: version is in range if `version >= introduced`
- `fixed` event: range closes at `version < fixed`
- `last_affected` event: range closes at `version <= last_affected`
- Version comparison is strict semver with a lenient tokenizer fallback (build metadata ignored, as semver mandates)
- GIT ranges and unknown range types are recorded as unevaluable rather than guessed

Every finding records `matched_by` (the identity rule that fired) so an auditor can reconstruct the decision.

## VEX application semantics

A VEX statement matches a finding when the statement's product target (purl, component ref, or name) equals the finding's component and the vuln id (CVE or OSV id) equals. Status transitions are recorded: `affected → not_affected`, `affected → fixed`, etc. Statements carrying CSAF justification labels (`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, ...) are propagated into CSAF `flags` verbatim; free-text justifications become `general` notes.

Multiple statements for the same (component, vuln): the most severe wins, severity order `affected > under_investigation > fixed > not_affected`.

## CSAF document construction

- `document.tracking.id` = `slug(vendor-name)-year-hex8(sha256(sorted evidence ids))` — deterministic, reproducible, and unique per evidence set
- Product tree: the SBOM product gets `CSAFPID-0000`; each affected-or-triaged component gets a numbered id with `product_identification_helper` (purl, cpe when present)
- Product status groups: `known_affected`, `fixed`, `known_not_affected`, `under_investigation`; **product-level inheritance** — the product inherits the most severe component status so consumers can filter on the product id alone
- `flags` carry CSAF justification labels for suppressed vulnerabilities
- `remediations` (`vendor_fix`) are emitted when the feed supplies a fixed version
- `threats` (`exploit_status`) are emitted only for vulnerabilities with known-affected products, only under `--exploited` — the "actively exploited" determination is yours; the tool records it, never invents it

## ENISA envelope

Envelope schema: `schemas/enisa/envelope/v0.1.0/schema.json`. Contents:

- `report_type`: `early-warning` (24 h), `notification` (72 h), `final-report` (336 h)
- `classification`: `public`, `green`, `amber`, `red`
- `aware_at`, `due_at`, and computed deadline verdicts (`ON TRACK`, `CRITICAL` inside 20% of window, `OVERDUE`)
- Embedded validated CSAF document + per-evidence hashes (SBOM sha256, VEX source paths, feed record ids)

`enisa submit` performs an offline dry-run: re-validates the envelope and embedded CSAF, evaluates the clock against `--now`, and prints a curl-style dispatch template for when the ENISA SRP publishes its machine API.

## Validation

Embedded schemas (see `schemas/`):

| Target | Schema |
|---|---|
| CSAF 2.0 documents | OASIS CSAF 2.0 JSON Schema, errata 01, with FIRST CVSS 2.0/3.0/3.1 bundled inline (`schemas/csaf/2.0/csaf-2.0-bundled.schema.json`) |
| Findings interchange | `schemas/openenisa/findings/v0.1.0/schema.json` |
| ENISA envelope | `schemas/enisa/envelope/v0.1.0/schema.json` |

The bundled CSAF schema is regenerated by `scripts/bundle_csaf.py`, which inlines the CVSS `$ref`s and verifies zero unresolved references. CI re-runs it and fails on drift, so upstream schema updates are always a visible, reviewable commit.

Beyond JSON Schema, `validate` enforces the conformance checks listed in the README (date ordering, revision sync, product id resolution, purl shape, RFC 3339, category convention).

## Determinism guarantee

Given identical inputs and `--at T`:

1. `document.tracking.id` derives from sorted evidence, not time
2. All inserted timestamps equal `T`
3. `serde_json` preserves insertion order, and the builder constructs keys in a fixed order

...outputs are byte-identical. The example outputs in `examples/output/` are regenerated with pinned `--at 2026-10-10T09:30:00Z` and committed for exactly this reason.
