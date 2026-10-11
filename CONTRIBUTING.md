# Contributing to openenisa

Thanks for helping build the open CSAF 2.0 & ENISA reporting engine.

## Setup

```console
$ git clone https://github.com/daikiito-dk/Openenisa
$ cd Openenisa
$ cargo build
$ cargo test
```

Requirements: Rust 1.85+, Python 3.9+ (only for `scripts/bundle_csaf.py`).

## Everyday commands

```console
$ make test        # full suite (unit + end-to-end CLI tests)
$ make lint        # rustfmt --check + clippy with warnings denied
$ make smoke       # end-to-end pipeline on the example corpus
$ make schemas     # regenerate the offline CSAF schema bundle
```

CI runs all of these plus a schema-freshness check: if you touch anything in `schemas/csaf/2.0/`, run `make schemas` and commit the regenerated bundle, or CI fails with drift.

## Code layout

| Path | What lives there |
|---|---|
| `src/model/` | Normalized model: `Sbom`, `Component`, `Finding`, purl parsing, semver. Everything downstream depends only on this. |
| `src/ingest/` | SBOM parsers. One module per format family. |
| `src/feed/` | OSV feed loading and the matching engine. |
| `src/vex/` | VEX parsers and the triage correlator. |
| `src/csaf/` | CSAF 2.0 builder and the embedded-schema validator. |
| `src/enisa/` | CRA Article 14 clock math, envelope builder, dry-run. |
| `src/cli/` | Command surface. |
| `tests/cli.rs` | End-to-end CLI tests that exercise the full narrative. |
| `examples/` | Runnable corpus; `examples/output/` holds pinned-timestamp reference outputs. |

## Adding a parser

The high-value contributions. Rules:

1. **Never let format details leak past your parser.** It translates into the normalized `model::Sbom` and stops there. If matching or CSAF generation needs format-specific logic, the model is missing a field — propose that instead.
2. **Add format detection** in the appropriate `mod.rs` dispatch (JSON key sniffing, XML root element, whatever the format gives you).
3. **Ship three fixtures**: a minimal document, a realistic document in `examples/`, and a unit test. If you add an `examples/sbom/` or `examples/vex/` file, consider extending `tests/cli.rs` so the format is covered end-to-end.
4. **Document limits.** XML formats are parsed with streaming readers; if a construct is not supported, record it (code comment + README limitations section) rather than silently misparsing.

## Adding validation checks

`src/csaf/validate.rs` runs strict conformance checks beyond JSON Schema. A new check:

- has a stable `group/name` id (tests and users filter on these)
- returns pass/fail with a human-readable detail line
- never blocks on missing optional data (absent ≠ invalid)

## Determinism is a contract

Same inputs + same `--at` ⇒ byte-identical outputs. This means:

- no wall-clock reads except through the `--at`/`--now` flags
- no iteration over unordered collections into ordered output (sort first)
- no HashMap iteration feeding output keys

If your change breaks byte-determinism, `make smoke` output or `examples/output/` diffs will show it. They are the tripwire.

## Commit style

Imperative subject, one line, no period: `Add SPDX 3.0 JSON-LD parser`, `Fix product-status inheritance order`. Japanese or English commit messages are both fine.

## Pull requests

- `make lint && make test && make smoke` green locally before you push
- new parsers: link the format spec and note which version you tested against
- schema changes: include the `make schemas` regeneration in the same commit
