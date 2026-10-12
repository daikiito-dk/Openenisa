//! openenisa — the open-source CSAF 2.0 & ENISA reporting engine for DevOps.
//!
//! `openenisa` automates the regulatory chain demanded by Article 14 of the
//! EU Cyber Resilience Act: parse an SBOM, match it against vulnerability
//! feeds, correlate [VEX](https://www.cisa.gov/sites/default/files/2023-11/README-OpenVEX-v1.0-e1670018367040.pdf)
//! statements to eliminate false positives, emit a schema-valid
//! [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
//! document, and prepare ENISA-ready report envelopes on the CRA Article 14
//! statutory clock (24 h / 72 h from awareness, then the final report) —
//! fully offline.
//!
//! The crate is deliberately lean: `serde_json`, `quick-xml`, `chrono`,
//! `sha2`, `clap`, and the `jsonschema` validator. Everything else — SBOM
//! parsing, VEX correlation, version-range math, CSAF construction and
//! regulatory timelines — is implemented here and unit-tested.
//!
//! # Module map
//!
//! - [`ingest`] — SBOM ingestion: CycloneDX 1.4/1.5/1.6 (JSON + XML),
//!   SPDX 2.3 (JSON + XML), SPDX 3.0 (JSON-LD), normalized to [`model::Sbom`].
//! - [`feed`] — OSV-format vulnerability feed loading and matching.
//! - [`vex`] — VEX correlation across OpenVEX, CSAF VEX and CycloneDX VEX.
//! - [`csaf`] — CSAF 2.0 document construction and offline validation.
//! - [`enisa`] — ENISA report envelopes, CRA Article 14 deadline math.
//! - [`report`] — human-readable output helpers.

pub mod cli;
pub mod csaf;
pub mod enisa;
pub mod feed;
pub mod ingest;
pub mod model;
pub mod report;
pub mod schemas;
pub mod semver;
pub mod vex;

/// Crate version, stamped into generated artifacts.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Engine identifier written into generated documents (e.g. CSAF `generator.engine`).
pub fn engine() -> String {
    format!("openenisa {}", VERSION)
}
