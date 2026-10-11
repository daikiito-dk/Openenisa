//! JSON Schemas embedded into the binary — validation is 100% offline.
//!
//! The bundled CSAF 2.0 schema (errata 01) inlines the FIRST CVSS v2.0 /
//! v3.0 / v3.1 schemas so no network resolution is ever needed. See
//! `scripts/bundle_csaf.py` for provenance and the freshness check that
//! CI enforces.

use serde_json::Value;
use std::sync::OnceLock;

pub const CSAF_2_0_BUNDLED: &str = include_str!("../schemas/csaf/2.0/csaf-2.0-bundled.schema.json");
pub const ENISA_ENVELOPE_V0_1: &str = include_str!("../schemas/enisa/envelope/v0.1.0/schema.json");
pub const FINDINGS_V0_1: &str = include_str!("../schemas/openenisa/findings/v0.1.0/schema.json");

pub const ENISA_ENVELOPE_V0_1_ID: &str =
    "https://openenisa.dev/schemas/enisa/envelope/v0.1.0/schema.json";
pub const FINDINGS_V0_1_ID: &str = "https://openenisa.dev/schemas/findings/v0.1.0/schema.json";

pub fn csaf_2_0() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(CSAF_2_0_BUNDLED).expect("embedded CSAF 2.0 schema is valid JSON")
    })
}

pub fn enisa_envelope() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(ENISA_ENVELOPE_V0_1).expect("embedded envelope schema is valid JSON")
    })
}

pub fn findings() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(FINDINGS_V0_1).expect("embedded findings schema is valid JSON")
    })
}
