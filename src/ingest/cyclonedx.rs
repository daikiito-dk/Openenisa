//! CycloneDX 1.4 / 1.5 / 1.6 JSON ingestion.
//!
//! Parsing is intentionally lenient: the same code path serves all three
//! spec versions, unknown fields are ignored, and components missing a
//! name are skipped. Identity fields (name, version, purl, cpe, bom-ref)
//! are what the matching engine relies on.

use super::check_cyclonedx_version;
use crate::model::{Component, HashEntry, Purl, Sbom, v_str};
use anyhow::{Context, Result};
use serde_json::Value;

pub fn parse_json(value: &Value, bytes: &[u8]) -> Result<Sbom> {
    let spec_version = value
        .get("specVersion")
        .and_then(Value::as_str)
        .with_context(|| "CycloneDX document missing \"specVersion\"")?;
    let format = check_cyclonedx_version(spec_version, false)?;

    let mut sbom = Sbom {
        format: Some(format),
        serial: v_str(value, "serialNumber"),
        product: None,
        components: Vec::new(),
        raw: value.clone(),
        bytes: bytes.to_vec(),
    };

    if let Some(metadata) = value.get("metadata") {
        if let Some(component) = metadata.get("component") {
            if let Some(parsed) = component_from_json(component) {
                sbom.product = Some(parsed);
            }
        }
    }

    for component in value
        .get("components")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(parsed) = component_from_json(component) {
            sbom.components.push(parsed);
        }
    }

    Ok(sbom)
}

/// Extract the identity fields of a CycloneDX `component` object.
pub(crate) fn component_from_json(value: &Value) -> Option<Component> {
    let name = v_str(value, "name")?;
    if name.is_empty() {
        return None;
    }
    Some(
        Component {
            bom_ref: v_str(value, "bom-ref"),
            kind: v_str(value, "type").unwrap_or_default(),
            name,
            version: v_str(value, "version"),
            purl: None,
            purl_raw: v_str(value, "purl"),
            cpe: v_str(value, "cpe"),
            supplier: value
                .get("supplier")
                .and_then(|s| v_str(s, "name"))
                .or_else(|| {
                    value
                        .get("supplier")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                }),
            licenses: licenses_from_json(value.get("licenses")),
            hashes: value
                .get("hashes")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|h| {
                            Some(HashEntry {
                                alg: v_str(h, "alg")?,
                                content: v_str(h, "content")?,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            scope: v_str(value, "scope"),
        }
        .normalized_purl(),
    )
}

fn licenses_from_json(value: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    let entries = match value.and_then(Value::as_array) {
        Some(a) => a,
        None => return out,
    };
    for entry in entries {
        if let Some(expr) = entry.get("expression").and_then(Value::as_str) {
            out.push(expr.to_string());
            continue;
        }
        if let Some(license) = entry.get("license") {
            if let Some(id) = v_str(license, "id").or_else(|| v_str(license, "name")) {
                out.push(id);
            }
        }
    }
    out
}

trait ComponentPurl {
    fn normalized_purl(self) -> Self;
}

impl ComponentPurl for Component {
    fn normalized_purl(mut self) -> Self {
        if let Some(raw) = &self.purl_raw {
            self.purl = Purl::parse(raw).ok();
        }
        self
    }
}

/// Collect `vulnerabilities[].affects[].ref` bom-refs for embedded CycloneDX VEX.
pub(crate) fn affects_refs(vuln: &Value) -> Vec<String> {
    vuln.get("affects")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|item| v_str(item, "ref")).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOM: &str = r#"{
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "serialNumber": "urn:uuid:1234",
      "metadata": { "component": { "bom-ref": "root", "type": "firmware", "name": "Device", "version": "1.0" } },
      "components": [
        { "bom-ref": "c1", "type": "library", "name": "openssl", "version": "3.0.12", "purl": "pkg:generic/openssl@3.0.12", "licenses": [{"license": {"id": "Apache-2.0"}}] },
        { "bom-ref": "c2", "type": "library", "name": "", "version": "x" }
      ]
    }"#;

    #[test]
    fn parses_components() {
        let value: Value = serde_json::from_str(BOM).unwrap();
        let sbom = parse_json(&value, BOM.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "openssl");
        assert!(sbom.components[0].purl.is_some());
        assert_eq!(sbom.components[0].licenses, vec!["Apache-2.0"]);
        assert_eq!(sbom.product.as_ref().unwrap().name, "Device");
        assert_eq!(sbom.serial.as_deref(), Some("urn:uuid:1234"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let doc = r#"{ "bomFormat": "CycloneDX", "specVersion": "1.3" }"#;
        let value: Value = serde_json::from_str(doc).unwrap();
        assert!(parse_json(&value, doc.as_bytes()).is_err());
    }
}
