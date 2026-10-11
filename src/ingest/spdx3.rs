//! SPDX 3.0 JSON-LD ingestion.
//!
//! SPDX 3.0 serializes to JSON-LD with an `@graph` array of elements.
//! Packages appear with `@type`/`type` of `software_Package` (or `Package`)
//! and carry `name`, `packageVersion` and an `externalIdentifier` array
//! whose `purl` entries map directly to package-URLs. Parsing is
//! deliberately tolerant of both prefixed and unprefixed type names.

use super::spdx3_format;
use crate::model::{Component, Purl, Sbom};
use anyhow::{Context, Result};
use serde_json::Value;

pub fn parse_json(value: &Value, bytes: &[u8]) -> Result<Sbom> {
    let context = value.get("@context").and_then(Value::as_str).or_else(|| {
        value
            .get("@context")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find_map(Value::as_str))
    });

    let mut sbom = Sbom {
        format: Some(spdx3_format(context)),
        serial: None,
        product: None,
        components: Vec::new(),
        raw: value.clone(),
        bytes: bytes.to_vec(),
    };

    let graph = value
        .get("@graph")
        .and_then(Value::as_array)
        .context("SPDX 3.0 document missing \"@graph\" array")?;

    for element in graph {
        let ty = type_of(element);
        if !matches!(
            ty.as_str(),
            "software_Package" | "Package" | "spdx:software_Package"
        ) {
            continue;
        }
        if let Some(component) = package_from_element(element) {
            sbom.components.push(component);
        }
    }

    Ok(sbom)
}

fn type_of(element: &Value) -> String {
    element
        .get("type")
        .or_else(|| element.get("@type"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn package_from_element(element: &Value) -> Option<Component> {
    let name = element
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)?;
    if name.is_empty() {
        return None;
    }

    let mut component = Component {
        bom_ref: element
            .get("spdxId")
            .or_else(|| element.get("@id"))
            .and_then(Value::as_str)
            .map(str::to_string),
        kind: "software_Package".to_string(),
        name,
        version: element
            .get("packageVersion")
            .or_else(|| element.get("version"))
            .and_then(Value::as_str)
            .map(str::to_string),
        purl: None,
        purl_raw: None,
        cpe: None,
        supplier: None,
        licenses: Vec::new(),
        hashes: Vec::new(),
        scope: None,
    };

    for key in ["externalIdentifier", "externalIdentifiers"] {
        for identifier in element
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let ty = identifier
                .get("externalIdentifierType")
                .or_else(|| identifier.get("type"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let value = identifier
                .get("identifier")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if value.is_empty() {
                continue;
            }
            match ty {
                "purl" | "packageUrl" if component.purl_raw.is_none() => {
                    component.purl_raw = Some(value.to_string());
                    component.purl = Purl::parse(value).ok();
                }
                _ => {}
            }
        }
    }

    Some(component)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{
      "@context": ["https://spdx.org/rdf/3.0.0/spdx-context.jsonld"],
      "@graph": [
        {
          "type": "software_Package",
          "spdxId": "spdx:software-package-zlib",
          "name": "zlib",
          "packageVersion": "1.2.13",
          "externalIdentifier": [
            {"externalIdentifierType": "purl", "identifier": "pkg:generic/zlib@1.2.13"}
          ]
        },
        {
          "type": "CreationInfo",
          "spdxId": "spdx:creation-info",
          "name": "not a package"
        }
      ]
    }"#;

    #[test]
    fn parses_spdx3_packages() {
        let value: Value = serde_json::from_str(DOC).unwrap();
        let sbom = parse_json(&value, DOC.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        let zlib = &sbom.components[0];
        assert_eq!(zlib.name, "zlib");
        assert_eq!(zlib.version.as_deref(), Some("1.2.13"));
        assert!(zlib.purl.is_some());
        assert_eq!(sbom.spec_version().as_deref(), Some("3.0.0"));
    }
}
