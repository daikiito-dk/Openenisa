//! SPDX 2.3 JSON ingestion.

use super::spdx2_version;
use crate::model::{Component, Purl, Sbom, v_str, v_strs};
use anyhow::{Context, Result};
use serde_json::Value;

pub fn parse_json(value: &Value, bytes: &[u8]) -> Result<Sbom> {
    let spdx_version = value
        .get("spdxVersion")
        .and_then(Value::as_str)
        .context("SPDX document missing \"spdxVersion\"")?;
    let format = spdx2_version(spdx_version, true)?;

    let mut sbom = Sbom {
        format: Some(format),
        serial: None,
        product: None,
        components: Vec::new(),
        raw: value.clone(),
        bytes: bytes.to_vec(),
    };

    let described = v_strs(value, "documentDescribes");

    for package in value
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(component) = package_from_json(package) else {
            continue;
        };
        if described
            .iter()
            .any(|id| component.bom_ref.as_deref() == Some(id.as_str()))
            && sbom.product.is_none()
        {
            sbom.product = Some(component.clone());
            // Keep the described package among components as well: it is
            // still part of the artifact and must be matched against feeds.
            let mut entry = component;
            entry.kind = "described-package".to_string();
            sbom.components.push(entry);
            continue;
        }
        sbom.components.push(component);
    }

    Ok(sbom)
}

fn package_from_json(package: &Value) -> Option<Component> {
    let name = v_str(package, "name")?;
    if name.is_empty() {
        return None;
    }
    let mut component = Component {
        bom_ref: v_str(package, "SPDXID"),
        kind: "package".to_string(),
        name,
        version: v_str(package, "versionInfo"),
        purl: None,
        purl_raw: None,
        cpe: None,
        supplier: v_str(package, "supplier").map(strip_agent_prefix),
        licenses: Vec::new(),
        hashes: Vec::new(),
        scope: None,
    };

    for external in package
        .get("externalRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let reference_type = v_str(external, "referenceType").unwrap_or_default();
        let locator = v_str(external, "referenceLocator").unwrap_or_default();
        if locator.is_empty() {
            continue;
        }
        match reference_type.as_str() {
            "purl" | "PACKAGE-MANAGER" if component.purl_raw.is_none() => {
                component.purl_raw = Some(locator.clone());
                component.purl = Purl::parse(&locator).ok();
            }
            "cpe22Type" | "cpe23Type" if component.cpe.is_none() => {
                component.cpe = Some(locator);
            }
            _ => {}
        }
    }

    for license_field in ["licenseConcluded", "licenseDeclared"] {
        if let Some(license) = v_str(package, license_field) {
            if license != "NOASSERTION" && !component.licenses.contains(&license) {
                component.licenses.push(license);
            }
        }
    }

    Some(component)
}

/// SPDX supplier strings look like `Organization: Example Inc.` /
/// `Person: Jane Doe`.
fn strip_agent_prefix(raw: String) -> String {
    for prefix in ["Organization: ", "Person: ", "NOASSERTION"] {
        if let Some(stripped) = raw.strip_prefix(prefix) {
            return stripped.trim().to_string();
        }
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{
      "spdxVersion": "SPDX-2.3",
      "name": "gateway",
      "documentDescribes": ["SPDXRef-Package-gateway"],
      "packages": [
        {
          "SPDXID": "SPDXRef-Package-gateway",
          "name": "Aurora Gateway",
          "versionInfo": "1.4.0",
          "supplier": "Organization: Meridian Systems",
          "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:generic/aurora-gateway@1.4.0"}]
        },
        {
          "SPDXID": "SPDXRef-Package-openssl",
          "name": "openssl",
          "versionInfo": "3.0.12",
          "licenseConcluded": "Apache-2.0",
          "externalRefs": [{"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:openssl:openssl:3.0.12"}]
        }
      ]
    }"#;

    #[test]
    fn parses_spdx_packages() {
        let value: Value = serde_json::from_str(DOC).unwrap();
        let sbom = parse_json(&value, DOC.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);
        assert_eq!(sbom.product.as_ref().unwrap().name, "Aurora Gateway");
        let openssl = sbom
            .components
            .iter()
            .find(|c| c.name == "openssl")
            .unwrap();
        assert_eq!(openssl.version.as_deref(), Some("3.0.12"));
        assert_eq!(
            openssl.cpe.as_deref(),
            Some("cpe:2.3:a:openssl:openssl:3.0.12")
        );
        assert_eq!(openssl.supplier, None);
        assert_eq!(
            sbom.product.as_ref().unwrap().supplier,
            Some("Meridian Systems".to_string())
        );
    }
}
