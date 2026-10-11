//! CycloneDX 1.4 / 1.5 / 1.6 XML ingestion.
//!
//! Uses a streaming event parser and extracts only the identity fields the
//! matching engine needs (name, version, purl, cpe, bom-ref, licenses,
//! hashes). Component names/versions/purls are child elements in the
//! CycloneDX XML schema; `type` and `bom-ref` are attributes.

use super::check_cyclonedx_version;
use crate::model::{Component, HashEntry, Purl, Sbom};
use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::Event;

pub fn parse(bytes: &[u8]) -> Result<Sbom> {
    let text = std::str::from_utf8(bytes).context("CycloneDX XML is not valid UTF-8")?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);

    let mut sbom = Sbom {
        format: None,
        serial: None,
        product: None,
        components: Vec::new(),
        raw: serde_json::Value::Null,
        bytes: bytes.to_vec(),
    };

    // XML element stack, e.g. ["bom", "components", "component", "licenses", "expression"]
    let mut stack: Vec<String> = Vec::new();
    let mut in_metadata = false;
    let mut current: Option<Component> = None;
    let mut component_depth = 0usize;
    let mut nested_barrier: Option<usize> = None;
    let mut pending_hash_alg: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name().as_ref());
                if name == "bom" {
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            // The CycloneDX XML spec version lives in the
                            // schema namespace, not the document version attr.
                            "xmlns" => {
                                let ns = attr.value.to_string();
                                if let Some(version) =
                                    ns.strip_prefix("http://cyclonedx.org/schema/bom/")
                                {
                                    sbom.format = Some(check_cyclonedx_version(version, true)?);
                                }
                            }
                            "serialNumber" => {
                                sbom.serial = Some(attr.value.to_string());
                            }
                            _ => {}
                        }
                    }
                }
                if name == "metadata" {
                    in_metadata = true;
                }
                if name == "component" {
                    if current.is_none() {
                        let mut c = Component {
                            kind: String::new(),
                            name: String::new(),
                            ..Component::default()
                        };
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                "type" => c.kind = attr.value.to_string(),
                                "bom-ref" => c.bom_ref = Some(attr.value.to_string()),
                                _ => {}
                            }
                        }
                        current = Some(c);
                        component_depth = stack.len() + 1;
                    } else if nested_barrier.is_none() {
                        // CycloneDX allows subcomponents; their text must
                        // not leak into the component currently being read.
                        nested_barrier = Some(stack.len() + 1);
                    }
                }
                if name == "hash" {
                    pending_hash_alg = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.as_ref() == "alg")
                        .map(|a| a.value.to_string());
                }
                stack.push(name);
            }
            Ok(Event::Text(t)) => {
                let value = t.as_ref().to_string();
                if value.is_empty() {
                    continue;
                }
                if nested_barrier.is_some_and(|barrier| stack.len() >= barrier) {
                    continue;
                }
                let Some(component) = current.as_mut() else {
                    continue;
                };
                let top = stack.last().map(String::as_str).unwrap_or("");
                let parent = stack
                    .get(stack.len().saturating_sub(2))
                    .map(String::as_str)
                    .unwrap_or("");
                match (top, parent) {
                    ("name", "component") => component.name.push_str(&value),
                    ("version", "component") => component.version = Some(value),
                    ("purl", "component") => component.purl_raw = Some(value),
                    ("cpe", "component") => component.cpe = Some(value),
                    ("scope", "component") => component.scope = Some(value),
                    ("publisher", "component") => component.supplier = Some(value),
                    ("name", "supplier") => component.supplier = Some(value),
                    ("id", "license") | ("name", "license") => {
                        if !component.licenses.contains(&value) {
                            component.licenses.push(value);
                        }
                    }
                    ("expression", "licenses") => {
                        component.licenses.push(value);
                    }
                    ("hash", "hashes") => {
                        if let Some(alg) = pending_hash_alg.take() {
                            component.hashes.push(HashEntry {
                                alg,
                                content: value,
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = local_name(e.name().as_ref());
                if name == "metadata" {
                    in_metadata = false;
                }
                if name == "component" {
                    if current.is_some() && stack.len() == component_depth {
                        let component = current.take().expect("checked above");
                        let component = Component {
                            purl: component
                                .purl_raw
                                .as_deref()
                                .and_then(|p| Purl::parse(p).ok()),
                            ..component
                        };
                        if !component.name.is_empty() {
                            if in_metadata {
                                sbom.product = Some(component);
                            } else {
                                sbom.components.push(component);
                            }
                        }
                    } else if nested_barrier.is_some_and(|barrier| barrier == stack.len()) {
                        nested_barrier = None;
                    }
                }
                if name == "hash" {
                    pending_hash_alg = None;
                }
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => bail!("invalid CycloneDX XML: {e}"),
        }
    }

    match &sbom.format {
        Some(_) => Ok(sbom),
        None => bail!(
            "CycloneDX XML root is missing its xmlns schema version (http://cyclonedx.org/schema/bom/1.x)"
        ),
    }
}

fn local_name(qname: &str) -> String {
    let s = qname;
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" serialNumber="urn:uuid:1234" version="1">
  <metadata>
    <component type="firmware" bom-ref="root">
      <name>Device</name>
      <version>1.0</version>
    </component>
  </metadata>
  <components>
    <component type="library" bom-ref="c1">
      <name>openssl</name>
      <version>3.0.12</version>
      <purl>pkg:generic/openssl@3.0.12</purl>
      <hashes><hash alg="SHA-256">aabb</hash></hashes>
      <licenses><license><id>Apache-2.0</id></license></licenses>
      <supplier><name>OpenSSL Project</name></supplier>
    </component>
    <component type="library">
      <name></name>
    </component>
  </components>
</bom>"#;

    #[test]
    fn parses_cyclonedx_xml() {
        let sbom = parse(BOM.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        let c = &sbom.components[0];
        assert_eq!(c.name, "openssl");
        assert_eq!(c.version.as_deref(), Some("3.0.12"));
        assert!(c.purl.is_some());
        assert_eq!(c.bom_ref.as_deref(), Some("c1"));
        assert_eq!(c.kind, "library");
        assert_eq!(c.supplier.as_deref(), Some("OpenSSL Project"));
        assert_eq!(c.licenses, vec!["Apache-2.0"]);
        assert_eq!(c.hashes.len(), 1);
        assert_eq!(sbom.product.as_ref().unwrap().name, "Device");
        assert_eq!(sbom.serial.as_deref(), Some("urn:uuid:1234"));
    }
}
