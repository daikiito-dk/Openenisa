//! SPDX 2.3 XML ingestion.
//!
//! The SPDX 2.3 XML representation nests packages under `<packages>` and
//! identifies the described product through a `DESCRIBES` relationship
//! (`<relationshipType>DESCRIBES</relationshipType>` with a
//! `<relatedSpdxElement>` pointing at the root package). Text values are
//! captured with the same stack-driven approach as the CycloneDX XML
//! parser.

use super::spdx2_version;
use crate::model::{Component, Purl, Sbom};
use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::Event;

pub fn parse(bytes: &[u8]) -> Result<Sbom> {
    let text = std::str::from_utf8(bytes).context("SPDX XML is not valid UTF-8")?;
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

    let mut stack: Vec<String> = Vec::new();
    let mut current: Option<PackageBuilder> = None;
    let mut relationship: Option<RelationshipBuilder> = None;
    let mut described: Vec<String> = Vec::new();
    let mut spdx_version: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name().as_ref());
                if name == "package" && current.is_none() {
                    current = Some(PackageBuilder::default());
                }
                if name == "externalRef" {
                    if let Some(builder) = current.as_mut() {
                        builder.ref_type = None;
                        builder.ref_locator = None;
                    }
                }
                if name == "relationship" && relationship.is_none() {
                    relationship = Some(RelationshipBuilder::default());
                }
                stack.push(name);
            }
            Ok(Event::Text(t)) => {
                let value = t.as_ref().to_string();
                if value.is_empty() {
                    continue;
                }
                let top = stack.last().map(String::as_str).unwrap_or("");
                match top {
                    "spdxVersion" => spdx_version = Some(value),
                    "SPDXID" | "spdxId" => {
                        if let Some(builder) = current.as_mut() {
                            builder.spdx_id = Some(value);
                        }
                    }
                    "name" => {
                        if let Some(builder) = current.as_mut() {
                            builder.name = Some(value);
                        }
                    }
                    "versionInfo" => {
                        if let Some(builder) = current.as_mut() {
                            builder.version = Some(value);
                        }
                    }
                    "packageSupplier" => {
                        if let Some(builder) = current.as_mut() {
                            builder.supplier = Some(value);
                        }
                    }
                    "referenceType" => {
                        if let Some(builder) = current.as_mut() {
                            builder.ref_type = Some(value);
                        }
                    }
                    "referenceLocator" => {
                        if let Some(builder) = current.as_mut() {
                            builder.ref_locator = Some(value);
                        }
                    }
                    "relationshipType" => {
                        if let Some(rel) = relationship.as_mut() {
                            rel.relationship_type = Some(value);
                        }
                    }
                    "relatedSpdxElement" => {
                        if let Some(rel) = relationship.as_mut() {
                            rel.related_element = Some(value);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = local_name(e.name().as_ref());
                if name == "package" && current.is_some() {
                    if let Some(builder) = current.take() {
                        if let Some(component) = builder.into_component() {
                            sbom.components.push(component);
                        }
                    }
                }
                if name == "relationship" {
                    if let Some(rel) = relationship.take() {
                        if rel.relationship_type.as_deref() == Some("DESCRIBES") {
                            if let Some(related) = rel.related_element {
                                described.push(related);
                            }
                        }
                    }
                }
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => bail!("invalid SPDX XML: {e}"),
        }
    }

    let spdx_version = spdx_version.unwrap_or_else(|| "SPDX-2.3".to_string());
    sbom.format = Some(spdx2_version(&spdx_version, false)?);

    if let Some(first) = described.first() {
        if let Some(index) = sbom
            .components
            .iter()
            .position(|c| c.bom_ref.as_deref() == Some(first.as_str()))
        {
            sbom.product = Some(sbom.components[index].clone());
        }
    }

    Ok(sbom)
}

#[derive(Default)]
struct PackageBuilder {
    spdx_id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    supplier: Option<String>,
    ref_type: Option<String>,
    ref_locator: Option<String>,
}

impl PackageBuilder {
    fn into_component(self) -> Option<Component> {
        let name = self.name?;
        if name.is_empty() {
            return None;
        }
        let mut purl_raw = None;
        let mut cpe = None;
        match self.ref_type.as_deref() {
            Some("purl") | Some("PACKAGE-MANAGER") => purl_raw = self.ref_locator,
            Some("cpe22Type") | Some("cpe23Type") => cpe = self.ref_locator,
            _ => {}
        }
        Some(Component {
            bom_ref: self.spdx_id,
            kind: "package".to_string(),
            name,
            version: self.version,
            purl: purl_raw.as_deref().and_then(|p| Purl::parse(p).ok()),
            purl_raw,
            cpe,
            supplier: self.supplier.map(|s| {
                s.trim_start_matches("Organization: ")
                    .trim_start_matches("Person: ")
                    .trim()
                    .to_string()
            }),
            licenses: Vec::new(),
            hashes: Vec::new(),
            scope: None,
        })
    }
}

#[derive(Default)]
struct RelationshipBuilder {
    relationship_type: Option<String>,
    related_element: Option<String>,
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

    const DOC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <packages>
    <package>
      <SPDXID>SPDXRef-Package-openssl</SPDXID>
      <name>openssl</name>
      <versionInfo>3.0.12</versionInfo>
      <externalRefs>
        <externalRef>
          <referenceType>purl</referenceType>
          <referenceLocator>pkg:generic/openssl@3.0.12</referenceLocator>
        </externalRef>
      </externalRefs>
    </package>
  </packages>
  <relationships>
    <relationship>
      <relationshipType>DESCRIBES</relationshipType>
      <relatedSpdxElement>SPDXRef-Package-openssl</relatedSpdxElement>
    </relationship>
  </relationships>
</Document>"#;

    #[test]
    fn parses_spdx_xml() {
        let sbom = parse(DOC.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "openssl");
        assert!(sbom.components[0].purl.is_some());
        assert_eq!(sbom.product.as_ref().unwrap().name, "openssl");
    }
}
