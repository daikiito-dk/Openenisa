//! SBOM ingestion: format detection + parsing into the normalized model.

pub mod cyclonedx;
pub mod cyclonedx_xml;
pub mod spdx;
pub mod spdx3;
pub mod spdx_xml;

use crate::model::{Sbom, SbomFormat};
use anyhow::{Context, Result, bail};
use std::path::Path;

/// Read and parse an SBOM file, auto-detecting its format.
pub fn parse_path(path: &Path) -> Result<Sbom> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_bytes(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

/// Parse an SBOM from in-memory bytes (JSON or XML).
pub fn parse_bytes(bytes: &[u8]) -> Result<Sbom> {
    let trimmed = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &bytes[i..])
        .unwrap_or(bytes);

    match trimmed.first() {
        Some(b'<') => parse_xml(trimmed),
        Some(b'{') => parse_json(trimmed),
        Some(b'[') => parse_json(trimmed),
        _ => bail!("unrecognized document: expected JSON or XML input"),
    }
}

fn parse_xml(bytes: &[u8]) -> Result<Sbom> {
    let root = xml_root_name(bytes)?;
    if root == "bom" {
        cyclonedx_xml::parse(bytes)
    } else if root == "Document" || root == "SpdxDocument" || root == "SPDXDocument" {
        spdx_xml::parse(bytes)
    } else {
        bail!(
            "unrecognized XML root element <{root}>: expected CycloneDX <bom> or SPDX <Document>"
        );
    }
}

fn parse_json(bytes: &[u8]) -> Result<Sbom> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if !value.is_object() {
        bail!("expected a JSON object at the document root");
    }
    if value.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX") {
        return cyclonedx::parse_json(&value, bytes);
    }
    if let Some(spdx_version) = value.get("spdxVersion").and_then(|v| v.as_str()) {
        if spdx_version.starts_with("SPDX-2") {
            return spdx::parse_json(&value, bytes);
        }
        bail!(
            "unsupported SPDX version {spdx_version} (supported: SPDX-2.3 JSON; SPDX 3.0 JSON-LD)"
        );
    }
    if value.get("@graph").is_some() || value.get("@context").is_some() {
        return spdx3::parse_json(&value, bytes);
    }
    bail!("unrecognized JSON document: expected CycloneDX, SPDX 2.3, or SPDX 3.0");
}

/// First XML element name, ignoring prolog/comments.
fn xml_root_name(bytes: &[u8]) -> Result<String> {
    use quick_xml::events::Event;
    let s = std::str::from_utf8(bytes)?;
    let mut reader = quick_xml::Reader::from_str(s);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => return Ok(e.name().as_ref().to_string()),
            Ok(Event::Eof) => bail!("empty XML document"),
            Ok(_) => continue,
            Err(e) => bail!("invalid XML: {e}"),
        }
    }
}

/// Format guard shared by the CycloneDX parsers.
pub(crate) fn check_cyclonedx_version(version: &str, xml: bool) -> Result<SbomFormat> {
    if matches!(version, "1.4" | "1.5" | "1.6") {
        Ok(if xml {
            SbomFormat::CycloneDxXml(version.to_string())
        } else {
            SbomFormat::CycloneDxJson(version.to_string())
        })
    } else {
        bail!("unsupported CycloneDX specVersion {version} (supported: 1.4, 1.5, 1.6)")
    }
}

/// SPDX 2.x version guard.
pub(crate) fn spdx2_version(spdx_version: &str, json: bool) -> Result<SbomFormat> {
    let version = spdx_version
        .trim_start_matches("SPDX-")
        .split('-')
        .next()
        .unwrap_or("2.3")
        .to_string();
    if !version.starts_with("2.") {
        bail!("unsupported SPDX version {spdx_version} (supported: 2.3, 3.0)");
    }
    Ok(if json {
        SbomFormat::SpdxJson(version)
    } else {
        SbomFormat::SpdxXml(version)
    })
}

/// SPDX 3.x format tag.
pub(crate) fn spdx3_format(context: Option<&str>) -> SbomFormat {
    let version = context
        .and_then(|c| {
            // context like "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"
            c.split("spdx-context.jsonld")
                .next()
                .map(|prefix| prefix.trim_end_matches('/'))
        })
        .and_then(|prefix| prefix.rsplit('/').next())
        .filter(|v| v.starts_with("3."))
        .unwrap_or("3.0")
        .to_string();
    SbomFormat::Spdx3Json(version)
}
