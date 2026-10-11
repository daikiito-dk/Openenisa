//! VEX correlation: turn vulnerability *matches* into *triaged* findings.
//!
//! Statements are loaded from any of the three widely deployed VEX shapes
//! and normalized to [`VexStatement`]:
//!
//! - [OpenVEX](https://github.com/openvex/spec) (`statements[]`)
//! - CSAF VEX profile (CSAF documents with `document.category == "csaf_vex"`)
//! - CycloneDX embedded VEX (`vulnerabilities[].analysis` inside the SBOM)
//!
//! Applying a statement flips the matched finding's status — `not_affected`
//! and `fixed` suppress the alert (with the recorded justification), which
//! is what removes the noise that makes 24-hour CRA reporting by hand
//! impossible.

pub mod csaf_vex;
pub mod cyclonedx_vex;
pub mod openvex;

use crate::model::{Component, Finding, Purl, VexStatus};
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::path::Path;

/// One normalized, format-agnostic VEX statement.
#[derive(Debug, Clone)]
pub struct VexStatement {
    pub vulnerability_id: String,
    pub product: VexProduct,
    pub status: VexStatus,
    pub justification: Option<String>,
    pub impact: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone)]
pub enum VexProduct {
    /// purl identity; `version` pins the statement to one version when the
    /// source document carried one.
    Purl { purl: Purl, version: Option<String> },
    /// A bom-ref / CSAF product_id.
    Ref(String),
    /// A bare component name (OpenVEX allows free-form product ids).
    Name(String),
}

impl VexProduct {
    fn matches(&self, component: &Component) -> bool {
        match self {
            VexProduct::Purl { purl, version } => {
                let Some(component_purl) = &component.purl else {
                    return false;
                };
                component_purl.matches(purl)
                    && version.as_ref().is_none_or(|v| {
                        component
                            .version
                            .as_deref()
                            .is_some_and(|cv| cv == v.as_str())
                    })
            }
            VexProduct::Ref(r) => component.bom_ref.as_deref() == Some(r.as_str()),
            VexProduct::Name(n) => n.eq_ignore_ascii_case(&component.name),
        }
    }
}

/// A parsed VEX document.
#[derive(Debug, Clone)]
pub struct VexDoc {
    pub source: String,
    pub statements: Vec<VexStatement>,
}

/// Load a VEX document, auto-detecting its format.
pub fn load(path: &Path) -> Result<VexDoc> {
    let source = path.display().to_string();
    let text = std::fs::read_to_string(path).with_context(|| format!("failed to read {source}"))?;
    let value: Value =
        serde_json::from_str(&text).with_context(|| format!("{source}: invalid JSON"))?;
    let statements = detect_and_parse(&value, &source)?;
    Ok(VexDoc { source, statements })
}

/// Parse an in-memory VEX document, auto-detecting the format.
pub fn detect_and_parse(value: &Value, source: &str) -> Result<Vec<VexStatement>> {
    if value.get("statements").is_some() {
        return openvex::parse(value, source);
    }
    if value
        .get("document")
        .and_then(|d| d.get("csaf_version"))
        .is_some()
    {
        return csaf_vex::parse(value, source);
    }
    if value.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        let sbom = crate::ingest::cyclonedx::parse_json(value, &[])?;
        return Ok(cyclonedx_vex::parse(&sbom, source));
    }
    bail!(
        "{source}: unrecognized VEX format (expected OpenVEX, CSAF VEX, or a CycloneDX SBOM with embedded VEX)"
    );
}

#[derive(Debug, Default, Clone)]
pub struct TriageStats {
    pub statements: usize,
    pub applied: usize,
    pub unmatched: usize,
    /// e.g. `affected -> not_affected (pkg:generic/openssl@3.0.12)`
    pub transitions: Vec<String>,
}

/// Apply statements to findings in document order; later statements win.
pub fn apply(findings: &mut [Finding], vexes: &[VexDoc]) -> TriageStats {
    let mut stats = TriageStats::default();

    for doc in vexes {
        for statement in &doc.statements {
            stats.statements += 1;
            let mut matched_any = false;
            for finding in findings.iter_mut() {
                if !finding.vuln.matches_id(&statement.vulnerability_id) {
                    continue;
                }
                if !statement.product.matches(&finding.component) {
                    continue;
                }
                matched_any = true;
                if finding.status != statement.status {
                    stats.transitions.push(format!(
                        "{} -> {} ({})",
                        finding.status, statement.status, statement.vulnerability_id
                    ));
                }
                finding.status = statement.status;
                finding.justification = statement.justification.clone();
                finding.impact = statement.impact.clone();
                finding.vex_source = Some(statement.source.clone());
            }
            if matched_any {
                stats.applied += 1;
            } else {
                stats.unmatched += 1;
            }
        }
    }

    stats
}

/// Parse a product id (`pkg:...` purl vs free-form name).
pub(crate) fn product_from_id(id: &str) -> Option<VexProduct> {
    if let Some(stripped) = id.strip_prefix("pkg:") {
        let purl = Purl::parse(&format!("pkg:{stripped}")).ok()?;
        let version = purl.version.clone();
        Some(VexProduct::Purl { purl, version })
    } else if id.is_empty() {
        None
    } else {
        Some(VexProduct::Name(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Vulnerability;

    fn openssl_finding() -> Finding {
        Finding {
            vuln: Vulnerability {
                id: "CVE-2024-0727".into(),
                ..Vulnerability::default()
            },
            component: Component {
                name: "openssl".into(),
                version: Some("3.0.12".into()),
                purl_raw: Some("pkg:generic/openssl@3.0.12".into()),
                purl: Purl::parse("pkg:generic/openssl@3.0.12").ok(),
                ..Component::default()
            },
            status: VexStatus::Affected,
            matched_by: "purl".into(),
            justification: None,
            impact: None,
            vex_source: None,
            fixed_in: None,
        }
    }

    const OPENVEX: &str = r#"{
      "statements": [{
        "vulnerability": {"id": "CVE-2024-0727"},
        "products": [{"@id": "pkg:generic/openssl@3.0.12"}],
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "impact_statement": "PKCS#12 parsing is disabled in this build."
      }]
    }"#;

    #[test]
    fn openvex_suppresses_finding() {
        let value: Value = serde_json::from_str(OPENVEX).unwrap();
        let statements = detect_and_parse(&value, "test.openvex.json").unwrap();
        assert_eq!(statements.len(), 1);

        let mut findings = vec![openssl_finding()];
        let stats = apply(
            &mut findings,
            &[VexDoc {
                source: "test.openvex.json".into(),
                statements,
            }],
        );
        assert_eq!(stats.applied, 1);
        assert_eq!(findings[0].status, VexStatus::NotAffected);
        assert_eq!(
            findings[0].justification.as_deref(),
            Some("vulnerable_code_not_in_execute_path")
        );
        assert!(findings[0].vex_source.is_some());
    }

    #[test]
    fn version_pinned_purl_requires_same_version() {
        let value: Value = serde_json::from_str(
            r#"{"statements": [{
                "vulnerability": {"id": "CVE-2024-0727"},
                "products": [{"@id": "pkg:generic/openssl@3.0.13"}],
                "status": "fixed"
            }]}"#,
        )
        .unwrap();
        let statements = detect_and_parse(&value, "t").unwrap();
        let mut findings = vec![openssl_finding()];
        let stats = apply(
            &mut findings,
            &[VexDoc {
                source: "t".into(),
                statements,
            }],
        );
        assert_eq!(stats.unmatched, 1);
        assert_eq!(findings[0].status, VexStatus::Affected);
    }
}
