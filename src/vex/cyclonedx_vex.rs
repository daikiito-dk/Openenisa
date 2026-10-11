//! CycloneDX embedded VEX parsing (`vulnerabilities[].analysis` inside a
//! CycloneDX SBOM).

use super::{VexProduct, VexStatement};
use crate::model::{Sbom, VexStatus, v_str, v_strs};
use serde_json::Value;

/// Extract embedded VEX statements from a parsed CycloneDX SBOM.
pub fn parse(sbom: &Sbom, source: &str) -> Vec<VexStatement> {
    let mut out = Vec::new();
    for vulnerability in sbom
        .raw
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(id) = vulnerability_id(vulnerability) else {
            continue;
        };
        let Some(analysis) = vulnerability.get("analysis") else {
            continue;
        };
        let Some(state) = v_str(analysis, "state").and_then(|s| map_state(&s)) else {
            continue;
        };
        for bom_ref in crate::ingest::cyclonedx::affects_refs(vulnerability) {
            out.push(VexStatement {
                vulnerability_id: id.clone(),
                product: VexProduct::Ref(bom_ref),
                status: state,
                justification: v_str(analysis, "justification"),
                impact: v_str(analysis, "detail"),
                source: source.to_string(),
            });
        }
    }
    out
}

fn vulnerability_id(vulnerability: &Value) -> Option<String> {
    v_str(vulnerability, "id")
        .or_else(|| v_str(vulnerability, "cve"))
        .or_else(|| {
            vulnerability
                .get("references")
                .and_then(|r| v_strs(r, "id").first().cloned())
        })
}

/// Map CycloneDX `analysis.state` values onto VEX statuses.
fn map_state(state: &str) -> Option<VexStatus> {
    match state {
        "exploitable" => Some(VexStatus::Affected),
        "not_affected" => Some(VexStatus::NotAffected),
        "in_triage" => Some(VexStatus::UnderInvestigation),
        "resolved" | "resolved_with_pedigree" => Some(VexStatus::Fixed),
        // false_positive is noise by definition.
        "false_positive" => Some(VexStatus::NotAffected),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOM: &str = r#"{
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "components": [{"bom-ref": "c1", "type": "library", "name": "openssl", "version": "3.0.12"}],
      "vulnerabilities": [
        {
          "id": "CVE-2024-0727",
          "affects": [{"ref": "c1"}],
          "analysis": {"state": "not_affected", "justification": "vulnerable_code_not_present"}
        }
      ]
    }"#;

    #[test]
    fn parses_embedded_vex() {
        let value: Value = serde_json::from_str(BOM).unwrap();
        let sbom = crate::ingest::cyclonedx::parse_json(&value, BOM.as_bytes()).unwrap();
        let statements = parse(&sbom, "bom.json");
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].vulnerability_id, "CVE-2024-0727");
        assert_eq!(statements[0].status, VexStatus::NotAffected);
        assert!(matches!(&statements[0].product, VexProduct::Ref(r) if r == "c1"));
    }
}
