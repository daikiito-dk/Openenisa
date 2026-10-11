//! CSAF 2.0 document construction.
//!
//! Builds schema-valid CSAF documents from a triaged [`FindingsDoc`]:
//! the analyzed product and every matched component become
//! `full_product_names` (identified by purl where available), each
//! vulnerability becomes a `vulnerabilities[]` entry with `product_status`
//! groups reflecting the VEX triage, and `flags` carry the machine-readable
//! justifications. The output is byte-deterministic for identical inputs
//! and timestamps, which keeps audits reproducible.

pub mod validate;

use crate::model::{FindingsDoc, VexStatus, sha256_hex};
use anyhow::{Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

/// The CSAF `flags` label vocabulary (also the VEX justification vocabulary).
pub const FLAG_LABELS: [&str; 5] = [
    "component_not_present",
    "inline_mitigations_already_exist",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_not_present",
];

#[derive(Debug, Clone)]
pub struct CsafConfig {
    /// `csaf_vex`, `csaf_security_advisory`, or a custom producer category.
    pub category: String,
    pub title: Option<String>,
    pub lang: String,
    /// One of `coordinator|discoverer|other|translator|user|vendor`.
    pub publisher_category: String,
    pub publisher_name: String,
    pub publisher_namespace: String,
    pub tracking_id: Option<String>,
    /// `WHITE|GREEN|AMBER|RED` when a TLP classification should be recorded.
    pub tlp: Option<String>,
    /// `draft|final|interim`.
    pub status: String,
    /// Marks the vulnerabilities as actively exploited (CRA trigger).
    pub exploited: bool,
    pub now: DateTime<Utc>,
}

impl Default for CsafConfig {
    fn default() -> Self {
        CsafConfig {
            category: "csaf_vex".to_string(),
            title: None,
            lang: "en".to_string(),
            publisher_category: "vendor".to_string(),
            publisher_name: String::new(),
            publisher_namespace: String::new(),
            tracking_id: None,
            tlp: None,
            status: "final".to_string(),
            exploited: false,
            now: Utc::now(),
        }
    }
}

fn rfc3339(now: &DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Build a CSAF 2.0 document. Panics never: returns errors for invalid config.
pub fn build_document(cfg: &CsafConfig, doc: &FindingsDoc) -> Result<Value> {
    if cfg.publisher_name.is_empty() {
        bail!("publisher name is required (pass --vendor-name)");
    }
    if cfg.publisher_namespace.is_empty() {
        bail!("publisher namespace is required (pass --vendor-namespace)");
    }
    if !matches!(
        cfg.publisher_category.as_str(),
        "coordinator" | "discoverer" | "other" | "translator" | "user" | "vendor"
    ) {
        bail!("invalid publisher category \"{}\"", cfg.publisher_category);
    }
    if !matches!(cfg.status.as_str(), "draft" | "final" | "interim") {
        bail!(
            "invalid tracking status \"{}\" (draft|final|interim)",
            cfg.status
        );
    }
    if let Some(tlp) = &cfg.tlp {
        if !matches!(tlp.as_str(), "WHITE" | "GREEN" | "AMBER" | "RED") {
            bail!("invalid TLP label \"{tlp}\" (WHITE|GREEN|AMBER|RED)");
        }
    }

    let timestamp = rfc3339(&cfg.now);
    let product_display = doc
        .sbom
        .product
        .as_ref()
        .map(|p| p.display_name())
        .unwrap_or_else(|| "the analyzed product".to_string());

    // ------------------------------------------------------------------
    // product tree: main product + every component referenced by findings
    // ------------------------------------------------------------------
    let main_id = "CSAFPID-0000".to_string();
    let mut full_product_names: Vec<Value> = Vec::new();
    let mut component_ids: HashMap<(String, Option<String>, Option<String>), String> =
        HashMap::new();

    if let Some(product) = &doc.sbom.product {
        full_product_names.push(full_product_name(
            &main_id,
            &product.display_name(),
            product,
        ));
        component_ids.insert(
            (
                product.name.clone(),
                product.version.clone(),
                product.purl_raw.clone(),
            ),
            main_id.clone(),
        );
    }

    for finding in &doc.findings {
        let c = &finding.component;
        let key = (c.name.clone(), c.version.clone(), c.purl_raw.clone());
        if let std::collections::hash_map::Entry::Vacant(entry) = component_ids.entry(key) {
            let id = format!("CSAFPID-{:04}", full_product_names.len());
            full_product_names.push(full_product_name(&id, &c.display_name(), c));
            entry.insert(id);
        }
    }

    let component_id = |c: &crate::model::Component| -> Option<String> {
        component_ids
            .get(&(c.name.clone(), c.version.clone(), c.purl_raw.clone()))
            .cloned()
    };

    // ------------------------------------------------------------------
    // group findings by vulnerability
    // ------------------------------------------------------------------
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, finding) in doc.findings.iter().enumerate() {
        if !groups.contains_key(&finding.vuln.id) {
            order.push(finding.vuln.id.clone());
        }
        groups
            .entry(finding.vuln.id.clone())
            .or_default()
            .push(index);
    }

    let mut vulnerabilities: Vec<Value> = Vec::new();
    for vuln_id in &order {
        let indices = &groups[vuln_id];
        let first = &doc.findings[indices[0]];
        let vuln = &first.vuln;

        let mut known_affected: Vec<String> = Vec::new();
        let mut known_not_affected: Vec<String> = Vec::new();
        let mut fixed: Vec<String> = Vec::new();
        let mut under_investigation: Vec<String> = Vec::new();
        let mut flags: Vec<Value> = Vec::new();
        let mut remediation_groups: HashMap<String, Vec<String>> = HashMap::new();
        let mut component_lines: Vec<String> = Vec::new();

        for &index in indices {
            let finding = &doc.findings[index];
            let Some(product_id) = component_id(&finding.component) else {
                continue;
            };
            component_lines.push(format!(
                "- {}: {}",
                finding.component.display_name(),
                finding.status
            ));

            match finding.status {
                VexStatus::Affected => {
                    known_affected.push(product_id.clone());
                    if let Some(fixed_in) = &finding.fixed_in {
                        remediation_groups
                            .entry(fixed_in.clone())
                            .or_default()
                            .push(product_id);
                    }
                }
                VexStatus::UnderInvestigation => {
                    under_investigation.push(product_id.clone());
                }
                VexStatus::NotAffected => {
                    known_not_affected.push(product_id.clone());
                    if let Some(justification) = finding
                        .justification
                        .as_deref()
                        .filter(|j| FLAG_LABELS.contains(j))
                    {
                        flags.push(json!({
                            "label": justification,
                            "product_ids": [product_id],
                        }));
                    }
                }
                VexStatus::Fixed => fixed.push(product_id),
            }
        }

        // Product-level status: the product inherits the most severe status
        // of its components (affected > under investigation > fixed /
        // not affected), so consumers can filter on the product id alone.
        let has_affected = !known_affected.is_empty();
        if !full_product_names.is_empty() {
            let product_status = if !known_affected.is_empty() {
                Some(VexStatus::Affected)
            } else if !under_investigation.is_empty() {
                Some(VexStatus::UnderInvestigation)
            } else if !fixed.is_empty() {
                Some(VexStatus::Fixed)
            } else if !known_not_affected.is_empty() {
                Some(VexStatus::NotAffected)
            } else {
                None
            };
            let target = match product_status {
                Some(VexStatus::Affected) => Some(&mut known_affected),
                Some(VexStatus::UnderInvestigation) => Some(&mut under_investigation),
                Some(VexStatus::Fixed) => Some(&mut fixed),
                Some(VexStatus::NotAffected) => Some(&mut known_not_affected),
                None => None,
            };
            if let Some(group) = target {
                if !group.contains(&main_id) {
                    group.push(main_id.clone());
                }
            }
        }

        let mut notes = Vec::new();
        if let Some(summary) = vuln.summary.as_ref().filter(|s| !s.is_empty()) {
            notes.push(json!({
                "category": "summary",
                "text": summary,
            }));
        }
        if component_lines.len() > 1 || !known_not_affected.is_empty() {
            notes.push(json!({
                "category": "details",
                "text": format!(
                    "Component-level triage for {product_display}:\n{}",
                    component_lines.join("\n")
                ),
            }));
        }

        let mut vulnerability = Map::new();
        if is_cve(vuln_id) {
            vulnerability.insert("cve".into(), json!(vuln_id));
        } else {
            vulnerability.insert(
                "ids".into(),
                json!([{ "system_name": "Open Source Vulnerability Database", "text": vuln_id }]),
            );
        }
        vulnerability.insert(
            "title".into(),
            json!(format!(
                "{} in {product_display}",
                vuln.summary
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(|s| format!("{vuln_id}: {s}"))
                    .unwrap_or_else(|| vuln_id.to_string())
            )),
        );
        if let Some(cvss) = vuln.cvss.as_deref().filter(|c| !c.is_empty()) {
            // Only scores with full CVSS objects validate against the
            // embedded FIRST schemas; vectors alone are recorded as a note.
            notes.push(json!({
                "category": "general",
                "text": format!("CVSS vector: {cvss}"),
            }));
        }
        if !notes.is_empty() {
            vulnerability.insert("notes".into(), Value::Array(notes));
        }
        let mut product_status = Map::new();
        if !known_affected.is_empty() {
            product_status.insert("known_affected".into(), json!(known_affected));
        }
        if !known_not_affected.is_empty() {
            product_status.insert("known_not_affected".into(), json!(known_not_affected));
        }
        if !fixed.is_empty() {
            product_status.insert("fixed".into(), json!(fixed));
        }
        if !under_investigation.is_empty() {
            product_status.insert("under_investigation".into(), json!(under_investigation));
        }
        if !product_status.is_empty() {
            vulnerability.insert("product_status".into(), Value::Object(product_status));
        }
        if !flags.is_empty() {
            vulnerability.insert("flags".into(), json!(flags));
        }
        if !remediation_groups.is_empty() {
            let mut remediations = Vec::new();
            for (fixed_in, product_ids) in &remediation_groups {
                let component = doc
                    .findings
                    .iter()
                    .find(|f| f.fixed_in.as_deref() == Some(fixed_in.as_str()))
                    .map(|f| f.component.display_name())
                    .unwrap_or_default();
                remediations.push(json!({
                    "category": "vendor_fix",
                    "details": format!("Upgrade {component} to {fixed_in} or later."),
                    "product_ids": product_ids,
                }));
            }
            vulnerability.insert("remediations".into(), json!(remediations));
        }
        // An exploit_status threat ("actively exploited in the wild") is the
        // CRA reporting trigger and only makes sense where something is
        // actually affected — never on suppressed entries.
        if cfg.exploited && has_affected {
            vulnerability.insert(
                "threats".into(),
                json!([{
                    "category": "exploit_status",
                    "details": "The vulnerability is being actively exploited in the wild.",
                    "date": timestamp,
                }]),
            );
        }
        vulnerabilities.push(Value::Object(vulnerability));
    }

    // ------------------------------------------------------------------
    // document tracking block with deterministic ids
    // ------------------------------------------------------------------
    let tracking_id = cfg.tracking_id.clone().unwrap_or_else(|| {
        let mut vuln_ids: Vec<&str> = groups.keys().map(String::as_str).collect();
        vuln_ids.sort_unstable();
        let hash = sha256_hex(
            format!(
                "{}|{}|{}|{}",
                cfg.publisher_name,
                product_display,
                vuln_ids.join(","),
                cfg.now.format("%Y-%m-%d")
            )
            .as_bytes(),
        );
        format!(
            "{}-{}-{}",
            slug(&cfg.publisher_name),
            cfg.now.format("%Y"),
            &hash[..8]
        )
    });

    let mut document = Map::new();
    document.insert("category".into(), json!(cfg.category));
    document.insert("csaf_version".into(), json!("2.0"));
    document.insert("lang".into(), json!(cfg.lang));
    document.insert(
        "title".into(),
        json!(cfg.title.clone().unwrap_or_else(|| {
            format!(
                "Vulnerability triage report for {product_display} ({})",
                cfg.now.format("%Y-%m-%d")
            )
        })),
    );
    document.insert(
        "publisher".into(),
        json!({
            "category": cfg.publisher_category,
            "name": cfg.publisher_name,
            "namespace": cfg.publisher_namespace,
        }),
    );
    if let Some(tlp) = &cfg.tlp {
        document.insert(
            "distribution".into(),
            json!({
                "tlp": {"label": tlp, "url": "https://www.first.org/tlp/"},
            }),
        );
    }
    document.insert(
        "tracking".into(),
        json!({
            "id": tracking_id,
            "status": cfg.status,
            "version": "1",
            "initial_release_date": timestamp,
            "current_release_date": timestamp,
            "generator": {
                "engine": {"name": "openenisa", "version": crate::VERSION},
                "date": timestamp,
            },
            "revision_history": [
                {"date": timestamp, "number": "1", "summary": "Initial version generated by openenisa"},
            ],
        }),
    );
    document.insert(
        "notes".into(),
        json!([{
            "category": "description",
            "text": format!(
                "This document was generated by {} from the product SBOM ({}, sha256 {}) and {} finding(s).",
                crate::engine(),
                doc.sbom.format.as_deref().unwrap_or("unknown format"),
                doc.sbom.sha256.as_deref().unwrap_or("-"),
                doc.findings.len()
            ),
        }]),
    );

    let mut csaf = Map::new();
    csaf.insert("document".into(), Value::Object(document));
    if !full_product_names.is_empty() {
        csaf.insert(
            "product_tree".into(),
            json!({"full_product_names": full_product_names}),
        );
    }
    if !vulnerabilities.is_empty() {
        csaf.insert("vulnerabilities".into(), Value::Array(vulnerabilities));
    }

    Ok(Value::Object(csaf))
}

fn full_product_name(product_id: &str, name: &str, component: &crate::model::Component) -> Value {
    let mut entry = json!({
        "product_id": product_id,
        "name": name,
    });
    let mut helper = Map::new();
    if let Some(purl) = &component.purl_raw {
        helper.insert("purl".into(), json!(purl));
    }
    if let Some(cpe) = &component.cpe {
        helper.insert("cpe".into(), json!(cpe));
    }
    if !helper.is_empty() {
        entry["product_identification_helper"] = Value::Object(helper);
    }
    entry
}

fn is_cve(id: &str) -> bool {
    let rest = id.strip_prefix("CVE-").unwrap_or(id);
    let mut parts = rest.splitn(2, '-');
    let year = parts.next().unwrap_or_default();
    let digits = parts.next().unwrap_or_default();
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut pending_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(c.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() {
        "vendor".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, Vulnerability};

    fn doc_with(findings: Vec<crate::model::Finding>) -> FindingsDoc {
        FindingsDoc {
            sbom: crate::model::SbomMeta {
                path: "examples/sbom/mx2400.cyclonedx-1.5.json".into(),
                format: Some("CycloneDX 1.5 (JSON)".into()),
                spec_version: Some("1.5".into()),
                sha256: Some("ab".into()),
                components: 4,
                product: Some(Component {
                    name: "MX-2400 Server Firmware".into(),
                    version: Some("2.4.1".into()),
                    purl_raw: None,
                    ..Component::default()
                }),
            },
            generator: "openenisa test".into(),
            generated_at: "2026-10-10T00:00:00Z".into(),
            findings,
        }
    }

    fn affected_finding() -> crate::model::Finding {
        crate::model::Finding {
            vuln: Vulnerability {
                id: "CVE-2023-48795".into(),
                summary: Some("Terrapin attack".into()),
                ..Vulnerability::default()
            },
            component: Component {
                name: "libssh2".into(),
                version: Some("1.11.0".into()),
                purl_raw: Some("pkg:generic/libssh2@1.11.0".into()),
                purl: crate::model::Purl::parse("pkg:generic/libssh2@1.11.0").ok(),
                ..Component::default()
            },
            status: VexStatus::Affected,
            matched_by: "purl".into(),
            justification: None,
            impact: None,
            vex_source: None,
            fixed_in: Some("1.11.1".into()),
        }
    }

    #[test]
    fn builds_schema_valid_document() {
        let doc = doc_with(vec![affected_finding()]);
        let cfg = CsafConfig {
            publisher_name: "Meridian Systems".into(),
            publisher_namespace: "https://meridian.example".into(),
            exploited: true,
            ..CsafConfig::default()
        };
        let csaf = build_document(&cfg, &doc).unwrap();
        let result = validate::validate_csaf(&csaf);
        assert!(result.valid, "schema errors: {:?}", result.issues);

        let tracking_id = csaf["document"]["tracking"]["id"].as_str().unwrap();
        assert!(
            tracking_id.starts_with("meridian-systems-"),
            "got {tracking_id}"
        );

        let vuln = &csaf["vulnerabilities"][0];
        assert_eq!(vuln["cve"], json!("CVE-2023-48795"));
        assert!(
            vuln["product_status"]["known_affected"]
                .as_array()
                .unwrap()
                .contains(&json!("CSAFPID-0000"))
        );
        assert_eq!(vuln["threats"][0]["category"], json!("exploit_status"));
        assert!(
            vuln["remediations"][0]["details"]
                .as_str()
                .unwrap()
                .contains("1.11.1")
        );
    }

    #[test]
    fn rejects_missing_publisher() {
        let doc = doc_with(vec![affected_finding()]);
        assert!(build_document(&CsafConfig::default(), &doc).is_err());
    }
}
