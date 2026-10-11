//! CSAF VEX profile parsing.
//!
//! Statements are extracted from `product_status` groups; product ids are
//! resolved to purls through the document's own `product_tree` (both
//! top-level `full_product_names` and branch-embedded ones). `flags`
//! contribute the VEX justification labels for the flagged products.

use super::{VexProduct, VexStatement};
use crate::model::{VexStatus, v_str};
use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

pub fn parse(value: &Value, source: &str) -> Result<Vec<VexStatement>> {
    let mut product_purls: HashMap<String, Option<String>> = HashMap::new();
    if let Some(tree) = value.get("product_tree") {
        collect_product_names(tree, &mut product_purls);
    }

    let mut statements: Vec<VexStatement> = Vec::new();
    // (vulnerability_id, product_id) -> indices into `statements`
    let mut by_product_id: HashMap<(String, String), Vec<usize>> = HashMap::new();

    for vulnerability in value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(vulnerability_id) = vulnerability
            .get("cve")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                vulnerability
                    .get("ids")
                    .and_then(Value::as_array)
                    .and_then(|ids| ids.first())
                    .and_then(|id| v_str(id, "text"))
            })
        else {
            continue;
        };

        let status_groups: &[(&str, VexStatus)] = &[
            ("known_affected", VexStatus::Affected),
            ("first_affected", VexStatus::Affected),
            ("last_affected", VexStatus::Affected),
            ("known_not_affected", VexStatus::NotAffected),
            ("fixed", VexStatus::Fixed),
            ("first_fixed", VexStatus::Fixed),
            ("under_investigation", VexStatus::UnderInvestigation),
        ];

        for (group, status) in status_groups {
            for product_id in vulnerability
                .get("product_status")
                .and_then(|s| s.get(*group))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                // Same product in the same group twice -> one statement.
                let key = (vulnerability_id.clone(), product_id.to_string());
                if by_product_id.contains_key(&key) {
                    continue;
                }
                let product = resolve_product(product_id, &product_purls);
                let index = statements.len();
                by_product_id.entry(key).or_default().push(index);
                statements.push(VexStatement {
                    vulnerability_id: vulnerability_id.clone(),
                    product,
                    status: *status,
                    justification: None,
                    impact: None,
                    source: source.to_string(),
                });
            }
        }

        // flags carry the VEX justification label for flagged products.
        for flag in vulnerability
            .get("flags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let label = v_str(flag, "label").unwrap_or_default();
            if label.is_empty() {
                continue;
            }
            for product_id in flag
                .get("product_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if let Some(indices) =
                    by_product_id.get(&(vulnerability_id.clone(), product_id.to_string()))
                {
                    for index in indices {
                        statements[*index].justification = Some(label.clone());
                    }
                }
            }
        }
    }

    Ok(statements)
}

fn resolve_product(
    product_id: &str,
    product_purls: &HashMap<String, Option<String>>,
) -> VexProduct {
    match product_purls.get(product_id) {
        Some(Some(purl_raw)) => match crate::model::Purl::parse(purl_raw) {
            Ok(purl) => VexProduct::Purl {
                purl,
                version: None,
            },
            Err(_) => VexProduct::Ref(product_id.to_string()),
        },
        _ => VexProduct::Ref(product_id.to_string()),
    }
}

/// Recursively collect `full_product_name` entries: `{"product_id": ..., "purl": ...}`.
fn collect_product_names(node: &Value, out: &mut HashMap<String, Option<String>>) {
    if let Some(full_names) = node.get("full_product_names").and_then(Value::as_array) {
        for full_name in full_names {
            let Some(product_id) = v_str(full_name, "product_id") else {
                continue;
            };
            let purl = full_name
                .get("product_identification_helper")
                .and_then(|helper| v_str(helper, "purl"));
            out.insert(product_id, purl);
        }
    }
    for branch in node
        .get("branches")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        collect_product_names(branch, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSAF_VEX: &str = r#"{
      "document": {"csaf_version": "2.0", "category": "csaf_vex"},
      "product_tree": {
        "full_product_names": [
          {
            "product_id": "CSAFPID-0001",
            "name": "openssl 3.0.12",
            "product_identification_helper": {"purl": "pkg:generic/openssl@3.0.12"}
          },
          {"product_id": "CSAFPID-0002", "name": "busybox 1.36.0"}
        ]
      },
      "vulnerabilities": [
        {
          "cve": "CVE-2024-0727",
          "product_status": {"known_not_affected": ["CSAFPID-0001"]},
          "flags": [{"label": "vulnerable_code_not_in_execute_path", "product_ids": ["CSAFPID-0001"]}]
        },
        {
          "ids": [{"system_name": "OSV", "text": "CVE-2023-42366"}],
          "product_status": {"fixed": ["CSAFPID-0002"]}
        }
      ]
    }"#;

    #[test]
    fn parses_csaf_vex() {
        let value: Value = serde_json::from_str(CSAF_VEX).unwrap();
        let statements = parse(&value, "csaf.json").unwrap();
        assert_eq!(statements.len(), 2);

        let openssl = statements
            .iter()
            .find(|s| s.vulnerability_id == "CVE-2024-0727")
            .unwrap();
        assert_eq!(openssl.status, VexStatus::NotAffected);
        assert!(matches!(&openssl.product, VexProduct::Purl { .. }));
        assert_eq!(
            openssl.justification.as_deref(),
            Some("vulnerable_code_not_in_execute_path")
        );

        let busybox = statements
            .iter()
            .find(|s| s.vulnerability_id == "CVE-2023-42366")
            .unwrap();
        assert_eq!(busybox.status, VexStatus::Fixed);
        assert!(matches!(&busybox.product, VexProduct::Ref(_)));
    }
}
