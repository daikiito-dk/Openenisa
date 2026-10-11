//! [OpenVEX](https://github.com/openvex/spec) document parsing.

use super::{VexStatement, product_from_id};
use crate::model::{VexStatus, v_str};
use anyhow::{Context, Result};
use serde_json::Value;

pub fn parse(value: &Value, source: &str) -> Result<Vec<VexStatement>> {
    let statements = value
        .get("statements")
        .and_then(Value::as_array)
        .with_context(|| format!("{source}: OpenVEX document missing \"statements\""))?;

    let mut out = Vec::new();
    for statement in statements {
        let vulnerability_id = statement
            .get("vulnerability")
            .and_then(|v| v_str(v, "id"))
            .or_else(|| {
                statement
                    .get("vulnerability")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .with_context(|| format!("{source}: OpenVEX statement missing vulnerability id"))?;

        let status = v_str(statement, "status")
            .and_then(|s| VexStatus::parse(&s))
            .with_context(|| {
                format!(
                    "{source}: OpenVEX statement for {vulnerability_id} has missing/unknown status"
                )
            })?;

        let products = statement
            .get("products")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for product in products {
            let id = product
                .get("@id")
                .or_else(|| product.get("id"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Some(product) = product_from_id(id) else {
                continue;
            };
            out.push(VexStatement {
                vulnerability_id: vulnerability_id.clone(),
                product,
                status,
                justification: v_str(statement, "justification"),
                impact: v_str(statement, "impact_statement").or_else(|| v_str(statement, "impact")),
                source: source.to_string(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vex::VexProduct;

    #[test]
    fn parses_statements() {
        let doc: Value = serde_json::from_str(
            r#"{
              "document": {"@context": "https://openvex.dev/v1.0.0"},
              "statements": [
                {
                  "vulnerability": {"id": "CVE-2023-48795"},
                  "products": [{"@id": "pkg:generic/libssh2@1.11.0"}],
                  "status": "fixed",
                  "justification": "",
                  "impact_statement": "Fixed in 1.11.1 via strict KEX."
                },
                {
                  "vulnerability": {"id": "CVE-2020-0000"},
                  "products": [{"@id": "some-component-name"}],
                  "status": "under_investigation"
                }
              ]
            }"#,
        )
        .unwrap();
        let statements = parse(&doc, "openvex.json").unwrap();
        assert_eq!(statements.len(), 2);
        assert!(matches!(
            statements[0].product,
            VexProduct::Purl { ref version, .. } if version.as_deref() == Some("1.11.0")
        ));
        assert_eq!(statements[0].status, VexStatus::Fixed);
        assert!(matches!(statements[1].product, VexProduct::Name(_)));
    }
}
