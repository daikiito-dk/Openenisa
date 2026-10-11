//! Offline validation: embedded JSON Schema + CSAF conformance checks.
//!
//! Everything the validator needs is compiled into the binary — no network,
//! ever. Schema validation uses the bundled official OASIS CSAF 2.0 schema
//! (errata 01, with FIRST CVSS schemas inlined). On top of the schema,
//! [`strict_checks`] implements the structural invariants required by the
//! CSAF 2.0 specification that JSON Schema alone cannot express
//! (cross-references, cross-field consistency, date ordering).

use crate::model::{Purl, v_str, v_strs};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "pass",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StrictCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Human-readable document kind, e.g. "CSAF 2.0".
    pub kind: &'static str,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub checks: Vec<StrictCheck>,
}

impl ValidationResult {
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "valid": self.valid,
            "issues": self.issues.iter().map(|i| json!({
                "path": i.path,
                "message": i.message,
            })).collect::<Vec<_>>(),
            "checks": self.checks.iter().map(|c| json!({
                "name": c.name,
                "status": c.status.as_str(),
                "detail": c.detail,
            })).collect::<Vec<_>>(),
        })
    }

    /// Schema errors plus failed/warned checks, human-readable.
    pub fn problems(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .issues
            .iter()
            .map(|i| format!("{}: {}", i.path, i.message))
            .collect();
        for check in &self.checks {
            if check.status != CheckStatus::Pass {
                out.push(format!(
                    "[{}] {}: {}",
                    check.status.as_str(),
                    check.name,
                    check.detail
                ));
            }
        }
        out
    }
}

fn schema_validate(schema: &Value, doc: &Value, out: &mut Vec<ValidationIssue>) -> bool {
    let validator = match jsonschema::validator_for(schema) {
        Ok(validator) => validator,
        Err(e) => {
            out.push(ValidationIssue {
                path: "$schema".to_string(),
                message: format!("embedded schema failed to compile: {e}"),
            });
            return false;
        }
    };
    let mut valid = true;
    for error in validator.iter_errors(doc) {
        valid = false;
        let path = error.instance_path().to_string();
        out.push(ValidationIssue {
            path: if path.is_empty() {
                "/".to_string()
            } else {
                path
            },
            message: error.to_string(),
        });
    }
    valid
}

// ---------------------------------------------------------------------------
// CSAF validation
// ---------------------------------------------------------------------------

/// Validate a CSAF 2.0 document against the embedded schema + conformance
/// checks. Fully offline.
pub fn validate_csaf(doc: &Value) -> ValidationResult {
    let mut issues = Vec::new();
    let valid_schema = schema_validate(crate::schemas::csaf_2_0(), doc, &mut issues);
    let checks = strict_checks(doc);
    let valid = valid_schema && checks.iter().all(|c| c.status != CheckStatus::Fail);
    ValidationResult {
        kind: "CSAF 2.0",
        valid,
        issues,
        checks,
    }
}

/// Validate an openenisa findings document against the embedded schema.
pub fn validate_findings(doc: &Value) -> ValidationResult {
    let mut issues = Vec::new();
    let valid = schema_validate(crate::schemas::findings(), doc, &mut issues);
    ValidationResult {
        kind: "openenisa findings",
        valid,
        issues,
        checks: Vec::new(),
    }
}

/// Validate an ENISA envelope against the embedded schema.
pub fn validate_envelope(doc: &Value) -> ValidationResult {
    let mut issues = Vec::new();
    let valid = schema_validate(crate::schemas::enisa_envelope(), doc, &mut issues);
    ValidationResult {
        kind: "ENISA envelope",
        valid,
        issues,
        checks: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// CSAF conformance checks
// ---------------------------------------------------------------------------

fn strict_checks(doc: &Value) -> Vec<StrictCheck> {
    let checks = vec![
        dates_ordered(doc),
        revision_history_sync(doc),
        product_ids_resolvable(doc),
        purls_well_formed(doc),
        dates_parseable(doc),
        category_convention(doc),
    ];
    checks
}

fn parse_ts(value: Option<&str>) -> Option<DateTime<Utc>> {
    value.and_then(|s| {
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    })
}

fn dates_ordered(doc: &Value) -> StrictCheck {
    let tracking = doc.pointer("/document/tracking");
    let initial = tracking.and_then(|t| v_str(t, "initial_release_date"));
    let current = tracking.and_then(|t| v_str(t, "current_release_date"));
    match (initial.as_deref(), current.as_deref()) {
        (Some(i), Some(c)) => match (parse_ts(Some(i)), parse_ts(Some(c))) {
            (Some(ti), Some(tc)) if ti <= tc => StrictCheck {
                name: "tracking/dates_ordered".into(),
                status: CheckStatus::Pass,
                detail: "initial_release_date <= current_release_date".into(),
            },
            _ => StrictCheck {
                name: "tracking/dates_ordered".into(),
                status: CheckStatus::Fail,
                detail: format!("initial_release_date {i:?} is after current_release_date {c:?}"),
            },
        },
        (None, _) | (_, None) => StrictCheck {
            name: "tracking/dates_ordered".into(),
            status: CheckStatus::Fail,
            detail: "tracking dates are missing (schema should have caught this)".into(),
        },
    }
}

fn revision_history_sync(doc: &Value) -> StrictCheck {
    let tracking = match doc.pointer("/document/tracking") {
        Some(t) => t,
        None => {
            return StrictCheck {
                name: "tracking/revision_history_sync".into(),
                status: CheckStatus::Fail,
                detail: "document/tracking is missing".into(),
            };
        }
    };
    let current = v_str(tracking, "current_release_date").unwrap_or_default();
    let version = v_str(tracking, "version").unwrap_or_default();
    let last = tracking
        .get("revision_history")
        .and_then(Value::as_array)
        .and_then(|entries| entries.last());

    match last {
        Some(last) => {
            let date_ok = v_str(last, "date").as_deref() == Some(current.as_str());
            let number_ok = v_str(last, "number").as_deref() == Some(version.as_str());
            if date_ok && number_ok {
                StrictCheck {
                    name: "tracking/revision_history_sync".into(),
                    status: CheckStatus::Pass,
                    detail: format!("latest revision matches version {version}"),
                }
            } else {
                StrictCheck {
                    name: "tracking/revision_history_sync".into(),
                    status: CheckStatus::Fail,
                    detail: format!(
                        "latest revision (date {}, number {}) does not match tracking (current_release_date {current}, version {version})",
                        v_str(last, "date").unwrap_or_default(),
                        v_str(last, "number").unwrap_or_default(),
                    ),
                }
            }
        }
        None => StrictCheck {
            name: "tracking/revision_history_sync".into(),
            status: CheckStatus::Fail,
            detail: "revision_history is empty or missing".into(),
        },
    }
}

fn product_ids_resolvable(doc: &Value) -> StrictCheck {
    let mut defined: Vec<String> = Vec::new();
    if let Some(tree) = doc.get("product_tree") {
        collect_defined_ids(tree, &mut defined);
    }
    let mut referenced: Vec<String> = Vec::new();
    if let Some(vulns) = doc.get("vulnerabilities").and_then(Value::as_array) {
        for vuln in vulns {
            if let Some(status) = vuln.get("product_status").and_then(Value::as_object) {
                for group in status.values() {
                    referenced.extend(
                        group
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .map(str::to_string),
                    );
                }
            }
            for section in ["flags", "remediations", "threats", "involvements"] {
                for entry in vuln
                    .get(section)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    referenced.extend(v_strs(entry, "product_ids"));
                }
            }
            referenced.extend(v_strs(
                vuln.get("scores").unwrap_or(&Value::Null),
                "products",
            ));
        }
    }

    let missing: Vec<String> = referenced
        .into_iter()
        .filter(|id| !defined.contains(id))
        .collect();

    if missing.is_empty() {
        StrictCheck {
            name: "product_ids/resolvable".into(),
            status: CheckStatus::Pass,
            detail: format!(
                "{} product id(s) all resolve in product_tree",
                defined.len()
            ),
        }
    } else {
        StrictCheck {
            name: "product_ids/resolvable".into(),
            status: CheckStatus::Fail,
            detail: format!(
                "referenced but undefined product ids: {}",
                missing.join(", ")
            ),
        }
    }
}

fn collect_defined_ids(node: &Value, out: &mut Vec<String>) {
    if let Some(full_names) = node.get("full_product_names").and_then(Value::as_array) {
        for full_name in full_names {
            if let Some(id) = v_str(full_name, "product_id") {
                out.push(id);
            }
        }
    }
    for group in ["groups", "branches"] {
        for branch in node
            .get(group)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            collect_defined_ids(branch, out);
        }
    }
}

fn purls_well_formed(doc: &Value) -> StrictCheck {
    let mut bad: Vec<String> = Vec::new();
    let check = |purl: Option<String>, bad: &mut Vec<String>| {
        if let Some(p) = purl {
            if Purl::parse(&p).is_err() {
                bad.push(p);
            }
        }
    };
    if let Some(tree) = doc.get("product_tree") {
        collect_purls(tree, &mut bad, &check);
    }
    if bad.is_empty() {
        StrictCheck {
            name: "product_tree/purl_format".into(),
            status: CheckStatus::Pass,
            detail: "all product_identification_helper purls are well-formed".into(),
        }
    } else {
        StrictCheck {
            name: "product_tree/purl_format".into(),
            status: CheckStatus::Fail,
            detail: format!("malformed purls: {}", bad.join(", ")),
        }
    }
}

fn collect_purls<F>(node: &Value, bad: &mut Vec<String>, check: &F)
where
    F: Fn(Option<String>, &mut Vec<String>),
{
    if let Some(full_names) = node.get("full_product_names").and_then(Value::as_array) {
        for full_name in full_names {
            check(
                full_name
                    .get("product_identification_helper")
                    .and_then(|helper| v_str(helper, "purl")),
                bad,
            );
        }
    }
    for branch in node
        .get("branches")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        collect_purls(branch, bad, check);
    }
}

fn dates_parseable(doc: &Value) -> StrictCheck {
    let mut bad: Vec<String> = Vec::new();
    let check_date = |value: Option<String>, bad: &mut Vec<String>| {
        if let Some(s) = value {
            if parse_ts(Some(&s)).is_none() {
                bad.push(s);
            }
        }
    };
    if let Some(tracking) = doc.pointer("/document/tracking") {
        check_date(v_str(tracking, "initial_release_date"), &mut bad);
        check_date(v_str(tracking, "current_release_date"), &mut bad);
        for entry in tracking
            .get("revision_history")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            check_date(v_str(entry, "date"), &mut bad);
        }
    }
    if let Some(vulns) = doc.get("vulnerabilities").and_then(Value::as_array) {
        for vuln in vulns {
            check_date(v_str(vuln, "discovery_date"), &mut bad);
            check_date(v_str(vuln, "release_date"), &mut bad);
            for threat in vuln
                .get("threats")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                check_date(v_str(threat, "date"), &mut bad);
            }
        }
    }
    if bad.is_empty() {
        StrictCheck {
            name: "dates/rfc3339".into(),
            status: CheckStatus::Pass,
            detail: "all timestamps are valid RFC 3339".into(),
        }
    } else {
        StrictCheck {
            name: "dates/rfc3339".into(),
            status: CheckStatus::Fail,
            detail: format!("unparseable dates: {}", bad.join(", ")),
        }
    }
}

fn category_convention(doc: &Value) -> StrictCheck {
    let category = doc
        .pointer("/document/category")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if category.starts_with("csaf_") {
        StrictCheck {
            name: "document/category_convention".into(),
            status: CheckStatus::Pass,
            detail: format!("category \"{category}\" follows the csaf_* convention"),
        }
    } else {
        StrictCheck {
            name: "document/category_convention".into(),
            status: CheckStatus::Warn,
            detail: format!(
                "category \"{category}\" does not start with \"csaf_\"; consumers may not recognize it"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_csaf_fails_schema() {
        let bad = json!({"document": {"csaf_version": "2.0"}});
        let result = validate_csaf(&bad);
        assert!(!result.valid);
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn referential_integrity_catches_dangling_ids() {
        let doc = json!({
            "document": {
                "csaf_version": "2.0",
                "category": "csaf_vex",
                "lang": "en",
                "title": "t",
                "publisher": {"category": "vendor", "name": "n", "namespace": "https://x"},
                "tracking": {
                    "id": "x-2026-1",
                    "status": "final",
                    "version": "1",
                    "initial_release_date": "2026-10-10T00:00:00Z",
                    "current_release_date": "2026-10-10T00:00:00Z",
                    "revision_history": [{"date": "2026-10-10T00:00:00Z", "number": "1", "summary": "i"}],
                },
            },
            "product_tree": {
                "full_product_names": [{"product_id": "CSAFPID-0001", "name": "x"}]
            },
            "vulnerabilities": [{
                "cve": "CVE-2023-48795",
                "product_status": {"known_affected": ["CSAFPID-9999"]},
            }],
        });
        let result = validate_csaf(&doc);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "product_ids/resolvable" && c.status == CheckStatus::Fail)
        );
    }

    #[test]
    fn embedded_schemas_compile() {
        // Fails loudly at first use if a vendored schema is broken.
        assert!(jsonschema::validator_for(crate::schemas::csaf_2_0()).is_ok());
        assert!(jsonschema::validator_for(crate::schemas::enisa_envelope()).is_ok());
        assert!(jsonschema::validator_for(crate::schemas::findings()).is_ok());
    }
}
