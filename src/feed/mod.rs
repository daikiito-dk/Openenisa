//! Vulnerability feed ingestion and matching.
//!
//! Feeds follow the [OSV schema](https://ossf.github.io/osv-schema/):
//! either one record per line (`.jsonl`) or a single record / array of
//! records (`.json`). Matching prefers package-URL identity and falls
//! back to name+ecosystem for SBOMs without purls — the heuristic is
//! always recorded in `finding.matched_by` so triage output stays
//! auditable.
//!
//! Version evaluation implements the OSV event algorithm (`introduced` /
//! `fixed` / `last_affected`) with `SEMVER` and `ECOSYSTEM` ranges.
//! `GIT` ranges are commit-based and are reported as unevaluable rather
//! than guessed at.

use crate::model::{Component, Finding, Purl, Sbom, VexStatus, Vulnerability, v_str};
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Feed {
    pub source: String,
    pub records: Vec<OsvRecord>,
}

impl Feed {
    /// Load an OSV feed from a `.jsonl`/`.ndjson` file or a `.json` file
    /// holding a single record, an array, or an `{"advisories": [...]}` bundle.
    pub fn load(path: &Path) -> Result<Feed> {
        let source = path.display().to_string();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read feed {source}"))?;
        let name = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let mut records = Vec::new();
        if name == "jsonl" || name == "ndjson" {
            for (line_no, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let value: Value = serde_json::from_str(line)
                    .with_context(|| format!("{source}: invalid JSON on line {}", line_no + 1))?;
                if let Some(record) = OsvRecord::from_value(&value) {
                    records.push(record);
                }
            }
        } else {
            let value: Value =
                serde_json::from_str(&text).context(format!("{source}: invalid JSON"))?;
            let items: Vec<&Value> = match &value {
                Value::Array(a) => a.iter().collect(),
                Value::Object(o) => {
                    if let Some(advisories) = o.get("advisories").and_then(Value::as_array) {
                        advisories.iter().collect()
                    } else if o.contains_key("id") {
                        vec![&value]
                    } else {
                        bail!(
                            "{source}: expected an OSV record, an array of records, or an {{\"advisories\": [...]}} bundle"
                        );
                    }
                }
                _ => bail!("{source}: expected a JSON object or array"),
            };
            for item in items {
                if let Some(record) = OsvRecord::from_value(item) {
                    records.push(record);
                }
            }
        }

        Ok(Feed { source, records })
    }
}

// ---------------------------------------------------------------------------
// OSV model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OsvRecord {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
    pub cvss: Option<String>,
    pub references: Vec<String>,
    pub affected: Vec<OsvAffected>,
}

impl OsvRecord {
    fn from_value(value: &Value) -> Option<OsvRecord> {
        let id = v_str(value, "id")?;
        Some(OsvRecord {
            id,
            aliases: crate::model::v_strs(value, "aliases"),
            summary: v_str(value, "summary"),
            details: v_str(value, "details"),
            published: v_str(value, "published"),
            modified: v_str(value, "modified"),
            cvss: value
                .get("severity")
                .and_then(Value::as_array)
                .and_then(|severities| {
                    severities
                        .iter()
                        .find(|s| {
                            matches!(
                                v_str(s, "type").as_deref(),
                                Some("CVSS_V3") | Some("CVSS_V4") | Some("CVSS_V3.1")
                            )
                        })
                        .and_then(|s| v_str(s, "score"))
                }),
            references: value
                .get("references")
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .filter_map(|r| v_str(r, "url"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            affected: value
                .get("affected")
                .and_then(Value::as_array)
                .map(|areas| areas.iter().filter_map(OsvAffected::from_value).collect())
                .unwrap_or_default(),
        })
    }

    fn to_vulnerability(&self) -> Vulnerability {
        Vulnerability {
            id: self.id.clone(),
            aliases: self.aliases.clone(),
            summary: self.summary.clone(),
            details: self.details.clone(),
            cvss: self.cvss.clone(),
            references: self.references.clone(),
            published: self.published.clone(),
            modified: self.modified.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OsvAffected {
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub purl: Option<String>,
    pub ranges: Vec<OsvRange>,
    pub versions: Vec<String>,
}

impl OsvAffected {
    fn from_value(value: &Value) -> Option<OsvAffected> {
        let package = value.get("package");
        Some(OsvAffected {
            ecosystem: package.as_ref().and_then(|p| v_str(p, "ecosystem")),
            name: package.as_ref().and_then(|p| v_str(p, "name")),
            purl: package.as_ref().and_then(|p| v_str(p, "purl")),
            ranges: value
                .get("ranges")
                .and_then(Value::as_array)
                .map(|ranges| {
                    ranges
                        .iter()
                        .filter_map(|r| {
                            Some(OsvRange {
                                range_type: v_str(r, "type")?,
                                events: r
                                    .get("events")
                                    .and_then(Value::as_array)
                                    .map(|events| {
                                        events
                                            .iter()
                                            .filter_map(|e| {
                                                match (
                                                    v_str(e, "introduced"),
                                                    v_str(e, "fixed"),
                                                    v_str(e, "last_affected"),
                                                ) {
                                                    (Some(introduced), _, _) => {
                                                        Some(OsvEvent::Introduced(introduced))
                                                    }
                                                    (None, Some(fixed), _) => {
                                                        Some(OsvEvent::Fixed(fixed))
                                                    }
                                                    (None, None, Some(last)) => {
                                                        Some(OsvEvent::LastAffected(last))
                                                    }
                                                    (None, None, None) => None,
                                                }
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            versions: crate::model::v_strs(value, "versions"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OsvRange {
    pub range_type: String,
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone)]
pub enum OsvEvent {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Match every component of `sbom` against every record of `feeds`.
pub fn match_sbom(sbom: &Sbom, feeds: &[Feed]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for feed in feeds {
        for record in &feed.records {
            for component in sbom.all_components() {
                for area in &record.affected {
                    let Some(identity) = area_matches(component, area) else {
                        continue;
                    };
                    let key = format!(
                        "{}|{}|{}",
                        record.id,
                        component.name,
                        component.version.as_deref().unwrap_or("")
                    );
                    if !seen.insert(key) {
                        continue;
                    }

                    let (status, matched_by, fixed_in) = match &component.version {
                        None => (
                            VexStatus::UnderInvestigation,
                            format!("{identity}+unknown-version"),
                            None,
                        ),
                        Some(version) => match version_status(version, area) {
                            VersionStatus::Affected { fixed_in } => {
                                (VexStatus::Affected, identity, fixed_in)
                            }
                            VersionStatus::AllVersions => {
                                (VexStatus::Affected, format!("{identity}+no-range"), None)
                            }
                            VersionStatus::NotAffected => continue,
                            VersionStatus::Unevaluable => {
                                (VexStatus::UnderInvestigation, identity, None)
                            }
                        },
                    };

                    findings.push(Finding {
                        vuln: record.to_vulnerability(),
                        component: component.clone(),
                        status,
                        matched_by,
                        justification: if status == VexStatus::UnderInvestigation {
                            Some(
                                "component version applicability could not be determined from the feed"
                                    .to_string(),
                            )
                        } else {
                            None
                        },
                        impact: None,
                        vex_source: None,
                        fixed_in,
                    });
                }
            }
        }
    }

    findings.sort_by(|a, b| {
        a.vuln
            .id
            .cmp(&b.vuln.id)
            .then_with(|| a.component.name.cmp(&b.component.name))
    });
    findings
}

enum VersionStatus {
    Affected {
        fixed_in: Option<String>,
    },
    AllVersions,
    NotAffected,
    /// e.g. only GIT ranges present.
    Unevaluable,
}

fn version_status(version: &str, area: &OsvAffected) -> VersionStatus {
    if !area.versions.is_empty() {
        return if area.versions.iter().any(|v| v == version) {
            VersionStatus::Affected { fixed_in: None }
        } else {
            VersionStatus::NotAffected
        };
    }

    let mut affected = false;
    let mut fixed_in: Option<String> = None;
    let mut saw_evaluable = false;

    for range in &area.ranges {
        if !matches!(range.range_type.as_str(), "SEMVER" | "ECOSYSTEM") {
            continue; // GIT ranges are commit-based
        }
        saw_evaluable = true;
        if eval_events(version, &range.events) {
            affected = true;
            if fixed_in.is_none() {
                fixed_in = first_fixed_after(version, &range.events);
            }
        }
    }

    if affected {
        VersionStatus::Affected { fixed_in }
    } else if saw_evaluable {
        VersionStatus::NotAffected
    } else if area.ranges.is_empty() {
        // No constraints at all: OSV treats every version as affected.
        VersionStatus::AllVersions
    } else {
        VersionStatus::Unevaluable
    }
}

/// The OSV event evaluation algorithm. Events arrive in version order;
/// `introduced` enables, `fixed` / `last_affected` disable. `"0"` means
/// "from the beginning".
fn eval_events(version: &str, events: &[OsvEvent]) -> bool {
    let mut affected = false;
    for event in events {
        match event {
            OsvEvent::Introduced(v) => {
                if v == "0" || crate::semver::ge(version, v) {
                    affected = true;
                }
            }
            OsvEvent::Fixed(v) => {
                if crate::semver::ge(version, v) {
                    affected = false;
                }
            }
            OsvEvent::LastAffected(v) => {
                if crate::semver::gt(version, v) {
                    affected = false;
                }
            }
        }
    }
    affected
}

/// Smallest `fixed` event at or after `version`.
fn first_fixed_after(version: &str, events: &[OsvEvent]) -> Option<String> {
    events
        .iter()
        .filter_map(|e| match e {
            OsvEvent::Fixed(v) => Some(v.clone()),
            _ => None,
        })
        .filter(|v| crate::semver::ge(v, version))
        .min_by(|a, b| crate::semver::cmp(a, b))
}

/// How a component's identity matched an OSV affected-area.
fn area_matches(component: &Component, area: &OsvAffected) -> Option<String> {
    // 1. purl-vs-purl: strict identity, no heuristics.
    if let Some(area_purl_raw) = &area.purl {
        if let Ok(area_purl) = Purl::parse(area_purl_raw) {
            if let Some(component_purl) = &component.purl {
                return if component_purl.matches(&area_purl) {
                    Some("purl".to_string())
                } else {
                    None
                };
            }
        }
    }

    // 2. name (+ ecosystem when both sides know it).
    if let Some(area_name) = &area.name {
        if area_name.eq_ignore_ascii_case(&component.name) {
            let component_ecosystem = component
                .purl
                .as_ref()
                .map(|p| ecosystem_for_purl_type(&p.r#type));
            match (component_ecosystem, area.ecosystem.as_deref()) {
                (Some(eco), Some(area_eco)) if eco == area_eco => {
                    return Some("name+ecosystem".to_string());
                }
                (Some(_), Some("Generic")) => {
                    return Some("name+ecosystem".to_string());
                }
                (Some(_), Some(_)) => return None, // same name, different ecosystem
                _ => return Some("name".to_string()), // no ecosystem info on either side
            }
        }
    }

    None
}

/// purl type → OSV ecosystem name for the ecosystems we know.
fn ecosystem_for_purl_type(ty: &str) -> &'static str {
    match ty {
        "cargo" => "crates.io",
        "npm" => "npm",
        "pypi" => "PyPI",
        "golang" => "Go",
        "maven" => "Maven",
        "gem" => "RubyGems",
        "nuget" => "NuGet",
        "composer" => "Packagist",
        "hex" => "Hex",
        "generic" => "Generic",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SbomFormat;

    fn component(name: &str, version: &str, purl: Option<&str>) -> Component {
        let purl_raw = purl.map(str::to_string);
        Component {
            name: name.to_string(),
            version: Some(version.to_string()),
            purl: purl_raw.as_deref().and_then(|p| Purl::parse(p).ok()),
            purl_raw,
            ..Component::default()
        }
    }

    fn record(id: &str, purl: &str, introduced: &str, fixed: &str) -> OsvRecord {
        let value: Value = serde_json::json!({
            "id": id,
            "affected": [{
                "package": {"ecosystem": "Generic", "name": purl.split('/').next_back().unwrap(), "purl": purl},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": introduced},
                    {"fixed": fixed}
                ]}]
            }]
        });
        OsvRecord::from_value(&value).unwrap()
    }

    #[test]
    fn osv_range_evaluation() {
        let r = record("CVE-2018-25032", "pkg:generic/zlib", "0", "1.2.12");
        let area = &r.affected[0];
        assert!(matches!(
            version_status("1.2.13", area),
            VersionStatus::NotAffected
        ));
        assert!(matches!(
            version_status("1.2.11", area),
            VersionStatus::Affected { .. }
        ));

        let r2 = record("CVE-X", "pkg:generic/libssh2", "0", "1.11.1");
        match version_status("1.11.0", &r2.affected[0]) {
            VersionStatus::Affected { fixed_in } => {
                assert_eq!(fixed_in.as_deref(), Some("1.11.1"))
            }
            _ => panic!("expected affected"),
        }
    }

    #[test]
    fn introduced_from_zero_always_applies() {
        let events = vec![
            OsvEvent::Introduced("0".to_string()),
            OsvEvent::Fixed("1.2.12".to_string()),
        ];
        assert!(eval_events("0.9.0", &events));
        assert!(eval_events("1.2.11", &events));
        assert!(!eval_events("1.2.12", &events));
    }

    #[test]
    fn last_affected_exclusive_upper_bound() {
        let events = vec![
            OsvEvent::Introduced("1.0".to_string()),
            OsvEvent::LastAffected("1.4.9".to_string()),
        ];
        assert!(eval_events("1.4.9", &events));
        assert!(!eval_events("1.5.0", &events));
    }

    #[test]
    fn purl_identity_match() {
        let c = component("openssl", "3.0.12", Some("pkg:generic/openssl@3.0.12"));
        let area = OsvAffected {
            ecosystem: Some("Generic".into()),
            name: Some("openssl".into()),
            purl: Some("pkg:generic/openssl".into()),
            ranges: vec![],
            versions: vec![],
        };
        assert_eq!(area_matches(&c, &area).as_deref(), Some("purl"));

        let other = OsvAffected {
            purl: Some("pkg:generic/zlib".into()),
            name: Some("zlib".into()),
            ecosystem: Some("Generic".into()),
            ranges: vec![],
            versions: vec![],
        };
        assert_eq!(area_matches(&c, &other), None);
    }

    #[test]
    fn name_only_fallback() {
        let c = component("openssl", "3.0.12", None);
        let area = OsvAffected {
            ecosystem: None,
            name: Some("OpenSSL".into()),
            purl: None,
            ranges: vec![],
            versions: vec!["3.0.12".to_string()],
        };
        assert_eq!(area_matches(&c, &area).as_deref(), Some("name"));
        assert!(matches!(
            version_status("3.0.12", &area),
            VersionStatus::Affected { fixed_in: None }
        ));
    }

    #[test]
    fn end_to_end_match_sbom() {
        let sbom = Sbom {
            format: Some(SbomFormat::CycloneDxJson("1.5".into())),
            components: vec![
                component("zlib", "1.2.13", Some("pkg:generic/zlib@1.2.13")),
                component("libssh2", "1.11.0", Some("pkg:generic/libssh2@1.11.0")),
            ],
            ..Sbom::default()
        };
        let feed = Feed {
            source: "test".into(),
            records: vec![
                record("CVE-2018-25032", "pkg:generic/zlib", "0", "1.2.12"),
                record("CVE-2023-48795", "pkg:generic/libssh2", "0", "1.11.1"),
            ],
        };
        let findings = match_sbom(&sbom, &[feed]);
        assert_eq!(findings.len(), 1, "zlib 1.2.13 is fixed, libssh2 affected");
        assert_eq!(findings[0].vuln.id, "CVE-2023-48795");
        assert_eq!(findings[0].fixed_in.as_deref(), Some("1.11.1"));
        assert_eq!(findings[0].status, VexStatus::Affected);
    }
}
