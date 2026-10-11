//! Normalized data model shared by every pipeline stage.
//!
//! Every ingestion format (CycloneDX 1.4/1.5/1.6, SPDX 2.3, SPDX 3.0) is
//! normalized into [`Sbom`] + [`Component`]; every feed record into
//! [`Vulnerability`]; every VEX statement into [`VexStatus`]. Downstream
//! stages (CSAF generation, ENISA envelopes) only ever see this model, so
//! adding a new SBOM format never touches reporting logic.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::fmt;

/// SHA-256 as lowercase hex (used for evidence hashes and deterministic IDs).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// SBOM
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SbomFormat {
    CycloneDxJson(String),
    CycloneDxXml(String),
    SpdxJson(String),
    SpdxXml(String),
    Spdx3Json(String),
}

impl fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SbomFormat::CycloneDxJson(v) => write!(f, "CycloneDX {v} (JSON)"),
            SbomFormat::CycloneDxXml(v) => write!(f, "CycloneDX {v} (XML)"),
            SbomFormat::SpdxJson(v) => write!(f, "SPDX {v} (JSON)"),
            SbomFormat::SpdxXml(v) => write!(f, "SPDX {v} (XML)"),
            SbomFormat::Spdx3Json(v) => write!(f, "SPDX {v} (JSON-LD)"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Sbom {
    pub format: Option<SbomFormat>,
    pub serial: Option<String>,
    /// The product described by the SBOM (CycloneDX `metadata.component`,
    /// SPDX `documentDescribes`), when present.
    pub product: Option<Component>,
    pub components: Vec<Component>,
    /// Original document, kept for embedded VEX extraction (CycloneDX).
    pub raw: Value,
    pub bytes: Vec<u8>,
}

impl Sbom {
    pub fn spec_version(&self) -> Option<String> {
        match &self.format {
            Some(SbomFormat::CycloneDxJson(v) | SbomFormat::CycloneDxXml(v)) => Some(v.clone()),
            Some(SbomFormat::SpdxJson(v) | SbomFormat::SpdxXml(v)) => Some(v.clone()),
            Some(SbomFormat::Spdx3Json(v)) => Some(v.clone()),
            None => None,
        }
    }

    pub fn sha256(&self) -> String {
        sha256_hex(&self.bytes)
    }

    /// Product plus components, for matching.
    pub fn all_components(&self) -> Vec<&Component> {
        let mut out: Vec<&Component> = Vec::with_capacity(self.components.len() + 1);
        if let Some(p) = &self.product {
            out.push(p);
        }
        out.extend(self.components.iter());
        out
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Component {
    pub bom_ref: Option<String>,
    /// e.g. `library`, `application`, `firmware`, `operating-system`. Never
    /// used for matching; purely informational.
    pub kind: String,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<Purl>,
    pub purl_raw: Option<String>,
    pub cpe: Option<String>,
    pub supplier: Option<String>,
    pub licenses: Vec<String>,
    pub hashes: Vec<HashEntry>,
    pub scope: Option<String>,
}

impl Component {
    pub fn with_purl_from_str(mut self, raw: Option<&str>) -> Self {
        self.purl_raw = raw.map(str::to_string);
        self.purl = raw.and_then(|s| Purl::parse(s).ok());
        self
    }

    pub fn display_name(&self) -> String {
        match &self.version {
            Some(v) if !v.is_empty() => format!("{} {}", self.name, v),
            _ => self.name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HashEntry {
    pub alg: String,
    pub content: String,
}

// ---------------------------------------------------------------------------
// package-URL
// ---------------------------------------------------------------------------

/// Parsed [package-URL](https://github.com/package-url/purl-spec).
#[derive(Debug, Clone, PartialEq)]
pub struct Purl {
    pub r#type: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: Vec<(String, String)>,
    pub subpath: Option<String>,
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pkg:{}", self.r#type)?;
        if let Some(ns) = &self.namespace {
            write!(f, "/{ns}")?;
        }
        write!(f, "/{}", self.name)?;
        if let Some(v) = &self.version {
            write!(f, "@{v}")?;
        }
        Ok(())
    }
}

impl Purl {
    /// Ecosystems whose package names are canonicalized to lowercase per the
    /// purl spec.
    fn name_must_be_lowercase(ty: &str) -> bool {
        matches!(
            ty,
            "bioconda" | "composer" | "conda" | "golang" | "maven" | "npm" | "pypi"
        )
    }

    pub fn parse(s: &str) -> Result<Purl> {
        let rest = s
            .strip_prefix("pkg:")
            .with_context(|| format!("purl must start with \"pkg:\": {s}"))?;

        let (rest, subpath) = match rest.split_once('#') {
            Some((a, b)) => (a, Some(b.to_string())),
            None => (rest, None),
        };

        let (rest, qualifiers) = match rest.split_once('?') {
            Some((a, b)) => (a, parse_qualifiers(b)),
            None => (rest, Vec::new()),
        };

        let (path, version) = match rest.rsplit_once('@') {
            Some((a, b)) => (a, Some(b.to_string())),
            None => (rest, None),
        };

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 2 {
            bail!("purl must contain a type and a name: {s}");
        }
        if segments.len() == 2
            && segments[0] != "generic"
            && !segments[0].chars().all(|c| c.is_ascii_alphanumeric())
        {
            bail!("purl type must be alphanumeric: {s}");
        }

        let ty = segments[0].to_ascii_lowercase();
        let mut name = segments[segments.len() - 1].to_string();
        if Self::name_must_be_lowercase(&ty) {
            name = name.to_ascii_lowercase();
        }
        let namespace = if segments.len() > 2 {
            Some(segments[1..segments.len() - 1].join("/"))
        } else {
            None
        };

        Ok(Purl {
            r#type: ty,
            namespace,
            name,
            version,
            qualifiers,
            subpath,
        })
    }

    /// Type + namespace + name equality (the identity used for feed matching).
    pub fn matches(&self, other: &Purl) -> bool {
        self.r#type == other.r#type && self.namespace == other.namespace && self.name == other.name
    }
}

fn parse_qualifiers(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// VEX status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexStatus {
    Affected,
    NotAffected,
    Fixed,
    UnderInvestigation,
}

impl VexStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            VexStatus::Affected => "affected",
            VexStatus::NotAffected => "not_affected",
            VexStatus::Fixed => "fixed",
            VexStatus::UnderInvestigation => "under_investigation",
        }
    }

    pub fn parse(s: &str) -> Option<VexStatus> {
        match s.trim().to_ascii_lowercase().as_str() {
            "affected" | "known_affected" => Some(VexStatus::Affected),
            "not_affected" | "known_not_affected" | "not affected" | "known not affected" => {
                Some(VexStatus::NotAffected)
            }
            "fixed" | "first_fixed" => Some(VexStatus::Fixed),
            "under_investigation" | "in_triage" => Some(VexStatus::UnderInvestigation),
            _ => None,
        }
    }
}

impl fmt::Display for VexStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Vulnerabilities & findings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Vulnerability {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub cvss: Option<String>,
    pub references: Vec<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
}

impl Vulnerability {
    pub fn matches_id(&self, other: &str) -> bool {
        self.id == other || self.aliases.iter().any(|a| a == other)
    }
}

/// A vulnerability matched to a component, with post-VEX triage status.
#[derive(Debug, Clone)]
pub struct Finding {
    pub vuln: Vulnerability,
    pub component: Component,
    pub status: VexStatus,
    /// e.g. `purl+semver-range`, `purl+exact-version`, `name+ecosystem`.
    pub matched_by: String,
    pub justification: Option<String>,
    pub impact: Option<String>,
    pub vex_source: Option<String>,
    /// Next version that fixes the vulnerability (from the feed's `fixed` event).
    pub fixed_in: Option<String>,
}

impl Finding {
    pub fn is_actionable(&self) -> bool {
        matches!(
            self.status,
            VexStatus::Affected | VexStatus::UnderInvestigation
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "vulnerability": {
                "id": self.vuln.id,
                "aliases": self.vuln.aliases,
                "summary": self.vuln.summary,
                "cvss": self.vuln.cvss,
                "references": self.vuln.references,
            },
            "component": {
                "name": self.component.name,
                "version": self.component.version,
                "purl": self.component.purl_raw,
                "cpe": self.component.cpe,
                "bom_ref": self.component.bom_ref,
            },
            "status": self.status.as_str(),
            "justification": self.justification,
            "impact": self.impact,
            "matched_by": self.matched_by,
            "vex_source": self.vex_source,
            "fixed_in": self.fixed_in,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SbomMeta {
    pub path: String,
    pub format: Option<String>,
    pub spec_version: Option<String>,
    pub sha256: Option<String>,
    pub components: usize,
    pub product: Option<Component>,
}

/// The on-disk interchange format between pipeline stages
/// (see `schemas/openenisa/findings/`).
#[derive(Debug, Clone, Default)]
pub struct FindingsDoc {
    pub generator: String,
    pub generated_at: String,
    pub sbom: SbomMeta,
    pub findings: Vec<Finding>,
}

impl FindingsDoc {
    pub fn new(sbom: &Sbom, path: &str, generated_at: &str) -> FindingsDoc {
        FindingsDoc {
            generator: crate::engine(),
            generated_at: generated_at.to_string(),
            sbom: SbomMeta {
                path: path.to_string(),
                format: sbom.format.as_ref().map(|f| f.to_string()),
                spec_version: sbom.spec_version(),
                sha256: Some(sbom.sha256()),
                components: sbom.components.len(),
                product: sbom.product.clone(),
            },
            findings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "document": {
                "generator": self.generator,
                "generated_at": self.generated_at,
                "sbom": {
                    "path": self.sbom.path,
                    "format": self.sbom.format,
                    "spec_version": self.sbom.spec_version,
                    "sha256": self.sbom.sha256,
                    "components": self.sbom.components,
                    "product": self.sbom.product.as_ref().map(product_json),
                },
                "findings": self.findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
            }
        })
    }

    pub fn from_json(value: &Value) -> Result<FindingsDoc> {
        let doc = value
            .get("document")
            .ok_or_else(|| anyhow::anyhow!("missing \"document\" object"))?;
        let sbom = doc.get("sbom").cloned().unwrap_or(Value::Null);
        let mut out = FindingsDoc {
            generator: v_str(doc, "generator").unwrap_or_default(),
            generated_at: v_str(doc, "generated_at").unwrap_or_default(),
            sbom: SbomMeta {
                path: v_str(&sbom, "path").unwrap_or_default(),
                format: v_str(&sbom, "format"),
                spec_version: v_str(&sbom, "spec_version"),
                sha256: v_str(&sbom, "sha256"),
                components: sbom.get("components").and_then(Value::as_u64).unwrap_or(0) as usize,
                product: sbom
                    .get("product")
                    .filter(|p| !p.is_null())
                    .map(|p| Component {
                        bom_ref: None,
                        kind: String::new(),
                        name: v_str(p, "name").unwrap_or_default(),
                        version: v_str(p, "version"),
                        purl: None,
                        purl_raw: v_str(p, "purl"),
                        cpe: v_str(p, "cpe"),
                        supplier: None,
                        licenses: Vec::new(),
                        hashes: Vec::new(),
                        scope: None,
                    }),
            },
            findings: Vec::new(),
        };
        for f in doc
            .get("findings")
            .and_then(Value::as_array)
            .with_context(|| "missing \"findings\" array")?
        {
            out.findings.push(finding_from_json(f)?);
        }
        Ok(out)
    }

    pub fn counts_by_status(&self) -> [(VexStatus, usize); 4] {
        let mut counts = [
            (VexStatus::Affected, 0),
            (VexStatus::NotAffected, 0),
            (VexStatus::Fixed, 0),
            (VexStatus::UnderInvestigation, 0),
        ];
        for f in &self.findings {
            if let Some(entry) = counts.iter_mut().find(|(s, _)| *s == f.status) {
                entry.1 += 1;
            }
        }
        counts
    }
}

fn product_json(c: &Component) -> Value {
    json!({
        "name": c.name,
        "version": c.version,
        "purl": c.purl_raw,
        "cpe": c.cpe,
    })
}

fn finding_from_json(value: &Value) -> Result<Finding> {
    let vuln_v = value
        .get("vulnerability")
        .ok_or_else(|| anyhow::anyhow!("finding missing \"vulnerability\""))?;
    let comp_v = value
        .get("component")
        .ok_or_else(|| anyhow::anyhow!("finding missing \"component\""))?;
    let status = VexStatus::parse(&v_str(value, "status").unwrap_or_default())
        .ok_or_else(|| anyhow::anyhow!("finding has unknown status"))?;

    Ok(Finding {
        vuln: Vulnerability {
            id: v_str(vuln_v, "id").ok_or_else(|| anyhow::anyhow!("vulnerability missing id"))?,
            aliases: v_strs(vuln_v, "aliases"),
            summary: v_str(vuln_v, "summary"),
            details: v_str(vuln_v, "details"),
            cvss: v_str(vuln_v, "cvss"),
            references: v_strs(vuln_v, "references"),
            published: None,
            modified: None,
        },
        component: Component {
            bom_ref: v_str(comp_v, "bom_ref"),
            kind: v_str(comp_v, "kind").unwrap_or_default(),
            name: v_str(comp_v, "name").ok_or_else(|| anyhow::anyhow!("component missing name"))?,
            version: v_str(comp_v, "version"),
            purl: v_str(comp_v, "purl").and_then(|s| Purl::parse(&s).ok()),
            purl_raw: v_str(comp_v, "purl"),
            cpe: v_str(comp_v, "cpe"),
            supplier: None,
            licenses: Vec::new(),
            hashes: Vec::new(),
            scope: None,
        },
        status,
        justification: v_str(value, "justification"),
        impact: v_str(value, "impact"),
        vex_source: v_str(value, "vex_source"),
        fixed_in: v_str(value, "fixed_in"),
        matched_by: v_str(value, "matched_by").unwrap_or_default(),
    })
}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

pub fn v_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

pub fn v_strs(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn json_object(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (k, v) in pairs {
        map.insert(k.to_string(), v);
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_purl() {
        let p = Purl::parse("pkg:generic/openssl@3.0.12?arch=amd64#src").unwrap();
        assert_eq!(p.r#type, "generic");
        assert_eq!(p.name, "openssl");
        assert_eq!(p.version.as_deref(), Some("3.0.12"));
        assert_eq!(
            p.qualifiers,
            vec![("arch".to_string(), "amd64".to_string())]
        );
        assert_eq!(p.subpath.as_deref(), Some("src"));
    }

    #[test]
    fn parses_namespaced_purl() {
        let p = Purl::parse("pkg:npm/@babel/core@7.0.0").unwrap();
        assert_eq!(p.r#type, "npm");
        assert_eq!(p.namespace.as_deref(), Some("@babel"));
        assert_eq!(p.name, "core");
    }

    #[test]
    fn lowercases_npm_names() {
        let a = Purl::parse("pkg:npm/Lodash@4.17.21").unwrap();
        assert_eq!(a.name, "lodash");
    }

    #[test]
    fn rejects_non_purl() {
        assert!(Purl::parse("https://example.com").is_err());
        assert!(Purl::parse("pkg:openssl").is_err());
    }

    #[test]
    fn purl_identity_matching() {
        let a = Purl::parse("pkg:generic/openssl@3.0.12").unwrap();
        let b = Purl::parse("pkg:generic/openssl@3.0.13").unwrap();
        let c = Purl::parse("pkg:generic/zlib@3.0.12").unwrap();
        assert!(a.matches(&b));
        assert!(!a.matches(&c));
    }

    #[test]
    fn vex_status_roundtrip() {
        for s in [
            VexStatus::Affected,
            VexStatus::NotAffected,
            VexStatus::Fixed,
            VexStatus::UnderInvestigation,
        ] {
            assert_eq!(VexStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(
            VexStatus::parse("known_affected"),
            Some(VexStatus::Affected)
        );
        assert_eq!(
            VexStatus::parse("in_triage"),
            Some(VexStatus::UnderInvestigation)
        );
    }
}
