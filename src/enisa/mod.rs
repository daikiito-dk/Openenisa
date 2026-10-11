//! ENISA report envelopes and the CRA Article 14 statutory clock.
//!
//! Since 11 September 2026, manufacturers must report actively exploited
//! vulnerabilities and severe incidents to ENISA and their national CSIRT:
//! early warning within **24 hours**, incident notification within **72
//! hours**, and the final report within **14 days** of becoming aware.
//! The ENISA Single Reporting Platform (SRP) is live at
//! <https://portal.cra-srp.enisa.europa.eu/> as a web portal; its machine
//! API surface has not been published yet.
//!
//! openenisa therefore produces **submission-ready envelopes**: a fully
//! validated CSAF 2.0 document embedded with its evidence (SBOM hash, VEX
//! sources), plus the statutory timeline computed from the moment of
//! awareness. Dispatch is a pluggable transport concern — the CLI ships a
//! dry-run readiness check and a curl template; live API dispatch arrives
//! with the ENISA SRP API.

use crate::model::{FindingsDoc, VexStatus, sha256_hex};
use anyhow::{Result, bail};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{Value, json};

/// The three statutory report types under CRA Article 14.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    EarlyWarning,
    Notification,
    FinalReport,
}

impl ReportType {
    pub fn parse(s: &str) -> Result<ReportType> {
        match s.trim().to_ascii_lowercase().as_str() {
            "early-warning" | "early_warning" | "early" | "earlywarning" => {
                Ok(ReportType::EarlyWarning)
            }
            "notification" | "notify" => Ok(ReportType::Notification),
            "final-report" | "final_report" | "final" => Ok(ReportType::FinalReport),
            _ => bail!(
                "unknown report type \"{s}\" (expected early-warning, notification, or final-report)"
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ReportType::EarlyWarning => "early_warning",
            ReportType::Notification => "notification",
            ReportType::FinalReport => "final_report",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ReportType::EarlyWarning => "Early warning",
            ReportType::Notification => "Notification",
            ReportType::FinalReport => "Final report",
        }
    }

    /// Statutory window in hours: 24 / 72 / 336 (14 days).
    pub fn sla_hours(&self) -> i64 {
        match self {
            ReportType::EarlyWarning => 24,
            ReportType::Notification => 72,
            ReportType::FinalReport => 336,
        }
    }

    pub fn all() -> [ReportType; 3] {
        [
            ReportType::EarlyWarning,
            ReportType::Notification,
            ReportType::FinalReport,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Vulnerability,
    Incident,
}

impl Classification {
    pub fn parse(s: &str) -> Result<Classification> {
        match s.trim().to_ascii_lowercase().as_str() {
            "vulnerability" | "vuln" => Ok(Classification::Vulnerability),
            "incident" => Ok(Classification::Incident),
            _ => bail!("unknown classification \"{s}\" (expected vulnerability or incident)"),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Classification::Vulnerability => "vulnerability",
            Classification::Incident => "incident",
        }
    }
}

/// Statutory deadline for a report type, given the moment of awareness.
pub fn deadline(aware_at: &DateTime<Utc>, report_type: ReportType) -> DateTime<Utc> {
    *aware_at + Duration::hours(report_type.sla_hours())
}

fn rfc3339(now: &DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Options for envelope construction.
pub struct EnisaOptions {
    pub report_type: ReportType,
    pub classification: Classification,
    pub reporter_name: String,
    pub reporter_contact: Option<String>,
    pub national_csirt: Option<String>,
    /// Moment the manufacturer became aware (Article 14 clock start).
    pub aware_at: DateTime<Utc>,
    pub exploited: bool,
    pub now: DateTime<Utc>,
}

/// Build a submission-ready ENISA envelope around an embedded CSAF document.
pub fn build_envelope(opts: &EnisaOptions, doc: &FindingsDoc, csaf: &Value) -> Result<Value> {
    let actionable: Vec<&crate::model::Finding> = doc
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.status,
                VexStatus::Affected | VexStatus::UnderInvestigation
            )
        })
        .collect();
    if actionable.is_empty() {
        bail!(
            "nothing actionable to report: every finding is suppressed by VEX (not_affected / fixed)"
        );
    }

    let vulnerabilities: Vec<Value> = actionable
        .iter()
        .map(|f| {
            json!({
                "id": f.vuln.id,
                "status": f.status.as_str(),
                "actively_exploited": opts.exploited && f.status == VexStatus::Affected,
                "details": f.vuln.summary.clone().or_else(|| f.vuln.details.clone()),
            })
        })
        .collect();

    let mut vex_sources: Vec<String> = Vec::new();
    for finding in &actionable {
        if let Some(source) = &finding.vex_source {
            if !vex_sources.contains(source) {
                vex_sources.push(source.clone());
            }
        }
    }

    let product = doc.sbom.product.as_ref();
    let due_at = deadline(&opts.aware_at, opts.report_type);

    let mut vuln_ids: Vec<&str> = actionable.iter().map(|f| f.vuln.id.as_str()).collect();
    vuln_ids.sort_unstable();
    vuln_ids.dedup();
    let report_id = format!(
        "urn:openenisa:report:{}",
        &sha256_hex(
            format!(
                "{}|{}|{}|{}",
                opts.report_type.as_str(),
                rfc3339(&opts.aware_at),
                product.map(|p| p.display_name()).unwrap_or_default(),
                vuln_ids.join(",")
            )
            .as_bytes(),
        )[..16]
    );

    Ok(json!({
        "enisa_envelope": {
            "schema": crate::schemas::ENISA_ENVELOPE_V0_1_ID,
            "report": {
                "type": opts.report_type.as_str(),
                "classification": opts.classification.as_str(),
                "reporter": {
                    "name": opts.reporter_name,
                    "contact": opts.reporter_contact,
                    "national_csirt": opts.national_csirt,
                },
                "product": {
                    "name": product.map(|p| p.name.clone()),
                    "version": product.and_then(|p| p.version.clone()),
                    "vendor": opts.reporter_name,
                },
                "timeline": {
                    "aware_at": rfc3339(&opts.aware_at),
                    "due_at": rfc3339(&due_at),
                    "sla_hours": opts.report_type.sla_hours(),
                },
                "vulnerabilities": vulnerabilities,
                "evidence": {
                    "sbom": {
                        "path": doc.sbom.path,
                        "format": doc.sbom.format,
                        "sha256": doc.sbom.sha256,
                    },
                    "vex_sources": vex_sources,
                },
                "csaf": csaf,
            },
            "meta": {
                "generator": crate::engine(),
                "generated_at": rfc3339(&opts.now),
                "report_id": report_id,
                "openenisa_version": crate::VERSION,
                "notes": [
                    "This envelope is a validated, submission-ready payload bundle for CRA Article 14 reporting.",
                    "Dispatch it through your ENISA Single Reporting Platform submission channel; openenisa performs offline validation, evidence binding and timeline tracking."
                ],
            },
        }
    }))
}

/// Timeline verdict for a report deadline relative to `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineVerdict {
    OnTrack(Duration),
    /// Less than two hours remain.
    Critical(Duration),
    Overdue(Duration),
}

impl TimelineVerdict {
    pub fn evaluate(due_at: &DateTime<Utc>, now: DateTime<Utc>) -> TimelineVerdict {
        let remaining = *due_at - now;
        if remaining <= Duration::zero() {
            TimelineVerdict::Overdue(-remaining)
        } else if remaining < Duration::hours(2) {
            TimelineVerdict::Critical(remaining)
        } else {
            TimelineVerdict::OnTrack(remaining)
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            TimelineVerdict::OnTrack(_) => "ON TRACK",
            TimelineVerdict::Critical(_) => "CRITICAL",
            TimelineVerdict::Overdue(_) => "OVERDUE",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            TimelineVerdict::OnTrack(d) | TimelineVerdict::Critical(d) => {
                format!("{} remaining", humanize(*d))
            }
            TimelineVerdict::Overdue(d) => format!("{} overdue", humanize(*d)),
        }
    }
}

/// Readiness of an envelope for dispatch.
pub struct Readiness {
    pub envelope_valid: bool,
    pub csaf_valid: bool,
    pub problems: Vec<String>,
    pub timeline: Option<TimelineVerdict>,
    pub report_type: Option<ReportType>,
    pub due_at: Option<String>,
}

impl Readiness {
    pub fn ready(&self) -> bool {
        self.envelope_valid
            && self.csaf_valid
            && !matches!(self.timeline, Some(TimelineVerdict::Overdue(_)))
    }
}

/// Dry-run readiness check: schema validation of the envelope, of the
/// embedded CSAF, and the statutory timeline.
pub fn check_envelope(envelope: &Value, now: DateTime<Utc>) -> Readiness {
    let envelope_result = crate::csaf::validate::validate_envelope(envelope);
    let csaf = envelope.pointer("/enisa_envelope/report/csaf");
    let csaf_result = csaf.map(crate::csaf::validate::validate_csaf);

    let report_type = envelope
        .pointer("/enisa_envelope/report/type")
        .and_then(Value::as_str)
        .and_then(|t| ReportType::parse(t).ok());
    let due_at = envelope
        .pointer("/enisa_envelope/report/timeline/due_at")
        .and_then(Value::as_str)
        .map(str::to_string);

    let timeline = due_at
        .as_deref()
        .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
        .map(|d| TimelineVerdict::evaluate(&d.with_timezone(&Utc), now));

    let mut problems = envelope_result.problems();
    if let Some(csaf_result) = &csaf_result {
        problems.extend(csaf_result.problems());
    }

    Readiness {
        envelope_valid: envelope_result.valid,
        csaf_valid: csaf_result.map(|r| r.valid).unwrap_or(false),
        problems,
        timeline,
        report_type,
        due_at,
    }
}

/// A curl template for the (upcoming) SRP API transport.
pub fn curl_command(endpoint: &str, envelope_path: &str) -> String {
    format!(
        r#"curl --request POST "{endpoint}" \
  --header 'Content-Type: application/json' \
  --cert /path/to/client.crt \
  --key /path/to/client.key \
  --tlsv1.3 \
  --data-binary @{envelope_path}"#
    )
}

fn humanize(duration: Duration) -> String {
    let seconds = duration.num_seconds().max(0);
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let secs = seconds % 60;
    if days > 0 {
        format!("{days}d {hours:02}h {minutes:02}m")
    } else if hours > 0 {
        format!("{hours}h {minutes:02}m {secs:02}s")
    } else {
        format!("{minutes}m {secs:02}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csaf::{CsafConfig, build_document};
    use crate::model::{Component, Vulnerability};

    fn triaged_doc() -> FindingsDoc {
        let finding = crate::model::Finding {
            vuln: Vulnerability {
                id: "CVE-2023-48795".into(),
                summary: Some("Terrapin attack".into()),
                ..Vulnerability::default()
            },
            component: Component {
                name: "libssh2".into(),
                version: Some("1.11.0".into()),
                ..Component::default()
            },
            status: VexStatus::Affected,
            matched_by: "purl".into(),
            justification: None,
            impact: None,
            vex_source: None,
            fixed_in: Some("1.11.1".into()),
        };
        FindingsDoc {
            generator: crate::engine(),
            generated_at: "2026-10-10T00:00:00Z".into(),
            sbom: crate::model::SbomMeta {
                path: "sbom.json".into(),
                format: Some("CycloneDX 1.5 (JSON)".into()),
                spec_version: Some("1.5".into()),
                sha256: Some("ab".into()),
                components: 4,
                product: Some(Component {
                    name: "MX-2400 Server Firmware".into(),
                    version: Some("2.4.1".into()),
                    ..Component::default()
                }),
            },
            findings: vec![finding],
        }
    }

    #[test]
    fn deadlines_match_the_statute() {
        let aware = DateTime::parse_from_rfc3339("2026-10-10T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            rfc3339(&deadline(&aware, ReportType::EarlyWarning)),
            "2026-10-11T09:00:00Z"
        );
        assert_eq!(
            rfc3339(&deadline(&aware, ReportType::Notification)),
            "2026-10-13T09:00:00Z"
        );
        assert_eq!(
            rfc3339(&deadline(&aware, ReportType::FinalReport)),
            "2026-10-24T09:00:00Z"
        );
    }

    #[test]
    fn envelope_is_schema_valid_and_ready() {
        let doc = triaged_doc();
        let csaf = build_document(
            &CsafConfig {
                publisher_name: "Meridian Systems".into(),
                publisher_namespace: "https://meridian.example".into(),
                ..CsafConfig::default()
            },
            &doc,
        )
        .unwrap();

        let now = Utc::now();
        let opts = EnisaOptions {
            report_type: ReportType::EarlyWarning,
            classification: Classification::Vulnerability,
            reporter_name: "Meridian Systems".into(),
            reporter_contact: Some("psirt@meridian.example".into()),
            national_csirt: Some("CERT-EU".into()),
            aware_at: now,
            exploited: true,
            now,
        };
        let envelope = build_envelope(&opts, &doc, &csaf).unwrap();

        let envelope_result = crate::csaf::validate::validate_envelope(&envelope);
        assert!(envelope_result.valid, "{:?}", envelope_result.problems());

        let readiness = check_envelope(&envelope, now);
        assert!(readiness.ready(), "{:?}", readiness.problems);
        assert!(matches!(
            readiness.timeline,
            Some(TimelineVerdict::OnTrack(_))
        ));
    }

    #[test]
    fn overdue_timeline_detected() {
        let aware = DateTime::parse_from_rfc3339("2026-10-09T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let due = deadline(&aware, ReportType::EarlyWarning);
        let now = DateTime::parse_from_rfc3339("2026-10-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(matches!(
            TimelineVerdict::evaluate(&due, now),
            TimelineVerdict::Overdue(_)
        ));
    }

    #[test]
    fn empty_report_rejected() {
        let mut doc = triaged_doc();
        doc.findings[0].status = VexStatus::NotAffected;
        let opts = EnisaOptions {
            report_type: ReportType::EarlyWarning,
            classification: Classification::Vulnerability,
            reporter_name: "x".into(),
            reporter_contact: None,
            national_csirt: None,
            aware_at: Utc::now(),
            exploited: false,
            now: Utc::now(),
        };
        assert!(build_envelope(&opts, &doc, &serde_json::json!({})).is_err());
    }
}
