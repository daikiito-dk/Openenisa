//! Command-line interface.
//!
//! Pipeline stages compose: `parse` → `match` → `triage` → `csaf` →
//! `enisa report` → `enisa submit` (dry-run). `pipeline` runs the whole
//! chain in one command for CI. Exit codes: `0` success, `1` error,
//! `2` findings breached the `--fail-on` threshold.

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::csaf::CsafConfig;
use crate::enisa::{ReportType, TimelineVerdict};
use crate::feed::Feed;
use crate::model::{FindingsDoc, VexStatus};
use crate::vex::VexDoc;
use crate::{csaf, enisa, feed, ingest, report, vex};

const LONG_ABOUT: &str = r#"
The open-source CSAF 2.0 & ENISA reporting engine for DevOps.

Parse an SBOM, match it against OSV vulnerability feeds, correlate VEX
statements to eliminate false positives, generate a schema-valid CSAF 2.0
document, and track the CRA Article 14 statutory clock (24h / 72h / 14d)
— fully offline, deterministic, CI-native.
"#;

#[derive(Parser)]
#[command(
    name = "openenisa",
    version = crate::VERSION,
    about = "The open-source CSAF 2.0 & ENISA reporting engine for DevOps",
    long_about = LONG_ABOUT,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// Exit 2 when any finding has status `affected` after VEX triage.
    Affected,
    /// Exit 2 when any finding exists at all.
    Any,
}

/// Shared document-construction options (`csaf`, `enisa report`, `pipeline`).
#[derive(clap::Args)]
pub struct CsafArgs {
    /// Publisher (vendor) name, written to document/publisher/name.
    #[arg(long = "vendor-name", required = true)]
    vendor_name: String,
    /// Publisher namespace URL, written to document/publisher/namespace.
    #[arg(long = "vendor-namespace", required = true)]
    vendor_namespace: String,
    /// Publisher category (vendor|coordinator|discoverer|other|translator|user).
    #[arg(long = "vendor-category", default_value = "vendor")]
    vendor_category: String,
    /// CSAF document category, e.g. csaf_vex or csaf_security_advisory.
    #[arg(long, default_value = "csaf_vex")]
    category: String,
    /// Tracking ID; derived deterministically from content when omitted.
    #[arg(long = "tracking-id")]
    tracking_id: Option<String>,
    /// Document title.
    #[arg(long)]
    title: Option<String>,
    /// Document language tag.
    #[arg(long, default_value = "en")]
    lang: String,
    /// TLP label: WHITE, GREEN, AMBER or RED.
    #[arg(long)]
    tlp: Option<String>,
    /// Tracking status: draft, final or interim.
    #[arg(long, default_value = "final")]
    status: String,
    /// Mark vulnerabilities as actively exploited (adds exploit_status threats).
    #[arg(long)]
    exploited: bool,
    /// Pin all timestamps to this RFC 3339 moment for reproducible output.
    #[arg(long)]
    at: Option<String>,
}

impl CsafArgs {
    fn config(&self) -> Result<CsafConfig> {
        Ok(CsafConfig {
            category: self.category.clone(),
            title: self.title.clone(),
            lang: self.lang.clone(),
            publisher_category: self.vendor_category.clone(),
            publisher_name: self.vendor_name.clone(),
            publisher_namespace: self.vendor_namespace.clone(),
            tracking_id: self.tracking_id.clone(),
            tlp: self.tlp.clone().map(|t| t.to_ascii_uppercase()),
            status: self.status.clone(),
            exploited: self.exploited,
            now: now_or(self.at.as_deref())?,
        })
    }
}

#[derive(Subcommand)]
enum Command {
    /// Parse an SBOM, auto-detect its format, print the normalized inventory.
    Parse {
        /// SBOM file (CycloneDX 1.4/1.5/1.6 JSON+XML, SPDX 2.3 JSON+XML, SPDX 3.0).
        sbom: PathBuf,
        #[arg(long)]
        json: bool,
    },

    /// Match SBOM components against OSV-format vulnerability feeds.
    Match {
        sbom: PathBuf,
        /// OSV feed (.jsonl one-record-per-line, or .json record/array/bundle). Repeatable.
        #[arg(long = "feed", required = true)]
        feeds: Vec<PathBuf>,
        /// Write the findings JSON document here.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Exit 2 when findings breach the threshold.
        #[arg(long = "fail-on", value_enum)]
        fail_on: Option<FailOn>,
    },

    /// Apply VEX statements (OpenVEX, CSAF VEX, CycloneDX embedded) to findings.
    Triage {
        /// Findings JSON from `openenisa match`.
        findings: PathBuf,
        /// VEX document. Repeatable; format auto-detected.
        #[arg(long = "vex")]
        vex: Vec<PathBuf>,
        /// SBOM with embedded CycloneDX VEX (vulnerabilities[].analysis).
        #[arg(long)]
        sbom: Option<PathBuf>,
        /// Write the triaged findings JSON here (in-place when omitted).
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long = "fail-on", value_enum)]
        fail_on: Option<FailOn>,
    },

    /// Generate a CSAF 2.0 document from triaged findings.
    Csaf {
        /// Triaged findings JSON from `openenisa triage`.
        findings: PathBuf,
        #[command(flatten)]
        csaf_args: CsafArgs,
        /// Output path (default: csaf.json).
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },

    /// Validate a CSAF 2.0, ENISA envelope, findings document or SBOM offline.
    Validate {
        doc: PathBuf,
        #[arg(long)]
        json: bool,
    },

    /// ENISA submission tooling (CRA Article 14 clock).
    Enisa {
        #[command(subcommand)]
        command: EnisaCommand,
    },

    /// Full chain: SBOM -> match -> VEX triage -> CSAF 2.0 -> ENISA envelope.
    Pipeline {
        #[arg(long)]
        sbom: PathBuf,
        #[arg(long = "feed", required = true)]
        feeds: Vec<PathBuf>,
        #[arg(long = "vex")]
        vex: Vec<PathBuf>,
        /// Output directory (default: openenisa-out).
        #[arg(long = "out-dir", default_value = "openenisa-out")]
        out_dir: PathBuf,
        /// Moment of awareness (RFC 3339 or "now"); starts the statutory clock.
        #[arg(long = "aware-at")]
        aware_at: Option<String>,
        #[command(flatten)]
        csaf_args: CsafArgs,
        #[arg(long = "fail-on", value_enum)]
        fail_on: Option<FailOn>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // clap-generated variants; size spread is fine here
enum EnisaCommand {
    /// Print the 24h / 72h / 14-day statutory deadlines for an event.
    Deadlines {
        /// Moment of awareness (RFC 3339 or "now").
        #[arg(long = "aware-at", required = true)]
        aware_at: String,
        /// Reference "now" for remaining-time computation (default: actual now).
        #[arg(long)]
        now: Option<String>,
        #[arg(long)]
        json: bool,
    },

    /// Build a submission-ready ENISA report envelope around a CSAF document.
    Report {
        /// Triaged findings JSON.
        findings: PathBuf,
        /// Report type: early-warning (24h), notification (72h), final-report (14d).
        #[arg(long = "type", default_value = "early-warning")]
        report_type: String,
        /// Vulnerability or incident.
        #[arg(long, default_value = "vulnerability")]
        classification: String,
        /// Moment of awareness (RFC 3339 or "now"); defaults to --at / now.
        #[arg(long = "aware-at")]
        aware_at: Option<String>,
        /// Reporter name (defaults to --vendor-name).
        #[arg(long = "reporter-name")]
        reporter_name: Option<String>,
        /// Reporter contact (email / phone).
        #[arg(long)]
        contact: Option<String>,
        /// Designated national CSIRT.
        #[arg(long = "csirt")]
        national_csirt: Option<String>,
        /// Output path (default: enisa-<type>.json).
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        csaf_args: CsafArgs,
        #[arg(long)]
        json: bool,
        #[arg(long = "fail-on", value_enum)]
        fail_on: Option<FailOn>,
    },

    /// Dry-run readiness check of an envelope before dispatch.
    Submit {
        /// ENISA envelope JSON.
        envelope: PathBuf,
        /// Reference "now" for the timeline (default: actual now).
        #[arg(long)]
        now: Option<String>,
        /// Print a curl template for the future SRP API transport.
        #[arg(long = "print-curl")]
        print_curl: bool,
        /// SRP API endpoint URL for the curl template.
        #[arg(
            long = "endpoint",
            default_value = "https://portal.cra-srp.enisa.europa.eu/<reports-endpoint>"
        )]
        endpoint: String,
        #[arg(long)]
        json: bool,
    },
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("openenisa: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Parse { sbom, json } => {
            cmd_parse(&sbom, json)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Match {
            sbom,
            feeds,
            out,
            json,
            fail_on,
        } => cmd_match(&sbom, &feeds, out.as_deref(), json, fail_on),
        Command::Triage {
            findings,
            vex,
            sbom,
            out,
            json,
            fail_on,
        } => cmd_triage(
            &findings,
            &vex,
            sbom.as_deref(),
            out.as_deref(),
            json,
            fail_on,
        ),
        Command::Csaf {
            findings,
            csaf_args,
            out,
            json,
        } => cmd_csaf(&findings, &csaf_args, out.as_deref(), json),
        Command::Validate { doc, json } => cmd_validate(&doc, json),
        Command::Enisa { command } => match command {
            EnisaCommand::Deadlines {
                aware_at,
                now,
                json,
            } => cmd_enisa_deadlines(&aware_at, now.as_deref(), json),
            EnisaCommand::Report {
                findings,
                report_type,
                classification,
                aware_at,
                reporter_name,
                contact,
                national_csirt,
                out,
                csaf_args,
                json,
                fail_on,
            } => cmd_enisa_report(
                &findings,
                &report_type,
                &classification,
                aware_at.as_deref(),
                reporter_name.as_deref(),
                contact.as_deref(),
                national_csirt.as_deref(),
                out.as_deref(),
                &csaf_args,
                json,
                fail_on,
            ),
            EnisaCommand::Submit {
                envelope,
                now,
                print_curl,
                endpoint,
                json,
            } => cmd_enisa_submit(&envelope, now.as_deref(), print_curl, &endpoint, json),
        },
        Command::Pipeline {
            sbom,
            feeds,
            vex,
            out_dir,
            aware_at,
            csaf_args,
            fail_on,
        } => cmd_pipeline(
            &sbom,
            &feeds,
            &vex,
            &out_dir,
            aware_at.as_deref(),
            &csaf_args,
            fail_on,
        ),
    }
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

fn rfc3339(now: &DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn now_or(at: Option<&str>) -> Result<DateTime<Utc>> {
    match at {
        None | Some("now") => Ok(Utc::now()),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| anyhow::anyhow!("invalid timestamp {s:?}: {e}")),
    }
}

fn read_json(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let text = serde_json::to_string_pretty(value)?;
    std::fs::write(path, text + "\n")
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn load_findings(path: &Path) -> Result<FindingsDoc> {
    let value = read_json(path)?;
    FindingsDoc::from_json(&value)
        .with_context(|| format!("invalid findings document: {}", path.display()))
}

fn findings_rows(doc: &FindingsDoc) -> Vec<Vec<String>> {
    doc.findings
        .iter()
        .map(|f| {
            vec![
                format!(
                    "{} {}",
                    f.status,
                    if f.is_actionable() {
                        "(ACTIVE)"
                    } else {
                        "(suppressed)"
                    }
                ),
                f.vuln.id.clone(),
                report::truncate(&f.component.display_name(), 40),
                f.matched_by.clone(),
                f.fixed_in.clone().unwrap_or_else(|| "-".into()),
                f.vex_source.clone().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect()
}

const FINDINGS_HEADERS: [&str; 6] = [
    "STATUS",
    "VULNERABILITY",
    "COMPONENT",
    "MATCHED BY",
    "FIXED IN",
    "VEX SOURCE",
];

fn print_findings(doc: &FindingsDoc) {
    let counts = doc.counts_by_status();
    report::kv(
        &counts
            .iter()
            .map(|(status, n)| (status.as_str().to_string(), n.to_string()))
            .collect::<Vec<_>>(),
    );
    println!();
    report::table(&FINDINGS_HEADERS, &findings_rows(doc));
}

fn fail_on_exit(fail_on: Option<FailOn>, doc: &FindingsDoc) -> ExitCode {
    let breached = match fail_on {
        None => false,
        Some(FailOn::Any) => !doc.findings.is_empty(),
        Some(FailOn::Affected) => doc.findings.iter().any(|f| f.status == VexStatus::Affected),
    };
    if breached {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

fn cmd_parse(path: &Path, json: bool) -> Result<()> {
    let sbom = ingest::parse_path(path)?;

    if json {
        let value = json!({
            "path": path.display().to_string(),
            "format": sbom.format.as_ref().map(|f| f.to_string()),
            "serial": sbom.serial,
            "sha256": sbom.sha256(),
            "components": sbom.components.len(),
            "product": sbom.product.as_ref().map(|p| json!({
                "name": p.name, "version": p.version, "purl": p.purl_raw, "cpe": p.cpe,
            })),
            "items": sbom.all_components().iter().map(|c| json!({
                "name": c.name,
                "version": c.version,
                "type": c.kind,
                "purl": c.purl_raw,
                "cpe": c.cpe,
                "licenses": c.licenses,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    println!("SBOM: {}", path.display());
    report::kv(&[
        (
            "Format".to_string(),
            sbom.format
                .as_ref()
                .map(|f| f.to_string())
                .unwrap_or_else(|| "unknown".into()),
        ),
        (
            "Serial".to_string(),
            sbom.serial.clone().unwrap_or_else(|| "-".into()),
        ),
        ("Components".to_string(), sbom.components.len().to_string()),
        (
            "Product".to_string(),
            sbom.product
                .as_ref()
                .map(|p| p.display_name())
                .unwrap_or_else(|| "-".into()),
        ),
        ("SHA-256".to_string(), sbom.sha256()),
    ]);
    println!();

    let rows: Vec<Vec<String>> = sbom
        .all_components()
        .iter()
        .map(|c| {
            vec![
                c.name.clone(),
                c.version.clone().unwrap_or_else(|| "-".into()),
                c.kind.clone(),
                c.purl_raw
                    .clone()
                    .unwrap_or_else(|| c.cpe.clone().unwrap_or_else(|| "-".into())),
                c.licenses.first().cloned().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    report::table(
        &["COMPONENT", "VERSION", "TYPE", "PURL / CPE", "LICENSE"],
        &rows,
    );
    Ok(())
}

fn cmd_match(
    sbom_path: &Path,
    feeds: &[PathBuf],
    out: Option<&Path>,
    json: bool,
    fail_on: Option<FailOn>,
) -> Result<ExitCode> {
    let sbom = ingest::parse_path(sbom_path)?;
    let mut loaded = Vec::new();
    for path in feeds {
        loaded.push(Feed::load(path)?);
    }
    let records: usize = loaded.iter().map(|f| f.records.len()).sum();

    let findings = feed::match_sbom(&sbom, &loaded);
    let now = Utc::now();
    let mut doc = FindingsDoc::new(&sbom, &sbom_path.display().to_string(), &rfc3339(&now));
    doc.findings = findings;

    if json {
        println!("{}", serde_json::to_string_pretty(&doc.to_json())?);
    } else {
        println!(
            "Matched {} component(s) against {} record(s) from {} feed(s).",
            sbom.all_components().len(),
            records,
            loaded.len()
        );
        println!();
        print_findings(&doc);
    }

    if let Some(out) = out {
        write_json(out, &doc.to_json())?;
        if !json {
            eprintln!("wrote {}", out.display());
        }
    }

    Ok(fail_on_exit(fail_on, &doc))
}

fn cmd_triage(
    findings_path: &Path,
    vex_paths: &[PathBuf],
    sbom_path: Option<&Path>,
    out: Option<&Path>,
    json: bool,
    fail_on: Option<FailOn>,
) -> Result<ExitCode> {
    let mut doc = load_findings(findings_path)?;

    let mut vexes: Vec<VexDoc> = Vec::new();
    for path in vex_paths {
        vexes.push(vex::load(path)?);
    }
    if let Some(sbom_path) = sbom_path {
        let sbom = ingest::parse_path(sbom_path)?;
        if let Some(
            crate::model::SbomFormat::CycloneDxJson(_) | crate::model::SbomFormat::CycloneDxXml(_),
        ) = sbom.format
        {
            let source = format!("embedded:{}", sbom_path.display());
            let statements = vex::cyclonedx_vex::parse(&sbom, &source);
            if statements.is_empty() {
                eprintln!(
                    "note: {} has no embedded VEX statements",
                    sbom_path.display()
                );
            }
            vexes.push(VexDoc { source, statements });
        } else {
            eprintln!(
                "note: embedded VEX applies to CycloneDX SBOMs only; ignoring {}",
                sbom_path.display()
            );
        }
    }

    let stats = vex::apply(&mut doc.findings, &vexes);

    if json {
        println!("{}", serde_json::to_string_pretty(&doc.to_json())?);
    } else {
        println!(
            "Applied {} VEX statement(s) from {} document(s): {} applied, {} unmatched.",
            stats.statements,
            vexes.len(),
            stats.applied,
            stats.unmatched
        );
        for transition in &stats.transitions {
            println!("  {transition}");
        }
        println!();
        print_findings(&doc);
    }

    let target = out.unwrap_or(findings_path);
    write_json(target, &doc.to_json())?;
    if !json {
        eprintln!("wrote {}", target.display());
    }

    Ok(fail_on_exit(fail_on, &doc))
}

fn cmd_csaf(
    findings_path: &Path,
    args: &CsafArgs,
    out: Option<&Path>,
    json: bool,
) -> Result<ExitCode> {
    let doc = load_findings(findings_path)?;
    let cfg = args.config()?;
    let value = csaf::build_document(&cfg, &doc)?;
    let validation = csaf::validate::validate_csaf(&value);

    let out = out.unwrap_or(Path::new("csaf.json"));
    write_json(out, &value)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        eprintln!("wrote {}", out.display());
    } else {
        println!(
            "CSAF document: {}",
            value
                .pointer("/document/tracking/id")
                .and_then(Value::as_str)
                .unwrap_or("(no tracking id)")
        );
        report::kv(&[
            (
                "Title".into(),
                value["document"]["title"].as_str().unwrap_or("-").into(),
            ),
            ("Category".into(), cfg.category.clone()),
            ("Findings".into(), doc.findings.len().to_string()),
            ("Output".into(), out.display().to_string()),
        ]);
        println!();
        print_validation(&validation);
    }

    if validation.valid {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn print_validation(validation: &csaf::validate::ValidationResult) {
    let rows: Vec<Vec<String>> = validation
        .checks
        .iter()
        .map(|c| {
            vec![
                c.status.as_str().to_string(),
                c.name.clone(),
                report::truncate(&c.detail, 60),
            ]
        })
        .collect();
    report::table(&["RESULT", "CHECK", "DETAIL"], &rows);

    if validation.valid {
        println!(
            "\nVALID: {} document conforms to the embedded schema and conformance checks.",
            validation.kind
        );
    } else {
        println!("\nINVALID: {} document failed validation:", validation.kind);
        for problem in validation.problems() {
            println!("  - {problem}");
        }
    }
}

fn cmd_validate(path: &Path, json: bool) -> Result<ExitCode> {
    let value = read_json(path)?;

    let mut results: Vec<csaf::validate::ValidationResult> = Vec::new();
    if value.get("enisa_envelope").is_some() {
        results.push(csaf::validate::validate_envelope(&value));
        if let Some(csaf_doc) = value.pointer("/enisa_envelope/report/csaf") {
            results.push(csaf::validate::validate_csaf(csaf_doc));
        }
    } else if value.pointer("/document/csaf_version").is_some() {
        results.push(csaf::validate::validate_csaf(&value));
    } else if value.pointer("/document/findings").is_some() {
        results.push(csaf::validate::validate_findings(&value));
    } else {
        // Structural SBOM check: parse it.
        let bytes = std::fs::read(path)?;
        match ingest::parse_bytes(&bytes) {
            Ok(sbom) => {
                if json {
                    let summary = json!({
                        "kind": format!("{}", sbom.format.as_ref().map(|f| f.to_string()).unwrap_or_default()),
                        "valid": true,
                        "components": sbom.components.len(),
                    });
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                } else {
                    println!(
                        "{} is a structurally valid {} SBOM with {} component(s).",
                        path.display(),
                        sbom.format
                            .as_ref()
                            .map(|f| f.to_string())
                            .unwrap_or_default(),
                        sbom.components.len()
                    );
                }
                return Ok(ExitCode::SUCCESS);
            }
            Err(e) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &json!({"valid": false, "errors": [format!("{e:#}")]})
                        )?
                    );
                } else {
                    println!("SBOM structural check FAILED for {}: {e:#}", path.display());
                }
                return Ok(ExitCode::FAILURE);
            }
        }
    }

    let valid = results.iter().all(|r| r.valid);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "valid": valid,
                "results": results.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
            }))?
        );
    } else {
        for result in &results {
            print_validation(result);
        }
    }

    if valid {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn cmd_enisa_deadlines(aware_at: &str, now: Option<&str>, json: bool) -> Result<ExitCode> {
    let aware = now_or(Some(aware_at))?;
    let now = now_or(now)?;

    let rows: Vec<(ReportType, DateTime<Utc>, TimelineVerdict)> = ReportType::all()
        .into_iter()
        .map(|t| {
            (
                t,
                enisa::deadline(&aware, t),
                TimelineVerdict::evaluate(&enisa::deadline(&aware, t), now),
            )
        })
        .collect();

    if json {
        let value = json!({
            "aware_at": rfc3339(&aware),
            "now": rfc3339(&now),
            "deadlines": rows.iter().map(|(t, due, verdict)| json!({
                "type": t.as_str(),
                "sla_hours": t.sla_hours(),
                "due_at": rfc3339(due),
                "status": verdict.label(),
                "remaining_seconds": (due.timestamp() - now.timestamp()).to_string(),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(ExitCode::SUCCESS);
    }

    println!(
        "Statutory clock (CRA Article 14) — aware at {}",
        rfc3339(&aware)
    );
    println!();
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|(t, due, verdict)| {
            vec![
                format!("{} ({}h)", t.label(), t.sla_hours()),
                rfc3339(due),
                verdict.label().to_string(),
                verdict.detail(),
            ]
        })
        .collect();
    report::table(&["REPORT", "DUE AT (UTC)", "STATUS", "TIME"], &table_rows);
    Ok(ExitCode::SUCCESS)
}

// The CLI dispatcher mirrors the clap subcommand fields 1:1; grouping them
// into a struct would hide the command surface rather than simplify it.
#[allow(clippy::too_many_arguments)]
fn cmd_enisa_report(
    findings_path: &Path,
    report_type: &str,
    classification: &str,
    aware_at: Option<&str>,
    reporter_name: Option<&str>,
    contact: Option<&str>,
    national_csirt: Option<&str>,
    out: Option<&Path>,
    args: &CsafArgs,
    json: bool,
    fail_on: Option<FailOn>,
) -> Result<ExitCode> {
    let doc = load_findings(findings_path)?;
    let report_type = ReportType::parse(report_type)?;
    let classification = enisa::Classification::parse(classification)?;
    let now = now_or(args.at.as_deref())?;
    let aware_at = match aware_at {
        Some(s) => now_or(Some(s))?,
        None => now,
    };

    let csaf_value = csaf::build_document(&args.config()?, &doc)?;
    let csaf_validation = csaf::validate::validate_csaf(&csaf_value);
    if !csaf_validation.valid {
        eprintln!("embedded CSAF document failed validation:");
        for problem in csaf_validation.problems() {
            eprintln!("  - {problem}");
        }
        return Err(anyhow::anyhow!(
            "cannot build an envelope around an invalid CSAF document"
        ));
    }

    let opts = enisa::EnisaOptions {
        report_type,
        classification,
        reporter_name: reporter_name.unwrap_or(&args.vendor_name).to_string(),
        reporter_contact: contact.map(str::to_string),
        national_csirt: national_csirt.map(str::to_string),
        aware_at,
        exploited: args.exploited,
        now,
    };
    let envelope = enisa::build_envelope(&opts, &doc, &csaf_value)?;
    let validation = csaf::validate::validate_envelope(&envelope);

    let out_path = out.map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(format!(
            "enisa-{}.json",
            report_type.as_str().replace('_', "-")
        ))
    });
    write_json(&out_path, &envelope)?;

    let due_at = envelope
        .pointer("/enisa_envelope/report/timeline/due_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let verdict = TimelineVerdict::evaluate(
        &DateTime::parse_from_rfc3339(due_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or(now),
        now,
    );

    if json {
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        eprintln!("wrote {}", out_path.display());
    } else {
        println!(
            "ENISA {} envelope ({})",
            report_type.label(),
            classification.as_str()
        );
        report::kv(&[
            (
                "Report ID".into(),
                envelope
                    .pointer("/enisa_envelope/meta/report_id")
                    .and_then(Value::as_str)
                    .unwrap_or("-")
                    .into(),
            ),
            ("Aware at".into(), rfc3339(&aware_at)),
            ("Due at".into(), due_at.to_string()),
            (
                "Timeline".into(),
                format!("{} — {}", verdict.label(), verdict.detail()),
            ),
            (
                "Vulnerabilities".into(),
                envelope
                    .pointer("/enisa_envelope/report/vulnerabilities")
                    .and_then(Value::as_array)
                    .map(|a| a.len().to_string())
                    .unwrap_or_else(|| "0".into()),
            ),
            ("Envelope valid".into(), validation.valid.to_string()),
            ("Output".into(), out_path.display().to_string()),
        ]);
    }

    if !validation.valid {
        for problem in validation.problems() {
            eprintln!("  - {problem}");
        }
        return Ok(ExitCode::FAILURE);
    }

    Ok(fail_on_exit(fail_on, &doc))
}

fn cmd_enisa_submit(
    envelope_path: &Path,
    now: Option<&str>,
    print_curl: bool,
    endpoint: &str,
    json: bool,
) -> Result<ExitCode> {
    let envelope = read_json(envelope_path)?;
    let now = now_or(now)?;
    let readiness = enisa::check_envelope(&envelope, now);

    if print_curl {
        println!(
            "{}",
            enisa::curl_command(endpoint, &envelope_path.display().to_string())
        );
        println!();
    }

    if json {
        let value = json!({
            "ready": readiness.ready(),
            "envelope_valid": readiness.envelope_valid,
            "csaf_valid": readiness.csaf_valid,
            "report_type": readiness.report_type.map(|t| t.as_str()),
            "due_at": readiness.due_at,
            "timeline": readiness.timeline.map(|t| json!({
                "status": t.label(),
                "detail": t.detail(),
            })),
            "problems": readiness.problems,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return if readiness.ready() {
            Ok(ExitCode::SUCCESS)
        } else {
            Ok(ExitCode::FAILURE)
        };
    }

    println!("ENISA envelope dry-run: {}", envelope_path.display());
    report::kv(&[
        (
            "Envelope".into(),
            if readiness.envelope_valid {
                "valid".into()
            } else {
                "INVALID".into()
            },
        ),
        (
            "Embedded CSAF".into(),
            if readiness.csaf_valid {
                "valid".into()
            } else {
                "INVALID".into()
            },
        ),
        (
            "Report type".into(),
            readiness
                .report_type
                .map(|t| t.label().to_string())
                .unwrap_or_else(|| "unknown".into()),
        ),
        (
            "Due at".into(),
            readiness.due_at.clone().unwrap_or_else(|| "-".into()),
        ),
        (
            "Timeline".into(),
            readiness
                .timeline
                .map(|t| format!("{} — {}", t.label(), t.detail()))
                .unwrap_or_else(|| "-".into()),
        ),
    ]);

    for problem in &readiness.problems {
        println!("  ! {problem}");
    }

    if !readiness.csaf_valid && readiness.problems.is_empty() {
        println!("  ! embedded CSAF document is missing");
    }

    println!();
    if readiness.ready() {
        println!("READY for dispatch through your ENISA SRP submission channel.");
        println!("  openenisa keeps dispatch pluggable: submit via the SRP portal, or wire the");
        println!("  envelope to your transport once the SRP API is published.");
    } else {
        println!("NOT READY — fix the problems above (and check the statutory clock).");
    }

    if readiness.ready() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn cmd_pipeline(
    sbom_path: &Path,
    feeds: &[PathBuf],
    vex_paths: &[PathBuf],
    out_dir: &Path,
    aware_at: Option<&str>,
    args: &CsafArgs,
    fail_on: Option<FailOn>,
) -> Result<ExitCode> {
    let now = now_or(args.at.as_deref())?;
    let aware_at = match aware_at {
        Some(s) => now_or(Some(s))?,
        None => now,
    };

    // 1. parse
    let sbom = ingest::parse_path(sbom_path)?;
    println!("== 1/4 SBOM ==");
    report::kv(&[
        ("Path".into(), sbom_path.display().to_string()),
        (
            "Format".into(),
            sbom.format
                .as_ref()
                .map(|f| f.to_string())
                .unwrap_or_else(|| "unknown".into()),
        ),
        ("Components".into(), sbom.components.len().to_string()),
        (
            "Product".into(),
            sbom.product
                .as_ref()
                .map(|p| p.display_name())
                .unwrap_or_else(|| "-".into()),
        ),
    ]);

    // 2. match
    let mut loaded = Vec::new();
    for path in feeds {
        loaded.push(Feed::load(path)?);
    }
    let records: usize = loaded.iter().map(|f| f.records.len()).sum();
    let findings = feed::match_sbom(&sbom, &loaded);
    println!("\n== 2/4 MATCH ==");
    println!(
        "{} finding(s) from {} feed record(s) across {} feed(s).",
        findings.len(),
        records,
        loaded.len()
    );

    let mut doc = FindingsDoc::new(&sbom, &sbom_path.display().to_string(), &rfc3339(&now));
    doc.findings = findings;

    // 3. triage
    println!("\n== 3/4 VEX TRIAGE ==");
    let mut vexes: Vec<VexDoc> = Vec::new();
    for path in vex_paths {
        vexes.push(vex::load(path)?);
    }
    // CycloneDX embedded VEX travels with the SBOM itself.
    if let Some(
        crate::model::SbomFormat::CycloneDxJson(_) | crate::model::SbomFormat::CycloneDxXml(_),
    ) = sbom.format
    {
        let source = format!("embedded:{}", sbom_path.display());
        let statements = vex::cyclonedx_vex::parse(&sbom, &source);
        if !statements.is_empty() {
            vexes.push(VexDoc { source, statements });
        }
    }
    let stats = vex::apply(&mut doc.findings, &vexes);
    println!(
        "{} VEX statement(s) applied ({} matched, {} unmatched).",
        stats.statements, stats.applied, stats.unmatched
    );
    for transition in &stats.transitions {
        println!("  {transition}");
    }
    let findings_path = out_dir.join("findings.json");
    write_json(&findings_path, &doc.to_json())?;

    // 4. CSAF + ENISA envelope
    println!("\n== 4/4 DOCUMENTS ==");
    let cfg = args.config()?;
    let csaf_value = csaf::build_document(&cfg, &doc)?;
    let csaf_validation = csaf::validate::validate_csaf(&csaf_value);
    let csaf_path = out_dir.join("csaf.json");
    write_json(&csaf_path, &csaf_value)?;

    let envelope_path = out_dir.join(format!(
        "enisa-{}.json",
        ReportType::EarlyWarning.as_str().replace('_', "-")
    ));
    let wrote_envelope = if doc.findings.iter().any(|f| f.is_actionable()) {
        let opts = enisa::EnisaOptions {
            report_type: ReportType::EarlyWarning,
            classification: enisa::Classification::Vulnerability,
            reporter_name: args.vendor_name.clone(),
            reporter_contact: None,
            national_csirt: None,
            aware_at,
            exploited: args.exploited,
            now,
        };
        match enisa::build_envelope(&opts, &doc, &csaf_value) {
            Ok(envelope) => {
                let validation = csaf::validate::validate_envelope(&envelope);
                write_json(&envelope_path, &envelope)?;
                let due_at = envelope
                    .pointer("/enisa_envelope/report/timeline/due_at")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let verdict = TimelineVerdict::evaluate(
                    &DateTime::parse_from_rfc3339(due_at)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or(now),
                    now,
                );
                println!(
                    "ENISA early-warning envelope: due {due_at} [{}] (envelope valid: {})",
                    verdict.label(),
                    validation.valid
                );
                if !validation.valid {
                    for problem in validation.problems() {
                        eprintln!("  ! {problem}");
                    }
                }
                true
            }
            Err(e) => {
                println!("ENISA early-warning envelope skipped: {e}");
                false
            }
        }
    } else {
        println!(
            "ENISA early-warning envelope skipped: all findings suppressed by VEX (not_affected / fixed)."
        );
        false
    };

    println!("\n== OUTPUT ==");
    report::kv(&[
        ("Findings".into(), findings_path.display().to_string()),
        ("CSAF".into(), csaf_path.display().to_string()),
        (
            "ENISA envelope".into(),
            if wrote_envelope {
                envelope_path.display().to_string()
            } else {
                "(none)".to_string()
            },
        ),
        ("CSAF valid".into(), csaf_validation.valid.to_string()),
    ]);

    if !csaf_validation.valid {
        for problem in csaf_validation.problems() {
            eprintln!("  ! {problem}");
        }
        return Ok(ExitCode::FAILURE);
    }

    Ok(fail_on_exit(fail_on, &doc))
}
