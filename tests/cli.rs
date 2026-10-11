//! End-to-end CLI tests: the real binary against the example corpus.
//!
//! The corpus encodes the demo narrative:
//! - 4 components in the firmware SBOM (openssl, zlib, busybox, libssh2)
//! - zlib 1.2.13 falls outside CVE-2018-25032's range (no finding)
//! - openssl 3.0.12 matches CVE-2024-0727 but OpenVEX suppresses it
//!   (`vulnerable_code_not_in_execute_path`)
//! - busybox 1.36.0 matches CVE-2023-42366 but a CSAF VEX marks it fixed
//! - libssh2 1.11.0 matches CVE-2023-48795 and stays actively affected

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo(relative: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(relative)
        .display()
        .to_string()
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!("openenisa-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    Command::new(env!("CARGO_BIN_EXE_openenisa"))
        .args(&args)
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn openenisa binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

const SBOM: &str = "examples/sbom/mx2400-firmware.cyclonedx-1.5.json";
const SBOM_XML: &str = "examples/sbom/mx2400-firmware.cyclonedx-1.6.xml";
const SBOM_SPDX: &str = "examples/sbom/aurora-gateway.spdx-2.3.json";
const SBOM_SPDX3: &str = "examples/sbom/aurora-sensor.spdx-3.0.json";
const FEED: &str = "examples/vulns/osv-feed.jsonl";
const OPENVEX: &str = "examples/vex/mx2400-openssl.openvex.json";
const CSAF_VEX: &str = "examples/vex/mx2400-busybox.csaf-vex.json";
const VENDOR: &str = "Meridian Systems";
const NAMESPACE: &str = "https://meridian.example";

#[test]
fn parses_every_sbom_format() {
    for (doc, expected) in [
        (SBOM, "CycloneDX 1.5 (JSON)"),
        (SBOM_XML, "CycloneDX 1.6 (XML)"),
        (SBOM_SPDX, "SPDX 2.3 (JSON)"),
        (SBOM_SPDX3, "SPDX 3.0.0 (JSON-LD)"),
    ] {
        let out = run(&["parse", &repo(doc)]);
        assert!(out.status.success(), "parse {doc} failed: {}", stderr(&out));
        let text = stdout(&out);
        assert!(
            text.contains(expected),
            "{doc}: expected {expected} in\n{text}"
        );
    }

    let out = run(&["parse", &repo(SBOM)]);
    assert!(stdout(&out).contains("openssl"));
    assert!(stdout(&out).contains("pkg:generic/zlib@1.2.13"));
}

#[test]
fn parse_json_output_is_machine_readable() {
    let out = run(&["parse", &repo(SBOM), "--json"]);
    assert!(out.status.success());
    let value: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["format"].as_str().unwrap(), "CycloneDX 1.5 (JSON)");
    assert_eq!(value["components"].as_u64().unwrap(), 4);
    assert_eq!(
        value["product"]["name"].as_str().unwrap(),
        "MX-2400 Server Firmware"
    );
}

#[test]
fn match_finds_affected_and_excludes_out_of_range() {
    let out = run(&["match", &repo(SBOM), "--feed", &repo(FEED), "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let value: Value = serde_json::from_str(&stdout(&out)).unwrap();
    let findings = value["document"]["findings"].as_array().unwrap();

    let ids: Vec<&str> = findings
        .iter()
        .map(|f| f["vulnerability"]["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["CVE-2023-42366", "CVE-2023-48795", "CVE-2024-0727"]);

    // zlib 1.2.13 is above the CVE-2018-25032 fix: no finding at all.
    assert!(!ids.contains(&"CVE-2018-25032"));

    let libssh2 = findings
        .iter()
        .find(|f| f["vulnerability"]["id"] == "CVE-2023-48795")
        .unwrap();
    assert_eq!(libssh2["status"], "affected");
    assert_eq!(libssh2["fixed_in"], "1.11.1");
    assert_eq!(libssh2["matched_by"], "purl");
}

#[test]
fn triage_suppresses_noise() {
    let tmp = TempDir::new("triage");
    let findings = tmp.path("findings.json");
    let triaged = tmp.path("triaged.json");

    let out = run(&[
        "match",
        &repo(SBOM),
        "--feed",
        &repo(FEED),
        "--out",
        &findings,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    let out = run(&[
        "triage",
        &findings,
        "--vex",
        &repo(OPENVEX),
        "--vex",
        &repo(CSAF_VEX),
        "--out",
        &triaged,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("affected -> not_affected"));
    assert!(stdout(&out).contains("affected -> fixed"));

    let value: Value = serde_json::from_str(&std::fs::read_to_string(&triaged).unwrap()).unwrap();
    let findings = value["document"]["findings"].as_array().unwrap();

    let status_of = |cve: &str| {
        findings
            .iter()
            .find(|f| f["vulnerability"]["id"] == cve)
            .map(|f| f["status"].as_str().unwrap())
            .unwrap()
    };
    assert_eq!(status_of("CVE-2024-0727"), "not_affected");
    assert_eq!(status_of("CVE-2023-42366"), "fixed");
    assert_eq!(status_of("CVE-2023-48795"), "affected");

    let openssl = findings
        .iter()
        .find(|f| f["vulnerability"]["id"] == "CVE-2024-0727")
        .unwrap();
    assert_eq!(
        openssl["justification"],
        "vulnerable_code_not_in_execute_path"
    );
    assert!(openssl["vex_source"].as_str().unwrap().contains("openvex"));
}

#[test]
fn triage_finds_embedded_cyclonedx_vex() {
    let tmp = TempDir::new("embedded");
    let bom = tmp.path("sbom.json");
    std::fs::write(
        &bom,
        r#"{
          "bomFormat": "CycloneDX",
          "specVersion": "1.5",
          "components": [{"bom-ref": "c1", "type": "library", "name": "openssl", "version": "3.0.12", "purl": "pkg:generic/openssl@3.0.12"}],
          "vulnerabilities": [
            {"id": "CVE-2024-0727", "affects": [{"ref": "c1"}],
             "analysis": {"state": "not_affected", "justification": "component_not_present"}}
          ]
        }"#,
    )
    .unwrap();

    let findings = tmp.path("findings.json");
    let triaged = tmp.path("triaged.json");
    let out = run(&["match", &bom, "--feed", &repo(FEED), "--out", &findings]);
    assert!(out.status.success(), "{}", stderr(&out));

    let out = run(&["triage", &findings, "--sbom", &bom, "--out", &triaged]);
    assert!(out.status.success(), "{}", stderr(&out));

    let value: Value = serde_json::from_str(&std::fs::read_to_string(&triaged).unwrap()).unwrap();
    let finding = &value["document"]["findings"][0];
    assert_eq!(finding["status"], "not_affected");
    assert_eq!(finding["justification"], "component_not_present");
}

#[test]
fn csaf_generation_validates_offline() {
    let tmp = TempDir::new("csaf");
    let findings = tmp.path("findings.json");
    let triaged = tmp.path("triaged.json");
    let csaf = tmp.path("csaf.json");

    run(&[
        "match",
        &repo(SBOM),
        "--feed",
        &repo(FEED),
        "--out",
        &findings,
    ]);
    run(&[
        "triage",
        &findings,
        "--vex",
        &repo(OPENVEX),
        "--vex",
        &repo(CSAF_VEX),
        "--out",
        &triaged,
    ]);

    let out = run(&[
        "csaf",
        &triaged,
        "--vendor-name",
        VENDOR,
        "--vendor-namespace",
        NAMESPACE,
        "--exploited",
        "--out",
        &csaf,
    ]);
    assert!(out.status.success(), "{}\n{}", stderr(&out), stdout(&out));

    let out = run(&["validate", &csaf]);
    assert!(out.status.success(), "validation failed:\n{}", stdout(&out));
    assert!(stdout(&out).contains("VALID"));

    let value: Value = serde_json::from_str(&std::fs::read_to_string(&csaf).unwrap()).unwrap();
    assert_eq!(value["document"]["csaf_version"], "2.0");
    assert!(
        value["document"]["tracking"]["id"]
            .as_str()
            .unwrap()
            .starts_with("meridian-systems-")
    );

    let vuln = value["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["cve"] == "CVE-2023-48795")
        .expect("libssh2 vulnerability entry");
    assert!(
        vuln["product_status"]["known_affected"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("CSAFPID-0000"))
    );
    assert!(vuln["threats"][0]["category"] == "exploit_status");

    let suppressed = value["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["cve"] == "CVE-2024-0727")
        .expect("openssl vulnerability entry");
    assert!(
        suppressed["product_status"]["known_not_affected"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("CSAFPID-0000"))
    );
    assert_eq!(
        suppressed["flags"][0]["label"],
        "vulnerable_code_not_in_execute_path"
    );
}

#[test]
fn enisa_early_warning_lifecycle() {
    let tmp = TempDir::new("enisa");
    let findings = tmp.path("findings.json");
    let triaged = tmp.path("triaged.json");
    let envelope = tmp.path("enisa-early-warning.json");

    run(&[
        "match",
        &repo(SBOM),
        "--feed",
        &repo(FEED),
        "--out",
        &findings,
    ]);
    run(&[
        "triage",
        &findings,
        "--vex",
        &repo(OPENVEX),
        "--vex",
        &repo(CSAF_VEX),
        "--out",
        &triaged,
    ]);

    let out = run(&[
        "enisa",
        "report",
        &triaged,
        "--type",
        "early-warning",
        "--aware-at",
        "2026-10-10T09:00:00Z",
        "--contact",
        "psirt@meridian.example",
        "--csirt",
        "CERT-EU",
        "--vendor-name",
        VENDOR,
        "--vendor-namespace",
        NAMESPACE,
        "--exploited",
        "--out",
        &envelope,
    ]);
    assert!(out.status.success(), "{}\n{}", stderr(&out), stdout(&out));

    let value: Value = serde_json::from_str(&std::fs::read_to_string(&envelope).unwrap()).unwrap();
    let report = &value["enisa_envelope"]["report"];
    assert_eq!(report["type"], "early_warning");
    assert_eq!(report["timeline"]["aware_at"], "2026-10-10T09:00:00Z");
    assert_eq!(report["timeline"]["due_at"], "2026-10-11T09:00:00Z");
    assert_eq!(report["timeline"]["sla_hours"], 24);
    assert_eq!(report["vulnerabilities"][0]["id"], "CVE-2023-48795");
    assert_eq!(report["vulnerabilities"][0]["actively_exploited"], true);
    assert!(report["csaf"]["document"]["csaf_version"] == "2.0");

    // Well within the 24h window: ready.
    let out = run(&[
        "enisa",
        "submit",
        &envelope,
        "--now",
        "2026-10-10T10:30:00Z",
    ]);
    assert!(out.status.success(), "{}\n{}", stderr(&out), stdout(&out));
    assert!(stdout(&out).contains("READY"));

    // The envelope validates as a document too.
    let out = run(&["validate", &envelope]);
    assert!(out.status.success(), "{}", stdout(&out));

    // Past the deadline: not ready, exit failure.
    let out = run(&[
        "enisa",
        "submit",
        &envelope,
        "--now",
        "2026-10-12T00:00:00Z",
    ]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("OVERDUE"));

    // The curl template renders.
    let out = run(&[
        "enisa",
        "submit",
        &envelope,
        "--now",
        "2026-10-10T10:30:00Z",
        "--print-curl",
        "--endpoint",
        "https://srp.example/api/v1/reports",
    ]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("curl --request POST"));
    assert!(stdout(&out).contains("--tlsv1.3"));
}

#[test]
fn deadlines_table_shows_all_three_statutory_windows() {
    let out = run(&["enisa", "deadlines", "--aware-at", "2026-10-10T09:00:00Z"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("2026-10-11T09:00:00Z"),
        "24h missing in\n{text}"
    );
    assert!(
        text.contains("2026-10-13T09:00:00Z"),
        "72h missing in\n{text}"
    );
    assert!(
        text.contains("2026-10-24T09:00:00Z"),
        "14d missing in\n{text}"
    );
}

#[test]
fn validate_rejects_invalid_csaf() {
    let tmp = TempDir::new("invalid");
    let bad = tmp.path("bad.json");
    std::fs::write(&bad, r#"{"document": {"csaf_version": "2.0"}}"#).unwrap();
    let out = run(&["validate", &bad]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("INVALID"));
}

#[test]
fn validate_accepts_the_example_csaf_vex() {
    let out = run(&["validate", &repo(CSAF_VEX)]);
    assert!(out.status.success(), "{}", stdout(&out));
}

#[test]
fn triage_fail_on_affected_sets_exit_code_2() {
    let tmp = TempDir::new("failon");
    let findings = tmp.path("findings.json");
    run(&[
        "match",
        &repo(SBOM),
        "--feed",
        &repo(FEED),
        "--out",
        &findings,
    ]);

    // No VEX applied: openssl + busybox + libssh2 are all still affected.
    let out = run(&["triage", &findings, "--fail-on", "affected"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn match_fail_on_any_sets_exit_code_2() {
    let out = run(&[
        "match",
        &repo(SBOM),
        "--feed",
        &repo(FEED),
        "--fail-on",
        "any",
    ]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn match_exit_2_with_affected_even_after_triage() {
    let tmp = TempDir::new("exit2");
    let findings = tmp.path("findings.json");
    let triaged = tmp.path("triaged.json");
    run(&[
        "match",
        &repo(SBOM),
        "--feed",
        &repo(FEED),
        "--out",
        &findings,
    ]);
    let out = run(&[
        "triage",
        &findings,
        "--vex",
        &repo(OPENVEX),
        "--vex",
        &repo(CSAF_VEX),
        "--out",
        &triaged,
        "--fail-on",
        "affected",
    ]);
    // libssh2 remains affected after triage.
    assert_eq!(out.status.code(), Some(2));

    let out = run(&[
        "triage",
        &triaged,
        "--vex",
        &repo(OPENVEX),
        "--out",
        &tmp.path("t2.json"),
        "--fail-on",
        "affected",
    ]);
    // Re-triaging changes nothing (libssh2 still affected).
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn pipeline_runs_the_whole_chain() {
    let tmp = TempDir::new("pipeline");
    let out_dir = tmp.path("out");

    let out = run(&[
        "pipeline",
        "--sbom",
        &repo(SBOM),
        "--feed",
        &repo(FEED),
        "--vex",
        &repo(OPENVEX),
        "--vex",
        &repo(CSAF_VEX),
        "--out-dir",
        &out_dir,
        "--vendor-name",
        VENDOR,
        "--vendor-namespace",
        NAMESPACE,
        "--exploited",
        "--aware-at",
        "2026-10-10T09:00:00Z",
        "--fail-on",
        "affected",
    ]);
    let text = format!("{}\n{}", stdout(&out), stderr(&out));
    assert!(text.contains("1/4 SBOM"));
    assert!(text.contains("2/4 MATCH"));
    assert!(text.contains("3/4 VEX TRIAGE"));
    assert!(text.contains("4/4 DOCUMENTS"));

    // libssh2 is still affected -> exit code 2.
    assert_eq!(out.status.code(), Some(2));

    for file in ["findings.json", "csaf.json", "enisa-early-warning.json"] {
        assert!(
            Path::new(&out_dir).join(file).exists(),
            "pipeline output {file} missing"
        );
    }

    let out = run(&[
        "validate",
        &Path::new(&out_dir).join("csaf.json").display().to_string(),
    ]);
    assert!(out.status.success(), "{}", stdout(&out));

    let envelope = Path::new(&out_dir).join("enisa-early-warning.json");
    let out = run(&["validate", &envelope.display().to_string()]);
    assert!(out.status.success(), "{}", stdout(&out));
}

#[test]
fn pipeline_without_actionable_findings_skips_envelope() {
    // The SPDX SBOM only contains openssl + libssh2; combined with both VEX
    // documents, openssl is suppressed but libssh2 is still affected, so the
    // envelope is still produced. Instead, use a feed-less pipeline:
    // no findings at all -> no envelope, exit 0.
    let tmp = TempDir::new("noenv");
    let feed = tmp.path("empty.jsonl");
    std::fs::write(&feed, "\n").unwrap();
    let out_dir = tmp.path("out");

    let out = run(&[
        "pipeline",
        "--sbom",
        &repo(SBOM),
        "--feed",
        &feed,
        "--out-dir",
        &out_dir,
        "--vendor-name",
        VENDOR,
        "--vendor-namespace",
        NAMESPACE,
    ]);
    assert!(out.status.success(), "{}\n{}", stderr(&out), stdout(&out));
    assert!(stdout(&out).contains("envelope skipped"));
    assert!(
        !Path::new(&out_dir)
            .join("enisa-early-warning.json")
            .exists()
    );
    assert!(Path::new(&out_dir).join("csaf.json").exists());
}

#[test]
fn unknown_sbom_format_fails_with_helpful_error() {
    let tmp = TempDir::new("badbom");
    let bad = tmp.path("bad.json");
    std::fs::write(&bad, r#"{"hello": "world"}"#).unwrap();
    let out = run(&["parse", &bad]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unrecognized JSON document"));
}
