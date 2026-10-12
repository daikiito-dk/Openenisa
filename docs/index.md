---
layout: default
title: openenisa
---

Turn SBOMs, vulnerability feeds, and VEX statements into a **schema-valid CSAF 2.0 document** and an **ENISA-ready early-warning envelope**, on the Cyber Resilience Act's 24-hour clock. One static binary, 100% offline, built for CI pipelines and incident response.

## Why

Since **11 September 2026**, manufacturers placing products with digital elements on the EU market must report actively-exploited vulnerabilities to ENISA:

| Stage | Deadline | Clock starts at | Article |
|---|---|---|---|
| Early warning | 24 hours | awareness | 14(2)(a) / 14(4)(a) |
| Notification | 72 hours | awareness | 14(2)(b) / 14(4)(b) |
| Final report (vulnerability) | 14 days | a corrective or mitigating measure is available | 14(2)(c) |
| Final report (severe incident) | 1 month | the 72 h notification | 14(4)(c) |

Your feed flags an exploited CVE in your firmware. What do you send ENISA, in what format, by when? `openenisa` answers in one command: **SBOM in, validated submission-ready documents out.**

## 30-second demo

```console
$ openenisa pipeline \
    --sbom examples/sbom/mx2400-firmware.cyclonedx-1.5.json \
    --feed examples/vulns/osv-feed.jsonl \
    --vex examples/vex/mx2400-openssl.openvex.json \
    --vex examples/vex/mx2400-busybox.csaf-vex.json \
    --out-dir openenisa-out \
    --vendor-name "Meridian Systems" \
    --vendor-namespace "https://meridian.example" \
    --exploited

== 1/4 SBOM ==
  Format      CycloneDX 1.5 (JSON)
  Components  4
  Product     MX-2400 Server Firmware 2.4.1

== 2/4 MATCH ==
3 finding(s) from 4 feed record(s) across 1 feed(s).

== 3/4 VEX TRIAGE ==
2 VEX statement(s) applied (2 matched, 0 unmatched).
  affected -> not_affected (CVE-2024-0727)
  affected -> fixed (CVE-2023-42366)

== 4/4 DOCUMENTS ==
ENISA early-warning envelope: due 2026-10-11T09:00:00Z [ON TRACK] (envelope valid: true)
```

4 components in the SBOM, 3 CVE matches, 2 suppressed by VEX — **only the real one lands in the ENISA envelope**, with a full audit trail.

## Install

```console
$ cargo install --git https://github.com/daikiito-dk/Openenisa openenisa
```

Prebuilt binaries for Linux (amd64/arm64), macOS (arm64), and Windows ship with every [release](https://github.com/daikiito-dk/Openenisa/releases).

## Documentation

- [Technical specification]({{ site.baseurl }}/specification/) — architecture, matching semantics, validation guarantees, determinism contract
- [CRA Article 14 reporting guide]({{ site.baseurl }}/cra-reporting/) — the obligation, the clock, the ENISA Single Reporting Platform status
- [CI/CD recipes]({{ site.baseurl }}/ci-cd/) — GitHub Actions, GitLab CI, Jenkins, exit codes, JSON mode

[GitHub repository](https://github.com/daikiito-dk/Openenisa) · [README (English)](https://github.com/daikiito-dk/Openenisa/blob/main/README.md) · [README (日本語)](https://github.com/daikiito-dk/Openenisa/blob/main/README.ja.md)

## Honest limitations

Not legal advice. "Actively exploited" is a human determination — `--exploited` records it, never invents it. The ENISA SRP has no public machine API yet, so `enisa submit` is an offline dry-run with a dispatch template; transport is pluggable. No feed downloading — bring your own OSV mirror, deterministically.

## License

Apache-2.0. Redistributes the OASIS CSAF 2.0 JSON Schema (Non-Assertion Mode) and FIRST CVSS schemas; see the [NOTICE](https://github.com/daikiito-dk/Openenisa/blob/main/NOTICE).
