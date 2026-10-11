---
layout: default
title: CI/CD recipes
---

# CI/CD recipes

openenisa is a single static binary with machine-readable output (`--json`) and CI-friendly exit codes. Every recipe below assumes you produce an SBOM during build (CycloneDX and SPDX both supported).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, thresholds not breached |
| 1 | Error (bad input, I/O, invalid flags) |
| 2 | Threshold breached: `--fail-on affected` and known-affected findings remain after triage |

## GitHub Actions (bundled action)

```yaml
name: release-gate
on: [push]

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo '{"bomFormat":"CycloneDX","specVersion":"1.5", ...}' > dist/bom.json  # your SBOM build step
      - uses: daikiito-dk/Openenisa@main
        with:
          sbom: dist/bom.json
          feeds: |
            advisories/osv-feed.jsonl
          vex: |
            vex/release-vex.json
          vendor-name: "Meridian Systems"
          vendor-namespace: "https://meridian.example"
          fail-on: affected
```

The action installs openenisa, runs the pipeline, and uploads `findings.json`, `csaf.json`, and the ENISA envelope as artifacts. Find more inputs in [action.yml](https://github.com/daikiito-dk/Openenisa/blob/main/action.yml).

## GitHub Actions (raw binary)

```yaml
- name: install openenisa
  run: cargo install --locked --git https://github.com/daikiito-dk/Openenisa openenisa

- name: vulnerability gate
  run: |
    openenisa pipeline \
      --sbom dist/bom.json \
      --feed advisories/osv-feed.jsonl \
      --out-dir openenisa-out \
      --vendor-name "Meridian Systems" \
      --vendor-namespace "https://meridian.example" \
      --fail-on affected

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: openenisa-report
    path: openenisa-out/
```

## GitLab CI

```yaml
vulnerability-gate:
  stage: test
  image: rust:1-bookworm
  before_script:
    - cargo install --locked --git https://github.com/daikiito-dk/Openenisa openenisa
  script:
    - openenisa pipeline
        --sbom dist/bom.json
        --feed advisories/osv-feed.jsonl
        --out-dir openenisa-out
        --vendor-name "Meridian Systems"
        --vendor-namespace "https://meridian.example"
        --fail-on affected
  artifacts:
    when: always
    paths:
      - openenisa-out/
```

## Jenkins (declarative)

```groovy
pipeline {
  agent any
  stages {
    stage('sbom') { steps { sh './gradlew cyclonedxBom' } }
    stage('vulnerability gate') {
      steps {
        sh '''
          cargo install --locked --git https://github.com/daikiito-dk/Openenisa openenisa
          openenisa pipeline \
            --sbom build/reports/bom.json \
            --feed advisories/osv-feed.jsonl \
            --out-dir openenisa-out \
            --vendor-name "Meridian Systems" \
            --vendor-namespace "https://meridian.example" \
            --fail-on affected
        '''
      }
    }
  }
  post {
    always { archiveArtifacts artifacts: 'openenisa-out/**', allowEmptyArchive: true }
  }
}
```

## JSON mode for custom tooling

Every command supports `--json`:

```console
$ openenisa match --sbom dist/bom.json --feed advisories/osv-feed.jsonl --json
```

For gates that need only a verdict:

```console
$ openenisa triage --findings findings.json --vex vex.json --json \
    | jq -e '.stats.remaining_affected == 0'
```

## Keeping the feed fresh

openenisa does not download feeds. Mirror OSV.dev dumps (or your curated subset) on a schedule — a cron job committing `advisories/osv-feed.jsonl`, or an S3/object-store sync — and keep the pipeline deterministic by pinning the feed commit. The feed file is evidence; treat it like one.
