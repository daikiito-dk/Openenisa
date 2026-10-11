---
layout: default
title: CRA Article 14 reporting
---

# CRA Article 14 vulnerability reporting, and where openenisa fits

**This document is engineering context, not legal advice.** Consult counsel for your obligations under Regulation (EU) 2024/2847.

## The obligation

The Cyber Resilience Act (CRA, Regulation (EU) 2024/2847) applies to products with digital elements sold in the EU. Its reporting duty (Article 14) became live on **11 September 2026**. Manufacturers must report to ENISA (and, per Member State arrangements, the national CSIRT) when they become aware that a vulnerability in their product is **being actively exploited**, with severe consequences per Article 15 for non-compliance.

Key dates:

| Date | Event |
|---|---|
| 11 September 2026 | Reporting obligations live (Art. 14) |
| 11 December 2027 | Main product obligations apply |
| 11 December 2027 | Obligations extend to stewards of open-source components under certain conditions (Art. 24(3)) |

## The clock

Awareness (`aware_at`) starts the statutory clock. Three deadlines follow:

| Stage | Deadline | Article | openenisa report type |
|---|---|---|---|
| Early warning | within **24 hours** | 14(1) | `early-warning` |
| Notification | within **72 hours** | 14(2) | `notification` |
| Final report | within **14 days** (336 h) | 14(3) | `final-report` |

`openenisa enisa deadlines --aware-at 2026-10-10T09:00:00Z` prints all three:

```console
$ openenisa enisa deadlines --aware-at 2026-10-10T09:00:00Z
Report type      Due at                Remaining
Early warning    2026-10-11T09:00:00Z  22h 45m 00s   ON TRACK
Notification    2026-10-13T09:00:00Z  70h 45m 00s   ON TRACK
Final report     2026-10-24T09:00:00Z  334h 45m 0s   ON TRACK
```

## What you must actually determine

The trigger is *"aware of a vulnerability ... being actively exploited."* That determination is inherently human and contextual:

- Is there credible public evidence of in-the-wild exploitation (CISA KEV, vendor advisories, incident reports)?
- Is the vulnerable code reachable in *your* product's configuration?

`openenisa` cannot and does not make this call. What it does:

1. `--exploited` records your determination as a structured `exploit_status` threat on the affected vulnerabilities — evidence attached, not asserted
2. The ENISA envelope carries the awareness timestamp you supply, and computes deadlines from it
3. `enisa submit` tracks the clock against `--now` and warns at `CRITICAL` (inside 20% of the window) and `OVERDUE`

A defensible audit trail looks like: feed match (automated) → VEX suppression (automated, justification preserved) → human exploitation determination (recorded) → validated documents (reproducible).

## The ENISA Single Reporting Platform

ENISA's Single Reporting Platform (SRP) went live on **11 September 2026** at [portal.cra-srp.enisa.europa.eu](https://portal.cra-srp.enisa.europa.eu). Submissions today happen through the portal. **No public machine API has been published.**

openenisa's position on this:

- Generate **submission-ready envelopes**: a validated CSAF 2.0 document embedded in a typed envelope with deadlines, classification, and evidence hashes
- `enisa submit` is an **offline dry-run**: readiness check, clock, and a curl-style dispatch template that becomes a real call when the API lands
- When ENISA publishes the API, `enisa dispatch --transport` plugins close the loop without changing any upstream stage

This is deliberate. A compliance tool that half-implements an unpublished API is a liability; a tool that guarantees your documents are valid and your clock is visible is an asset on day one.

## Suggested workflow

1. **Continuous (CI):** every release builds the SBOM, runs `openenisa pipeline --fail-on affected` against your curated OSV feed mirror. Known-affected findings gate the release.
2. **Monitoring:** your threat intel (KEV feeds, vendor advisories) flags exploitation of a CVE present in your findings. A human confirms.
3. **T+0 (awareness):** rerun the pipeline with `--exploited --aware-at <now>`. You get a valid CSAF VEX document and an early-warning envelope in seconds, not hours.
4. **T+24h:** envelope is ready for the SRP portal. `enisa submit` confirms validity and shows remaining time.
5. **T+72h / T+14d:** escalate report types as your investigation matures. The same evidence base regenerates each document deterministically.

## Sources

- Regulation (EU) 2024/2847 (Cyber Resilience Act), Articles 14–15, 24(3)
- European Commission CRA overview: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- ENISA SRP: https://portal.cra-srp.enisa.europa.eu
