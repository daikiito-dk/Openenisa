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

Awareness (`aware_at`) starts the clock for the first two reports. The final report has its own starting point:

| Stage | Deadline | Clock starts at | Article | openenisa report type |
|---|---|---|---|---|
| Early warning | within **24 hours** | awareness | 14(2)(a) / 14(4)(a) | `early-warning` |
| Notification | within **72 hours** | awareness | 14(2)(b) / 14(4)(b) | `notification` |
| Final report, vulnerability | within **14 days** | a corrective or mitigating measure is available | 14(2)(c) | `final-report` + `--measure-available-at` |
| Final report, severe incident | within **one month** | the 72 h notification | 14(4)(c) | `final-report --classification incident` + `--notified-at` |

The final report does **not** run from awareness. Until its clock-start event has happened, `enisa deadlines` shows it as `PENDING`:

```console
$ openenisa enisa deadlines --aware-at 2026-10-10T09:00:00Z --now 2026-10-10T09:15:00Z
Statutory clock (CRA Article 14, vulnerability) — aware at 2026-10-10T09:00:00Z

REPORT                        DUE AT (UTC)          STATUS    TIME
----------------------------  --------------------  --------  --------------------------------------------
Early warning (24h)           2026-10-11T09:00:00Z  ON TRACK  23h 45m 00s remaining
Notification (72h)            2026-10-13T09:00:00Z  ON TRACK  2d 23h 45m remaining
Final report (14d after fix)  -                     PENDING   pass --measure-available-at to start the clock
```

Once the fix ships, pass the moment it became available:

```console
$ openenisa enisa deadlines --aware-at 2026-10-10T09:00:00Z \
    --measure-available-at 2026-11-02T12:00:00Z --now 2026-11-03T09:00:00Z
...
Final report (14d after fix)  2026-11-16T12:00:00Z  ON TRACK  13d 03h 00m remaining
```

## What you must actually determine

The trigger is *"aware of a vulnerability ... being actively exploited."* That determination is inherently human and contextual:

- Is there credible public evidence of in-the-wild exploitation (CISA KEV, vendor advisories, incident reports)?
- Is the vulnerable code reachable in *your* product's configuration?

`openenisa` cannot and does not make this call. What it does:

1. `--exploited` records your determination as a structured `exploit_status` threat on the affected vulnerabilities — evidence attached, not asserted
2. The ENISA envelope carries the awareness timestamp you supply, and computes deadlines from it
3. `enisa submit` tracks the clock against `--now` and warns at `CRITICAL` (under 2 hours remaining) and `OVERDUE`

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
5. **T+72h, then the final report:** escalate report types as your investigation matures. The final report is due 14 days after your fix or mitigation is available (one month after the notification for a severe incident), so record that moment and pass it as `--measure-available-at` / `--notified-at`. The same evidence base regenerates each document deterministically.

## Sources

- Regulation (EU) 2024/2847 (Cyber Resilience Act), Article 14 (reporting obligations and deadlines), Article 24(3)
- European Commission CRA overview: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- ENISA SRP: https://portal.cra-srp.enisa.europa.eu
