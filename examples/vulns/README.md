# Example vulnerability feed

`osv-feed.jsonl` is a hand-curated, illustrative snapshot in the
[OSV schema](https://ossf.github.io/osv-schema/) used by the examples,
tests and quickstart. The four records reference real CVEs with their
real affected ranges, but the file is not a live feed and is frozen at
retrieval time.

In production, feed openenisa from your real sources:

- **OSV.dev**: pull the ecosystem dumps (`https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`),
  or query the API and persist the JSONL locally so scanning stays offline.
- **NVD**: the NVD CVE feeds can be converted to OSV-style ranges, or
  wrapped in a small adapter.
- **Commercial intel / your internal tracker**: emit OSV JSONL — the schema
  is intentionally minimal, which is why it was chosen as the interchange
  format.

The `generic` purl type is used for the firmware-style components in the
example SBOMs (`pkg:generic/openssl@3.0.12`); ecosystem-native purls
(`pkg:npm/...`, `pkg:cargo/...`) work identically.
