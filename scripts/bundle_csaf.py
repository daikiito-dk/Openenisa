#!/usr/bin/env python3
"""Bundle the official CSAF 2.0 JSON Schema with the FIRST CVSS schemas.

CSAF 2.0 references the CVSS v2.0 / v3.0 / v3.1 JSON Schemas from FIRST
by absolute URL:

    "$ref": "https://www.first.org/cvss/cvss-v3.1.json"

openenisa validates completely offline, so this script inlines those
external references into the CSAF schema's ``$defs`` section and rewrites
all JSON pointers accordingly. Run from the repository root:

    python3 scripts/bundle_csaf.py      # or: make schemas

CI re-runs the script and fails on any diff, so the committed bundle can
never drift from the vendored upstream files.

Vendored sources (retrieved 2026-10-10):
  - OASIS CSAF 2.0 Errata 01, published under the OASIS IPR policy
    (Non-Assertion Mode): https://github.com/oasis-tcs/csaf
  - FIRST CVSS JSON schemas: https://www.first.org/cvss/specification-document
"""

import json
import pathlib
import sys

SCHEMA_DIR = pathlib.Path(__file__).resolve().parent.parent / "schemas" / "csaf" / "2.0"
UPSTREAM = SCHEMA_DIR / "csaf_json_schema.json"
BUNDLED = SCHEMA_DIR / "csaf-2.0-bundled.schema.json"

# external $ref URL -> (local file, $defs name under the bundled root)
CVSS_MAP = {
    "https://www.first.org/cvss/cvss-v2.0.json": ("cvss-v2.0.json", "cvss_v2_0_t"),
    "https://www.first.org/cvss/cvss-v3.0.json": ("cvss-v3.0.json", "cvss_v3_0_t"),
    "https://www.first.org/cvss/cvss-v3.1.json": ("cvss-v3.1.json", "cvss_v3_1_t"),
}


def inline_refs(obj, url, def_name):
    """Replace external ``$ref`` and rewrite ``#/definitions/...`` pointers."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "$ref" and isinstance(v, str):
                if v == url:
                    out[k] = f"#/$defs/{def_name}"
                elif v.startswith("#/definitions/"):
                    out[k] = f"#/$defs/{def_name}/definitions/" + v[len("#/definitions/"):]
                else:
                    out[k] = v
            else:
                out[k] = inline_refs(v, url, def_name)
        return out
    if isinstance(obj, list):
        return [inline_refs(x, url, def_name) for x in obj]
    return obj


def main() -> int:
    csaf = json.loads(UPSTREAM.read_text(encoding="utf-8"))
    for url, (fname, def_name) in CVSS_MAP.items():
        cvss = json.loads((SCHEMA_DIR / fname).read_text(encoding="utf-8"))
        # $schema / $id are only meaningful at the root of a schema resource;
        # drop them so the embedded schema behaves as a plain subschema.
        for drop in ("$schema", "$id", "id"):
            cvss.pop(drop, None)
        # The CVSS schemas keep their FIRST license statement, preserving
        # attribution inside the bundled artifact.
        csaf["$defs"][def_name] = inline_refs(cvss, url, def_name)
        csaf = inline_refs(csaf, url, def_name)

    leftover = [
        ref
        for ref in (
            json.dumps(csaf).split('"$ref": "')[1:]
        )
        if ref.startswith("https://")
    ]
    if leftover:
        print("ERROR: unresolved external references remain", file=sys.stderr)
        return 1

    BUNDLED.write_text(json.dumps(csaf, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {BUNDLED} ({BUNDLED.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
