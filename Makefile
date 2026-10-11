.PHONY: build release test lint fmt schemas schema-check smoke clean install

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt

# CI-grade lint: formatting + clippy with warnings denied.
lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

# Regenerate the offline CSAF 2.0 schema bundle from the vendored upstream
# files. Commit the result; `schema-check` fails if the bundle is stale.
schemas:
	python3 scripts/bundle_csaf.py

schema-check: schemas
	git diff --exit-code -- schemas/

# End-to-end smoke test on the example corpus (mirrors the README quickstart).
smoke:
	cargo run -q -- pipeline \
		--sbom examples/sbom/mx2400-firmware.cyclonedx-1.5.json \
		--feed examples/vulns/osv-feed.jsonl \
		--vex examples/vex/mx2400-openssl.openvex.json \
		--vex examples/vex/mx2400-busybox.csaf-vex.json \
		--out-dir target/smoke \
		--vendor-name "Meridian Systems" \
		--vendor-namespace "https://meridian.example" \
		--exploited \
		--aware-at "2026-10-10T09:00:00Z" \
		--at "2026-10-10T09:30:00Z"
	cargo run -q -- validate target/smoke/csaf.json
	cargo run -q -- validate target/smoke/enisa-early-warning.json
	cargo run -q -- validate examples/vex/mx2400-busybox.csaf-vex.json
	cargo run -q -- enisa submit target/smoke/enisa-early-warning.json --now "2026-10-10T10:00:00Z"

install:
	cargo install --path .

clean:
	rm -rf target
