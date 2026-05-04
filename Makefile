.PHONY: build test lint fmt fmt-check check clean coverage deny doc pbt

build:
	cargo build --release

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

coverage:
	cargo tarpaulin --out html --out json \
		--skip-clean \
		--fail-under 95 \
		--exclude-files "src/main.rs" \
		--timeout 300 \
		-- --test-threads=1

deny:
	cargo deny check advisories licenses bans sources

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# Deep property-based testing run. Defaults to 10000 cases per
# property; override with `make pbt PBT_CASES=N`. Runs every test
# binary (lib unit tests + integration tests) so each module's
# `proptest!` block is exercised at the configured case count.
PBT_CASES ?= 10000
pbt:
	PROPTEST_CASES=$(PBT_CASES) cargo test

check: fmt-check lint test doc deny

clean:
	cargo clean
