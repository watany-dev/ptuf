.PHONY: build test lint fmt fmt-check check clean coverage deny doc pbt install-hooks

build:
	cargo build --release --locked

test:
	cargo test --locked --features testing

lint:
	cargo clippy --all-targets --locked --features testing -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

coverage:
	cargo tarpaulin --out html --out json \
		--locked \
		--features testing \
		--skip-clean \
		--features testing \
		--fail-under 95 \
		--exclude-files "src/main.rs" \
		--exclude-files "src/**/windows*.rs" \
		--exclude-files "src/**/*_windows.rs" \
		--timeout 300 \
		-- --test-threads=1

deny:
	cargo deny check advisories licenses bans sources

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked

# Deep property-based testing run. Defaults to 10000 cases per
# property; override with `make pbt PBT_CASES=N`. Runs every test
# binary (lib unit tests + integration tests) so each module's
# `proptest!` block is exercised at the configured case count.
PBT_CASES ?= 10000
pbt:
	PROPTEST_CASES=$(PBT_CASES) cargo test --locked --features testing

check: fmt-check lint test doc deny

install-hooks:
	bash scripts/install-hooks.sh

clean:
	cargo clean
