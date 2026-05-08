.PHONY: build test lint fmt fmt-check check clean coverage deny doc pbt tools install-hooks

# Keep these aligned with .github/workflows/ci.yml:
# - CARGO_DENY_VERSION must match the cargo-deny pinned in
#   EmbarkStudios/cargo-deny-action's Dockerfile (currently v2.0.17 -> 0.19.2).
# - CARGO_TARPAULIN_VERSION must match the `taiki-e/install-action` tool pin
#   in the coverage job.
CARGO_DENY_VERSION ?= 0.19.2
CARGO_TARPAULIN_VERSION ?= 0.35.1

# When set to a non-empty value, `tools` only verifies presence and exits
# non-zero if a required binary is missing (no `cargo install`). Useful in CI
# or environments that pre-provision toolchains.
SKIP_TOOL_INSTALL ?=

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

coverage: tools
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

tools:
ifeq ($(SKIP_TOOL_INSTALL),)
	@command -v cargo-deny >/dev/null 2>&1 || \
		cargo install --locked cargo-deny@$(CARGO_DENY_VERSION)
	@command -v cargo-tarpaulin >/dev/null 2>&1 || \
		cargo install --locked cargo-tarpaulin@$(CARGO_TARPAULIN_VERSION)
else
	@command -v cargo-deny >/dev/null 2>&1 || { \
		echo "cargo-deny not found. Run 'make tools' (or unset SKIP_TOOL_INSTALL)." >&2; \
		exit 1; }
	@command -v cargo-tarpaulin >/dev/null 2>&1 || { \
		echo "cargo-tarpaulin not found. Run 'make tools' (or unset SKIP_TOOL_INSTALL)." >&2; \
		exit 1; }
endif

check: tools fmt-check lint test doc deny

install-hooks:
	bash scripts/install-hooks.sh

clean:
	cargo clean
