.PHONY: build test lint fmt fmt-check check clean coverage deny doc e2e pbt pbt-quick pbt-deep tools install-hooks

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

# Property-based testing tiers. Three case-count budgets that trade
# breadth for runtime so the same `proptest!` blocks can be exercised
# at the right depth for the layer they run in:
#   - `pbt-quick` (1024) ............ PR CI gate (`.github/workflows/ci.yml`).
#   - `pbt`        (10000) .......... default deep run, also nightly CI.
#   - `pbt-deep`  (100000) .......... pre-release / local soak; not on CI.
# Override per-tier with `make pbt-deep PBT_DEEP_CASES=N` etc.
PBT_QUICK_CASES ?= 1024
pbt-quick:
	PROPTEST_CASES=$(PBT_QUICK_CASES) cargo test --locked --features testing

PBT_CASES ?= 10000
pbt:
	PROPTEST_CASES=$(PBT_CASES) cargo test --locked --features testing

PBT_DEEP_CASES ?= 100000
pbt-deep:
	PROPTEST_CASES=$(PBT_DEEP_CASES) cargo test --locked --features testing

# Heavy E2E tests reproducing real-world ptuf invocation patterns
# (fd / tempfile leak checks, 8 MiB stdin boundary, sequential and
# parallel hook spawns, 4-layer config + plugin + audit end-to-end).
# Not part of `make check` because each axis takes minutes; intended
# for nightly CI and pre-release validation. `--test-threads=1` is
# required: the fd-leak axis and the shared-audit axis interfere if
# run in parallel.
e2e:
	cargo test --locked --features testing --test e2e_heavy -- --ignored --test-threads=1

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
