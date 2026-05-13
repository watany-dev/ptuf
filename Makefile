.PHONY: build test lint fmt fmt-check check clean coverage deny doc e2e pbt pbt-quick pbt-deep tools install-hooks mutants mutants-quick sanitize sanitize-asan sanitize-leak verify-reproducible

# Keep these aligned with .github/workflows/ci.yml:
# - CARGO_DENY_VERSION must match the cargo-deny pinned in
#   EmbarkStudios/cargo-deny-action's Dockerfile (currently v2.0.17 -> 0.19.2).
# - CARGO_TARPAULIN_VERSION must match the `taiki-e/install-action` tool pin
#   in the coverage job.
# - CARGO_MUTANTS_VERSION must match the pin in `.github/workflows/mutants.yml`.
CARGO_DENY_VERSION ?= 0.19.2
CARGO_TARPAULIN_VERSION ?= 0.35.1
CARGO_MUTANTS_VERSION ?= 27.0.0

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

# Mutation testing. Verifies the test suite *kills* changes injected
# into security-critical modules. Surviving mutants indicate gaps in
# the test contracts (e.g. a missing assertion lets `==` flip to `!=`
# without a failure). Two tiers:
#   - `mutants` ........ full run on engine + plugin loader + audit
#                        redaction. Slow (~30 min on a laptop).
#   - `mutants-quick` .. diff-only since origin/main (~5 min in PRs).
# Bound to the threat-model entries T-3 (redaction) and D-2/D-3
# (engine resource limits) in docs/design/threat-model.md.
MUTANTS_FILES = \
	src/engine/mod.rs \
	src/engine/decision.rs \
	src/plugin/loader.rs \
	src/plugin/dsl.rs \
	src/plugin/rule.rs \
	src/audit/redaction.rs \
	src/decision.rs

mutants:
ifeq ($(SKIP_TOOL_INSTALL),)
	@command -v cargo-mutants >/dev/null 2>&1 || \
		cargo install --locked cargo-mutants@$(CARGO_MUTANTS_VERSION)
else
	@command -v cargo-mutants >/dev/null 2>&1 || { \
		echo "cargo-mutants not found. Run 'make tools' (or unset SKIP_TOOL_INSTALL)." >&2; \
		exit 1; }
endif
	cargo mutants --no-shuffle --features testing \
		$(addprefix --file ,$(MUTANTS_FILES)) \
		--minimum-test-timeout 60 \
		--timeout-multiplier 2.0

mutants-quick:
ifeq ($(SKIP_TOOL_INSTALL),)
	@command -v cargo-mutants >/dev/null 2>&1 || \
		cargo install --locked cargo-mutants@$(CARGO_MUTANTS_VERSION)
endif
	cargo mutants --no-shuffle --features testing \
		--in-diff <(git diff origin/main...HEAD -- 'src/*.rs')

# Sanitizer runs. Even though `unsafe_code = "forbid"` rules out our
# own UB, transitive C-adjacent crates (`regex` build-time, libc bits
# inside `std`, `serde_yaml_ng`'s parser tape) can still leak / OOB.
# Requires nightly Rust; not part of `make check`. Linux-only.
# Address: out-of-bounds, use-after-free, double-free.
# Leak: explicit leak detection at process exit.
sanitize: sanitize-asan sanitize-leak

sanitize-asan:
	RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes" \
	RUSTDOCFLAGS="-Zsanitizer=address" \
		cargo +nightly test \
		--target x86_64-unknown-linux-gnu \
		--features testing \
		-Z build-std \
		-- --test-threads=1

sanitize-leak:
	RUSTFLAGS="-Zsanitizer=leak" \
	RUSTDOCFLAGS="-Zsanitizer=leak" \
		cargo +nightly test \
		--target x86_64-unknown-linux-gnu \
		--features testing \
		-Z build-std \
		-- --test-threads=1

# Reproducible build verification. Builds the release binary twice
# under `SOURCE_DATE_EPOCH` pinning, then compares SHA256. If they
# differ, something in the toolchain or build graph leaks build-host
# state (timestamps, paths, env). Bound to threat-model E-4 (binary
# substitution resistance).
verify-reproducible:
	@bash scripts/verify-reproducible.sh

install-hooks:
	bash scripts/install-hooks.sh

clean:
	cargo clean
