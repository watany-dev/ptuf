# ptuf

`ptuf` (PreToolUseFilter) is a guardrail for coding agents. It runs from a
`PreToolUse` hook, reads the tool request JSON from stdin, evaluates built-in
rules plus optional YAML plugins, and returns the result through exit code,
stderr, and agent-specific `hookSpecificOutput` JSON.

- `0` — allow, monitor, or ask
- `2` — deny
- `1` — internal error such as invalid JSON, bad CLI arguments, or policy load
  failure

`ptuf` currently ships first-class adapters for Claude Code and Codex.

## Status

v0.0.1 ships:

- Built-in packs for filesystem, network, secrets, git, self-protection, the
  dynamic-eval engine guard, and opt-in project hygiene
- Tool-aware fact extraction for `Bash`, `Read`, `Edit`, `Write`, `WebFetch`,
  and generic `mcp__<server>__<tool>` payloads
- Bounded wrapper inspection for `bash -c`, `sh -c`, `eval`, `xargs`, and
  `find -exec`, including wrapped redirect targets for self-protection
- Layered YAML config and YAML plugins with rule-local `tests:`
- `ptuf init <agent>` for Claude Code and Codex hook installation
- `ptuf doctor [--json]` for binary/config/plugin/hook diagnostics
- Audit JSONL with `schemaVersion: 1`, `agent`, `pluginVersions`, and
  `allowlistId`
- Contract tests for hook JSON, `doctor --json`, audit schema, allowlists, MCP
  nested paths, and hook-script self-protection

## Requirements

- Rust `1.93.0` or newer
- `lld` for the default Linux build profile
- `cargo-deny` and `cargo-tarpaulin` for the full local quality pipeline

## Install

### Verified install (recommended)

Set the exact version and target you want, download the canonical archive,
verify its checksum, and verify the GitHub artifact attestation before
extracting.

Linux:

```bash
VERSION=v0.0.1
TARGET=x86_64-unknown-linux-musl
ARCHIVE=ptuf-$TARGET.tar.gz
BASE=https://github.com/watany-dev/ptuf/releases/download/$VERSION

curl -LO "$BASE/$ARCHIVE"
curl -LO "$BASE/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "$ARCHIVE" \
  --repo watany-dev/ptuf \
  --source-ref refs/tags/$VERSION
tar -xzf "$ARCHIVE" --strip-components=1
install -m 0755 ptuf ~/.cargo/bin/ptuf
```

macOS:

```bash
VERSION=v0.0.1
TARGET=aarch64-apple-darwin
ARCHIVE=ptuf-$TARGET.tar.gz
BASE=https://github.com/watany-dev/ptuf/releases/download/$VERSION

curl -LO "$BASE/$ARCHIVE"
curl -LO "$BASE/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "$ARCHIVE" \
  --repo watany-dev/ptuf \
  --source-ref refs/tags/$VERSION
tar -xzf "$ARCHIVE" --strip-components=1
install -m 0755 ptuf ~/.cargo/bin/ptuf
```

Windows (PowerShell):

```powershell
$Version = "v0.0.1"
$Target = "x86_64-pc-windows-msvc"
$Archive = "ptuf-$Target.zip"
$Base = "https://github.com/watany-dev/ptuf/releases/download/$Version"

curl.exe -LO "$Base/$Archive"
curl.exe -LO "$Base/SHA256SUMS"
$Expected = (Get-Content SHA256SUMS | Where-Object { $_ -match ([regex]::Escape($Archive) + "$") } | ForEach-Object { ($_ -split "\s+")[0] })
$Actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "checksum mismatch for $Archive" }
gh attestation verify $Archive `
  --repo watany-dev/ptuf `
  --source-ref refs/tags/$Version
Expand-Archive $Archive -DestinationPath .
```

### Installer scripts (unverified)

Linux / macOS:

```bash
PTUF_VERSION=v0.0.1
curl -LsSf "https://github.com/watany-dev/ptuf/releases/download/$PTUF_VERSION/ptuf-installer.sh" | sh
```

Windows (PowerShell):

```powershell
$env:PTUF_VERSION = "v0.0.1"
powershell -ExecutionPolicy Bypass -c "irm https://github.com/watany-dev/ptuf/releases/download/$env:PTUF_VERSION/ptuf-installer.ps1 | iex"
```

Installer scripts remain available for compatibility, but the verified archive
path above is preferred for pinned installs.

### From crates.io

```bash
cargo install ptuf
```

### From source

```bash
make build
cargo install --path .
```

## CLI

```text
ptuf hook <agent>
ptuf eval --tool <name> <command>
ptuf plugin test <path>
ptuf init claude-code [--dry-run] [--settings <path>] [--verify [--json]]
ptuf init codex [--dry-run] [--root <path>] [--hooks <path>] [--config <path>] [--verify [--json]]
ptuf doctor [--json]
ptuf --help
ptuf --version
```

`ptuf hook <agent>` is the hook entry point. `ptuf eval` is the manual,
one-shot evaluator for shell use and debugging.

## Hook Behavior

The hook reads a payload such as:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf /"
  }
}
```

Claude Code behavior:

- `Allow` / `Monitor` — exit `0`, no hook JSON on stdout
- `Ask` — exit `0`, `hookSpecificOutput.permissionDecision = "ask"`
- `Deny` — exit `2`, `hookSpecificOutput.permissionDecision = "deny"`

Codex behavior:

- `Allow` / `Monitor` — exit `0`, no hook JSON on stdout
- `Ask` is converted to `Deny` because Codex `PreToolUse` cannot prompt
  interactively
- `Deny` — exit `2`, `hookSpecificOutput.permissionDecision = "deny"`

For both adapters, the human-readable reason is also written to stderr for
`Ask` or `Deny`. Hook stdin payloads are capped at 8 MiB. Unreadable, oversized,
or invalid-JSON stdin is rejected with `Deny` (exit `2`) under the reserved
`core.engine.invalid-payload` rule so Claude Code blocks the tool — `exit 1`
would only surface a non-blocking warning and let the call through.

## Claude Code

The simplest path is:

```bash
ptuf init claude-code
ptuf init claude-code --dry-run
ptuf init claude-code --verify           # install + run synthetic deny check
ptuf init claude-code --verify --json    # machine-readable verify report
```

This writes or updates `~/.claude/settings.json` with a `PreToolUse` entry like:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|WebFetch|mcp__.*",
        "hooks": [
          {
            "name": "ptuf",
            "type": "command",
            "command": "/absolute/path/to/ptuf hook claude-code"
          }
        ]
      }
    ]
  }
}
```

The installer is idempotent. It detects an existing ptuf entry by the
`name: "ptuf"` marker, and still recognizes the legacy command tail
`hook claude-code` regardless of the absolute binary path.

## Codex

The default install target is repo-local:

```bash
ptuf init codex
ptuf init codex --dry-run
ptuf init codex --root /path/to/repo
ptuf init codex --hooks /tmp/hooks.json --config /tmp/config.toml
ptuf init codex --verify           # install + run synthetic deny check
```

That writes:

- `<repo>/.codex/hooks.json`
- `<repo>/.codex/config.toml`

with:

- matcher: `Bash|apply_patch|mcp__.*`
- command: `/absolute/path/to/ptuf hook codex`
- `features.codex_hooks = true`

## Configuration

ptuf merges YAML config in this order:

1. `/etc/ptuf/policy.yaml`
2. `~/.config/ptuf/config.yaml`
3. `<repo>/.ptuf.yaml`
4. `<repo>/.ptuf.local.yaml`

Example:

```yaml
version: 1

mode: enforce
failClosed: true

packs:
  core.project_hygiene:
    enabled: true
    protectedBranches:
      - main
      - master
      - release/*

rules:
  core.git.reset-hard:
    decision: ask

plugins:
  - path: ~/.config/ptuf/plugins/team.yaml
    enabled: true

allowlists:
  - id: allow-local-dev-webhook
    appliesTo:
      rules:
        - acme.dev.local-post
    when:
      url.hostAny:
        - localhost
        - 127.0.0.1
    expiresAt: "2026-12-31T23:59:59Z"
    reason: Local development callback.

audit:
  path: ~/.local/share/ptuf/audit.jsonl
  includeAllowed: false
  includeDenied: true
  redaction: strict
```

## Plugins

Plugin files use `apiVersion: ptuf.dev/v1` and `kind: Plugin`. Each rule can
include `tests.deny` and `tests.allow`, which are executed with:

```bash
ptuf plugin test ./ptuf-plugin.yaml
```

Plugin tests evaluate the plugin rule itself, not the full built-in engine.

For end-to-end protocol regressions, the repository also keeps
`tests/contracts.rs` plus JSON fixtures for hook/audit/doctor behavior.

## Library Use

```rust
use ptuf::{Decision, HookInput, decide};

let input: HookInput = serde_json::from_str(payload)?;
match decide(&input) {
    Decision::Allow => {}
    Decision::Monitor { .. } => {}
    Decision::Ask { reason, .. } => {}
    Decision::Deny { reason, .. } => {}
}
```

`decide()` is intentionally backward-compatible and lenient: it tries
`Engine::for_cwd()` first and falls back to `Engine::builder().agent(
"embed-fallback").build()` if policy or plugin loading fails. The fallback
engine still populates `ProtectedPaths` (running binary, Claude/Codex
settings) so self-protection guardrails remain in place. The CLI path is
stricter and fails closed.

For embedded callers that want the same fail-closed contract as the CLI, use
`try_decide(&HookInput) -> Result<Decision, EngineError>` instead — it
surfaces config and plugin load errors rather than silently degrading.

## Develop

After cloning, install the tracked git hooks once:

```bash
make install-hooks
```

This points `core.hooksPath` at `scripts/hooks/`, so `git push` will run
`make check` automatically and refuse to push when CI gates would fail.
Bypass with `git push --no-verify` only in true emergencies.

Before pushing, run:

```bash
make check
make coverage
make pbt
```

- `make check` runs the five core gates that block CI:
  `fmt-check`, `clippy`, `test`, `cargo doc`, and `cargo-deny`. CI
  additionally runs `cargo tarpaulin` (95% floor, see `make coverage`),
  an MSRV `cargo check` on Rust 1.93.0, `actionlint`, and `cargo-machete`.
  Daily, `cargo audit` runs as a scheduled workflow.
- Lint policy: `unsafe_code` is forbidden, and `clippy::pedantic` /
  `nursery` / `cargo` run as group warnings. A curated `restriction`
  set is denied (`unwrap_used`, `expect_used`, `panic`, `todo`,
  `unimplemented`, `dbg_macro`, `print_stdout`, `print_stderr`, `exit`,
  `mem_forget`, `unreachable`, ...). See `Cargo.toml [lints.*]` and
  `clippy.toml` for the full matrix; tests are exempted via
  `clippy.toml`'s `allow-{unwrap,expect,panic,print,dbg}-in-tests`.
- `make coverage` runs `cargo tarpaulin` with a `95%` floor and excludes
  `src/main.rs` plus Windows-specific files (`*_windows.rs`,
  `windows*.rs`); the Windows code paths are exercised by the
  `windows-latest` test job
- `make pbt` reruns the property-based test suite at
  `PBT_CASES=10000` by default — run before tagging a release

The first invocation of `make check` or `make coverage` will run a `tools`
prerequisite that installs missing supply-chain binaries via
`cargo install --locked` (`cargo-deny` for `make check`, `cargo-tarpaulin`
for `make coverage`). Pinned versions live in the `Makefile` as
`CARGO_DENY_VERSION` / `CARGO_TARPAULIN_VERSION` and must stay in sync with
`.github/workflows/ci.yml`. To skip the auto-install (CI or pre-provisioned
environments), pass `SKIP_TOOL_INSTALL=1`; missing tools then fail fast
instead of being installed. To force a reinstall when an older copy is on
your `PATH`, run e.g.
`cargo install --locked --force cargo-deny@0.19.2`.

## Design Docs

Start with [`docs/design/overview.md`](docs/design/overview.md). The design set
covers architecture, decision semantics, built-in packs, config and plugins,
CLI and hook integration, audit logging, testing, and roadmap notes.

## License

Apache-2.0. See `LICENSE`.
