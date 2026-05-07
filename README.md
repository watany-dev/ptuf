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

- Built-in packs for filesystem, network, secrets, git, self-protection, and
  opt-in project hygiene
- Tool-aware fact extraction for `Bash`, `Read`, `Edit`, `Write`, `WebFetch`,
  and generic `mcp__<server>__<tool>` payloads
- Layered YAML config and YAML plugins with rule-local `tests:`
- `ptuf init <agent>` for Claude Code and Codex hook installation
- `ptuf doctor [--json]` for binary/config/plugin/hook diagnostics
- Audit JSONL with `schemaVersion: 1`, `agent`, `pluginVersions`, and
  `allowlistId`

## Requirements

- Rust `1.93.0` or newer
- `lld` for the default Linux build profile
- `cargo-deny` and `cargo-tarpaulin` for the full local quality pipeline

## Install

### Verified install (recommended)

Set the exact version you want, download the canonical archive for your
platform, and verify it before extracting:

```bash
PTUF_VERSION=v0.0.1
ASSET=ptuf-x86_64-unknown-linux-musl.tar.gz
BASE_URL=https://github.com/watany-dev/ptuf/releases/download/$PTUF_VERSION

curl -LsSfO "$BASE_URL/$ASSET"
curl -LsSfO "$BASE_URL/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf "$ASSET" --strip-components=1
install -m 0755 ptuf ~/.cargo/bin/ptuf
```

Optional provenance check with the GitHub CLI:

```bash
gh attestation verify "$ASSET" \
  --repo watany-dev/ptuf \
  --signer-workflow watany-dev/ptuf/.github/workflows/release.yml \
  --source-ref refs/tags/$PTUF_VERSION
```

Windows users can download `ptuf-x86_64-pc-windows-msvc.zip` and verify it
against the same `SHA256SUMS` file.

### Installer scripts

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
ptuf init claude-code [--dry-run] [--settings <path>]
ptuf init codex [--dry-run] [--root <path>] [--hooks <path>] [--config <path>]
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
`Ask` or `Deny`. Hook stdin payloads are capped at 8 MiB; larger payloads exit
`1` with a stderr error before JSON parsing.

## Claude Code

The simplest path is:

```bash
ptuf init claude-code
ptuf init claude-code --dry-run
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
            "type": "command",
            "command": "/absolute/path/to/ptuf hook claude-code"
          }
        ]
      }
    ]
  }
}
```

The installer is idempotent. It detects an existing ptuf entry by the command
tail `hook claude-code`, regardless of the absolute binary path.

## Codex

The default install target is repo-local:

```bash
ptuf init codex
ptuf init codex --dry-run
ptuf init codex --root /path/to/repo
ptuf init codex --hooks /tmp/hooks.json --config /tmp/config.toml
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
`Engine::for_cwd()` first and falls back to `Engine::default()` if policy or
plugin loading fails. The CLI path is stricter and fails closed.

## Develop

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
- `make coverage` runs `cargo tarpaulin` with a `95%` floor and excludes
  `src/main.rs` plus Windows-specific files (`*_windows.rs`,
  `windows*.rs`); the Windows code paths are exercised by the
  `windows-latest` test job
- `make pbt` reruns the property-based test suite at
  `PBT_CASES=10000` by default — run before tagging a release

## Design Docs

Start with [`docs/design/overview.md`](docs/design/overview.md). The design set
covers architecture, decision semantics, built-in packs, config and plugins,
CLI and hook integration, audit logging, testing, and roadmap notes.

## License

Apache-2.0. See `LICENSE`.
