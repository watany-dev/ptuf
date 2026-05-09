# ptuf

`ptuf` (PreToolUseFilter) is a guardrail for coding agents. It runs from a
`PreToolUse` hook, reads the tool request JSON from stdin, evaluates built-in
rules plus optional YAML plugins, and returns the result through exit code,
stderr, and agent-specific `hookSpecificOutput` JSON.

- `0` — allow, monitor, or ask
- `2` — deny
- `1` — internal error such as invalid JSON, bad CLI arguments, or policy load
  failure

`ptuf` currently ships first-class adapters for Claude Code, Codex,
GitHub Copilot, and Kiro CLI. Each adapter has matching `hook` and
`init` integration so the same policy engine and YAML plugins back
every host. `ptuf init` auto-detects every reachable agent under cwd /
`$HOME` and installs the `PreToolUse` hook into all of them, with
post-install verify enabled by default.

## Status

v0.0.1 ships:

- Built-in packs for filesystem, network, secrets, git, self-protection, the
  dynamic-eval engine guard, and opt-in project hygiene
- Tool-aware fact extraction for `Bash`, `Read`, `Edit`, `Write`, `WebFetch`,
  and generic `mcp__<server>__<tool>` payloads
- Bounded wrapper inspection for `bash -c`, `sh -c`, `eval`, `xargs`, and
  `find -exec`, including wrapped redirect targets for self-protection
- Layered YAML config and YAML plugins with rule-local `tests:`
- `ptuf init` auto-detects Claude Code, Codex, GitHub Copilot, and
  Kiro CLI under cwd / `$HOME` and installs hooks for each
- Audit JSONL with `schemaVersion: 1`, `agent`, `pluginVersions`, and
  `allowlistId`
- Contract tests for hook JSON, `init --json`, audit schema, allowlists, MCP
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
ptuf [--json] check --tool <name> <command>
ptuf [--json] plugin check <path>
ptuf [--json] init [<agent>] [--no-verify] [--dry-run]
ptuf --help
ptuf --version
```

`ptuf hook <agent>` is the hook entry point. `ptuf check` is the manual,
one-shot evaluator for shell use and debugging. `ptuf init` auto-detects
every agent reachable from cwd / `$HOME`, or you can pin to one
adapter (`claude-code` | `codex` | `copilot` | `kiro`).

`--json` is a global, top-level flag; it must appear *before* the
subcommand. `hook` does not accept `--json` because the hook protocol
output shape is fixed by the host. `init` runs the post-install verify
by default; pass `--no-verify` to skip, or `--dry-run` to plan only
(dry-run implicitly turns verify off because nothing is written).

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

GitHub Copilot behavior:

- Copilot's `preToolUse` hook protocol treats non-zero exit as a hook
  *failure* and may let the tool call proceed. To stay fail-closed, the
  Copilot adapter always exits `0` and emits a *bare* JSON envelope
  (no `hookSpecificOutput` wrapper):

  ```json
  {"permissionDecision":"deny","permissionDecisionReason":"…"}
  ```

- `Allow` / `Monitor` — exit `0`, empty stdout
- `Ask` is converted to `Deny` because Copilot's `preToolUse` cannot
  reliably prompt interactively
- `Deny` — exit `0`, bare deny JSON
- Invalid JSON, oversized stdin, and policy-load failures all emit a
  bare deny JSON at exit `0` under the reserved
  `core.engine.invalid-payload` / `core.engine.policy-load-failed`
  rules

Kiro CLI behavior:

- Kiro's `preToolUse` hook protocol carries no JSON envelope, so the
  Kiro adapter writes nothing to stdout
- `Allow` / `Monitor` — exit `0`, empty stdout/stderr
- `Ask` is converted to `Deny` because Kiro `preToolUse` does not
  define an interactive prompt channel
- `Deny` — exit `2`, deny reason on stderr only
- Invalid JSON, oversized stdin, and policy-load failures all emit a
  stderr-only deny at exit `2` under the reserved
  `core.engine.invalid-payload` / `core.engine.policy-load-failed`
  rules

Claude Code, Codex, and Kiro set the human-readable reason on stderr for
`Ask` or `Deny`. Copilot likewise writes the reason to stderr alongside
the bare JSON envelope.

Hook stdin payloads are capped at 8 MiB. For Claude Code, Codex, and
Kiro, unreadable, oversized, or invalid-JSON stdin is rejected with
`Deny` (exit `2`) under the reserved `core.engine.invalid-payload` rule
so the host blocks the tool — `exit 1` would only surface a non-blocking
warning and let the call through. Copilot uses the same reserved rule
but at exit `0` (see above).

## Auto-detect

```bash
ptuf init                  # detect every agent under cwd / $HOME
ptuf init --dry-run        # show plan only (no writes, no verify)
ptuf init --no-verify      # install but skip the synthetic deny check
ptuf --json init           # machine-readable verify report
```

`ptuf init` checks the following locations and installs into each
match:

| Agent       | Detection condition                              | Install target                          |
|-------------|--------------------------------------------------|-----------------------------------------|
| ClaudeCode  | `$HOME/.claude/`                                 | `$HOME/.claude/settings.json`           |
| Codex       | `<repo>/.codex/` or `$HOME/.codex/`              | `<repo>/.codex/{hooks.json,config.toml}` |
| Copilot     | `<repo>/.github/`                                | `<repo>/.github/hooks/ptuf.json`        |
| Kiro        | `<repo>/.kiro/` or `$HOME/.kiro/`                | `<repo>/.kiro/agents/ptuf-guarded.json`  |

To opt out of any auto-detected target, pass an explicit agent token:
`ptuf init claude-code` (or `codex` / `copilot` / `kiro`) restricts the
install to that single adapter. Use `--dry-run` first if you are unsure
which targets `ptuf init` would touch.

## Claude Code

```bash
ptuf init claude-code
ptuf init claude-code --dry-run
ptuf init claude-code --no-verify
ptuf --json init claude-code     # machine-readable verify report
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
ptuf init codex --no-verify
```

That writes:

- `<repo>/.codex/hooks.json`
- `<repo>/.codex/config.toml`

with:

- matcher: `Bash|apply_patch|mcp__.*`
- command: `/absolute/path/to/ptuf hook codex`
- `features.codex_hooks = true`

## GitHub Copilot

The default install target is repo-local:

```bash
ptuf init copilot
ptuf init copilot --dry-run
ptuf init copilot --no-verify
```

That writes `<repo>/.github/hooks/ptuf.json` with a `preToolUse` entry
containing both `bash` and `powershell` command strings. The installer
is idempotent — re-running it detects an existing ptuf entry by the
`hook copilot` command tail.

## Kiro CLI

The default install target is repo-local:

```bash
ptuf init kiro
ptuf init kiro --dry-run
ptuf init kiro --no-verify
```

That writes `<repo>/.kiro/agents/ptuf-guarded.json` with a
`hooks.preToolUse` entry whose `command` invokes `<ptuf> hook kiro`.
The installer falls back to `~/.kiro/agents/ptuf-guarded.json` when no
repo root with a `.kiro/` directory is found. The installer is
idempotent — re-running it detects an existing ptuf entry by the
`hook kiro` command tail and leaves the file untouched.

Kiro `preToolUse` payloads use a different vocabulary than Claude Code,
so the adapter normalises tool names and `tool_input` keys before the
engine sees them:

- `shell` / `execute_bash` / `execute_cmd` → `Bash` (`command` falls
  back to `cmd` → `script`)
- `read` / `fs_read` / `fsRead` → `Read` (`file_path` falls back to
  `path` → `paths[0]` → `operations[0].path` → `files[0].path` →
  `items[0].path`)
- `write` / `fs_write` / `fsWrite` → `Write` (`file_path` resolved as
  above; `content` falls back to `text` → `new_content`)
- `web_fetch` / `webFetch` → `WebFetch`
- `@server/tool` → `mcp__server__tool` (extra path segments collapse to
  `_`; empty segments fall through to the raw name)
- anything else passes through with its raw name and the engine's
  generic / MCP extractors handle it best-effort

`hook_event_name` other than `preToolUse` is rejected with
`core.engine.invalid-payload`.

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
ptuf plugin check ./ptuf-plugin.yaml
```

Plugin tests evaluate the plugin rule itself, not the full built-in engine.

For end-to-end protocol regressions, the repository also keeps
`tests/contracts.rs` plus JSON fixtures for hook, audit, and `init --json`
verify behavior.

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
