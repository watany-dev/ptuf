# ptuf

`ptuf` (PreToolUseFilter) is a generic guardrail layer for coding agents.
It is invoked from a `PreToolUse` hook (e.g. Claude Code), reads the hook
payload from stdin as JSON, evaluates it, and returns an Allow / Deny
decision via exit code and stderr.

- **Allow** — exit code `0`
- **Deny** — exit code `2`, with a human-readable reason on stderr

## Status

v0.4 — broader tool coverage (`Read` / `Edit` / `Write` / `WebFetch` in
addition to `Bash`), built-in packs for git and self-protection, MCP
fact extraction, and a streamlined CLI surface (`ptuf hook <agent>` /
`ptuf init <agent>` / `ptuf eval` / `ptuf doctor` / `ptuf plugin test`).
v0.3's bare-`ptuf` compatibility mode and the `pre-tool-use` hierarchy
token were removed; agents are now selected exclusively by the
positional `<agent>` argument.

Built-in rules (always enabled, hard-deny unless noted):

- `core.filesystem.destructive-rm` — `rm -rf /`, `rm -rf ~`, `rm -rf /etc`, …
- `core.network.remote-script-pipe` — `curl ... | bash` and friends
- `core.secrets.sensitive-path-to-network` — co-occurrence of a sensitive
  path with a network sink in the same command
- `core.secrets.sensitive-read` *(new in v0.3)* — `Read` / `Edit` of a
  credentials file (SSH key, AWS / gcloud / kube config, dotenv, npmrc,
  pypirc, tfstate, PEM blob, …)
- `core.git.*` *(new in v0.3, 7 rules)* — `force-push` (deny),
  `force-push-with-lease` / `reset --hard` / `clean -fdx` /
  `branch -D` / `stash clear` / `remote set-url` (ask)
- `core.self_protection.*` *(new in v0.3, 5 rules)* — modifications to the
  ptuf binary, its config files, registered plugin paths, the Claude Code
  `settings.json` file, or any hook-script referenced by it
- `core.project_hygiene.*` *(new in v0.4, 3 rules, opt-in)* —
  `lock-mismatch-pnpm` / `lock-mismatch-uv` block running the wrong
  package manager when a competing lockfile is checked in;
  `protected-branch-destructive-git` upgrades `core.git`'s `ask` rules
  to `deny` while on `main` / `master` / `release/*`. Disabled by
  default — enable with `packs.core.project_hygiene.enabled: true`.

v0.4 features (additive on top of v0.3):

- **MCP fact extraction** — `mcp__<server>__<tool>` calls are normalised
  on the generic top-level `path` / `url` / `content` keys, so existing
  rules (`core.self_protection.*`, `core.secrets.sensitive-read`,
  `core.secrets.sensitive-path-to-network`) protect MCP-driven edits
  without needing a per-server adapter.
- **Audit log v1 schema** — records carry `schemaVersion: 1`, `agent`,
  `pluginVersions`, and `allowlistId` (see above).
- **Structured `ptuf doctor --json`** — stable `schemaVersion: 1`
  envelope for CI / audit tooling.
- **`core.project_hygiene` v1** *(opt-in)* — see the rule list above.
- **Streamlined CLI surface** — `Compat` (bare `ptuf`) and the
  `pre-tool-use` hierarchy token were removed; use
  `ptuf hook claude-code` explicitly.

v0.3 features (additive on top of v0.2):

- **Tool-aware fact extraction** — `path` (`~`-expanded `file_path`),
  `url` (scheme/host/port/path), `sensitive_path` (variant-tagged), and
  `protected` (paths that ptuf must not let the agent touch).
- **Plugin DSL leaves** — `path.filePathPrefixAny`, `url.schemeAny`,
  `url.hostAny`, `sensitive.pathKindAny`. See
  [`docs/examples/cloud-metadata.yaml`](docs/examples/cloud-metadata.yaml)
  for an IMDS WebFetch deny sample.
- **`ptuf init claude-code`** — idempotent install of the PreToolUse hook
  entry into `~/.claude/settings.json` with `--dry-run` and
  `--settings <PATH>` flags. Detection is token-based so a re-run with a
  different binary path still recognises an existing entry.
- **`ptuf doctor`** — diagnostic report covering the binary, project
  scope, effective config, loaded plugins, and Claude Code integration.
  Exit 0 when every section is ✓ or ⚠; exit 1 when any section reports ✗.
  `--json` emits a stable `schemaVersion: 1` envelope (binary, config
  layers, plugins, claude integration state, `hasFailure`) for CI /
  audit tooling.
- **Fail-closed CLI** — every CLI entry point (`ptuf hook ...` /
  `ptuf eval`) deny-fails when the engine cannot load policy, surfacing
  the reserved rule id `core.engine.policy-load-failed`.
  Library-mode `crate::decide` still falls back to a default engine for
  embedded callers.

v0.2 features carried forward:

- **YAML config scope merge** — `/etc/ptuf/policy.yaml` →
  `~/.config/ptuf/config.yaml` → `<repo>/.ptuf.yaml` →
  `<repo>/.ptuf.local.yaml`. Each scope can set `mode`, `failClosed`,
  `packs.<id>.enabled`, `plugins`, `allowlists`, and `audit.*`.
- **YAML plugins** — `apiVersion: ptuf.dev/v1, kind: Plugin` with a
  `when:` DSL. `requires:` declarations validated at load time.
- **`ptuf plugin test <path>`** — runs the plugin's `tests:` section
  end-to-end and exits non-zero on regressions.
- **Audit JSONL** — every decision is recorded to
  `~/.local/share/ptuf/audit.jsonl` (overridable). Records carry
  `schemaVersion: 1`, the calling `agent` (`claude-code` / `cli`),
  loaded `pluginVersions` (`name@version` array), and the
  `allowlistId` that suppressed a rule when the outcome was `Allow`.
  Strict redaction masks env-var token assignments, GH / OpenAI / AWS
  keys, JWTs, HTTP basic auth, and PEM blobs.
- **Allowlists with `expiresAt`** — time-bound exceptions per rule id.
  `hardDeny: true` rules ignore allowlist suppression.

> **Note on Windows:** the audit JSONL writer relies on POSIX
> `O_APPEND` semantics for atomic concurrent appends. On Windows,
> ptuf still writes the file but interleaving across processes is
> best-effort.

## Requirements

- Rust `1.93.0` or newer (MSRV is pinned in `Cargo.toml`)
- `lld` linker for the default x86_64 Linux build profile
- `cargo-deny` and `cargo-tarpaulin` for the full quality pipeline

## Build

```bash
cargo build --release
# or, via the Makefile
make build
```

## Run

`ptuf` exposes two invocation styles. Both share the same `decide()`
core.

```bash
# 1. Hook subcommand: stdin JSON -> exit code + `hookSpecificOutput`
#    envelope on stdout (deny / ask only). The agent name is required
#    so the same binary can serve future Codex / Cursor / Gemini
#    adapters via `ptuf hook <agent>`.
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
    | cargo run -q -- hook claude-code

# 2. One-shot eval: handy for trying a rule from the shell.
cargo run -q -- eval --tool Bash 'rm -rf /'
```

Exit codes are uniform across both: `0` for allow / monitor / ask,
`2` for deny, `1` for an internal error (invalid JSON, missing
subcommand, ...).

## Use as a Claude Code PreToolUse hook

The simplest way is to let `ptuf init claude-code` write the entry for
you (idempotent; safe to re-run after upgrades):

```bash
ptuf init claude-code             # writes ~/.claude/settings.json
ptuf init claude-code --dry-run   # show the diff without touching the file
```

The resulting `~/.claude/settings.json` looks like:

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

Claude Code pipes the tool-use request to `ptuf` as JSON; a non-zero exit
code blocks the tool call and the `hookSpecificOutput` JSON / stderr
message is surfaced to both the agent and the user.

> **Migrating from v0.3:** the legacy 3-token entry
> (`ptuf hook claude-code pre-tool-use`) and the bare `ptuf`
> compatibility mode were removed in v0.4. Re-run
> `ptuf init claude-code` to append a fresh entry with the new
> 2-token form; the old entry is detected as unrelated and can be
> removed manually.

Run `ptuf doctor` afterwards to confirm the binary, repo scope, loaded
plugins, and hook registration are all healthy.

## Configure

Drop a YAML file at `~/.config/ptuf/config.yaml` (or any of the four
scope locations above) to control the engine:

```yaml
version: 1

mode: enforce            # enforce | monitor | observe
failClosed: true

packs:
  core.network:
    enabled: true

plugins:
  - path: ~/.config/ptuf/plugins/no-curl.yaml

allowlists:
  - id: allow-localhost-curl
    appliesTo:
      rules:
        - pack.demo.no-curl
    expiresAt: "2026-12-31T23:59:59Z"
    reason: Local dev callbacks.

audit:
  path: ~/.local/share/ptuf/audit.jsonl
  includeAllowed: false
  includeDenied: true
  redaction: strict      # or "off" if you understand the risk
```

Validate a plugin and its bundled `tests:` section:

```bash
ptuf plugin test ./ptuf-plugin.yaml
```

## Embed as a library

```rust
use ptuf::{Decision, HookInput, decide};

let input: HookInput = serde_json::from_str(payload)?;
match decide(&input) {
    Decision::Allow => { /* let it through */ }
    Decision::Monitor { .. } => { /* allow but log */ }
    Decision::Ask { reason, .. } => { /* prompt user */ }
    Decision::Deny { reason, .. } => { /* surface reason */ }
}
```

## Develop

Run the full pipeline locally before pushing:

```bash
make check       # fmt-check + clippy + test + doc + cargo-deny
make coverage    # cargo-tarpaulin (>= 95%)
make pbt         # property-based testing at PBT_CASES=10000 (override with PBT_CASES=N)
```

`cargo test` runs every `proptest!` block at the default 256 cases as part of
`make check`; `make pbt` re-runs the same suite at a higher case count for
release-time deep checks. Shrunk counterexamples are persisted under
`proptest-regressions/` and committed to git so the same seeds replay across
machines.

CI mirrors `make check` plus an MSRV check, an `actionlint` lint of the
workflow itself, and a coverage gate.

## Design docs

The intended scope reaches beyond the current v0.4 milestone (multi-agent
adapters, signed plugins, `dataflow.basic`, …). Start with
[`docs/design/overview.md`](docs/design/overview.md) for goals,
non-goals, and an index of the design notes (architecture, decision
model, policy packs, config and plugins, CLI and hook integration, audit
log, testing, roadmap).

## License

Apache-2.0. See `LICENSE`.
