# ptuf

`ptuf` (PreToolUseFilter) is a generic guardrail layer for coding agents.
It is invoked from a `PreToolUse` hook (e.g. Claude Code), reads the hook
payload from stdin as JSON, evaluates it, and returns an Allow / Deny
decision via exit code and stderr.

- **Allow** — exit code `0`
- **Deny** — exit code `2`, with a human-readable reason on stderr

## Status

v0.2 — three built-in `core.*` rules with fact-based evaluation, YAML
configuration scope merge, YAML plugin support with a `when:` DSL, and
audit JSONL with strict redaction.

Built-in rules (always enabled, hard-deny):

- `core.filesystem.destructive-rm` — `rm -rf /`, `rm -rf ~`, `rm -rf /etc`, etc.
- `core.network.remote-script-pipe` — `curl ... | bash` and friends
- `core.secrets.sensitive-path-to-network` — co-occurrence of a sensitive
  path (e.g. `~/.ssh/`, `*.tfstate`, `id_rsa`) with a network sink
  (`curl`, `scp`, `rsync`, ...) in the same command

v0.2 features:

- **Fact extraction** — shell argv / pipeline lexer, URL / path / sensitive-path
  classifiers, and a basic dataflow (sensitive → network) check; plugins write
  rules against these structured facts instead of raw shell regex.
- **YAML config scope merge** — `/etc/ptuf/policy.yaml` →
  `~/.config/ptuf/config.yaml` → `<repo>/.ptuf.yaml` →
  `<repo>/.ptuf.local.yaml`. Each scope can set `mode`, `failClosed`,
  `packs.<id>.enabled`, `plugins`, `allowlists`, and `audit.*`.
- **YAML plugins** — `apiVersion: ptuf.dev/v1, kind: Plugin` with a
  `when:` DSL (`all` / `any` / `not` / `tool` / `shell.argv` /
  `shell.pipeline` / `url.*` / `path.*`). `requires:` declarations
  validated at load time.
- **`ptuf plugin test <path>`** — runs the plugin's `tests:` section
  end-to-end and exits non-zero on regressions.
- **Audit JSONL** — every decision is recorded to
  `~/.local/share/ptuf/audit.jsonl` (overridable). Strict redaction
  masks env-var token assignments, GH / OpenAI / AWS keys, JWTs,
  HTTP basic auth, and PEM blobs.
- **Allowlists with `expiresAt`** — time-bound exceptions per rule id.
  `hardDeny: true` rules (the three builtins, and any plugin rule
  marked as such) ignore allowlist suppression.

Other tools (`Read`, `Write`, `Edit`, ...) are still passed through
unchanged in v0.2; broader tool coverage and `core.self_protection`
land in v0.3 ([`docs/design/roadmap.md`](docs/design/roadmap.md)).

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

`ptuf` exposes three invocation styles. All of them share the same
`decide()` core.

```bash
# 1. Compatibility mode: stdin JSON -> exit code (0 allow / 2 deny)
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | cargo run -q
echo "exit=$?"   # 0 = Allow

# 2. Hook subcommand: same as above, but also writes a Claude-Code
#    `hookSpecificOutput` JSON envelope to stdout on deny / ask.
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
    | cargo run -q -- hook claude-code pre-tool-use

# 3. One-shot eval: handy for trying a rule from the shell.
cargo run -q -- eval --tool Bash 'rm -rf /'
```

Exit codes are uniform across all three: `0` for allow / monitor / ask,
`2` for deny, `1` for an internal error (invalid JSON, unknown
subcommand, ...).

## Use as a Claude Code PreToolUse hook

Add an entry to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "command": "/absolute/path/to/ptuf hook claude-code pre-tool-use" }
    ]
  }
}
```

Claude Code pipes the tool-use request to `ptuf` as JSON; a non-zero exit
code blocks the tool call and the `hookSpecificOutput` JSON / stderr
message is surfaced to both the agent and the user. The bare
`/absolute/path/to/ptuf` form (without the subcommand) keeps working as a
compatibility mode for older configurations.

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
```

CI mirrors `make check` plus an MSRV check, an `actionlint` lint of the
workflow itself, and a coverage gate.

## Design docs

The intended scope reaches far beyond the current v0.1 milestone. Start
with [`docs/design/overview.md`](docs/design/overview.md) for goals,
non-goals, and an index of the design notes (architecture, decision
model, policy packs, config and plugins, CLI and hook integration, audit
log, roadmap).

## License

Apache-2.0. See `LICENSE`.
