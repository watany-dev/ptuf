# ptuf

`ptuf` (PreToolUseFilter) is a generic guardrail layer for coding agents.
It is invoked from a `PreToolUse` hook (e.g. Claude Code), reads the hook
payload from stdin as JSON, evaluates it, and returns an Allow / Deny
decision via exit code and stderr.

- **Allow** — exit code `0`
- **Deny** — exit code `2`, with a human-readable reason on stderr

## Status

Bootstrap. The `decide()` core currently allows everything; rule support
is the next milestone.

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

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | cargo run -q
echo "exit=$?"   # 0 = Allow
```

## Use as a Claude Code PreToolUse hook

Add an entry to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "command": "/absolute/path/to/ptuf" }
    ]
  }
}
```

Claude Code pipes the tool-use request to `ptuf` as JSON; a non-zero exit
code blocks the tool call and the stderr message is shown to the user.

## Embed as a library

```rust
use ptuf::{Decision, HookInput, decide};

let input: HookInput = serde_json::from_str(payload)?;
match decide(&input) {
    Decision::Allow => { /* let it through */ }
    Decision::Deny { reason } => { /* surface reason */ }
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

The intended scope reaches far beyond the current bootstrap. Start with
[`docs/design/overview.md`](docs/design/overview.md) for goals, non-goals, and
an index of the design notes (architecture, decision model, policy packs,
config and plugins, CLI and hook integration, audit log, roadmap).

## License

Apache-2.0. See `LICENSE`.
