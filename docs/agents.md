# Wiring ptuf into a coding agent

ptuf ships first-class adapters for **Claude Code**, **Codex**, **GitHub
Copilot**, and **Kiro CLI**. The same policy engine and YAML plugins back
every host; only the hook-protocol envelope differs.

This page is the user-facing how-to. For the underlying hook protocol, exit
codes per agent, and the full payload contract, see the design notes:

- `docs/design/cli-and-hooks.md` — CLI surface and per-host adapter contracts
- `docs/design/kiro-cli.md` — Kiro tool-name / payload normalization
- `docs/design/decision-model.md` — `Allow` / `Monitor` / `Ask` / `Deny`
  semantics

## Common verification flags

Every `ptuf init <agent>` accepts:

| Flag | Effect |
| --- | --- |
| `--dry-run` | Print what would be written without touching files |
| `--verify` | After install, run a synthetic deny payload + a synthetic policy-load failure to prove the wiring is fail-closed |
| `--verify --json` | Same as `--verify`, but emit a machine-readable report |

After install (or any time later), run `ptuf doctor` for a multi-section
status report covering binary path, config layers, plugins, and hook entries
across all four hosts.

## Claude Code

```bash
ptuf init claude-code            # writes ~/.claude/settings.json
ptuf init claude-code --dry-run
ptuf init claude-code --verify
ptuf init claude-code --verify --json
```

The installer adds (or updates, idempotently) a `PreToolUse` hook entry
matching `Bash|Read|Edit|Write|WebFetch|mcp__.*` and pointing at the
absolute path of `ptuf hook claude-code`. It detects an existing ptuf entry
by the `name: "ptuf"` marker and also recognises the legacy
`hook claude-code` command tail.

## Codex

The default install target is repo-local:

```bash
ptuf init codex                  # writes <repo>/.codex/{hooks.json,config.toml}
ptuf init codex --dry-run
ptuf init codex --root /path/to/repo
ptuf init codex --hooks /tmp/hooks.json --config /tmp/config.toml
ptuf init codex --verify
```

Hook matcher is `Bash|apply_patch|mcp__.*`, command is `<absolute>/ptuf hook
codex`, and `features.codex_hooks = true` is set. Because Codex `PreToolUse`
cannot prompt interactively, the adapter converts `Ask` decisions to `Deny`.

## GitHub Copilot

The default install target is repo-local:

```bash
ptuf init copilot --profile local            # writes <repo>/.github/hooks/ptuf.json
ptuf init copilot --profile local --dry-run
ptuf init copilot --profile local --root /path/to/repo
ptuf init copilot --profile local --hooks /tmp/ptuf.json
ptuf init copilot --profile local --verify
```

The written `preToolUse` entry contains both `bash` and `powershell` command
strings. The Copilot `preToolUse` protocol treats non-zero exit as a hook
**failure** and may let the tool call proceed — to stay fail-closed, the
adapter always exits `0` and emits a bare JSON envelope (no
`hookSpecificOutput` wrapper). `Ask` decisions become `Deny` for the same
non-interactive reason as Codex.

The `--profile cloud` variant (cloud-agent wrapper scripts) is post-MVP and
not yet wired up.

## Kiro CLI

The default install target is repo-local:

```bash
ptuf init kiro                                    # writes <repo>/.kiro/agents/ptuf-guarded.json
ptuf init kiro --dry-run
ptuf init kiro --root /path/to/repo
ptuf init kiro --agent guard-bot                  # custom file stem
ptuf init kiro --scope global                     # writes ~/.kiro/agents/<name>.json
ptuf init kiro --agent-config /tmp/agent.json     # bypass scope/root resolution
ptuf init kiro --verify
```

The written `hooks.preToolUse` entry invokes `<ptuf> hook kiro`. The
installer is idempotent — re-running it detects an existing ptuf entry by the
`hook kiro` command tail.

Kiro `preToolUse` payloads use a different vocabulary than Claude Code, so
the adapter normalises tool names and `tool_input` keys before the engine
sees them (`shell` / `execute_bash` → `Bash`, `fs_read` → `Read`, `fs_write`
→ `Write`, `web_fetch` → `WebFetch`, `@server/tool` → `mcp__server__tool`,
etc.). See `docs/design/kiro-cli.md` for the full normalization table. As
with Codex and Copilot, `Ask` decisions become `Deny` because Kiro
`preToolUse` does not define an interactive prompt channel.

## Behavior summary

| Host | Allow / Monitor | Ask | Deny | Failure mode |
| --- | --- | --- | --- | --- |
| Claude Code | exit `0`, no JSON | exit `0`, `permissionDecision: "ask"` | exit `2`, `permissionDecision: "deny"` + reason on stderr | `core.engine.invalid-payload` deny at exit `2` |
| Codex | exit `0`, no JSON | converted to **deny** | exit `2`, `permissionDecision: "deny"` + reason on stderr | `core.engine.invalid-payload` deny at exit `2` |
| GitHub Copilot | exit `0`, empty stdout | converted to **deny** | exit `0`, bare `{"permissionDecision":"deny",…}` JSON + reason on stderr | bare deny JSON at exit `0` |
| Kiro CLI | exit `0`, empty stdout | converted to **deny** | exit `2`, reason on stderr only (no envelope) | `core.engine.invalid-payload` deny at exit `2` |

Hook stdin payloads are capped at 8 MiB across every host. Unreadable,
oversized, or invalid-JSON stdin is rejected with the reserved
`core.engine.invalid-payload` rule so the host blocks the tool — `exit 1`
would only surface a non-blocking warning and let the call through.
