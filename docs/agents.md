# Wiring ptuf into a coding agent

ptuf ships first-class adapters for **Claude Code**, **Codex**, **GitHub
Copilot**, **Kiro CLI**, **Cline**, **Cursor**, **Pi Coding Agent**, and **OpenCode**. The same policy engine
and YAML plugins back every host; only the hook-protocol envelope differs.

This page is the user-facing how-to. For the underlying hook protocol, exit
codes per agent, and the full payload contract, see the design notes:

- `docs/design/cli-and-hooks.md` — CLI surface and per-host adapter contracts
- `docs/design/kiro-cli.md` — Kiro tool-name / payload normalization
- `docs/design/decision-model.md` — `Allow` / `Monitor` / `Ask` / `Deny`
  semantics

## Auto-detect

`ptuf init` with no agent argument scans cwd / `$HOME` and installs the
`PreToolUse` hook into every reachable host:

| Agent       | Detection condition                              | Install target                            |
|-------------|--------------------------------------------------|-------------------------------------------|
| ClaudeCode  | `$HOME/.claude/`                                 | `$HOME/.claude/settings.json`             |
| Codex       | `<repo>/.codex/` or `$HOME/.codex/`              | `<repo>/.codex/{hooks.json,config.toml}`  |
| Copilot     | `<repo>/.github/`                                | `<repo>/.github/hooks/ptuf.json`          |
| Kiro        | `<repo>/.kiro/` or `$HOME/.kiro/`                | `<repo>/.kiro/agents/*.json` and `$HOME/.kiro/agents/*.json` (all existing JSONs are patched; empty scope falls back to `agents/default.json`) |
| Cline       | `<repo>/.clinerules/`, `<repo>/.cline/`, `$HOME/Documents/Cline/`, or `$HOME/.cline/` | `<repo>/.clinerules/hooks/PreToolUse` |
| Cursor      | `<repo>/.cursor/` or `$HOME/.cursor/`            | `<repo>/.cursor/hooks.json` (`--scope global` → `$HOME/.cursor/hooks.json`) |
| Pi          | `<repo>/.pi/` or `$HOME/.pi/agent/`              | `$HOME/.pi/agent/extensions/ptuf.ts` (default global) or `<repo>/.pi/extensions/ptuf.ts` |
| OpenCode    | `<repo>/.opencode/` or `<repo>/opencode.json`     | `$XDG_CONFIG_HOME/opencode/plugins/ptuf.ts` (default global) or `<repo>/.opencode/plugins/ptuf.ts` |

Pin to a single adapter with `ptuf init <agent>` (`claude-code` / `codex`
/ `copilot` / `kiro` / `cline` / `cursor` / `pi`).

## Common flags

Every `ptuf init` invocation accepts:

| Flag | Effect |
| --- | --- |
| `--dry-run` | Print what would be written without touching files (verify is automatically off) |
| `--no-verify` | Skip the post-install synthetic deny + policy-load failure check (verify is on by default) |

`--json` is a global, top-level flag that emits a machine-readable
verify report: `ptuf --json init [<agent>]`.

## Claude Code

```bash
ptuf init claude-code            # writes ~/.claude/settings.json
ptuf init claude-code --dry-run
ptuf init claude-code --no-verify
```

The installer adds (or updates, idempotently) a `PreToolUse` hook entry
matching `Bash|Read|Edit|Write|WebFetch|mcp__.*` and pointing at the
absolute path of `ptuf hook claude-code`. It detects an existing ptuf entry
by the `name: "ptuf"` marker and also recognises the legacy
`hook claude-code` command tail.

## Codex

```bash
ptuf init codex                  # writes <repo>/.codex/{hooks.json,config.toml}
ptuf init codex --dry-run
ptuf init codex --no-verify
```

Hook matcher is `Bash|apply_patch|mcp__.*`, command is `<absolute>/ptuf hook
codex`, and `features.hooks = true` is set. Because Codex `PreToolUse`
cannot prompt interactively, the adapter converts `Ask` decisions to `Deny`.

## GitHub Copilot

```bash
ptuf init copilot                # writes <repo>/.github/hooks/ptuf.json
ptuf init copilot --dry-run
ptuf init copilot --no-verify
```

The written `preToolUse` entry contains both `bash` and `powershell` command
strings. The Copilot `preToolUse` protocol treats non-zero exit as a hook
**failure** and may let the tool call proceed — to stay fail-closed, the
adapter always exits `0` and emits a bare JSON envelope (no
`hookSpecificOutput` wrapper). `Ask` decisions become `Deny` for the same
non-interactive reason as Codex.

## Kiro CLI (v2)

```bash
ptuf init kiro-v2                   # patches every <repo>/.kiro/agents/*.json and $HOME/.kiro/agents/*.json
ptuf init kiro-v2 --dry-run
ptuf init kiro-v2 --no-verify
ptuf init kiro-v2 --workspace-only  # patch only <repo>/.kiro/agents/*.json
ptuf init kiro-v2 --global          # patch only $HOME/.kiro/agents/*.json
ptuf init kiro-v2 --new-agent       # legacy: create a single ptuf-guarded.json
```

Kiro CLI's hook contract changes in v3, so this adapter carries the
explicit `kiro-v2` token; `kiro` stays an accepted alias for it in both
`init` and `hook`. The audit name (`kiro`) and the hook command written
into agent JSON (`ptuf hook kiro`) are unchanged, so already installed
hooks keep matching. A future `kiro-v3` token is rejected as an unknown
agent until its own adapter lands.

The default mode reads every `*.json` directly under both
`<repo>/.kiro/agents/` and `$HOME/.kiro/agents/`, appends a
`hooks.preToolUse` entry that invokes `<ptuf> hook kiro`, and is
idempotent (re-running detects existing entries by the `hook kiro`
command tail). `.md` agents are skipped and reported under
`skipped_non_json_agents` in the verify report.

When neither scope contains any agent JSON, the installer falls back to
creating `agents/default.json` (not `ptuf-guarded.json`) in the highest-
priority scope so the hook still gets wired up. Each scope's
`settings/cli.json` `chat.defaultAgent` is consulted to verify the
referenced agent JSON exists; a dangling reference fails closed with
`InitError::Schema`. The patched JSON files are added to
`core.self_protection.kiro-settings`, so a guarded session cannot rewrite
them to remove the hook.

Kiro `preToolUse` payloads use a different vocabulary than Claude Code, so
the adapter normalises tool names and `tool_input` keys before the engine
sees them (`shell` / `execute_bash` → `Bash`, `fs_read` → `Read`, `fs_write`
→ `Write`, `web_fetch` → `WebFetch`, `@server/tool` → `mcp__server__tool`,
etc.). See `docs/design/kiro-cli.md` for the full normalization table. As
with Codex and Copilot, `Ask` decisions become `Deny` because Kiro
`preToolUse` does not define an interactive prompt channel.

## Cline

```bash
ptuf init cline                  # writes <repo>/.clinerules/hooks/PreToolUse
ptuf init cline --dry-run
ptuf init cline --no-verify
```

The installer writes a Cline `PreToolUse` file hook:

- Unix / macOS: `<repo>/.clinerules/hooks/PreToolUse`
- Windows: `<repo>/.clinerules/hooks/PreToolUse.ps1`
- Global fallback (no repo root): `~/Documents/Cline/Hooks/PreToolUse[.ps1]`

Unlike the other hosts, the Cline hook is an *executable wrapper script*
(installed mode `0700` on Unix) rather than a config-file command entry.
The wrapper `exec`s `<absolute>/ptuf hook cline`. Re-running the installer
is idempotent — it recognises a ptuf-managed wrapper by the
`ptuf-managed: cline PreToolUse` marker and refuses to overwrite an
unmanaged `PreToolUse` hook.

Cline delivers its payload inside a `hookName` envelope, in either the SDK
`tool_call` form or the legacy `preToolUse` form; the adapter accepts both
and normalises tool names / input keys before the engine sees them
(`run_commands` / `execute_command` → `Bash`, `read_files` → `Read`,
`write_file` → `Write`, `use_mcp_tool` → `mcp__server__tool`, etc.). Cline
file hooks are fail-open on process failures in some paths, so the adapter
always exits `0` and expresses blocks with `{"cancel":true,…}` JSON. `Ask`
decisions become `Deny` because Cline `PreToolUse` file hooks have no
uniformly reliable interactive review channel.

> Cline hooks are not a sandbox. If Cline is run with hooks disabled or in
> a mode that bypasses hooks, ptuf cannot inspect or block tool calls.

## Cursor

```bash
ptuf init cursor                 # writes <repo>/.cursor/hooks.json
ptuf init cursor --scope global  # writes $HOME/.cursor/hooks.json
ptuf init cursor --root <path>   # start repo discovery from <path>
ptuf init cursor --hooks <path>  # patch this exact hooks.json file
ptuf init cursor --dry-run
ptuf init cursor --no-verify
```

The installer adds (or updates, idempotently) a `version: 1`
`hooks.preToolUse` entry pointing at `<absolute>/ptuf hook cursor`, with a
`matcher` of `Shell|Bash|Read|ReadFile|Write|Edit|MCP|WebFetch|Fetch|mcp__.*`,
a `timeout` of `10`, and `failClosed: true`. Existing ptuf entries are
detected by the `hook cursor` command tail; other hooks in the file are
preserved. The `--scope` / `--root` / `--hooks` flags are Cursor-only and
are rejected for any other agent.

Cursor dispatches several hook events; the adapter enforces
`preToolUse`, `beforeShellExecution` (→`Bash`), `beforeReadFile` (→`Read`),
and `beforeMCPExecution` (→`mcp__server__tool`). Any other event
(`postToolUse`, `afterFileEdit`, `sessionStart`, …) fails closed with
`core.engine.invalid-payload`. Tool names and `tool_input` keys are
normalised before the engine sees them (`Shell` → `Bash`, `ReadFile` →
`Read`, `Fetch` → `WebFetch`, `mcp__*` → `mcp__server__tool`, etc.), with
camelCase (`hookEventName` / `toolName` / `toolInput`) accepted as aliases.

Unlike Codex / Copilot / Kiro / Cline, Cursor has its own interactive
`Ask` channel, so `Ask` decisions are **preserved** (`{"permission":"ask",…}`,
exit `0`) rather than demoted to a hard deny. Only hook-driven agent tool
execution is guarded; Tab completion, manual edits, and commands typed
directly into the terminal never reach a hook and are out of scope.

## Pi Coding Agent

```bash
ptuf init pi                     # writes $HOME/.pi/agent/extensions/ptuf.ts
ptuf init pi --scope local       # writes <repo>/.pi/extensions/ptuf.ts
ptuf init pi --root <path>       # start repo discovery from <path>
ptuf init pi --extension <path>  # write this exact extension file
ptuf init pi --dry-run
ptuf init pi --no-verify
```

The installer writes a managed TypeScript extension that registers a
`tool_call` handler spawning `ptuf hook pi` with Pi's raw event payload.
Normalisation (`bash`→`Bash`, `grep`→`mcp__pi__grep`, unknown tools→
`mcp__pi__*`) happens in Rust, not in the extension.

Environment variables read by the extension:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PTUF_PI_ASK_MODE` | `confirm-if-ui-else-deny` | How to handle `ask` decisions |
| `PTUF_PI_TIMEOUT_MS` | `10000` | Hook subprocess timeout |

Patched extension paths are covered by
`core.self_protection.pi-settings`, so a guarded session cannot rewrite
the extension to remove the hook.

Limitations: project-local installs trust the repo; **global scope is
recommended**. Each tool call spawns a fresh `ptuf` process. Non-interactive
`ask` decisions deny by default.

## Behavior summary

| Host | Allow / Monitor | Ask | Deny | Failure mode |
| --- | --- | --- | --- | --- |
| Claude Code | exit `0`, no JSON | exit `0`, `permissionDecision: "ask"` | exit `2`, `permissionDecision: "deny"` + reason on stderr | `core.engine.invalid-payload` deny at exit `2` |
| Codex | exit `0`, no JSON | converted to **deny** | exit `2`, `permissionDecision: "deny"` + reason on stderr | `core.engine.invalid-payload` deny at exit `2` |
| GitHub Copilot | exit `0`, empty stdout | converted to **deny** | exit `0`, bare `{"permissionDecision":"deny",…}` JSON + reason on stderr | bare deny JSON at exit `0` |
| Kiro CLI | exit `0`, empty stdout | converted to **deny** | exit `2`, reason on stderr only (no envelope) | `core.engine.invalid-payload` deny at exit `2` |
| Cline | exit `0`, stdout `{}` | converted to **deny**, exit `0`, cancel JSON | exit `0`, `{"cancel":true,…}` JSON + reason on stderr | `core.engine.invalid-payload` cancel JSON at exit `0` |
| Cursor | exit `0`, `{"permission":"allow"}` JSON | **preserved**, exit `0`, `{"permission":"ask",…}` JSON | exit `2`, `{"permission":"deny",…}` JSON + reason on stderr | `core.engine.invalid-payload` deny JSON at exit `2` |
| Pi | exit `0`, `{"decision":"allow"}` JSON | **preserved**, exit `0`, `{"decision":"ask",…}` JSON | exit `2`, `{"decision":"deny",…}` JSON + reason on stderr | `core.engine.invalid-payload` deny JSON at exit `2` |

Hook stdin payloads are capped at 8 MiB across every host. Unreadable,
oversized, or invalid-JSON stdin is rejected with the reserved
`core.engine.invalid-payload` rule so the host blocks the tool — `exit 1`
would only surface a non-blocking warning and let the call through.

## OpenCode

`ptuf init opencode` installs a managed TypeScript plugin that OpenCode
loads from the standard `plugins/` directory. The plugin
registers `tool.execute.before`, builds a minimal JSON payload
(`tool_name`, `tool_input`, optional `opencode` metadata), and spawns
`ptuf hook opencode` with an absolute binary path embedded at init time.
Older ptuf releases wrote `plugin/ptuf.ts`; rerunning init migrates the
managed file to `plugins/ptuf.ts`, while self-protection still guards
both paths.

OpenCode native tool names (`bash`, `read`, `patch`, `grep`, …) are
normalised in Rust (`src/cli/opencode_input.rs`) to the same canonical
vocabulary as the other adapters. Unknown tools map to
`mcp__opencode__<sanitized>` so existing MCP path extraction and
self-protection rules apply without a new subsystem.

**Ask demotion:** OpenCode has a `permission.ask` plugin hook, but it is
known to fail silently in some builds and `tool.execute.before` cannot
start interactive confirmation. ptuf therefore demotes Ask to Deny
(exit `2`, bare `{"decision":"deny",…}` JSON) — same posture as Codex /
Copilot / Kiro / Cline.

**Environment:** `PTUF_OPENCODE_TIMEOUT_MS` (default 10000).

**Limitations (MVP):** MCP / custom tools use generic `mcp__opencode__*`
identity; `opencode.json` permissions are not modified; audit metadata
(`sessionId`, `callId`, …) is not yet copied into audit records.
