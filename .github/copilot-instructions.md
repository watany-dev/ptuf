# GitHub Copilot instructions for ptuf

ptuf (PreToolUseFilter) is a guardrail for coding agents. It runs from
the agent's `PreToolUse` / `preToolUse` hook, evaluates built-in rules
plus optional YAML plugins, and returns `Allow` / `Monitor` / `Ask` /
`Deny` decisions back to the host. This file describes how Copilot
should interact with the repository when contributing changes.

## Hook integration

This repository is wired up to call `ptuf hook copilot` as a Copilot
`preToolUse` hook (see `.github/hooks/ptuf.json`). Copilot's hook
protocol treats non-zero exit as a hook *failure* and may still let
the tool call proceed. To stay fail-closed, the Copilot adapter:

- Always exits `0`, even on `Deny`, invalid payload, and
  policy-load failure.
- On `Deny`, writes a *bare* JSON envelope to stdout
  (no `hookSpecificOutput` wrapper):
  ```json
  {"permissionDecision":"deny","permissionDecisionReason":"…"}
  ```
- Demotes `Ask` to `Deny` because Copilot cannot reliably prompt
  interactively from a `preToolUse` hook.

If a tool call is denied, do not retry the same operation. Read the
`permissionDecisionReason` and either narrow the request, route it
through an allowlisted path, or ask the user.

## Repository conventions

The full coding guidelines live in `CLAUDE.md` and the
`docs/design/` set. The most load-bearing conventions are:

- `make check` must pass locally before any commit or push. It runs
  `fmt-check`, `clippy`, `test`, `cargo doc`, and `cargo-deny`.
- `unsafe_code` is forbidden (`Cargo.toml [lints.rust]`).
- `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`,
  `dbg_macro`, `print_stdout`, `print_stderr`, and `exit` are denied
  in production code. Use `Result` / `Option` for all paths. Tests
  may use these via `clippy.toml`'s `allow-{unwrap,expect,panic,
  print,dbg}-in-tests`.
- Test coverage is kept above 95% via `cargo-tarpaulin`.
- New logic goes under `src/lib.rs`. `src/main.rs` is a CLI shim and
  is excluded from coverage.

## What to change vs. what to leave alone

When asked to extend an adapter (e.g. Cursor, Gemini), follow the
Copilot adapter as a template:

- Add a variant to `HookAgent` (`src/cli/mod.rs`).
- Wire `parse_hook` (`src/cli/parse.rs`).
- Add input normalization in a CLI-layer module if the agent has a
  different input shape (see `src/cli/copilot_input.rs`).
- Add output rendering in a `hook_output::<agent>` submodule when the
  protocol is bare-JSON or otherwise distinct from Claude Code / Codex.
- Update `decision_exit_code` and `render_hook_response` to dispatch on
  the new variant.
- Add doctor + init + verify modules under `src/init/<agent>.rs` and
  `src/doctor/`.
- Add contract tests in `tests/contracts.rs` covering: synthetic
  `rm -rf /` deny, invalid payload deny, policy-load-failure deny,
  `Ask` handling, `Allow` empty stdout, and tool-name mapping.

Do **not** touch the engine, built-in rules, or plugin evaluation
layer when adding an adapter. Adapter work is confined to CLI
dispatch (input normalization + output rendering + exit code) plus
init / doctor / verify wiring.

## Asking for help

If a change is ambiguous (could be interpreted multiple ways or
touches something architecturally significant), open a discussion or
draft PR rather than guessing. The codebase's failure mode is silent
guardrail bypass, so over-cautious is the right default.
