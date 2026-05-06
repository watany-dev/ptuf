# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `try_decide(&HookInput) -> Result<Decision, EngineError>` — fallible
  variant of `decide()` that surfaces config / plugin load errors instead
  of falling back to a default-configured engine. Embedded callers that
  want the same fail-closed contract as the CLI now have a direct API
  (review §1.6).
- `Bash::has_command_substitution: bool` — the shell parser now flags
  whether the command string contained a `` ` … ` `` or `$(…)` opening
  (including `$(…)` inside double-quoted spans). The substitution body
  is still folded into the surrounding word as opaque text; rules that
  need pessimistic handling can opt in by reading this flag (review §3.3).
- `Engine::drain_audit_write_warnings()` — accumulates per-record audit
  write failures (permission denied, disk full, …). The CLI hook and
  eval entry points now drain these to stderr after each decision so
  silent audit loss is observable. Open failures continue to surface
  through `Engine::audit_warning()` (review D9).

### Changed
- `tokenize` in `src/facts/shell.rs` now asserts forward progress on
  every `read_word` call (`debug_assert!(advanced > 0)`), and
  `read_word` documents the contract that callers strip whitespace and
  separator bytes before invocation (review §3.5).

### BREAKING
- `Bash` (in `ptuf::facts::shell`) gained a public field
  `has_command_substitution`. Pattern-matching `Bash { segments }`
  exhaustively now requires `..`. The struct is constructed only by
  `parse()` so this matters for downstream consumers that destructure it.

## [0.0.1] - 2026-05-05

Initial public release.

### Added
- `ptuf hook <agent>` adapter for Claude Code and Codex `PreToolUse` hooks
- `ptuf eval` one-shot evaluator for shell use and debugging
- `ptuf init claude-code` / `ptuf init codex` idempotent installers
- `ptuf doctor [--json]` diagnostics for binary, config, plugins, and hook wiring
- `ptuf plugin test <path>` for rule-local `tests.deny` / `tests.allow`
- Built-in policy packs: filesystem, network, secrets, git, self-protection, and
  opt-in project hygiene
- Tool-aware fact extraction for `Bash`, `Read`, `Edit`, `Write`, `WebFetch`,
  and generic `mcp__<server>__<tool>` payloads
- Layered YAML config (`/etc/ptuf/policy.yaml`, `~/.config/ptuf/config.yaml`,
  `<repo>/.ptuf.yaml`, `<repo>/.ptuf.local.yaml`) with YAML plugins
- Audit JSONL with `schemaVersion: 1`, `agent`, `pluginVersions`, and
  `allowlistId`
- Pre-built binaries for `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`,
  and `x86_64-pc-windows-msvc`
- `curl | sh` and PowerShell installers via cargo-dist
- crates.io publication

[Unreleased]: https://github.com/watany-dev/ptuf/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/watany-dev/ptuf/releases/tag/v0.0.1
