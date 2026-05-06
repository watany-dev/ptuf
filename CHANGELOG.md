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
- `core.engine.dynamic-eval` rule (Ask / Medium / overridable) — flags
  two-stage execution shapes such as `bash -c …`, `sh -c …`,
  `python -c …`, `node -e …`, `perl -e …`, `ruby -c|-e …`, and
  `eval …`. The inner code is opaque to the parser, so other rules
  cannot inspect what will actually run; the new rule asks the user to
  confirm. `sudo` wrappers are unwrapped before matching. Default-enabled
  via the new `core.engine` policy pack (review §2 / D4).
- `Pipeline.redirects: Vec<Redirect>` and `Bash::has_redirect` /
  `has_heredoc` / `has_process_substitution` parser surfaces. The
  tokenizer now recognises `>` / `>>` / `<` / `2>` / `&>` redirect
  operators with their target words, captures heredoc bodies up to the
  terminator (`<<TAG` / `<<-TAG`), and absorbs process substitution
  (`<(…)` / `>(…)`) into a single paren-balanced word. These let rules
  judge per-pipeline shapes that previously fell through the parser
  (review §2 / D4).

### Changed
- `tokenize` in `src/facts/shell.rs` now asserts forward progress on
  every `read_word` call (`debug_assert!(advanced > 0)`), and
  `read_word` documents the contract that callers strip whitespace and
  separator bytes before invocation (review §3.5).
- `core.secrets.sensitive-path-to-network` is now judged per pipeline
  (segment) instead of command-wide. Unrelated segments such as
  `ls ~/.ssh; curl https://example.com` no longer fire the rule, while
  pipelines that redirect into a sensitive path
  (`curl https://x > ~/.ssh/foo`) still deny via the new
  `Pipeline.redirects` surface. When `Bash::has_command_substitution`
  is set the rule falls back to the previous command-wide co-occurrence
  to preserve the safety-first false-positive bias (review D5).

### BREAKING
- `Bash` (in `ptuf::facts::shell`) gained a public field
  `has_command_substitution`. Pattern-matching `Bash { segments }`
  exhaustively now requires `..`. The struct is constructed only by
  `parse()` so this matters for downstream consumers that destructure it.
- `Bash` further gained `has_redirect`, `has_heredoc`, and
  `has_process_substitution` public fields, and `Pipeline` gained
  `redirects: Vec<Redirect>` (with companion `Redirect` / `RedirectOp`
  types). Exhaustive destructuring of `Bash` / `Pipeline` requires `..`.
  Both types are constructed only by `parse()`.

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
