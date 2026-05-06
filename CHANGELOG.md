# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Release verification pipeline (P0-7): every tagged release now publishes
  an aggregate `SHA256SUMS` file, a Syft / SPDX 2.3 SBOM
  (`ptuf-<tag>.spdx.json`), GitHub Build Provenance Attestations on every
  archive plus `SHA256SUMS`, and an SBOM Attestation linking the SBOM to
  each archive. Verification is documented in `README.md` →
  "Verified install" and `SECURITY.md` → "Verifying Releases", and is
  driven by the new `.github/workflows/release-verify.yml` sibling
  workflow. The decisions and rationale are recorded in
  [`docs/adr/0001-release-verification.md`](docs/adr/0001-release-verification.md).
- `x86_64-unknown-linux-musl` pre-built binary
  (`ptuf-x86_64-unknown-linux-musl.tar.gz`) for Alpine and other minimal
  Linux containers, alongside the existing `gnu` builds.
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
- `Engine::builder()` — canonical entry point for embed callers that
  want to inject a `Config`, `PluginSet`, `AuditSink`, or `repo_root`
  without going through `Engine::for_cwd`. Every builder-built engine
  runs `ProtectedPaths::collect_with_env`, so `binary` / claude / codex
  settings are populated even with `Config::default()`. Closes the
  embed-fallback gap left by the removed `Engine::default` shim
  (review §1.7).
- `Engine::protected_paths()` — read-only accessor for the engine's
  resolved self-protection target set. Useful for embed callers and
  tests that want to assert the binary / settings guardrail was wired.
- `PathFact { tool, raw, expanded, absolute, canonical_or_raw, origin }`
  expanded out of the previous `FilePath` shape. `expanded` carries the
  `~` / `$HOME`-resolved form, `absolute` adds the `base_dir` join when
  the input was relative, and `canonical_or_raw` falls back to
  `absolute` for any I/O failure (missing file, permission denied,
  symlink loop). `pub type FilePath = PathFact;` keeps the historical
  name compiling. `PathOrigin` distinguishes `ToolInputDirect`
  (`file_path`, MCP `path`) / `ToolInputNested` (`files[].path`,
  `paths[]`, `items[].path`) / `ApplyPatch` / `BashRedirect` (engine
  emits these from `Pipeline.redirects` so self-protection sees the
  same view as file-tool inputs) (review D8).
- `facts::path::from_bash_redirects(bash, repo_root) -> Vec<PathFact>`
  — public helper that walks a parsed `Bash`'s `Pipeline.redirects` and
  returns one `PathFact { origin: BashRedirect, tool: Write }` per
  non-heredoc target. The engine uses it to feed self-protection;
  embed callers can reuse it without reimplementing the walk.
- `ProtectedPaths::classify_input_with_paths_pair(input, paths, extra)`
  — sibling of `classify_input_with_paths` that classifies the union
  of two `PathFact` slices (tool-input-derived and engine-supplied)
  without forcing the caller to allocate a merged `Vec`.

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
- `crate::decide` (and the engine's per-decide path) now classifies
  Bash redirect operands (`> file`, `>> file`, `< file`, `2> file`,
  `&> file`) against `ProtectedPaths`. Previously only positional
  arguments to known writer heads (`rm`, `cp`, `mv`, …) were inspected,
  so `echo y > ~/.claude/settings.json` slipped past
  `core.self_protection.claude-settings`. Scripts that intentionally
  redirect into a self-protection target may now produce new Deny
  decisions; this is a bug-fix-class behaviour change (review D8).
- `crate::decide`'s embed fallback (when `Engine::for_cwd` cannot
  discover a config) now goes through `Engine::builder().agent(
  "embed-fallback").build()`. The fallback engine therefore populates
  `ProtectedPaths` with the running binary and HOME-rooted claude /
  codex settings, where the previous `Engine::default()` fallback left
  those slots empty. Embedded callers that depended on the empty
  fallback to bypass self-protection will see new Deny decisions for
  binary / settings edits (review §1.7).
- `ProtectedPaths::collect_with_env` now pre-canonicalises every
  target path (binary, configs, plugins, claude / codex settings, hook
  scripts) at collect time. `path_matches` only canonicalises the
  candidate side at match time. Net effect is a single `canonicalize()`
  per target instead of per match; behaviour is unchanged for files
  whose canonical form is stable across decides (review D8).

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
- `impl Default for Engine` was removed. Callers that relied on
  `Engine::default()` should switch to `Engine::builder().build()` (or
  `Engine::for_cwd()` when project policy is desired). The builder
  populates `ProtectedPaths` whereas the deleted `Default` shim left
  it empty, so the new construction path is *not* a drop-in
  replacement when the caller expected self-protection to be a noop
  (review §1.7).
- `FilePath` is now a type alias for `PathFact`. Existing field
  accesses (`fp.tool` / `fp.raw` / `fp.absolute`) keep compiling, but
  exhaustive struct destructuring (`FilePath { tool, raw, absolute }`)
  now requires `..` because the underlying `PathFact` adds `expanded`,
  `canonical_or_raw`, and `origin` (review D8).

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
