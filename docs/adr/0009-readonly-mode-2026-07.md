# ADR 0009 — Forced readonly mode (orthogonal `Config.readonly`)

- Status: Accepted
- Date: 2026-07-29
- Issue: #182

## Context

ptuf's `mode` axis is only `enforce` / `monitor` (`demote_for_mode`).
Operators want a Claude Code plan-mode equivalent: a single toggle that
blocks all writes across every adapter, without inventing a third
`Mode` value or a toggleable pack.

## Decision

Add `Config.readonly: bool` (default `false`), orthogonal to `mode`.
When set, the engine synthesises High-severity Denies for file writers,
non-read MCP verbs, and bash commands outside a pure-read allowlist
*after* `demote_for_mode`, outside the `rules::iter()` loop.

Rule ids: `core.readonly.file-write` / `core.readonly.bash-write` /
`core.readonly.mcp-write`. They are hard-deny by `core.readonly.`
prefix (not registered as `ConfigRule`s), so pack disable / rule
override / allowlist / `mode: monitor` cannot weaken them.

`PTUF_READONLY=1|true|on` appends a synthetic merge layer that sets
`readonly: true` only — falsy values create no layer, so the env can
strengthen but never weaken a config-file `true`.

CLI: `ptuf readonly on|off|status [--global]` writes the `readonly:`
key into `<repo>/.ptuf.local.yaml` (or the user config).

## Alternatives rejected

1. **`Mode::Readonly` third variant** — cannot express
   `monitor + readonly`; forces `Outcome.mode` / audit / PBT rewrites.
2. **`core.readonly` pack toggle** — `is_pack_disabled` returns early
   `false` for hardDeny rules, so a hardDeny pack cannot be the
   toggle mechanism.
3. **Writer blocklist (fail-open)** — unknown binaries and custom
   scripts bypass it. Fail-closed head allowlist is the plan-mode
   semantics operators asked for (`cargo build` / `mkdir` deny).

## Consequences

- Readonly is intentionally strict: builds, installs, and mkdir deny.
  Git verbs that create refs without flags (`branch` / `tag` / `stash`)
  are off the read-subcommand list rather than special-cased. There is
  no allowlist relaxation path by design.
- Agents cannot self-disable: config edits hit
  `core.self_protection.config`; `Bash: ptuf readonly off` is an
  unknown head under the bash gate. Humans outside the hook remain
  free to toggle.
- Mid-word redirects (`echo x>f`) are now tokenised as redirects in
  `facts::shell` so the bash gate (and self-protection) see them.
