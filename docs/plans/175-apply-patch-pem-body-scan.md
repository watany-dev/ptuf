# Plan: apply_patch patch body PEM scan — issue #175

## Context

ADR 0001 known limitation: `apply_patch` extracted destination paths but did
not scan patch body content for PEM blobs. Non-sensitive paths such as
`src/notes.md` could receive `+-----BEGIN RSA PRIVATE KEY-----` added lines
without tripping `core.secrets.sensitive-read`.

Adjacent gap: Cline adapter passed `apply_patch` through without promoting
`patch` / `patchText` / `content` into `command`, so path extraction and
content scanning both missed Cline-shaped payloads.

## Design

1. **`facts::patch::added_content`** — collect `+`-prefixed lines only, strip
   the prefix, join with `
`, run through existing `classify_content_into`.
   Context (` `) and deletion (`-`) lines are excluded so remediation patches
   that delete leaked keys are not hard-denied.
2. **`facts::patch::paths`** — move Codex path directive parsing out of
   `facts::path` (behaviour unchanged).
3. **`HookInput::apply_patch_command`** — wire the raw patch command into
   the content lane from `extract()` without overloading `write_payload()` or
   extending the public `Event` struct (SemVer-safe).
4. **Cline `normalize_patch`** — same key priority as OpenCode
   `reshape_patch`: `command`, `patchText`, `patch`, `content`.

Parity invariant: for any body `B`, sensitive kinds from
`apply_patch` Add File + `B` equal those from `Write { content: B }`.

## Verification

- Unit tests in `src/facts/patch.rs`, `src/rules/sensitive_read.rs`,
  `src/cli/cline_input.rs`
- Parity / roundtrip PBT in `src/facts/patch.rs`
- Engine mirrors in `tests/engine_proptest.rs`
- Four `must_catch/deny` corpus entries + fuzz hook seed
- `make check`, `make pbt-quick`
