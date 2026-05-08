# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Verified release artifacts with `SHA256SUMS`, GitHub artifact attestations,
  and SPDX JSON SBOM publication.
- `x86_64-unknown-linux-musl` release target for portable Linux installs.

### Changed
- Unix release archives are published as `.tar.gz` and Windows archives as
  `.zip`.
- Installation docs now prefer pinned archive downloads with checksum and
  attestation verification over installer scripts.

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
