# Security Policy

## Reporting a Vulnerability

`ptuf` is a security-sensitive guardrail. If you discover a vulnerability —
whether a bypass of the built-in policy packs, a panic that turns into a
deny-of-service, a YAML / TOML / JSON parser issue exploitable through
plugin or hook input, or anything that affects audit-log integrity —
please report it privately.

**Preferred channel:** GitHub's [private vulnerability reporting] on
`watany-dev/ptuf`. Use the **Security** tab → **Report a vulnerability**.

[private vulnerability reporting]: https://github.com/watany-dev/ptuf/security/advisories/new

If you are unable to use GitHub Security Advisories, open an empty issue
titled `Security contact request` and we will arrange a private channel.

Please do **not** file a public issue, send the details to a public
mailing list, or include a working exploit in a public PR.

## Disclosure Process

1. We acknowledge the report within **3 business days**.
2. We confirm reproducibility and assign a severity within **10 business
   days**.
3. We aim to ship a patched release within **90 days** of confirmation.
   For high-severity issues we coordinate a faster disclosure.
4. We credit the reporter in the release notes unless they prefer
   anonymity.

## Scope

In scope:

- The `ptuf` binary on supported platforms (Linux x86_64/aarch64, macOS
  x86_64/aarch64, Windows MSVC x86_64).
- The `ptuf` library (`pub` API exposed from `src/lib.rs`).
- Built-in policy packs and hook adapters (Claude Code, Codex, Copilot,
  Kiro CLI, Cline, Cursor, Pi, OpenCode).
- Default plugin / config schema and YAML parsing.
- Audit JSONL emission (`schemaVersion: 1`).

Out of scope (treat as feature requests, not vulnerabilities):

- Pre-release versions before the first stable release.
- Issues in user-authored plugins or third-party agent integrations.
- Misuse of the CLI in environments where the user already has equivalent
  shell access.

## Supported Versions

Until a `1.0.0` release, only the latest published version receives
security fixes.

## No Telemetry

`ptuf` is a guardrail layer that sits inside the trust boundary of every
coding agent it filters. **It must not exfiltrate its own observations.**

- ptuf does not send any telemetry, metrics, crash reports, opt-in pings,
  or anonymous usage statistics, ever.
- Hook evaluation, `check`, config loading, plugin loading, and audit
  emission perform no network I/O.
- Network access occurs only when the user explicitly invokes
  `ptuf update` (or a package manager) to check for or install a release.

This is a permanent design constraint, not a default that can be turned
on. See `docs/design/threat-model.md` (I-3) for the rationale.

## Threat Model

The full STRIDE-based threat model — attacker types, trust boundaries,
mitigations, and residual risk — lives in
[`docs/design/threat-model.md`](docs/design/threat-model.md).
