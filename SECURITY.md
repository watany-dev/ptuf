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
- Built-in policy packs and hook adapters (Claude Code, Codex).
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

## Verifying Releases

Every tagged release publishes:

- One `ptuf-<target>.tar.gz` (or `.zip` on Windows) per supported target
- `SHA256SUMS` — aggregate SHA-256 of every archive plus the SBOM
- `ptuf-<tag>.spdx.json` — Syft-generated SPDX 2.3 SBOM of the
  source dependency tree (`Cargo.lock`)
- GitHub Build Provenance Attestations on every archive and on the
  `SHA256SUMS` file (Sigstore-backed, OIDC-issued, no long-lived keys)
- An SBOM Attestation linking the SBOM to each archive

The recommended verification flow (also documented in `README.md`):

```bash
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify <archive> --owner watany-dev
```

The `SHA256SUMS` file itself is covered by build-provenance attestation,
so `gh attestation verify SHA256SUMS --owner watany-dev` lets you anchor
trust on the aggregate file before relying on `sha256sum -c`.

### Operational notes

- Verification artifacts are attached by a separate workflow that runs
  on `release: published`. They typically appear within a few minutes
  of the release going live; for very fresh releases, allow some time
  before running the verification commands.
- If `gh attestation verify` returns a failure for a release that you
  obtained from an official source, treat it as a security incident and
  use the **Reporting a Vulnerability** channel above before installing.
