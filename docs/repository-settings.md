# Repository settings checklist

These settings live in GitHub, crates.io and npm, not in the repository, so
nothing in CI notices when one drifts. Review them when a maintainer, a
workflow, or a job name changes. Ported from watany-dev/chokkin's
`docs/dev/ci-porting-notes.md`.

## `main` branch ruleset

Settings → Rules → Rulesets:

- Restrict deletions and block force pushes.
- Require a pull request before merging, with review from Code Owners
  (`.github/CODEOWNERS`). A PR author cannot approve their own PR, so while
  there is a single maintainer, add them to the bypass list (for pull
  requests only) or no maintainer PR can merge.
- Require status checks to pass, with the branch up to date. The jobs that
  cover `make check` and the PR-only gates:
  - `Format check`
  - `Clippy + doc warnings`
  - `test (ubuntu-24.04)`, `test (macos-14)`
  - `Coverage (tarpaulin)`
  - `MSRV build (1.93.0)`
  - `npm smoke`
  - `cargo-deny`
  - `cargo-machete`
  - `actionlint`, `zizmor`
  - `Test scripts`
  - `SemVer check`
  - `Mutants (PR diff)`

  `PBT deep (10k cases)` runs only on pushes to `main`, so it cannot be a
  required check. A renamed job drops out of the required list silently, so
  update the ruleset in the same PR that renames it.

## Environments

Settings → Environments:

- **`crates-io`** (used by `.github/workflows/publish-crates.yml`):
  deployment branches and tags limited to tags matching `v*`; required
  reviewer: the maintainer. "Prevent self-review" would block the only
  maintainer, so leave it off until there is a second one.

## Releases

Settings → General → Releases: enable immutable releases. `release.yml`
attaches every asset before the release is published, so it works with them
unchanged.

## Registries

- **crates.io**: two-factor authentication on for every owner. Publishing
  still uses the scoped `CRATES_IO_TOKEN` secret (see `docs/RELEASING.md`);
  moving to crates.io Trusted Publishing would remove it.
- **npm** (`@ptuf` scope): two-factor authentication on for every owner, and
  Trusted Publishing for the `Release` workflow as the only publisher; no
  `NPM_TOKEN` secret exists.

## Code security

Settings → Code security: private vulnerability reporting stays on
(`SECURITY.md` points reporters to it), along with Dependabot alerts and
secret scanning with push protection.
