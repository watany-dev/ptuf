# Installing ptuf

`cargo binstall ptuf` downloads a prebuilt binary in seconds without a Rust
toolchain; `cargo install ptuf` compiles the same release from crates.io when
you already have Rust set up. The verified-install instructions below pin a
release, check the SHA-256 sum, and verify the GitHub artifact attestation
before extracting — use them when you want a reproducible install or are
deploying ptuf into a shared environment.

## Requirements

- Rust `1.93.0` or newer (only when building from source)
- `lld` for the default Linux build profile (only when building from source)
- `cargo-deny` and `cargo-tarpaulin` for the full local quality pipeline
  (developers only)

## Verified install (recommended for pinned deployments)

Set the exact version and target you want, download the canonical archive,
verify its checksum, and verify the GitHub artifact attestation before
extracting.

### Linux

```bash
VERSION=v0.0.1
TARGET=x86_64-unknown-linux-musl
ARCHIVE=ptuf-$TARGET.tar.gz
BASE=https://github.com/watany-dev/ptuf/releases/download/$VERSION

curl -LO "$BASE/$ARCHIVE"
curl -LO "$BASE/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "$ARCHIVE" \
  --repo watany-dev/ptuf \
  --source-ref refs/tags/$VERSION
tar -xzf "$ARCHIVE" --strip-components=1
install -m 0755 ptuf ~/.cargo/bin/ptuf
```

### macOS

```bash
VERSION=v0.0.1
TARGET=aarch64-apple-darwin
ARCHIVE=ptuf-$TARGET.tar.gz
BASE=https://github.com/watany-dev/ptuf/releases/download/$VERSION

curl -LO "$BASE/$ARCHIVE"
curl -LO "$BASE/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "$ARCHIVE" \
  --repo watany-dev/ptuf \
  --source-ref refs/tags/$VERSION
tar -xzf "$ARCHIVE" --strip-components=1
install -m 0755 ptuf ~/.cargo/bin/ptuf
```

### Windows (PowerShell)

```powershell
$Version = "v0.0.1"
$Target = "x86_64-pc-windows-msvc"
$Archive = "ptuf-$Target.zip"
$Base = "https://github.com/watany-dev/ptuf/releases/download/$Version"

curl.exe -LO "$Base/$Archive"
curl.exe -LO "$Base/SHA256SUMS"
$Expected = (Get-Content SHA256SUMS | Where-Object { $_ -match ([regex]::Escape($Archive) + "$") } | ForEach-Object { ($_ -split "\s+")[0] })
$Actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "checksum mismatch for $Archive" }
gh attestation verify $Archive `
  --repo watany-dev/ptuf `
  --source-ref refs/tags/$Version
Expand-Archive $Archive -DestinationPath .
```

## Installer scripts (unverified)

These remain available for compatibility. The verified-install path above is
preferred for pinned deployments.

Linux / macOS:

```bash
PTUF_VERSION=v0.0.1
curl -LsSf "https://github.com/watany-dev/ptuf/releases/download/$PTUF_VERSION/ptuf-installer.sh" | sh
```

Windows (PowerShell):

```powershell
$env:PTUF_VERSION = "v0.0.1"
powershell -ExecutionPolicy Bypass -c "irm https://github.com/watany-dev/ptuf/releases/download/$env:PTUF_VERSION/ptuf-installer.ps1 | iex"
```

## With cargo-binstall (fastest, no toolchain)

If you have [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall)
installed, it downloads the same prebuilt archive cargo-dist publishes and
skips compilation:

```bash
cargo binstall ptuf
```

cargo-binstall does not verify the SHA-256 sum or the GitHub artifact
attestation. For pinned or shared-environment deployments, use the
[Verified install](#verified-install-recommended-for-pinned-deployments)
path above instead.

## From crates.io

```bash
cargo install ptuf
```

## From source

```bash
make build
cargo install --path .
```

## Updating

`ptuf update` upgrades the installed binary in place. It auto-detects
the install path and dispatches to the matching updater:

- if `ptuf` lives under `$CARGO_HOME/bin` (or `~/.cargo/bin`) and `cargo`
  is on PATH, it runs `cargo install ptuf --force`;
- otherwise it pipes the cargo-dist installer (`ptuf-installer.sh` on
  Unix, `ptuf-installer.ps1` on Windows) for the requested release tag.

Common flags:

```bash
ptuf update            # upgrade to the latest GitHub release
ptuf update --check    # only print current vs. latest, no write
ptuf update --version v0.2.0   # pin to a specific tag
ptuf update --force    # reinstall even if already up to date
```

`ptuf update` shells out to `curl` (for the latest-release lookup) and
to either `cargo` or `sh` / `powershell` for the actual swap. It does
not embed an HTTP client. If you want to reproduce the verified install
manually (curl + SHA256SUMS + `gh attestation verify`), continue to
follow the steps under [Verified install](#verified-install-recommended).
