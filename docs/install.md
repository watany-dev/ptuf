# Installing ptuf

`ptuf` ships pre-built binaries for Linux / macOS / Windows on every GitHub
release. Pick the install path that matches your environment:

| Method | When to use |
|---|---|
| `ptuf-installer.sh` / `ptuf-installer.ps1` (README "Install") | Quickest path, no Rust toolchain required. |
| `cargo binstall ptuf` | You already have Rust and want a pre-built binary. |
| `cargo install ptuf` | You want to compile from source via crates.io. |
| `ubi` / `mise` | You manage tool versions centrally. |
| Verified install (below) | Reproducible / shared / production deployments — pins a release tag, validates SHA-256 sum, verifies the GitHub artifact attestation. |

> Examples below pin `v0.1.0-rc.2`. Substitute the tag you want, or use
> `latest` where the host supports it.

## Requirements

- Rust `1.93.0` or newer (only when building from source)
- `lld` for the default Linux build profile (only when building from source)
- `cargo-deny` and `cargo-tarpaulin` for the full local quality pipeline
  (developers only)

## cargo-binstall

```bash
cargo binstall ptuf
```

`ptuf` exposes a `[package.metadata.binstall]` block in `Cargo.toml` that
points at the canonical cargo-dist archives, so cargo-binstall fetches the
same artifacts the installer scripts use. Pass `--version 0.1.0-rc.2` while
RCs are in flight (cargo-binstall mirrors `cargo install`'s "stable only"
default).

## ubi

[`ubi`](https://github.com/houseabsolute/ubi) is a generic GitHub-release
binary installer — no per-tool config needed:

```bash
ubi -p watany-dev/ptuf                     # latest release into ./
ubi -p watany-dev/ptuf -t v0.1.0-rc.2 -i ~/.local/bin
```

## mise / asdf (via ubi backend)

[`mise`](https://mise.jdx.dev/) can install any GitHub release through its
`ubi:` backend without a dedicated plugin:

```bash
mise use -g ubi:watany-dev/ptuf@0.1.0-rc.2
```

asdf users can do the same via the `ubi` plugin
(`asdf plugin add ubi`).

## Verified install (recommended for pinned deployments)

Set the exact version and target you want, download the canonical archive,
verify its checksum, and verify the GitHub artifact attestation before
extracting.

### Linux

```bash
VERSION=v0.1.0-rc.2
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
VERSION=v0.1.0-rc.2
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
$Version = "v0.1.0-rc.2"
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
PTUF_VERSION=v0.1.0-rc.2
curl -LsSf "https://github.com/watany-dev/ptuf/releases/download/$PTUF_VERSION/ptuf-installer.sh" | sh
```

Windows (PowerShell):

```powershell
$env:PTUF_VERSION = "v0.1.0-rc.2"
powershell -ExecutionPolicy Bypass -c "irm https://github.com/watany-dev/ptuf/releases/download/$env:PTUF_VERSION/ptuf-installer.ps1 | iex"
```

## From crates.io

```bash
cargo install ptuf
```

## From source

```bash
make build
cargo install --path .
```
