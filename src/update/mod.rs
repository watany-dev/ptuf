//! `ptuf update` — auto-detect cargo install vs. prebuilt installer
//! and shell out to the appropriate updater.
//!
//! This module deliberately avoids pulling in any Rust HTTP / TLS crate.
//! The version check is a one-shot `curl -fsSLI` to the GitHub Releases
//! `latest` redirect, and the actual swap is delegated to either
//! `cargo install ptuf --force` or the cargo-dist-published installer
//! script (`ptuf-installer.sh` / `ptuf-installer.ps1`). SHA-256
//! verification and atomic file replacement are the installer's
//! responsibility.

pub mod exe;
pub mod spawn;

use std::io::{self, Write};
use std::path::Path;

use exe::ExeLocator;
use spawn::Spawner;

const GITHUB_REPO: &str = "watany-dev/ptuf";
const LATEST_REDIRECT_URL: &str = "https://github.com/watany-dev/ptuf/releases/latest";
const RELEASES_TAG_URL_PREFIX: &str = "https://github.com/watany-dev/ptuf/releases/tag/";
const RELEASES_DOWNLOAD_URL_PREFIX: &str = "https://github.com/watany-dev/ptuf/releases/download/";

/// Parsed `ptuf update [--check] [--version <TAG>] [--force]
/// [--skip-attestation]`.
///
/// Re-exported through `crate::cli::UpdateOptions` because it rides
/// inside the `pub Command::Update` variant.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateOptions {
    pub check: bool,
    pub version: Option<String>,
    pub force: bool,
    /// When `true`, the prebuilt installer is executed without first
    /// running `gh attestation verify`. Set by `--skip-attestation` or
    /// the `PTUF_UPDATE_SKIP_ATTESTATION=1` env override (the env read
    /// happens in `run`, not the test seam `run_with_platform`, so unit
    /// tests stay deterministic).
    pub skip_attestation: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    CargoInstall,
    PrebuiltInstaller,
}

impl Strategy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CargoInstall => "cargo install",
            Self::PrebuiltInstaller => "prebuilt installer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Unix,
    Windows,
}

impl Platform {
    pub const fn host() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

#[derive(Debug)]
pub enum UpdateError {
    CurlMissing,
    LatestTagFetch {
        exit_code: i32,
        stderr: String,
    },
    LatestTagParse(String),
    UpdaterSpawn {
        program: String,
        source: io::Error,
    },
    UpdaterExitCode {
        program: String,
        code: i32,
    },
    /// `gh` (the GitHub CLI used to verify artifact attestations) is not
    /// on PATH and `--skip-attestation` was not passed. Carries the path
    /// of the downloaded installer script so the user can verify it
    /// manually after installing `gh`.
    AttestationToolMissing {
        tmp_path: std::path::PathBuf,
    },
    /// `gh attestation verify` returned a non-zero exit. The downloaded
    /// installer is left at `tmp_path` for forensic inspection.
    AttestationFailed {
        tag: String,
        tmp_path: std::path::PathBuf,
        code: i32,
    },
    /// The download command (curl on Unix, `iwr` on Windows) returned a
    /// non-zero exit. We can't proceed because the installer file may be
    /// truncated.
    DownloadFailed {
        url: String,
        code: i32,
    },
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurlMissing => write!(
                f,
                "ptuf update requires curl on PATH (used for the GitHub release lookup)",
            ),
            Self::LatestTagFetch { exit_code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(
                        f,
                        "failed to fetch latest release tag (curl exit {exit_code})"
                    )
                } else {
                    write!(
                        f,
                        "failed to fetch latest release tag (curl exit {exit_code}): {trimmed}",
                    )
                }
            },
            Self::LatestTagParse(detail) => {
                write!(f, "could not parse latest release tag: {detail}")
            },
            Self::UpdaterSpawn { program, source } => {
                write!(f, "failed to launch {program}: {source}")
            },
            Self::UpdaterExitCode { program, code } => {
                write!(f, "{program} exited with status {code}")
            },
            Self::AttestationToolMissing { tmp_path } => write!(
                f,
                "ptuf update requires `gh` on PATH to verify the prebuilt installer's attestation; install GitHub CLI or pass --skip-attestation. Downloaded script kept at {} for manual verification",
                tmp_path.display(),
            ),
            Self::AttestationFailed {
                tag,
                tmp_path,
                code,
            } => write!(
                f,
                "gh attestation verify rejected the installer for {tag} (exit {code}); refusing to execute. Script kept at {} for inspection",
                tmp_path.display(),
            ),
            Self::DownloadFailed { url, code } => {
                write!(f, "failed to download installer from {url} (exit {code})")
            },
        }
    }
}

impl std::error::Error for UpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UpdaterSpawn { source, .. } => Some(source),
            Self::CurlMissing
            | Self::LatestTagFetch { .. }
            | Self::LatestTagParse(_)
            | Self::UpdaterExitCode { .. }
            | Self::AttestationToolMissing { .. }
            | Self::AttestationFailed { .. }
            | Self::DownloadFailed { .. } => None,
        }
    }
}

/// Auto-detect whether ptuf was placed by `cargo install` or by the
/// prebuilt installer.
///
/// Returns `(strategy, fallback_warning)`. The warning is non-empty when
/// the binary lives under cargo's bin directory but `cargo` itself is
/// not on PATH, in which case we fall back to the prebuilt installer
/// (which will replace the cargo-managed copy with one cargo no longer
/// tracks).
pub fn select_strategy<S, E>(spawner: &S, locator: &E) -> (Strategy, Option<String>)
where
    S: Spawner,
    E: ExeLocator,
{
    let exe = match locator.current_exe() {
        Ok(p) => p,
        Err(_) => return (Strategy::PrebuiltInstaller, None),
    };
    let cargo_home = match locator.cargo_home() {
        Some(p) => p,
        None => return (Strategy::PrebuiltInstaller, None),
    };
    if !is_under_cargo_bin(&exe, &cargo_home) {
        return (Strategy::PrebuiltInstaller, None);
    }
    if cargo_is_available(spawner) {
        (Strategy::CargoInstall, None)
    } else {
        (
            Strategy::PrebuiltInstaller,
            Some(format!(
                "ptuf update: cargo not found on PATH; falling back to the prebuilt installer (this will replace the cargo-managed binary at {})",
                exe.display(),
            )),
        )
    }
}

fn is_under_cargo_bin(exe: &Path, cargo_home: &Path) -> bool {
    let cargo_bin = cargo_home.join("bin");
    let canonical_cargo_bin = std::fs::canonicalize(&cargo_bin).unwrap_or(cargo_bin);
    let canonical_exe = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    canonical_exe
        .parent()
        .is_some_and(|parent| parent == canonical_cargo_bin)
}

fn cargo_is_available<S: Spawner>(spawner: &S) -> bool {
    matches!(
        spawner.run("cargo", &["--version"]),
        Ok(outcome) if outcome.exit_code == 0,
    )
}

/// Extract the release tag (e.g. `v0.2.0`) from the headers of a
/// `curl -fsSLI` response. The `latest` URL redirects to
/// `.../releases/tag/<TAG>`, so we look for the last `Location:` header
/// (curl prints one per hop) and strip the prefix.
pub fn parse_redirect_tag(headers: &str) -> Result<String, UpdateError> {
    let mut last_location: Option<&str> = None;
    for raw_line in headers.lines() {
        let line = raw_line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("location") {
            last_location = Some(value.trim());
        }
    }
    let location = last_location.ok_or_else(|| {
        UpdateError::LatestTagParse(
            "no Location header in response from GitHub releases/latest".to_string(),
        )
    })?;
    let tag = location
        .strip_prefix(RELEASES_TAG_URL_PREFIX)
        .ok_or_else(|| {
            UpdateError::LatestTagParse(format!(
                "Location header does not point to a release tag: {location}",
            ))
        })?;
    let tag = tag.trim_end_matches('/').trim();
    if tag.is_empty() {
        return Err(UpdateError::LatestTagParse(
            "Location header pointed to an empty tag".to_string(),
        ));
    }
    Ok(tag.to_string())
}

fn fetch_latest_tag<S: Spawner>(spawner: &S) -> Result<String, UpdateError> {
    let outcome = spawner
        .run("curl", &["-fsSLI", LATEST_REDIRECT_URL])
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                UpdateError::CurlMissing
            } else {
                UpdateError::UpdaterSpawn {
                    program: "curl".to_string(),
                    source: err,
                }
            }
        })?;
    if outcome.exit_code != 0 {
        return Err(UpdateError::LatestTagFetch {
            exit_code: outcome.exit_code,
            stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        });
    }
    let body = String::from_utf8_lossy(&outcome.stdout);
    parse_redirect_tag(&body)
}

/// Strip a leading `v` from a tag string for cargo's `--version` flag,
/// which expects bare semver.
fn strip_v_prefix(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Compare two version strings as `Vec<u64>` of dotted numeric segments.
/// Returns `None` if either side has a non-numeric / pre-release suffix
/// (e.g. `0.2.0-rc.1`) — callers should treat `None` as "cannot compare,
/// skip the guard rather than block legitimate updates".
fn version_lt(lhs: &str, rhs: &str) -> Option<std::cmp::Ordering> {
    let parse =
        |s: &str| -> Option<Vec<u64>> { s.split('.').map(|seg| seg.parse::<u64>().ok()).collect() };
    let l = parse(lhs)?;
    let r = parse(rhs)?;
    Some(l.cmp(&r))
}

#[derive(Debug)]
pub struct InstallerCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// Three-step plan for the prebuilt installer path: download the
/// installer to `tmp_path`, optionally verify its attestation with
/// `gh`, then execute it. Each step is a separately-spawnable
/// `InstallerCommand` so the run loop can stop and surface specific
/// errors between steps (and so unit tests can assert per-step argv).
///
/// Lifetime contract: the caller of `build_prebuilt_plan` owns
/// `tmp_path`. `run_prebuilt_plan` removes the file (best-effort) on
/// success and leaves it on disk for any failure so the user can
/// re-verify or inspect it.
#[derive(Debug)]
pub struct PrebuiltPlan {
    pub download: InstallerCommand,
    pub verify: Option<InstallerCommand>,
    pub execute: InstallerCommand,
    pub tmp_path: std::path::PathBuf,
    /// Source URL recorded so error messages can name the artifact even
    /// after `download` is consumed.
    pub url: String,
}

/// Build the argv for `cargo install`. Pure function so it can be
/// asserted from unit tests on any host. Prebuilt installers go
/// through `build_prebuilt_plan` instead because they need a
/// download → verify → execute pipeline.
pub fn build_installer_command(
    strategy: Strategy,
    tag: &str,
    pinned: bool,
    platform: Platform,
) -> InstallerCommand {
    match strategy {
        Strategy::CargoInstall => {
            // `--locked` pins transitive deps to the published Cargo.lock so
            // the binary the user lands on is bit-identical to the audited
            // release tree. Without it `cargo install` re-resolves the graph,
            // which a yanked / poisoned transitive could exploit.
            let mut args = vec![
                "install".to_string(),
                "ptuf".to_string(),
                "--locked".to_string(),
                "--force".to_string(),
            ];
            if pinned {
                args.push("--version".to_string());
                args.push(strip_v_prefix(tag).to_string());
            }
            InstallerCommand {
                program: "cargo".to_string(),
                args,
            }
        },
        Strategy::PrebuiltInstaller => {
            // Kept for backwards compatibility with callers / tests that
            // only need the shape of the prebuilt entry (program). The
            // production run loop uses `build_prebuilt_plan` so it can
            // verify the download.
            let plan = build_prebuilt_plan(tag, platform, std::path::Path::new(""), true);
            plan.execute
        },
    }
}

/// Build the 3-step prebuilt installer plan: curl/iwr download into
/// `tmp_path`, `gh attestation verify` (omitted when
/// `skip_attestation`), then execute the downloaded script. Pure
/// function so unit tests can assert each step's argv on any host.
pub fn build_prebuilt_plan(
    tag: &str,
    platform: Platform,
    tmp_path: &std::path::Path,
    skip_attestation: bool,
) -> PrebuiltPlan {
    let tmp = tmp_path.to_string_lossy().into_owned();
    match platform {
        Platform::Unix => {
            let url = format!("{RELEASES_DOWNLOAD_URL_PREFIX}{tag}/ptuf-installer.sh");
            PrebuiltPlan {
                download: InstallerCommand {
                    program: "curl".to_string(),
                    args: vec![
                        "--proto".to_string(),
                        "=https".to_string(),
                        "--tlsv1.2".to_string(),
                        "-fLsS".to_string(),
                        "-o".to_string(),
                        tmp.clone(),
                        url.clone(),
                    ],
                },
                verify: (!skip_attestation).then(|| build_attestation_verify(&tmp)),
                execute: InstallerCommand {
                    program: "sh".to_string(),
                    args: vec![tmp],
                },
                tmp_path: tmp_path.to_path_buf(),
                url,
            }
        },
        Platform::Windows => {
            let url = format!("{RELEASES_DOWNLOAD_URL_PREFIX}{tag}/ptuf-installer.ps1");
            PrebuiltPlan {
                download: InstallerCommand {
                    program: "powershell".to_string(),
                    args: vec![
                        "-NoProfile".to_string(),
                        "-Command".to_string(),
                        format!("iwr -useb '{url}' -OutFile '{tmp}'"),
                    ],
                },
                verify: (!skip_attestation).then(|| build_attestation_verify(&tmp)),
                execute: InstallerCommand {
                    program: "powershell".to_string(),
                    args: vec![
                        "-NoProfile".to_string(),
                        "-ExecutionPolicy".to_string(),
                        "Bypass".to_string(),
                        "-File".to_string(),
                        tmp,
                    ],
                },
                tmp_path: tmp_path.to_path_buf(),
                url,
            }
        },
    }
}

fn build_attestation_verify(tmp: &str) -> InstallerCommand {
    InstallerCommand {
        program: "gh".to_string(),
        args: vec![
            "attestation".to_string(),
            "verify".to_string(),
            tmp.to_string(),
            "--repo".to_string(),
            GITHUB_REPO.to_string(),
        ],
    }
}

/// Compute a process-unique tmp path for the prebuilt installer script.
/// Uses `<system tmp>/ptuf-update-<pid>/installer.{sh,ps1}` so concurrent
/// `ptuf update` invocations from the same shell don't collide.
fn installer_tmp_path(platform: Platform) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ptuf-update-{}", std::process::id()));
    let name = match platform {
        Platform::Unix => "installer.sh",
        Platform::Windows => "installer.ps1",
    };
    dir.join(name)
}

/// Top-level entry: drive the `ptuf update` flow against the injected
/// `Spawner` / `ExeLocator`. Always returns a u8 exit code (`0` on
/// success / `--check` / already-up-to-date, `1` on every failure).
///
/// Reads `PTUF_UPDATE_SKIP_ATTESTATION` here (rather than in
/// `run_with_platform`) so the test seam stays deterministic: tests
/// pass `skip_attestation` explicitly through `UpdateOptions`.
pub fn run<S, E, W1, W2>(
    mut opts: UpdateOptions,
    spawner: &S,
    locator: &E,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8
where
    S: Spawner,
    E: ExeLocator,
    W1: Write,
    W2: Write,
{
    if !opts.skip_attestation && env_truthy("PTUF_UPDATE_SKIP_ATTESTATION") {
        opts.skip_attestation = true;
    }
    run_with_platform(opts, spawner, locator, Platform::host(), stdout, stderr)
}

fn env_truthy(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

// Six args is the natural shape for a fully injected entry point
// (opts + Spawner + ExeLocator + Platform + stdout + stderr). The
// equivalent struct/builder shuffle would obscure rather than clarify
// the call site, and `run()` collapses to five for production callers.
#[expect(
    clippy::too_many_arguments,
    reason = "test seam — Platform is the only extra param vs. run()"
)]
pub fn run_with_platform<S, E, W1, W2>(
    opts: UpdateOptions,
    spawner: &S,
    locator: &E,
    platform: Platform,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8
where
    S: Spawner,
    E: ExeLocator,
    W1: Write,
    W2: Write,
{
    let current = env!("CARGO_PKG_VERSION");

    let pinned = opts.version.is_some();
    let tag = match opts.version {
        Some(v) => v,
        None => match fetch_latest_tag(spawner) {
            Ok(t) => t,
            Err(err) => {
                let _ = writeln!(stderr, "ptuf update: {err}");
                return 1;
            },
        },
    };
    let normalised = strip_v_prefix(&tag);

    if opts.check {
        let _ = writeln!(stdout, "ptuf {GITHUB_REPO}");
        let _ = writeln!(stdout, "  current: {current}");
        let _ = writeln!(stdout, "  latest:  {normalised}");
        if normalised == current {
            let _ = writeln!(stdout, "  status:  up to date");
        } else {
            let _ = writeln!(stdout, "  status:  update available");
        }
        return 0;
    }

    if !opts.force && normalised == current {
        let _ = writeln!(stdout, "ptuf is already up to date ({current})");
        return 0;
    }

    // Downgrade guard: when the user pinned an older tag without `--force`,
    // refuse rather than silently rolling back. `version_lt` returns None for
    // pre-release suffixes (e.g. `-rc.1`) — in that case we cannot compare
    // safely so we skip the guard and emit a single advisory line so the
    // skip is auditable.
    if pinned && !opts.force {
        match version_lt(normalised, current) {
            Some(std::cmp::Ordering::Less) => {
                let _ = writeln!(
                    stderr,
                    "ptuf update: refusing to downgrade — installed {current} is newer than the requested {normalised}; pass --force to override",
                );
                return 1;
            },
            Some(_) => {},
            None => {
                let _ = writeln!(
                    stderr,
                    "ptuf update: could not compare versions ({current} vs {normalised}); skipping downgrade guard",
                );
            },
        }
    }

    let (strategy, warning) = select_strategy(spawner, locator);
    if let Some(msg) = warning {
        let _ = writeln!(stderr, "{msg}");
    }

    let _ = writeln!(
        stdout,
        "ptuf update: {label} -> {normalised} (current {current})",
        label = strategy.label(),
    );

    match strategy {
        Strategy::CargoInstall => {
            let command = build_installer_command(strategy, &tag, pinned, platform);
            run_inherited_step(spawner, &command, stderr)
        },
        Strategy::PrebuiltInstaller => {
            let tmp_path = installer_tmp_path(platform);
            let plan = build_prebuilt_plan(&tag, platform, &tmp_path, opts.skip_attestation);
            run_prebuilt_plan(spawner, &plan, &tag, stderr)
        },
    }
}

fn run_inherited_step<S: Spawner, W: Write>(
    spawner: &S,
    command: &InstallerCommand,
    stderr: &mut W,
) -> u8 {
    let arg_refs: Vec<&str> = command.args.iter().map(String::as_str).collect();
    let exit_code = match spawner.run_inherited(&command.program, &arg_refs) {
        Ok(c) => c,
        Err(source) => {
            let mapped = UpdateError::UpdaterSpawn {
                program: command.program.clone(),
                source,
            };
            let _ = writeln!(stderr, "ptuf update: {mapped}");
            return 1;
        },
    };
    if exit_code != 0 {
        let err = UpdateError::UpdaterExitCode {
            program: command.program.clone(),
            code: exit_code,
        };
        let _ = writeln!(stderr, "ptuf update: {err}");
        return 1;
    }
    0
}

fn run_prebuilt_plan<S: Spawner, W: Write>(
    spawner: &S,
    plan: &PrebuiltPlan,
    tag: &str,
    stderr: &mut W,
) -> u8 {
    if let Some(parent) = plan.tmp_path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        let _ = writeln!(
            stderr,
            "ptuf update: failed to create temp directory {}: {err}",
            parent.display(),
        );
        return 1;
    }

    let download_args: Vec<&str> = plan.download.args.iter().map(String::as_str).collect();
    match spawner.run_inherited(&plan.download.program, &download_args) {
        Ok(0) => {},
        Ok(code) => {
            let err = UpdateError::DownloadFailed {
                url: plan.url.clone(),
                code,
            };
            let _ = writeln!(stderr, "ptuf update: {err}");
            return 1;
        },
        Err(source) => {
            // Curl on Unix is the most common missing prerequisite — surface
            // the friendly `CurlMissing` text rather than a raw spawn error.
            let mapped =
                if plan.download.program == "curl" && source.kind() == io::ErrorKind::NotFound {
                    UpdateError::CurlMissing
                } else {
                    UpdateError::UpdaterSpawn {
                        program: plan.download.program.clone(),
                        source,
                    }
                };
            let _ = writeln!(stderr, "ptuf update: {mapped}");
            return 1;
        },
    }

    if let Some(verify) = plan.verify.as_ref() {
        let verify_args: Vec<&str> = verify.args.iter().map(String::as_str).collect();
        match spawner.run_inherited(&verify.program, &verify_args) {
            Ok(0) => {},
            Ok(code) => {
                let err = UpdateError::AttestationFailed {
                    tag: tag.to_string(),
                    tmp_path: plan.tmp_path.clone(),
                    code,
                };
                let _ = writeln!(stderr, "ptuf update: {err}");
                return 1;
            },
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let err = UpdateError::AttestationToolMissing {
                    tmp_path: plan.tmp_path.clone(),
                };
                let _ = writeln!(stderr, "ptuf update: {err}");
                return 1;
            },
            Err(source) => {
                let mapped = UpdateError::UpdaterSpawn {
                    program: verify.program.clone(),
                    source,
                };
                let _ = writeln!(stderr, "ptuf update: {mapped}");
                return 1;
            },
        }
    } else {
        let _ = writeln!(
            stderr,
            "ptuf update: WARNING — running prebuilt installer without attestation verification (--skip-attestation set)",
        );
    }

    let exec_args: Vec<&str> = plan.execute.args.iter().map(String::as_str).collect();
    let exec_code = match spawner.run_inherited(&plan.execute.program, &exec_args) {
        Ok(c) => c,
        Err(source) => {
            let mapped = UpdateError::UpdaterSpawn {
                program: plan.execute.program.clone(),
                source,
            };
            let _ = writeln!(stderr, "ptuf update: {mapped}");
            return 1;
        },
    };
    if exec_code != 0 {
        let err = UpdateError::UpdaterExitCode {
            program: plan.execute.program.clone(),
            code: exec_code,
        };
        let _ = writeln!(stderr, "ptuf update: {err}");
        return 1;
    }

    // Best-effort cleanup on success. Failure to remove (eg. a separate
    // process holding the file open) is not a hard error — the script
    // already ran.
    let _ = std::fs::remove_file(&plan.tmp_path);
    if let Some(parent) = plan.tmp_path.parent() {
        let _ = std::fs::remove_dir(parent);
    }
    0
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use super::exe::FakeExeLocator;
    use super::spawn::SpawnOutcome;
    use super::spawn::testing::{RecordingSpawner, ok, ok_with_stderr};
    use super::*;

    fn cargo_locator(cargo_home: PathBuf) -> FakeExeLocator {
        FakeExeLocator {
            exe: cargo_home.join("bin").join("ptuf"),
            cargo_home: Some(cargo_home),
        }
    }

    fn system_locator() -> FakeExeLocator {
        // Paths chosen so they cannot exist on a test runner; canonicalize
        // will fall back to the literal strings, keeping the comparison
        // deterministic.
        FakeExeLocator {
            exe: PathBuf::from("/ptuf-test/system/usr/local/bin/ptuf"),
            cargo_home: Some(PathBuf::from("/ptuf-test/system/home/.cargo")),
        }
    }

    fn redirect_headers(tag: &str) -> String {
        format!(
            "HTTP/2 302\r\nlocation: https://github.com/watany-dev/ptuf/releases/tag/{tag}\r\n\r\n",
        )
    }

    #[test]
    fn parse_redirect_tag_extracts_tag_with_crlf() {
        let body = redirect_headers("v0.2.0");
        assert_eq!(parse_redirect_tag(&body).unwrap(), "v0.2.0");
    }

    #[test]
    fn parse_redirect_tag_handles_uppercase_header_name() {
        let body = "HTTP/2 302\r\nLOCATION: https://github.com/watany-dev/ptuf/releases/tag/v9.9.9\r\n\r\n";
        assert_eq!(parse_redirect_tag(body).unwrap(), "v9.9.9");
    }

    #[test]
    fn parse_redirect_tag_picks_last_location_when_multi_hop() {
        let body = "HTTP/2 301\r\nlocation: https://example.com/intermediate\r\n\r\nHTTP/2 302\r\nlocation: https://github.com/watany-dev/ptuf/releases/tag/v1.2.3\r\n\r\n";
        assert_eq!(parse_redirect_tag(body).unwrap(), "v1.2.3");
    }

    #[test]
    fn parse_redirect_tag_strips_trailing_slash() {
        let body =
            "HTTP/2 302\r\nlocation: https://github.com/watany-dev/ptuf/releases/tag/v0.0.1/\r\n";
        assert_eq!(parse_redirect_tag(body).unwrap(), "v0.0.1");
    }

    #[test]
    fn parse_redirect_tag_rejects_when_no_location() {
        let body = "HTTP/2 200\r\ncontent-type: text/html\r\n\r\n";
        let err = parse_redirect_tag(body).expect_err("must reject");
        assert!(matches!(err, UpdateError::LatestTagParse(_)));
    }

    #[test]
    fn parse_redirect_tag_rejects_non_release_tag_url() {
        let body = "HTTP/2 302\r\nlocation: https://example.com/elsewhere\r\n\r\n";
        let err = parse_redirect_tag(body).expect_err("must reject");
        assert!(matches!(err, UpdateError::LatestTagParse(_)));
    }

    #[test]
    fn parse_redirect_tag_rejects_empty_tag() {
        let body = "HTTP/2 302\r\nlocation: https://github.com/watany-dev/ptuf/releases/tag/\r\n";
        let err = parse_redirect_tag(body).expect_err("must reject");
        assert!(matches!(err, UpdateError::LatestTagParse(_)));
    }

    #[test]
    fn select_strategy_picks_prebuilt_for_system_install() {
        let spawner = RecordingSpawner::new(vec![]);
        let locator = system_locator();
        let (strategy, warning) = select_strategy(&spawner, &locator);
        assert_eq!(strategy, Strategy::PrebuiltInstaller);
        assert!(warning.is_none());
        assert!(spawner.calls().is_empty(), "no PATH lookup needed");
    }

    #[test]
    fn select_strategy_picks_cargo_when_under_cargo_bin_and_cargo_present() {
        let spawner = RecordingSpawner::new(vec![ok("cargo 1.93.0\n")]);
        let locator = cargo_locator(PathBuf::from("/ptuf-test/cargohome/.cargo"));
        let (strategy, warning) = select_strategy(&spawner, &locator);
        assert_eq!(strategy, Strategy::CargoInstall);
        assert!(warning.is_none());
        let calls = spawner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "cargo");
        assert_eq!(calls[0].args, vec!["--version".to_string()]);
    }

    #[test]
    fn select_strategy_falls_back_when_cargo_missing() {
        let spawner = RecordingSpawner::new(vec![Err(io::Error::from(io::ErrorKind::NotFound))]);
        let locator = cargo_locator(PathBuf::from("/ptuf-test/cargohome/.cargo"));
        let (strategy, warning) = select_strategy(&spawner, &locator);
        assert_eq!(strategy, Strategy::PrebuiltInstaller);
        let warning = warning.expect("warning must be emitted on fallback");
        assert!(warning.contains("cargo not found"), "warning: {warning}");
    }

    #[test]
    fn select_strategy_falls_back_when_cargo_returns_nonzero() {
        let spawner = RecordingSpawner::new(vec![ok_with_stderr(127, "cargo: command failed")]);
        let locator = cargo_locator(PathBuf::from("/ptuf-test/cargohome/.cargo"));
        let (strategy, _warning) = select_strategy(&spawner, &locator);
        assert_eq!(strategy, Strategy::PrebuiltInstaller);
    }

    #[test]
    fn build_installer_command_cargo_default() {
        let cmd = build_installer_command(Strategy::CargoInstall, "v0.2.0", false, Platform::Unix);
        assert_eq!(cmd.program, "cargo");
        assert_eq!(
            cmd.args,
            vec![
                "install".to_string(),
                "ptuf".to_string(),
                "--locked".to_string(),
                "--force".to_string(),
            ],
        );
    }

    #[test]
    fn build_installer_command_cargo_with_version_pin_strips_v() {
        let cmd = build_installer_command(Strategy::CargoInstall, "v0.3.1", true, Platform::Unix);
        assert_eq!(
            cmd.args,
            vec![
                "install".to_string(),
                "ptuf".to_string(),
                "--locked".to_string(),
                "--force".to_string(),
                "--version".to_string(),
                "0.3.1".to_string(),
            ],
        );
    }

    #[test]
    fn build_prebuilt_plan_unix_includes_curl_download_and_sh_execute() {
        let tmp = PathBuf::from("/tmp/ptuf-test-installer.sh");
        let plan = build_prebuilt_plan("v0.2.0", Platform::Unix, &tmp, true);
        assert_eq!(plan.download.program, "curl");
        assert!(plan.download.args.contains(&"--proto".to_string()));
        assert!(plan.download.args.contains(&"=https".to_string()));
        assert!(plan.download.args.contains(&"--tlsv1.2".to_string()));
        assert!(plan.download.args.contains(&"-fLsS".to_string()));
        assert!(plan.download.args.contains(&"-o".to_string()));
        assert!(
            plan.download
                .args
                .contains(&tmp.to_string_lossy().into_owned())
        );
        assert!(
            plan.url
                .contains("releases/download/v0.2.0/ptuf-installer.sh"),
            "url: {}",
            plan.url
        );
        assert_eq!(plan.execute.program, "sh");
        assert_eq!(plan.execute.args, vec![tmp.to_string_lossy().into_owned()]);
        assert_eq!(plan.tmp_path, tmp);
    }

    #[test]
    fn build_prebuilt_plan_windows_uses_iwr_and_powershell_file() {
        let tmp = PathBuf::from("C\\:tmp\\ptuf.ps1");
        let plan = build_prebuilt_plan("v0.2.0", Platform::Windows, &tmp, true);
        assert_eq!(plan.download.program, "powershell");
        let cmd = &plan.download.args[2];
        assert!(cmd.contains("iwr -useb"), "cmd: {cmd}");
        assert!(
            cmd.contains("ptuf-installer.ps1"),
            "cmd should reference the ps1 url: {cmd}"
        );
        assert!(cmd.contains("-OutFile"), "cmd should write to file: {cmd}");
        assert_eq!(plan.execute.program, "powershell");
        assert!(plan.execute.args.contains(&"-File".to_string()));
        assert!(
            plan.execute
                .args
                .contains(&tmp.to_string_lossy().into_owned()),
        );
    }

    #[test]
    fn build_prebuilt_plan_includes_verify_when_attestation_required() {
        let tmp = PathBuf::from("/tmp/ptuf-installer.sh");
        let plan = build_prebuilt_plan("v0.2.0", Platform::Unix, &tmp, false);
        let verify = plan
            .verify
            .expect("verify must be present when not skipped");
        assert_eq!(verify.program, "gh");
        assert!(verify.args.contains(&"attestation".to_string()));
        assert!(verify.args.contains(&"verify".to_string()));
        assert!(verify.args.contains(&tmp.to_string_lossy().into_owned()));
        assert!(verify.args.contains(&"--repo".to_string()));
        assert!(verify.args.contains(&"watany-dev/ptuf".to_string()));
    }

    #[test]
    fn build_prebuilt_plan_skips_verify_when_skip_attestation_true() {
        let tmp = PathBuf::from("/tmp/ptuf-installer.sh");
        let plan = build_prebuilt_plan("v0.2.0", Platform::Unix, &tmp, true);
        assert!(plan.verify.is_none(), "verify must be None when skipped");
    }

    #[test]
    fn run_check_only_does_not_invoke_updater() {
        let spawner = RecordingSpawner::new(vec![ok(&redirect_headers("v9.9.9"))]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: true,
            version: None,
            force: false,
            skip_attestation: false,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0);
        assert_eq!(spawner.calls().len(), 1);
        assert_eq!(spawner.calls()[0].program, "curl");
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("latest:  9.9.9"), "stdout: {stdout}");
        assert!(stdout.contains("update available"), "stdout: {stdout}");
    }

    #[test]
    fn run_check_reports_up_to_date() {
        let current = env!("CARGO_PKG_VERSION");
        let spawner = RecordingSpawner::new(vec![ok(&redirect_headers(&format!("v{current}")))]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: true,
            version: None,
            force: false,
            skip_attestation: false,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0);
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("up to date"), "stdout: {stdout}");
    }

    #[test]
    fn run_already_up_to_date_skips_updater() {
        let current = env!("CARGO_PKG_VERSION");
        let spawner = RecordingSpawner::new(vec![ok(&redirect_headers(&format!("v{current}")))]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions::default();
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0);
        assert_eq!(spawner.calls().len(), 1, "only the curl probe should run");
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("already up to date"), "stdout: {stdout}");
    }

    #[test]
    fn run_force_reinstalls_even_when_up_to_date() {
        let current = env!("CARGO_PKG_VERSION");
        let spawner = RecordingSpawner::new(vec![
            ok(&redirect_headers(&format!("v{current}"))),
            ok(""),
            ok(""),
        ]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: None,
            force: true,
            skip_attestation: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(calls.len(), 3, "curl probe + curl download + sh execute");
        assert_eq!(calls[1].program, "curl");
        assert_eq!(calls[2].program, "sh");
    }

    #[test]
    fn run_version_pin_skips_latest_lookup() {
        let spawner = RecordingSpawner::new(vec![ok(""), ok("")]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.3.0".to_string()),
            force: false,
            skip_attestation: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(
            calls.len(),
            2,
            "no curl probe when version is pinned; download + execute remain",
        );
        assert_eq!(calls[0].program, "curl");
        let download_url = calls[0]
            .args
            .last()
            .expect("download URL is the last curl arg");
        assert!(
            download_url.contains("releases/download/v0.3.0/ptuf-installer.sh"),
            "download URL: {download_url}",
        );
        assert_eq!(calls[1].program, "sh");
    }

    #[test]
    fn run_cargo_strategy_invokes_cargo_install_force() {
        let cargo_home = PathBuf::from("/ptuf-test/cargohome/.cargo");
        let spawner = RecordingSpawner::new(vec![
            ok(&redirect_headers("v9.9.9")),
            ok("cargo 1.93.0\n"),
            ok(""),
        ]);
        let locator = cargo_locator(cargo_home);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions::default();
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(calls.len(), 3, "curl + cargo --version + cargo install");
        assert_eq!(calls[2].program, "cargo");
        assert_eq!(
            calls[2].args,
            vec![
                "install".to_string(),
                "ptuf".to_string(),
                "--locked".to_string(),
                "--force".to_string(),
            ],
        );
    }

    #[test]
    fn run_cargo_strategy_with_version_pin_passes_version() {
        let cargo_home = PathBuf::from("/ptuf-test/cargohome/.cargo");
        let spawner = RecordingSpawner::new(vec![ok("cargo 1.93.0\n"), ok("")]);
        let locator = cargo_locator(cargo_home);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.4.2".to_string()),
            force: false,
            skip_attestation: false,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(calls[1].program, "cargo");
        assert!(calls[1].args.contains(&"--version".to_string()));
        assert!(calls[1].args.contains(&"0.4.2".to_string()));
    }

    #[test]
    fn run_curl_missing_is_friendly_error() {
        let spawner = RecordingSpawner::new(vec![Err(io::Error::from(io::ErrorKind::NotFound))]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions::default();
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 1);
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("requires curl on PATH"), "stderr: {err_s}");
    }

    #[test]
    fn run_updater_exit_code_is_normalised_to_one() {
        // The installer's own stdout/stderr are inherited (kernel
        // forwards them to the user terminal), so the test only needs
        // to verify that ptuf maps the non-zero exit to 1 and emits a
        // friendly summary on its own stderr.
        let spawner = RecordingSpawner::new(vec![
            ok(&redirect_headers("v9.9.9")),
            ok(""),
            Ok(SpawnOutcome {
                exit_code: 7,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        ]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: None,
            force: false,
            skip_attestation: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 1);
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("exited with status 7"), "stderr: {err_s}");
    }

    #[test]
    fn strategy_label_distinguishes_variants() {
        assert_eq!(Strategy::CargoInstall.label(), "cargo install");
        assert_eq!(Strategy::PrebuiltInstaller.label(), "prebuilt installer");
    }

    #[test]
    fn run_latest_tag_fetch_failure_propagates() {
        let spawner = RecordingSpawner::new(vec![ok_with_stderr(22, "curl: 22 Not Found")]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions::default();
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 1);
        let err_s = String::from_utf8_lossy(&err);
        assert!(
            err_s.contains("failed to fetch latest release tag"),
            "stderr: {err_s}",
        );
    }

    #[test]
    fn update_error_display_round_trips_for_every_variant() {
        let cases: Vec<UpdateError> = vec![
            UpdateError::CurlMissing,
            UpdateError::LatestTagFetch {
                exit_code: 22,
                stderr: "boom".to_string(),
            },
            UpdateError::LatestTagFetch {
                exit_code: 22,
                stderr: String::new(),
            },
            UpdateError::LatestTagParse("bad".to_string()),
            UpdateError::UpdaterSpawn {
                program: "sh".to_string(),
                source: io::Error::from(io::ErrorKind::NotFound),
            },
            UpdateError::UpdaterExitCode {
                program: "cargo".to_string(),
                code: 7,
            },
            UpdateError::AttestationToolMissing {
                tmp_path: PathBuf::from("/tmp/ptuf-installer.sh"),
            },
            UpdateError::AttestationFailed {
                tag: "v0.2.0".to_string(),
                tmp_path: PathBuf::from("/tmp/ptuf-installer.sh"),
                code: 1,
            },
            UpdateError::DownloadFailed {
                url: "https://example.com/installer.sh".to_string(),
                code: 22,
            },
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.is_empty(), "Display must produce text for {err:?}");
        }
    }

    #[test]
    fn platform_host_picks_a_valid_variant() {
        let p = Platform::host();
        assert!(matches!(p, Platform::Unix | Platform::Windows));
    }

    #[test]
    fn run_falls_back_with_warning_when_cargo_bin_but_no_cargo() {
        let cargo_home = PathBuf::from("/ptuf-test/cargohome/.cargo");
        let spawner = RecordingSpawner::new(vec![
            ok(&redirect_headers("v9.9.9")),
            Err(io::Error::from(io::ErrorKind::NotFound)),
            ok(""),
            ok(""),
        ]);
        let locator = cargo_locator(cargo_home);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: None,
            force: false,
            skip_attestation: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("cargo not found"), "stderr: {err_s}");
        let calls = spawner.calls();
        assert_eq!(
            calls.len(),
            4,
            "curl probe + cargo --version probe + curl download + sh installer",
        );
        assert_eq!(calls[2].program, "curl");
        assert_eq!(calls[3].program, "sh");
    }

    #[test]
    fn update_error_source_chains_for_io_variants() {
        let err = UpdateError::UpdaterSpawn {
            program: "sh".to_string(),
            source: io::Error::from(io::ErrorKind::NotFound),
        };
        assert!(std::error::Error::source(&err).is_some());
        let err = UpdateError::CurlMissing;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn version_lt_orders_dotted_numeric_segments() {
        use std::cmp::Ordering;
        assert_eq!(version_lt("0.1.0", "0.2.0"), Some(Ordering::Less));
        assert_eq!(version_lt("0.2.0", "0.2.0"), Some(Ordering::Equal));
        assert_eq!(version_lt("1.0.0", "0.9.9"), Some(Ordering::Greater));
    }

    #[test]
    fn version_lt_returns_none_for_prerelease_or_garbage() {
        assert_eq!(version_lt("0.2.0-rc.1", "0.2.0"), None);
        assert_eq!(version_lt("0.2.0", "0.2.0-rc.1"), None);
        assert_eq!(version_lt("nightly", "0.2.0"), None);
    }

    #[test]
    fn run_refuses_downgrade_without_force() {
        // current is `env!("CARGO_PKG_VERSION")`. Pin to v0.0.1 — strictly
        // older — and verify ptuf refuses without invoking any updater.
        let spawner = RecordingSpawner::new(vec![]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.0.1".to_string()),
            force: false,
            skip_attestation: false,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 1);
        assert!(spawner.calls().is_empty(), "no updater must be spawned");
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("refusing to downgrade"), "stderr: {err_s}",);
        assert!(err_s.contains("--force"), "stderr: {err_s}");
    }

    #[test]
    fn run_allows_downgrade_with_force() {
        let spawner = RecordingSpawner::new(vec![ok(""), ok("")]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.0.1".to_string()),
            force: true,
            skip_attestation: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(
            calls.len(),
            2,
            "installer should download + execute with --force"
        );
        assert_eq!(calls[0].program, "curl");
        assert_eq!(calls[1].program, "sh");
    }

    #[test]
    fn run_skips_downgrade_guard_for_prerelease_with_advisory() {
        // Pre-release tags can't be ordered against bare semver, so the
        // guard must skip rather than block — but emit an advisory line so
        // the skip is auditable.
        let spawner = RecordingSpawner::new(vec![ok(""), ok("")]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.0.1-rc.1".to_string()),
            force: false,
            skip_attestation: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let err_s = String::from_utf8_lossy(&err);
        assert!(
            err_s.contains("could not compare versions"),
            "stderr: {err_s}",
        );
        assert!(
            err_s.contains("skipping downgrade guard"),
            "stderr: {err_s}"
        );
    }

    #[test]
    fn run_prebuilt_invokes_curl_then_gh_then_sh_when_attestation_required() {
        // version pin skips the latest-tag probe, so the 3 spawns we
        // observe are exactly the new download / verify / execute pipeline.
        let spawner = RecordingSpawner::new(vec![ok(""), ok(""), ok("")]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.4.0".to_string()),
            force: false,
            skip_attestation: false,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(calls.len(), 3, "curl download + gh verify + sh execute");
        assert_eq!(calls[0].program, "curl");
        assert_eq!(calls[1].program, "gh");
        assert!(calls[1].args.contains(&"attestation".to_string()));
        assert!(calls[1].args.contains(&"verify".to_string()));
        assert!(calls[1].args.contains(&"--repo".to_string()));
        assert!(calls[1].args.contains(&"watany-dev/ptuf".to_string()));
        assert_eq!(calls[2].program, "sh");
    }

    #[test]
    fn run_prebuilt_fails_when_gh_missing_and_not_skipped() {
        // gh NotFound on the verify step must hard-fail before sh runs and
        // surface the friendly install / --skip-attestation hint.
        let spawner =
            RecordingSpawner::new(vec![ok(""), Err(io::Error::from(io::ErrorKind::NotFound))]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.4.0".to_string()),
            force: false,
            skip_attestation: false,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 1);
        let calls = spawner.calls();
        assert_eq!(calls.len(), 2, "execute must not run when gh is missing");
        assert_eq!(calls[0].program, "curl");
        assert_eq!(calls[1].program, "gh");
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("--skip-attestation"), "stderr: {err_s}");
        assert!(
            err_s.contains("install GitHub CLI") || err_s.contains("gh"),
            "stderr: {err_s}",
        );
    }

    #[test]
    fn run_prebuilt_warns_when_attestation_is_skipped() {
        let spawner = RecordingSpawner::new(vec![ok(""), ok("")]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.4.0".to_string()),
            force: false,
            skip_attestation: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(
            calls.len(),
            2,
            "gh must not run when --skip-attestation is set"
        );
        assert_eq!(calls[0].program, "curl");
        assert_eq!(calls[1].program, "sh");
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("WARNING"), "stderr: {err_s}");
        assert!(
            err_s.contains("attestation"),
            "WARNING must mention attestation: {err_s}",
        );
    }

    #[test]
    fn run_prebuilt_fails_when_attestation_verify_returns_nonzero() {
        let spawner = RecordingSpawner::new(vec![
            ok(""),
            Ok(SpawnOutcome {
                exit_code: 1,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        ]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.4.0".to_string()),
            force: false,
            skip_attestation: false,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 1);
        let calls = spawner.calls();
        assert_eq!(
            calls.len(),
            2,
            "execute must not run when attestation fails"
        );
        assert_eq!(calls[1].program, "gh");
        let err_s = String::from_utf8_lossy(&err);
        assert!(
            err_s.contains("gh attestation verify rejected"),
            "stderr: {err_s}",
        );
        assert!(err_s.contains("v0.4.0"), "stderr: {err_s}");
    }

    #[test]
    fn run_prebuilt_fails_when_download_returns_nonzero() {
        let spawner = RecordingSpawner::new(vec![Ok(SpawnOutcome {
            exit_code: 22,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.4.0".to_string()),
            force: false,
            skip_attestation: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 1);
        let calls = spawner.calls();
        assert_eq!(
            calls.len(),
            1,
            "verify / execute must not run after download failure"
        );
        assert_eq!(calls[0].program, "curl");
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("failed to download"), "stderr: {err_s}");
    }
}
