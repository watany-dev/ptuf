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

/// Parsed `ptuf update [--check] [--version <TAG>] [--force]`.
///
/// Re-exported through `crate::cli::UpdateOptions` because it rides
/// inside the `pub Command::Update` variant.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateOptions {
    pub check: bool,
    pub version: Option<String>,
    pub force: bool,
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
    LatestTagFetch { exit_code: i32, stderr: String },
    LatestTagParse(String),
    UpdaterSpawn { program: String, source: io::Error },
    UpdaterExitCode { program: String, code: i32 },
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
            | Self::UpdaterExitCode { .. } => None,
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

#[derive(Debug)]
pub struct InstallerCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// Build the argv for the chosen updater. Pure function so it can be
/// asserted from unit tests on any host.
pub fn build_installer_command(
    strategy: Strategy,
    tag: &str,
    pinned: bool,
    platform: Platform,
) -> InstallerCommand {
    match strategy {
        Strategy::CargoInstall => {
            let mut args = vec![
                "install".to_string(),
                "ptuf".to_string(),
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
        Strategy::PrebuiltInstaller => match platform {
            Platform::Unix => {
                let url = format!("{RELEASES_DOWNLOAD_URL_PREFIX}{tag}/ptuf-installer.sh");
                let script = format!("curl --proto '=https' --tlsv1.2 -LsSf {url} | sh");
                InstallerCommand {
                    program: "sh".to_string(),
                    args: vec!["-c".to_string(), script],
                }
            },
            Platform::Windows => {
                let url = format!("{RELEASES_DOWNLOAD_URL_PREFIX}{tag}/ptuf-installer.ps1");
                let script = format!("iwr -useb '{url}' | iex");
                InstallerCommand {
                    program: "powershell".to_string(),
                    args: vec!["-NoProfile".to_string(), "-Command".to_string(), script],
                }
            },
        },
    }
}

/// Top-level entry: drive the `ptuf update` flow against the injected
/// `Spawner` / `ExeLocator`. Always returns a u8 exit code (`0` on
/// success / `--check` / already-up-to-date, `1` on every failure).
pub fn run<S, E, W1, W2>(
    opts: UpdateOptions,
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
    run_with_platform(opts, spawner, locator, Platform::host(), stdout, stderr)
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

    let (strategy, warning) = select_strategy(spawner, locator);
    if let Some(msg) = warning {
        let _ = writeln!(stderr, "{msg}");
    }

    let command = build_installer_command(strategy, &tag, pinned, platform);
    let _ = writeln!(
        stdout,
        "ptuf update: {label} -> {normalised} (current {current})",
        label = strategy.label(),
    );

    let arg_refs: Vec<&str> = command.args.iter().map(String::as_str).collect();
    // Inherit stdio so `cargo install` / installer progress streams live
    // to the user instead of being buffered until exit.
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
                "--force".to_string(),
                "--version".to_string(),
                "0.3.1".to_string(),
            ],
        );
    }

    #[test]
    fn build_installer_command_unix_prebuilt_uses_curl_pipe_sh() {
        let cmd =
            build_installer_command(Strategy::PrebuiltInstaller, "v0.2.0", false, Platform::Unix);
        assert_eq!(cmd.program, "sh");
        assert_eq!(cmd.args.len(), 2);
        assert_eq!(cmd.args[0], "-c");
        let script = &cmd.args[1];
        assert!(script.contains("ptuf-installer.sh"), "script: {script}");
        assert!(
            script.contains("releases/download/v0.2.0/"),
            "script: {script}",
        );
        assert!(script.contains("--proto '=https'"), "script: {script}");
        assert!(script.contains("--tlsv1.2"), "script: {script}");
        assert!(script.contains("| sh"), "script: {script}");
    }

    #[test]
    fn build_installer_command_windows_prebuilt_uses_powershell() {
        let cmd = build_installer_command(
            Strategy::PrebuiltInstaller,
            "v0.2.0",
            false,
            Platform::Windows,
        );
        assert_eq!(cmd.program, "powershell");
        assert_eq!(cmd.args[0], "-NoProfile");
        assert_eq!(cmd.args[1], "-Command");
        let script = &cmd.args[2];
        assert!(script.contains("ptuf-installer.ps1"), "script: {script}");
        assert!(script.contains("iwr -useb"), "script: {script}");
        assert!(script.contains("| iex"), "script: {script}");
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
        let spawner =
            RecordingSpawner::new(vec![ok(&redirect_headers(&format!("v{current}"))), ok("")]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: None,
            force: true,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(calls.len(), 2, "curl + installer");
        assert_eq!(calls[1].program, "sh");
    }

    #[test]
    fn run_version_pin_skips_latest_lookup() {
        let spawner = RecordingSpawner::new(vec![ok("")]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions {
            check: false,
            version: Some("v0.3.0".to_string()),
            force: false,
        };
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let calls = spawner.calls();
        assert_eq!(calls.len(), 1, "no curl probe when version is pinned");
        assert_eq!(calls[0].program, "sh");
        let script = &calls[0].args[1];
        assert!(
            script.contains("releases/download/v0.3.0/"),
            "script: {script}",
        );
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
            Ok(SpawnOutcome {
                exit_code: 7,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        ]);
        let locator = system_locator();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions::default();
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
        ]);
        let locator = cargo_locator(cargo_home);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let opts = UpdateOptions::default();
        let code = run_with_platform(opts, &spawner, &locator, Platform::Unix, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("cargo not found"), "stderr: {err_s}");
        let calls = spawner.calls();
        assert_eq!(
            calls.len(),
            3,
            "curl + cargo --version probe + sh installer"
        );
        assert_eq!(calls[2].program, "sh");
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
}
