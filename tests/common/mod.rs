//! Shared helpers for heavy E2E test targets.
//!
//! Lives under `common/mod.rs` so cargo does not treat it as a
//! separate test binary. Used by `tests/e2e_heavy.rs`.

// `clippy.toml`'s `allow-*-in-tests` only matches `#[test]` bodies and
// `#[cfg(test)]` modules; free helpers at integration-test file scope
// fall outside both, so relax `unwrap`/`expect` explicitly here.
#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc
)]

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// stdin size ceiling enforced by `src/cli/run.rs:27`
/// (`MAX_HOOK_STDIN_BYTES = 8 * 1024 * 1024`). Mirrored here because
/// that constant is `pub(super)` and not reachable from integration
/// tests.
pub const MAX_STDIN: usize = 8 * 1024 * 1024;

pub struct SpawnConfig<'a> {
    pub args: &'a [&'a str],
    pub stdin: &'a [u8],
    pub cwd: Option<&'a Path>,
    pub envs: &'a [(&'a str, &'a OsStr)],
}

pub struct SpawnOutcome {
    /// Exit code, or `-1` when the process was killed by a signal.
    /// Kept as a plain `i32` so the existing cases that match on
    /// `code` compile unchanged; inspect `code_opt` / `signal` to tell
    /// a genuine `-1` exit from a signal kill.
    pub code: i32,
    /// `ExitStatus::code()` verbatim — `None` when killed by a signal.
    pub code_opt: Option<i32>,
    /// Unix signal that killed the process, if any.
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
    /// Set when the timeout fired and the child was force-killed.
    pub timed_out: bool,
}

impl SpawnOutcome {
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

pub fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ptuf"))
}

/// Default ceiling for [`spawn`]. Long enough that a healthy ptuf run
/// (even the 8 MiB stdin case under a debug build) finishes
/// comfortably, short enough that a genuine hang surfaces as a test
/// failure instead of wedging `make e2e` forever.
pub const DEFAULT_SPAWN_TIMEOUT: Duration = Duration::from_mins(1);

/// Spawn ptuf with [`DEFAULT_SPAWN_TIMEOUT`]. Thin wrapper over
/// [`spawn_with_timeout`] kept signature-compatible with the original
/// helper so existing cases need no change.
pub fn spawn(cfg: &SpawnConfig) -> SpawnOutcome {
    spawn_with_timeout(cfg, DEFAULT_SPAWN_TIMEOUT)
}

/// Spawn ptuf, drive stdin/stdout/stderr on dedicated threads, and wait
/// for exit with a hard `timeout`.
///
/// `Child::wait_with_output()` cannot be interrupted, so a hung child
/// would block `make e2e` indefinitely and a hang would never surface
/// as a *failure*. Instead the child is polled with `try_wait()`; once
/// `timeout` elapses it is force-killed and then reaped with `wait()`
/// so no zombie is left behind (`timed_out` records that this
/// happened). stdout/stderr are drained on their own threads so the
/// child cannot deadlock by filling a pipe buffer while we are blocked
/// writing stdin (or vice versa). stdin borrows `cfg.stdin` directly
/// so the 8 MiB ceiling case does not double-allocate.
pub fn spawn_with_timeout(cfg: &SpawnConfig, timeout: Duration) -> SpawnOutcome {
    let mut cmd = binary();
    cmd.args(cfg.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(d) = cfg.cwd {
        cmd.current_dir(d);
    }
    for (k, v) in cfg.envs {
        cmd.env(k, v);
    }

    let started = Instant::now();
    let mut child = cmd.spawn().expect("spawn ptuf");
    let sin = child.stdin.take().expect("child stdin");
    let mut sout = child.stdout.take().expect("child stdout");
    let mut serr = child.stderr.take().expect("child stderr");

    std::thread::scope(|s| {
        let stdin_buf = cfg.stdin;
        let writer = s.spawn(move || {
            let mut sin = sin;
            let _ = sin.write_all(stdin_buf);
            // `sin` drops here, closing the pipe so the child sees EOF.
        });
        let out_reader = s.spawn(move || {
            let mut buf = Vec::new();
            let _ = sout.read_to_end(&mut buf);
            buf
        });
        let err_reader = s.spawn(move || {
            let mut buf = Vec::new();
            let _ = serr.read_to_end(&mut buf);
            buf
        });

        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break (status, false);
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let status = child.wait().expect("wait after kill");
                break (status, true);
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let elapsed = started.elapsed();

        let _ = writer.join();
        let stdout = out_reader.join().expect("join stdout reader");
        let stderr = err_reader.join().expect("join stderr reader");

        let code_opt = status.code();
        SpawnOutcome {
            code: code_opt.unwrap_or(-1),
            code_opt,
            signal: exit_signal(&status),
            stdout,
            stderr,
            elapsed,
            timed_out,
        }
    })
}

#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Assert the process neither hung (timed out) nor crashed (died to a
/// signal). The shared "no crash, no hang" check every heavy E2E case
/// applies before inspecting decision output.
#[track_caller]
pub fn assert_clean_exit(outcome: &SpawnOutcome) {
    assert!(
        !outcome.timed_out,
        "ptuf hung: no exit within timeout (elapsed {:?})",
        outcome.elapsed
    );
    assert!(
        outcome.signal.is_none(),
        "ptuf killed by signal {:?} after {:?} (stderr: {})",
        outcome.signal,
        outcome.elapsed,
        outcome.stderr_string()
    );
}

pub struct LayerYaml {
    pub system: Option<String>,
    pub user: Option<String>,
    pub project: Option<String>,
    pub project_local: Option<String>,
    pub plugins: Vec<(String, String)>,
}

impl LayerYaml {
    pub fn empty() -> Self {
        Self {
            system: None,
            user: None,
            project: None,
            project_local: None,
            plugins: Vec::new(),
        }
    }
}

pub struct FullStackFixture {
    pub root: TempDir,
    pub etc_dir: PathBuf,
    pub config_dir: PathBuf,
    pub repo_root: PathBuf,
    pub plugin_dir: PathBuf,
    pub audit_path: PathBuf,
}

pub fn full_stack(layers: LayerYaml) -> FullStackFixture {
    let root = tempfile::tempdir().expect("tempdir");
    let etc_dir = root.path().join("etc");
    let config_dir = root.path().join("userconf");
    let repo_root = root.path().join("repo");
    let plugin_dir = repo_root.join(".ptuf").join("plugins");
    let audit_path = repo_root.join("audit.jsonl");

    std::fs::create_dir_all(&etc_dir).expect("mkdir etc");
    std::fs::create_dir_all(&config_dir).expect("mkdir userconf");
    std::fs::create_dir_all(&repo_root).expect("mkdir repo");
    std::fs::create_dir_all(repo_root.join(".git")).expect("mkdir .git");
    std::fs::create_dir_all(&plugin_dir).expect("mkdir plugin_dir");

    if let Some(yaml) = layers.system {
        std::fs::write(etc_dir.join("policy.yaml"), yaml).expect("write system yaml");
    }
    if let Some(yaml) = layers.user {
        std::fs::write(config_dir.join("config.yaml"), yaml).expect("write user yaml");
    }
    if let Some(yaml) = layers.project {
        std::fs::write(repo_root.join(".ptuf.yaml"), yaml).expect("write project yaml");
    }
    if let Some(yaml) = layers.project_local {
        std::fs::write(repo_root.join(".ptuf.local.yaml"), yaml).expect("write project_local yaml");
    }
    for (name, body) in &layers.plugins {
        std::fs::write(plugin_dir.join(name), body).expect("write plugin yaml");
    }

    FullStackFixture {
        root,
        etc_dir,
        config_dir,
        repo_root,
        plugin_dir,
        audit_path,
    }
}

/// Project-layer YAML that enables `enforce` mode and routes audit
/// output to `audit_path` with `includeDenied`. Used by every test
/// that needs to inspect the audit file after running deny payloads.
pub fn enforce_audit_yaml(audit_path: &Path) -> String {
    format!(
        "version: 1\nmode: enforce\naudit:\n  path: {audit}\n  enabled: true\n  includeAllowed: false\n  includeDenied: true\n",
        audit = audit_path.display()
    )
}

pub fn envs_for(fix: &FullStackFixture) -> Vec<(&'static str, OsString)> {
    vec![
        ("PTUF_ETC_DIR", fix.etc_dir.as_os_str().to_os_string()),
        ("PTUF_CONFIG_DIR", fix.config_dir.as_os_str().to_os_string()),
        (
            "XDG_CONFIG_HOME",
            fix.root.path().join("xdg").into_os_string(),
        ),
        ("HOME", fix.root.path().as_os_str().to_os_string()),
    ]
}

/// `SpawnConfig::envs` takes `&[(&str, &OsStr)]`; this borrows from
/// the owned `OsString` vec returned by `envs_for` to satisfy that
/// lifetime without cloning the values again.
pub fn as_env_refs<'a>(envs: &'a [(&'static str, OsString)]) -> Vec<(&'a str, &'a OsStr)> {
    envs.iter().map(|(k, v)| (*k, v.as_os_str())).collect()
}

#[cfg(target_os = "linux")]
pub fn open_fd_count() -> std::io::Result<usize> {
    let mut n = 0usize;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let _ = entry?;
        n += 1;
    }
    Ok(n)
}

/// Write an executable shell script at `path` (mode `0755`). Used to
/// build a hermetic `PATH` for `update`-style subcommand tests so they
/// never reach the real network or system binaries.
#[cfg(unix)]
pub fn write_fake_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).expect("write fake executable");
    let mut perms = std::fs::metadata(path)
        .expect("stat fake executable")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod fake executable");
}
