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
use std::io::Write;
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
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
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

/// Spawn ptuf. stdin is written from a scoped worker thread to avoid
/// deadlock when the payload exceeds the OS pipe buffer (Linux default
/// 64 KiB; an 8 MiB stdin would otherwise block on write). The scoped
/// thread borrows `cfg.stdin` directly so the 8 MiB ceiling case does
/// not double-allocate. When stdin is empty the writer thread is
/// skipped entirely.
pub fn spawn(cfg: &SpawnConfig) -> SpawnOutcome {
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

    let output = if cfg.stdin.is_empty() {
        drop(sin);
        child.wait_with_output().expect("wait_with_output")
    } else {
        std::thread::scope(|s| {
            let stdin_buf = cfg.stdin;
            let writer = s.spawn(move || {
                let mut sin = sin;
                let _ = sin.write_all(stdin_buf);
            });
            let out = child.wait_with_output().expect("wait_with_output");
            let _ = writer.join();
            out
        })
    };

    SpawnOutcome {
        code: output.status.code().expect("exit code"),
        stdout: output.stdout,
        stderr: output.stderr,
        elapsed: started.elapsed(),
    }
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
