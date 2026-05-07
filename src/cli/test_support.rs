//! Shared test helpers for the CLI submodule.
//!
//! Visible to `cli`'s descendants (`parse`, `run`, `output`, and the
//! `tests` block inside `mod.rs`). Compiled only under `#[cfg(test)]`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::path::PathBuf;

use super::{Command, ParseError, parse, run};

pub(super) fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

pub(super) fn run_with(args: &[&str], stdin: &str) -> (u8, String, String) {
    let parsed: Result<Command, ParseError> = parse(&s(args));
    let parsed = parsed.expect("parse must succeed in run_with");
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run(parsed, stdin.as_bytes(), &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

/// `Read` impl that always returns an error so tests can drive the
/// stdin-read failure arm of `run_hook`.
pub(super) struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("simulated stdin failure"))
    }
}

/// `Write` impl whose first `budget` bytes are accepted; every byte
/// after that returns an error. Drives the render-failure arm of
/// `run_plugin_test` and `run_doctor`.
pub(super) struct FailingWriter {
    pub(super) budget: usize,
}

impl Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.budget == 0 {
            return Err(std::io::Error::other("disk full"));
        }
        let n = buf.len().min(self.budget);
        self.budget -= n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// RAII guard that swaps the process cwd for the duration of a test
/// and restores it on drop. Tests using this helper rely on the
/// `--test-threads=1` setting in `Makefile` / CI so concurrent cwd
/// mutation cannot occur.
pub(super) struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    pub(super) fn change_to(target: &std::path::Path) -> std::io::Result<Self> {
        let original = std::env::current_dir()?;
        std::env::set_current_dir(target)?;
        Ok(Self { original })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

pub(super) fn make_engine_failing_repo(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ptuf-cli-engine-fail-{}-{}-{}",
        label,
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
    std::fs::write(
        dir.join(".ptuf.yaml"),
        "plugins:\n  - path: ./missing-plugin.yaml\n",
    )
    .expect("write .ptuf.yaml");
    dir
}
