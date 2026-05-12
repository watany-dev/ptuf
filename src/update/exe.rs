//! Filesystem-locator seam for `ptuf update`.
//!
//! `RealExeLocator` wraps `std::env::current_exe()` and resolves
//! `$CARGO_HOME` (or `~/.cargo`) for the cargo-install detection branch
//! in `select_strategy`. Tests inject `FakeExeLocator` to drive the
//! strategy logic without touching the real filesystem.

use std::io;
use std::path::{Path, PathBuf};

pub trait ExeLocator {
    fn current_exe(&self) -> io::Result<PathBuf>;
    fn cargo_home(&self) -> Option<PathBuf>;
}

/// Resolve the cargo home directory: `$CARGO_HOME` if set and non-empty,
/// otherwise `<HOME>/.cargo`. Returns `None` only when both are absent.
///
/// Pure function so unit tests can drive every branch without touching
/// real env vars.
pub fn compute_cargo_home(
    getenv: impl Fn(&str) -> Option<String>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(value) = getenv("CARGO_HOME")
        && !value.is_empty()
    {
        return Some(PathBuf::from(value));
    }
    home.map(|h| h.join(".cargo"))
}

#[derive(Debug, Default)]
pub struct RealExeLocator;

impl ExeLocator for RealExeLocator {
    fn current_exe(&self) -> io::Result<PathBuf> {
        std::env::current_exe()
    }

    fn cargo_home(&self) -> Option<PathBuf> {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        compute_cargo_home(|k| std::env::var(k).ok(), home.as_deref())
    }
}

#[cfg(test)]
pub struct FakeExeLocator {
    pub exe: PathBuf,
    pub cargo_home: Option<PathBuf>,
}

#[cfg(test)]
impl ExeLocator for FakeExeLocator {
    fn current_exe(&self) -> io::Result<PathBuf> {
        Ok(self.exe.clone())
    }

    fn cargo_home(&self) -> Option<PathBuf> {
        self.cargo_home.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_cargo_home_prefers_env_var_when_set() {
        let result = compute_cargo_home(
            |k| {
                if k == "CARGO_HOME" {
                    Some("/x/.cargo".to_string())
                } else {
                    None
                }
            },
            Some(Path::new("/h")),
        );
        assert_eq!(result, Some(PathBuf::from("/x/.cargo")));
    }

    #[test]
    fn compute_cargo_home_ignores_empty_env_var() {
        let result = compute_cargo_home(
            |k| {
                if k == "CARGO_HOME" {
                    Some(String::new())
                } else {
                    None
                }
            },
            Some(Path::new("/h")),
        );
        assert_eq!(result, Some(PathBuf::from("/h/.cargo")));
    }

    #[test]
    fn compute_cargo_home_falls_back_to_home_dot_cargo() {
        let result = compute_cargo_home(|_| None, Some(Path::new("/home/user")));
        assert_eq!(result, Some(PathBuf::from("/home/user/.cargo")));
    }

    #[test]
    fn compute_cargo_home_returns_none_without_home_or_env() {
        let result = compute_cargo_home(|_| None, None);
        assert_eq!(result, None);
    }

    #[test]
    fn real_exe_locator_returns_some_path() {
        let locator = RealExeLocator;
        let exe = locator.current_exe().expect("test runner has current_exe");
        assert!(exe.is_absolute());
    }

    #[test]
    fn fake_exe_locator_round_trips_inputs() {
        let locator = FakeExeLocator {
            exe: PathBuf::from("/tmp/ptuf"),
            cargo_home: Some(PathBuf::from("/tmp/.cargo")),
        };
        assert_eq!(locator.current_exe().unwrap(), PathBuf::from("/tmp/ptuf"));
        assert_eq!(locator.cargo_home(), Some(PathBuf::from("/tmp/.cargo")));
    }
}
