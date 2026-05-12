//! Filesystem-locator seam for `ptuf update`.
//!
//! `RealExeLocator` wraps `std::env::current_exe()` and resolves
//! `$CARGO_HOME` (or `~/.cargo`) for the cargo-install detection branch
//! in `select_strategy`. Tests inject `FakeExeLocator` to drive the
//! strategy logic without touching the real filesystem.

use std::io;
use std::path::PathBuf;

use crate::config::scope::{EnvLookup, SystemEnv};

pub trait ExeLocator {
    fn current_exe(&self) -> io::Result<PathBuf>;
    fn cargo_home(&self) -> Option<PathBuf>;
}

/// Resolve the cargo home directory: `$CARGO_HOME` if set and non-empty,
/// otherwise `<HOME>/.cargo`. Returns `None` when neither is available.
///
/// Threads the shared `EnvLookup` seam (also used by
/// `crate::config::scope` and `crate::self_paths`) so tests can drive
/// every branch with an in-memory env without mutating global state.
pub fn compute_cargo_home(env: &dyn EnvLookup) -> Option<PathBuf> {
    if let Some(value) = env.var_os("CARGO_HOME")
        && !value.is_empty()
    {
        return Some(PathBuf::from(value));
    }
    env.var_os("HOME").map(|h| PathBuf::from(h).join(".cargo"))
}

#[derive(Debug, Default)]
pub struct RealExeLocator;

impl ExeLocator for RealExeLocator {
    fn current_exe(&self) -> io::Result<PathBuf> {
        std::env::current_exe()
    }

    fn cargo_home(&self) -> Option<PathBuf> {
        compute_cargo_home(&SystemEnv)
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
    use std::collections::HashMap;
    use std::ffi::OsString;

    struct MapEnv(HashMap<String, OsString>);

    impl MapEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), OsString::from(*v)))
                    .collect(),
            )
        }
    }

    impl EnvLookup for MapEnv {
        fn var_os(&self, key: &str) -> Option<OsString> {
            self.0.get(key).cloned()
        }
    }

    #[test]
    fn compute_cargo_home_prefers_env_var_when_set() {
        let env = MapEnv::new(&[("CARGO_HOME", "/x/.cargo"), ("HOME", "/h")]);
        assert_eq!(compute_cargo_home(&env), Some(PathBuf::from("/x/.cargo")));
    }

    #[test]
    fn compute_cargo_home_ignores_empty_env_var() {
        let env = MapEnv::new(&[("CARGO_HOME", ""), ("HOME", "/h")]);
        assert_eq!(compute_cargo_home(&env), Some(PathBuf::from("/h/.cargo")));
    }

    #[test]
    fn compute_cargo_home_falls_back_to_home_dot_cargo() {
        let env = MapEnv::new(&[("HOME", "/home/user")]);
        assert_eq!(
            compute_cargo_home(&env),
            Some(PathBuf::from("/home/user/.cargo")),
        );
    }

    #[test]
    fn compute_cargo_home_returns_none_without_home_or_env() {
        let env = MapEnv::new(&[]);
        assert_eq!(compute_cargo_home(&env), None);
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
