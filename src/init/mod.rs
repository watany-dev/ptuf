//! `ptuf init <agent>` — install ptuf as a `PreToolUse` hook in the
//! target agent's settings file. v0.3 ships only the `claude-code`
//! adapter (`docs/design/cli-and-hooks.md:48-74`).

use std::path::PathBuf;

pub mod claude_code;

/// Errors surfaced by every `init` adapter.
#[derive(Debug)]
pub enum InitError {
    /// Agent name not recognised.
    UnknownAgent(String),
    /// Settings file or its parent directory could not be read / written.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Existing settings file is not valid JSON; refuse to overwrite.
    Json { path: PathBuf, message: String },
    /// Settings file is JSON but the path we expected to navigate
    /// (`hooks.PreToolUse[]`) is occupied by a value of the wrong type.
    Schema { path: PathBuf, message: String },
    /// `$HOME` is unset and no explicit `--settings` path was given.
    HomeNotSet,
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAgent(a) => write!(f, "unknown agent: {a}"),
            Self::Io { path, source } => {
                write!(f, "io error at {}: {source}", path.display())
            }
            Self::Json { path, message } => {
                write!(f, "invalid JSON in {}: {message}", path.display())
            }
            Self::Schema { path, message } => {
                write!(f, "unexpected settings shape in {}: {message}", path.display())
            }
            Self::HomeNotSet => write!(f, "$HOME is not set; pass --settings <PATH> explicitly"),
        }
    }
}

impl std::error::Error for InitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Outcome of an install attempt. Identical for dry-run and live runs;
/// the `dry_run` flag passed in determines whether [`InstallStatus`]
/// uses the `Would*` variants.
#[derive(Debug, PartialEq, Eq)]
pub struct InstallOutcome {
    pub status: InstallStatus,
    pub settings_path: PathBuf,
    pub matcher: String,
    pub command: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallStatus {
    /// File already contains a hook entry pointing at our binary; no
    /// change required.
    AlreadyPresent,
    /// Wrote a new entry to disk.
    Installed,
    /// `--dry-run`: an entry would have been written.
    WouldInstall,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn init_error_display_covers_all_variants() {
        assert!(format!("{}", InitError::UnknownAgent("x".into())).contains("unknown agent"));
        assert!(
            format!(
                "{}",
                InitError::Io {
                    path: PathBuf::from("/p"),
                    source: std::io::Error::other("boom")
                }
            )
            .contains("io error")
        );
        assert!(
            format!(
                "{}",
                InitError::Json {
                    path: PathBuf::from("/p"),
                    message: "bad".into()
                }
            )
            .contains("invalid JSON")
        );
        assert!(
            format!(
                "{}",
                InitError::Schema {
                    path: PathBuf::from("/p"),
                    message: "wrong type".into()
                }
            )
            .contains("unexpected settings shape")
        );
        assert!(format!("{}", InitError::HomeNotSet).contains("HOME"));
    }

    #[test]
    fn init_error_source_exposes_io_only() {
        let err = InitError::Io {
            path: PathBuf::from("/p"),
            source: std::io::Error::other("x"),
        };
        assert!(std::error::Error::source(&err).is_some());
        assert!(std::error::Error::source(&InitError::HomeNotSet).is_none());
    }
}
