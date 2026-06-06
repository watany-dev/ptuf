//! Project-level facts: lock-file kinds present at the repo root, and
//! the currently-checked-out git branch.
//!
//! All filesystem access is best-effort — the engine constructs
//! [`ProjectFacts`] once at startup and treats every read failure as
//! "this fact is unknown". Returning a `ProjectFacts` (rather than
//! `Result<ProjectFacts, _>`) keeps the engine constructors infallible
//! so policy fail-closed is governed solely by config / plugin loading.

use std::path::Path;

/// Lock files we recognise. The set is small on purpose — adding a
/// new manager only requires extending this enum and the `(filename,
/// kind)` table in `detect_lock_files`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    NpmPackageLock,
    PnpmLock,
    YarnLock,
    UvLock,
    PoetryLock,
}

/// Project-level facts shared by every rule. Fields default to "no
/// information" so a freshly-defaulted instance is a safe placeholder
/// when no repo root was discovered.
#[derive(Debug, Default, Clone)]
pub struct ProjectFacts {
    /// Lock files detected at the repo root, in stable enum order.
    pub lock_files: Vec<LockKind>,
    /// Current branch name, or `None` for detached HEAD / unreadable
    /// `.git/HEAD` / no repo root.
    pub current_branch: Option<String>,
    /// `true` when [`Self::current_branch`] matched any pattern in the
    /// `protected_branches` config list (see `wildcard_match`).
    pub on_protected_branch: bool,
}

/// Build [`ProjectFacts`] for `repo_root`. Returns an empty
/// `ProjectFacts` when `repo_root` is `None` so callers can wire the
/// engine without conditionals.
pub fn collect(repo_root: Option<&Path>, protected_patterns: &[String]) -> ProjectFacts {
    let Some(root) = repo_root else {
        return ProjectFacts::default();
    };
    let lock_files = detect_lock_files(root);
    let current_branch = read_current_branch(root);
    let on_protected_branch = current_branch.as_deref().is_some_and(|name| {
        protected_patterns
            .iter()
            .any(|pat| wildcard_match(pat, name))
    });
    ProjectFacts {
        lock_files,
        current_branch,
        on_protected_branch,
    }
}

fn detect_lock_files(root: &Path) -> Vec<LockKind> {
    const TABLE: &[(&str, LockKind)] = &[
        ("package-lock.json", LockKind::NpmPackageLock),
        ("pnpm-lock.yaml", LockKind::PnpmLock),
        ("yarn.lock", LockKind::YarnLock),
        ("uv.lock", LockKind::UvLock),
        ("poetry.lock", LockKind::PoetryLock),
    ];
    TABLE
        .iter()
        .filter(|(name, _)| root.join(name).is_file())
        .map(|(_, kind)| *kind)
        .collect()
}

fn read_current_branch(root: &Path) -> Option<String> {
    let head = root.join(".git").join("HEAD");
    let raw = std::fs::read_to_string(head).ok()?;
    let trimmed = raw.trim();
    let rest = trimmed.strip_prefix("ref:")?.trim_start();
    let name = rest.strip_prefix("refs/heads/")?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Minimal glob matcher: only `*` is special, and it matches any tail.
/// `main` matches `main`; `release/*` matches `release/v1.2`. Anchored
/// at both ends — `*main*` is not supported (and not needed by the v1
/// protected-branches use case).
fn wildcard_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return value.starts_with(prefix) && value[prefix.len()..].starts_with('/');
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

#[cfg(test)]
mod tests {

    use super::*;

    fn tempdir(suffix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-project-facts-{}-{suffix}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn collect_returns_default_when_repo_root_is_none() {
        let f = collect(None, &["main".into()]);
        assert!(f.lock_files.is_empty());
        assert!(f.current_branch.is_none());
        assert!(!f.on_protected_branch);
    }

    #[test]
    fn detects_pnpm_and_uv_lock_files_at_root() {
        let dir = tempdir("locks");
        std::fs::write(dir.join("pnpm-lock.yaml"), "").expect("write");
        std::fs::write(dir.join("uv.lock"), "").expect("write");
        let f = collect(Some(&dir), &[]);
        assert!(f.lock_files.contains(&LockKind::PnpmLock));
        assert!(f.lock_files.contains(&LockKind::UvLock));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignores_lock_files_in_subdirectories() {
        let dir = tempdir("nested-locks");
        std::fs::create_dir_all(dir.join("packages/a")).expect("mkdir");
        std::fs::write(dir.join("packages/a/pnpm-lock.yaml"), "").expect("write");
        let f = collect(Some(&dir), &[]);
        assert!(!f.lock_files.contains(&LockKind::PnpmLock));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_current_branch_from_dot_git_head() {
        let dir = tempdir("branch");
        std::fs::create_dir_all(dir.join(".git")).expect("mkdir");
        std::fs::write(dir.join(".git").join("HEAD"), "ref: refs/heads/main\n").expect("write");
        let f = collect(Some(&dir), &["main".into()]);
        assert_eq!(f.current_branch.as_deref(), Some("main"));
        assert!(f.on_protected_branch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn returns_none_for_detached_head() {
        let dir = tempdir("detached");
        std::fs::create_dir_all(dir.join(".git")).expect("mkdir");
        std::fs::write(dir.join(".git").join("HEAD"), "abcdef0123456789\n").expect("write");
        let f = collect(Some(&dir), &["main".into()]);
        assert!(f.current_branch.is_none());
        assert!(!f.on_protected_branch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn returns_none_when_dot_git_head_is_unreadable() {
        let dir = tempdir("nogit");
        let f = collect(Some(&dir), &["main".into()]);
        assert!(f.current_branch.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn protected_branch_flag_uses_pattern_list() {
        let dir = tempdir("protected");
        std::fs::create_dir_all(dir.join(".git")).expect("mkdir");
        std::fs::write(
            dir.join(".git").join("HEAD"),
            "ref: refs/heads/release/v2\n",
        )
        .expect("write");
        let f = collect(Some(&dir), &["main".into(), "release/*".into()]);
        assert!(f.on_protected_branch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn protected_flag_false_when_branch_does_not_match() {
        let dir = tempdir("notprotected");
        std::fs::create_dir_all(dir.join(".git")).expect("mkdir");
        std::fs::write(
            dir.join(".git").join("HEAD"),
            "ref: refs/heads/feature/new\n",
        )
        .expect("write");
        let f = collect(Some(&dir), &["main".into(), "release/*".into()]);
        assert!(!f.on_protected_branch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    use proptest::prelude::*;

    proptest! {
        // `wildcard_match` is reflexive: every pattern matches itself,
        // whether it ends in `/*`, a bare `*`, or neither.
        #[test]
        fn pbt_wildcard_match_is_reflexive(
            p in crate::testing::proptest::arbitrary_command(),
        ) {
            prop_assert!(wildcard_match(&p, &p));
        }

        // `wildcard_match` is total: arbitrary Unicode pattern/value
        // pairs never panic. The `/*` branch slices `value` at
        // `prefix.len()`, and the `starts_with` guard keeps that index
        // on a UTF-8 char boundary.
        #[test]
        fn pbt_wildcard_match_never_panics(
            pattern in crate::testing::proptest::arbitrary_command(),
            value in crate::testing::proptest::arbitrary_command(),
        ) {
            let _ = wildcard_match(&pattern, &value);
        }

        // A bare trailing `*` is a pure prefix test: `prefix*` matches
        // `value` exactly when `value` starts with `prefix`.
        #[test]
        fn pbt_wildcard_match_bare_star_is_prefix(
            prefix in "[A-Za-z0-9_.-]{0,8}",
            value in crate::testing::proptest::arbitrary_command(),
        ) {
            let pattern = format!("{prefix}*");
            prop_assert_eq!(
                wildcard_match(&pattern, &value),
                value.starts_with(prefix.as_str()),
            );
        }

        // A trailing `/*` matches any sub-path `prefix/<tail>` but never
        // the bare `prefix` itself.
        #[test]
        fn pbt_wildcard_match_slash_star_matches_subpaths(
            prefix in "[A-Za-z0-9_.-]{0,8}",
            tail in "[A-Za-z0-9_./-]{0,12}",
        ) {
            let pattern = format!("{prefix}/*");
            let subpath = format!("{prefix}/{tail}");
            prop_assert!(wildcard_match(&pattern, &subpath));
            prop_assert!(!wildcard_match(&pattern, &prefix));
        }

        // With no trailing `*`, `wildcard_match` degenerates to exact
        // string equality.
        #[test]
        fn pbt_wildcard_match_exact_pattern_is_equality(
            pattern in "[A-Za-z0-9/_.-]{0,10}",
            value in crate::testing::proptest::arbitrary_command(),
        ) {
            prop_assert_eq!(wildcard_match(&pattern, &value), pattern == value);
        }
    }
}
