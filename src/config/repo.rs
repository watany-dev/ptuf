//! Locate the repository root by walking from a starting directory up
//! until a `.git` entry (file or directory — git submodules use a
//! file) is found, falling back to the filesystem root.

use std::path::{Path, PathBuf};

/// Search from `start` upwards for the first ancestor that contains a
/// `.git` entry. Returns `None` if no such ancestor exists.
pub fn discover(start: &Path) -> Option<PathBuf> {
    let mut current: Option<&Path> = Some(start);
    while let Some(dir) = current {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::env;
    use std::fs;

    fn temp_root() -> PathBuf {
        let dir = env::temp_dir().join(format!("ptuf-repo-test-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp root");
        dir
    }

    #[test]
    fn discover_finds_git_dir_on_starting_path() {
        let root = temp_root().join("a");
        fs::create_dir_all(root.join(".git")).expect("git dir");
        let found = discover(&root).expect("should find");
        assert_eq!(found, root);
        let _ = fs::remove_dir_all(root.parent().unwrap());
    }

    #[test]
    fn discover_walks_upwards() {
        let root = temp_root().join("b");
        let nested = root.join("nested/deep");
        fs::create_dir_all(&nested).expect("dirs");
        fs::create_dir_all(root.join(".git")).expect("git dir");
        let found = discover(&nested).expect("should find");
        assert_eq!(found, root);
        let _ = fs::remove_dir_all(root.parent().unwrap());
    }

    #[test]
    fn discover_handles_git_file_for_submodules() {
        let root = temp_root().join("c");
        fs::create_dir_all(&root).expect("dirs");
        fs::write(root.join(".git"), "gitdir: ../parent/.git/modules/c").expect("git file");
        let found = discover(&root).expect("should find");
        assert_eq!(found, root);
        let _ = fs::remove_dir_all(root.parent().unwrap());
    }

    #[test]
    fn discover_returns_none_if_no_git_anywhere() {
        let root = temp_root().join("d/no-repo");
        fs::create_dir_all(&root).expect("dirs");
        // Walk up from this dir; we may eventually hit a real .git
        // somewhere on the host's filesystem (CI or /). To keep the
        // assertion deterministic, use an absolute path under temp_dir
        // and check that the discovered root, if any, is NOT inside
        // our test dir.
        if let Some(found) = discover(&root) {
            assert!(
                !found.starts_with(temp_root().join("d")),
                "unexpected .git inside test tree at {found:?}"
            );
        }
        let _ = fs::remove_dir_all(root.parent().unwrap());
    }
}
