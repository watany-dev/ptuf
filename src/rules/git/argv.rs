//! Argv-level helpers shared by every git rule matcher.
//!
//! Each function here works on a single parsed [`Argv`] and answers a
//! question the matchers want to ask (`is this git?`, `what is the
//! subcommand?`, `does any env assignment match a watched key?`).
//! Keeping them in one file means the per-subcommand rule files
//! only need to know the matchers they care about.

use crate::facts::shell::{Argv, head_basename};

/// Recognised invocation heads for `git`. Heads are compared by
/// basename, so absolute and relative invocation paths
/// (`/usr/bin/git`, `/opt/homebrew/bin/git`, `./git`) match too.
pub(super) const GIT_HEADS: &[&str] = &["git"];

pub(super) fn is_git(head: &str) -> bool {
    GIT_HEADS.contains(&head_basename(head))
}

/// First non-flag argument after `git` — i.e. the subcommand
/// (`push`, `reset`, `remote`, ...). `None` for `git --version`.
///
/// Skips git's value-taking global flags so that
/// `git -c core.hooksPath=/dev/null commit` resolves to `commit`, not to
/// the `-c`'s value.
pub(super) fn git_subcommand(argv: &Argv) -> Option<&str> {
    if !is_git(&argv.head) {
        return None;
    }
    let mut iter = argv.args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-c" | "--config" | "-C" | "--git-dir" | "--work-tree" | "--namespace"
            | "--exec-path" | "--super-prefix" => {
                iter.next();
                continue;
            },
            s if s.starts_with("--config=")
                || s.starts_with("--git-dir=")
                || s.starts_with("--work-tree=")
                || s.starts_with("--namespace=")
                || s.starts_with("--exec-path=")
                || s.starts_with("--super-prefix=") =>
            {
                continue;
            },
            s if s.starts_with('-') => continue,
            s => return Some(s),
        }
    }
    None
}

pub(super) fn args_after_subcommand<'a>(argv: &'a Argv, sub: &str) -> Vec<&'a str> {
    let mut iter = argv.args.iter().map(String::as_str);
    for a in iter.by_ref() {
        if a == sub {
            break;
        }
    }
    iter.collect()
}

/// Gather the values of git's `-c key=val` / `--config key=val` /
/// `--config=key=val` global options.
pub(super) fn config_overrides(argv: &Argv) -> impl Iterator<Item = &str> + '_ {
    let mut iter = argv.args.iter();
    std::iter::from_fn(move || {
        while let Some(a) = iter.next() {
            match a.as_str() {
                "-c" | "--config" => {
                    if let Some(v) = iter.next() {
                        return Some(v.as_str());
                    }
                },
                s => {
                    if let Some(rest) = s.strip_prefix("--config=") {
                        return Some(rest);
                    }
                },
            }
        }
        None
    })
}

#[derive(Clone, Copy)]
pub(super) enum BypassMatch {
    Any,
    Falsy,
    Truthy,
}

fn is_falsy(v: &str) -> bool {
    let v = v.trim();
    ["false", "no", "off", "0", ""]
        .iter()
        .any(|t| v.eq_ignore_ascii_case(t))
}

fn is_truthy(v: &str) -> bool {
    let v = v.trim();
    ["true", "yes", "on", "1"]
        .iter()
        .any(|t| v.eq_ignore_ascii_case(t))
}

pub(super) fn bypass_value_matches(mode: BypassMatch, value: &str) -> bool {
    match mode {
        BypassMatch::Any => !value.trim().is_empty(),
        BypassMatch::Falsy => is_falsy(value),
        BypassMatch::Truthy => is_truthy(value),
    }
}

/// Shared env-var matcher. `scope = Some(list)` restricts to specific git
/// subcommands; `scope = None` fires on any git subcommand.
pub(super) fn matches_env_keys(
    argv: &Argv,
    scope: Option<&[&str]>,
    keys: &[(&str, BypassMatch)],
) -> bool {
    let Some(sub) = git_subcommand(argv) else {
        return false;
    };
    if let Some(allowed) = scope
        && !allowed.contains(&sub)
    {
        return false;
    }
    argv.env_assignments.iter().any(|ea| {
        keys.iter().any(|(target, mode)| {
            ea.key.eq_ignore_ascii_case(target) && bypass_value_matches(*mode, &ea.value)
        })
    })
}
