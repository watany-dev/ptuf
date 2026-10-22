//! Git configuration facts shared by the shell parser and the
//! `core.git` rules: which `key = value` pairs an invocation sets (via
//! `git -c` / `--config` or a persistent `git config` write), and which
//! of those values git will run as a shell command.

use crate::facts::shell::{Argv, unwrap_all_prefix_wrappers};

/// Global `git` options that take the next token as their value.
const GLOBAL_VALUE_FLAGS: &[&str] = &[
    "-c",
    "--config",
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--super-prefix",
    "--config-env",
];

/// `git config` options that take the next token as their value.
const CONFIG_VALUE_FLAGS: &[&str] = &[
    "-f",
    "--file",
    "--blob",
    "--type",
    "--default",
    "--comment",
    "--value",
];

/// `git config` modes that read or remove rather than set.
const CONFIG_READ_FLAGS: &[&str] = &[
    "--get",
    "--get-all",
    "--get-regexp",
    "--get-urlmatch",
    "--get-color",
    "--get-colorbool",
    "-l",
    "--list",
    "--unset",
    "--unset-all",
    "--remove-section",
    "--rename-section",
    "-e",
    "--edit",
];

/// `git config <subcommand>` (git 2.46+) verbs other than `set`.
const CONFIG_READ_VERBS: &[&str] = &[
    "get",
    "list",
    "unset",
    "rename-section",
    "remove-section",
    "edit",
];

/// Config keys whose value git runs through the shell (`*` stands for
/// one subsection, which may itself contain dots). `alias.*` only runs
/// a shell when the value starts with `!`.
const EXEC_KEYS: &[&str] = &[
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.fsmonitor",
    "core.askpass",
    "credential.helper",
    "credential.*.helper",
    "diff.external",
    "diff.*.textconv",
    "diff.*.command",
    "merge.*.driver",
    "filter.*.clean",
    "filter.*.smudge",
    "filter.*.process",
    "gpg.program",
    "gpg.*.program",
    "sequence.editor",
    "pager.*",
    "difftool.*.cmd",
    "mergetool.*.cmd",
    "man.*.cmd",
    "browser.*.cmd",
    "remote.*.uploadpack",
    "remote.*.receivepack",
    "uploadpack.packobjectshook",
    "sendemail.sendmailcmd",
];

/// `(index of the subcommand in args, subcommand)` for a git argv.
fn subcommand(argv: &Argv) -> Option<(usize, &str)> {
    if argv.head_basename() != "git" {
        return None;
    }
    let mut i = 0;
    while let Some(a) = argv.args.get(i) {
        if GLOBAL_VALUE_FLAGS.contains(&a.as_str()) {
            i += 2;
            continue;
        }
        if !a.starts_with('-') {
            return Some((i, a.as_str()));
        }
        i += 1;
    }
    None
}

/// Every `(key, value)` this git invocation sets: `-c key=value`,
/// `--config key=value`, `--config=key=value`, and a persistent
/// `git config [scope] key value` / `git config set key value`.
pub(crate) fn config_assignments(argv: &Argv) -> Vec<(String, String)> {
    let argv = unwrap_all_prefix_wrappers(argv);
    if argv.head_basename() != "git" {
        return Vec::new();
    }
    let mut out = Vec::new();
    let sub = subcommand(&argv);
    let globals = sub.map_or(argv.args.as_slice(), |(i, _)| &argv.args[..i]);
    let mut iter = globals.iter();
    while let Some(a) = iter.next() {
        let raw = match a.as_str() {
            "-c" | "--config" => iter.next().map(String::as_str),
            s => s.strip_prefix("--config="),
        };
        if let Some((k, v)) = raw.and_then(|r| r.split_once('=')) {
            out.push((k.trim().to_owned(), v.to_owned()));
        }
    }
    if let Some((i, "config")) = sub {
        out.extend(persistent_assignment(&argv.args[i + 1..]));
    }
    out
}

fn persistent_assignment(args: &[String]) -> Option<(String, String)> {
    let mut positional = Vec::new();
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        let a = a.as_str();
        if CONFIG_READ_FLAGS.contains(&a) {
            return None;
        }
        if CONFIG_VALUE_FLAGS.contains(&a) {
            iter.next();
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        positional.push(a);
    }
    if let Some(verb) = positional.first() {
        if CONFIG_READ_VERBS.contains(verb) {
            return None;
        }
        if *verb == "set" {
            positional.remove(0);
        }
    }
    match positional.as_slice() {
        [key, value, ..] => Some(((*key).to_owned(), (*value).to_owned())),
        _ => None,
    }
}

/// Whether git runs `value` of `key` as a shell command.
pub(crate) fn is_exec_assignment(key: &str, value: &str) -> bool {
    let key = key.to_ascii_lowercase();
    if key.starts_with("alias.") {
        return value.trim_start().starts_with('!');
    }
    EXEC_KEYS.iter().any(|p| key_matches(p, &key))
}

fn key_matches(pattern: &str, key: &str) -> bool {
    match pattern.split_once(".*") {
        None => pattern == key,
        Some((section, tail)) => key
            .strip_prefix(section)
            .and_then(|r| r.strip_prefix('.'))
            .is_some_and(|rest| match tail {
                "" => !rest.is_empty(),
                tail => rest.strip_suffix(tail).is_some_and(|sub| !sub.is_empty()),
            }),
    }
}

/// Shell code this git invocation hands to `sh -c` through its config:
/// the values of exec keys, with an alias's leading `!` stripped.
pub(crate) fn exec_payloads(argv: &Argv) -> Vec<String> {
    config_assignments(argv)
        .into_iter()
        .filter(|(k, v)| is_exec_assignment(k, v))
        .map(|(k, v)| {
            if k.to_ascii_lowercase().starts_with("alias.") {
                v.trim_start().trim_start_matches('!').to_owned()
            } else {
                v
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::shell::parse;

    fn first(cmd: &str) -> Argv {
        parse(cmd).segments[0].commands[0].clone()
    }

    #[test]
    fn collects_overrides_and_persistent_writes() {
        assert_eq!(
            config_assignments(&first(
                "git -c core.hooksPath=/dev/null --config=a.b=c commit"
            )),
            [
                ("core.hooksPath".into(), "/dev/null".into()),
                ("a.b".into(), "c".into())
            ]
        );
        for cmd in [
            "git config core.hooksPath /dev/null",
            "git config --global core.hooksPath /dev/null",
            "git config --file x.cfg core.hooksPath /dev/null",
            "git config set core.hooksPath /dev/null",
            "sudo git config --add core.hooksPath /dev/null",
        ] {
            assert_eq!(
                config_assignments(&first(cmd)),
                [("core.hooksPath".to_string(), "/dev/null".to_string())],
                "{cmd}"
            );
        }
        for cmd in [
            "git config --unset core.hooksPath",
            "git config --get core.hooksPath",
            "git config get core.hooksPath",
            "git config core.hooksPath",
            "git config -l",
            "git status",
        ] {
            assert!(config_assignments(&first(cmd)).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn exec_keys_and_aliases() {
        for (k, v) in [
            ("core.sshCommand", "x"),
            ("core.pager", "x"),
            ("alias.x", "!rm -rf /"),
            ("diff.foo.textconv", "x"),
            ("filter.a.b.smudge", "x"),
            ("credential.https://x.helper", "x"),
            ("pager.log", "x"),
        ] {
            assert!(is_exec_assignment(k, v), "{k}");
        }
        for (k, v) in [
            ("alias.st", "status"),
            ("diff.textconv", "x"),
            ("pager", "x"),
            ("user.name", "x"),
        ] {
            assert!(!is_exec_assignment(k, v), "{k}");
        }
        assert_eq!(
            exec_payloads(&first("git -c alias.x='!rm -rf /' x")),
            ["rm -rf /"]
        );
    }
}
