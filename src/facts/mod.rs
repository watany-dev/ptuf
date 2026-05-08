//! Fact extraction layer.
//!
//! Rules evaluate against the structured [`Facts`] derived from a
//! [`HookInput`] rather than re-parsing raw shell strings. This keeps
//! the matching logic deterministic and lets future YAML plugins
//! declare a stable `requires:` set
//! (`docs/design/architecture.md` §fact extraction,
//! `docs/design/config-and-plugins.md:104-114`).
//!
//! v0.3 adds `path` (file-path facts for `Read`/`Edit`/`Write`),
//! `url` (parsed URL for `WebFetch`), and `sensitive` (per-token
//! credentials classification used by tool-side rules and the plugin
//! DSL). The `protected` field is left empty by `extract` and populated
//! by [`crate::engine::Engine::decide`] before rule dispatch.

use crate::HookInput;

pub mod path;
pub mod project;
pub mod sensitive;
pub mod shell;
pub mod url;

/// Aggregated facts derived from a single hook payload.
///
/// Populated lazily as the layered rule set demands: each new fact
/// extractor (urls, paths, dataflow, …) lands as another field with its
/// own `Option<…>` so that non-Bash tools simply leave the relevant
/// shapes unset.
#[derive(Debug, Default)]
pub struct Facts {
    /// Parsed Bash command line, present only for `Bash` tool calls
    /// whose payload carries a `command` string.
    pub bash: Option<shell::Bash>,
    /// `file_path` extracted from `Read`/`Edit`/`Write` payloads, with
    /// `~` / `$HOME` expansion attempted via the production env.
    pub path: Option<path::FilePath>,
    /// All extracted paths, including MCP multi-file payloads.
    pub paths: Vec<path::FilePath>,
    /// Parsed URL from a `WebFetch` payload.
    pub url: Option<url::Url>,
    /// Sensitive tokens detected across the payload's strings (Bash
    /// tokens, file paths, `WebFetch` URL components, Edit/Write
    /// content). Order is non-significant; rules typically just check
    /// `is_empty()`.
    pub sensitive: Vec<sensitive::SensitivePath>,
    /// Self-protection match labels populated by the engine layer; pure
    /// `extract` leaves this empty.
    pub protected: crate::self_paths::ProtectedKinds,
    /// Project-level facts (lock files, current branch, protected
    /// branch flag) populated by the engine layer; pure `extract`
    /// leaves this default-empty.
    pub project: project::ProjectFacts,
}

/// Build a [`Facts`] view of a hook input. Pure function with no I/O
/// other than the production env lookup used for `~` expansion.
pub fn extract(input: &HookInput) -> Facts {
    let event = input.event();
    let bash = event.command.map(shell::parse);
    let paths = path::extract_all(input);
    let path = paths.first().cloned();
    let url = event.urls.first().and_then(|url| url::parse(url));
    let sensitive = collect_sensitive(&event, bash.as_ref(), &paths, url.as_ref());
    Facts {
        bash,
        path,
        paths,
        url,
        sensitive,
        protected: crate::self_paths::ProtectedKinds::new(),
        project: project::ProjectFacts::default(),
    }
}

fn collect_sensitive(
    event: &crate::hook_input::Event<'_>,
    bash: Option<&shell::Bash>,
    paths: &[path::FilePath],
    url: Option<&url::Url>,
) -> Vec<sensitive::SensitivePath> {
    let mut out: Vec<sensitive::SensitivePath> = Vec::new();
    let mut push_all = |s: &str| out.extend(sensitive::classify(s));

    if let Some(b) = bash {
        for cmd in b.commands() {
            push_all(&cmd.head);
            for a in &cmd.args {
                push_all(a);
            }
            for e in &cmd.env_assignments {
                push_all(&e.value);
            }
        }
    }

    for p in paths {
        push_all(&p.raw);
    }

    if let Some(u) = url {
        push_all(&u.path);
        push_all(&u.host);
    }

    if let Some(s) = event.content {
        push_all(s);
    }

    out
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::hook_input::sample;

    #[test]
    fn extract_returns_default_facts_for_empty_input() {
        let f = extract(&sample("Bash"));
        assert!(f.bash.is_none() || f.bash.as_ref().is_some_and(|b| b.segments.is_empty()));
        assert!(f.path.is_none());
        assert!(f.paths.is_empty());
        assert!(f.url.is_none());
        assert!(f.sensitive.is_empty());
        assert!(f.protected.is_empty());
    }

    #[test]
    fn facts_default_is_constructible() {
        let _ = Facts::default();
    }

    #[test]
    fn extract_populates_path_for_read_tool() {
        let i = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "file_path": "/tmp/x" }),
        };
        let f = extract(&i);
        assert!(f.path.is_some());
        assert_eq!(f.paths.len(), 1);
        assert_eq!(f.path.as_ref().unwrap().raw, "/tmp/x");
    }

    #[test]
    fn extract_populates_url_for_webfetch_tool() {
        let i = HookInput {
            tool_name: "WebFetch".into(),
            tool_input: serde_json::json!({ "url": "https://example.com/x" }),
        };
        let f = extract(&i);
        assert!(f.url.is_some());
        assert_eq!(f.url.as_ref().unwrap().host, "example.com");
    }

    #[test]
    fn extract_collects_sensitive_from_bash_argv() {
        let i = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": "scp ~/.ssh/id_rsa user@host:" }),
        };
        let f = extract(&i);
        assert!(!f.sensitive.is_empty());
        let kinds: Vec<_> = f.sensitive.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&sensitive::SensitiveKind::SshDir));
    }

    #[test]
    fn extract_collects_sensitive_from_read_file_path() {
        let i = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "file_path": "~/.aws/credentials" }),
        };
        let f = extract(&i);
        assert!(
            f.sensitive
                .iter()
                .any(|s| s.kind == sensitive::SensitiveKind::AwsDir)
        );
    }

    #[test]
    fn extract_collects_sensitive_from_write_payload() {
        let i = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": "/tmp/key.pem",
                "content": "-----BEGIN RSA PRIVATE KEY-----\n..."
            }),
        };
        let f = extract(&i);
        assert!(
            f.sensitive
                .iter()
                .any(|s| s.kind == sensitive::SensitiveKind::PemBlob)
        );
    }
}
