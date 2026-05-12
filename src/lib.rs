pub mod audit;
pub mod cli;
pub mod config;
pub mod decision;
pub mod engine;
pub mod facts;
pub mod hook_input;
pub mod hook_output;
pub mod init;
pub mod io_runner;
pub mod plugin;
pub mod reason;
pub mod rules;
pub mod self_paths;
pub(crate) mod update;

#[cfg(any(test, feature = "testing"))]
#[doc(hidden)]
pub mod testing;

pub use decision::{Decision, aggregate};
pub use engine::{Engine, EngineError, Outcome};
pub use facts::Facts;
pub use hook_input::HookInput;

/// Stateless decision API kept for backward compatibility.
///
/// Tries the CWD-derived [`Engine::for_cwd`] first so embedded callers
/// pick up project policy when one exists. On failure (config / plugin
/// load error) falls back to an [`Engine::builder`]-built engine tagged
/// `embed-fallback`. The builder-built engine still populates
/// [`crate::self_paths::ProtectedPaths`] (binary + HOME-rooted claude
/// settings), so self-protection is preserved even when configuration
/// discovery fails — closing the gap that an empty `ProtectedPaths`
/// fallback used to leave open. CLI entry points instead route through
/// `cli::build_engine_or_fail_closed`, which fail-closes per
/// `docs/design/cli-and-hooks.md:104-114`.
///
/// Embedded callers that want the same fail-closed contract as the CLI
/// should call [`try_decide`] instead.
pub fn decide(input: &HookInput) -> Decision {
    let engine = match Engine::for_cwd() {
        Ok(engine) => engine,
        Err(_) => match Engine::builder().agent("embed-fallback").build() {
            Ok(engine) => engine,
            // `Config::default()` lists no plugin paths, so this branch
            // is structurally unreachable. Keep a `with_components`
            // fallback for documented invariance without using
            // `expect`, per CLAUDE.md.
            Err(_) => Engine::with_components(config::Config::default(), plugin::PluginSet::new()),
        },
    };
    engine.decide(input).decision
}

/// Fallible variant of [`decide`].
///
/// Returns the underlying [`EngineError`] when config or plugin loading
/// fails, so embedded callers can fail-closed (mirroring the CLI's
/// `core.engine.policy-load-failed` behaviour) instead of silently
/// falling back to a default-configured engine.
pub fn try_decide(input: &HookInput) -> Result<Decision, EngineError> {
    let engine = Engine::for_cwd()?;
    Ok(engine.decide(input).decision)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::hook_input::sample;

    #[test]
    fn decide_returns_allow_by_default() {
        assert_eq!(decide(&sample("Bash")), Decision::Allow);
        assert_eq!(decide(&sample("Read")), Decision::Allow);
    }

    #[test]
    fn try_decide_returns_ok_for_clean_cwd() {
        // Happy-path wrapper test. The error path is exercised by
        // `Engine::for_cwd` / `Engine::new` tests in `engine.rs`; we
        // avoid replicating those here because changing the process
        // CWD is racy under cargo's parallel test execution.
        let outcome = try_decide(&sample("Bash"));
        assert!(matches!(outcome, Ok(Decision::Allow)));
    }
}
