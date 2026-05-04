#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

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

pub use decision::{Decision, aggregate};
pub use engine::{Engine, EngineError, Outcome};
pub use facts::Facts;
pub use hook_input::HookInput;

/// Stateless decision API kept for backward compatibility.
///
/// Tries the CWD-derived [`Engine::for_cwd`] first so embedded callers
/// pick up project policy when one exists. On failure (config / plugin
/// load error) falls back silently to a default-configured engine —
/// CLI entry points instead route through `cli::build_engine_or_fail_closed`,
/// which fail-closes per `docs/design/cli-and-hooks.md:104-114`.
pub fn decide(input: &HookInput) -> Decision {
    let engine = Engine::for_cwd().unwrap_or_else(|_| Engine::default());
    engine.decide(input).decision
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::hook_input::sample;

    #[test]
    fn decide_returns_allow_by_default() {
        assert_eq!(decide(&sample("Bash")), Decision::Allow);
        assert_eq!(decide(&sample("Read")), Decision::Allow);
    }
}
