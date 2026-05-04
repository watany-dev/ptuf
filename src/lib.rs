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
pub mod io_runner;
pub mod plugin;
pub mod reason;
pub mod rules;

#[cfg(test)]
pub(crate) mod testing;

pub use decision::{Decision, aggregate};
pub use engine::{Engine, EngineError, Outcome};
pub use facts::Facts;
pub use hook_input::HookInput;

/// Stateless decision API kept for backward compatibility.
///
/// Internally delegates to a default-configured [`Engine`]; callers
/// that need YAML config, audit, or `mode: monitor` demotion should
/// instantiate [`Engine`] directly.
pub fn decide(input: &HookInput) -> Decision {
    Engine::default().decide(input).decision
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
