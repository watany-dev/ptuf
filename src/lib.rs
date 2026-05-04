#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

pub mod cli;
pub mod decision;
pub mod hook_input;
pub mod hook_output;
pub mod io_runner;
pub mod reason;
pub mod rules;

pub use decision::{Decision, aggregate};
pub use hook_input::HookInput;

pub fn decide(input: &HookInput) -> Decision {
    aggregate(rules::evaluate_all(input))
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
