//! Pi Coding Agent adapter — input normaliser (stub until M3).

use crate::hook_input::HookInput;

/// Reasons a Pi payload failed to normalise.
#[derive(Debug)]
pub(super) enum PiInputError {
    Empty,
}

impl std::fmt::Display for PiInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "hook payload is empty"),
        }
    }
}

/// Normalise a Pi stdin body into a [`HookInput`]. Full normalisation lands in M3.
pub(super) fn parse(body: &str) -> Result<HookInput, PiInputError> {
    if body.trim().is_empty() {
        return Err(PiInputError::Empty);
    }
    Err(PiInputError::Empty)
}
