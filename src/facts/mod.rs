//! Fact extraction layer.
//!
//! Rules evaluate against the structured [`Facts`] derived from a
//! [`HookInput`] rather than re-parsing raw shell strings. This keeps
//! the matching logic deterministic and lets future YAML plugins
//! declare a stable `requires:` set
//! (`docs/design/architecture.md` §fact extraction,
//! `docs/design/config-and-plugins.md:104-114`).
//!
//! v0.2 introduces the skeleton; individual fact extractors land in
//! follow-up commits.

use crate::HookInput;

pub mod shell;

/// Aggregated facts derived from a single hook payload.
///
/// Subsequent commits will populate `shell`, `urls`, `paths`, etc. The
/// initial skeleton is intentionally empty so that the
/// `evaluate(&Facts, &HookInput)` signature can be threaded through the
/// rule layer before any extractor exists.
#[derive(Debug, Default)]
pub struct Facts {}

/// Build a [`Facts`] view of a hook input. Pure function with no I/O.
pub fn extract(_input: &HookInput) -> Facts {
    Facts::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_input::sample;

    #[test]
    fn extract_returns_default_facts_for_any_input() {
        let _: Facts = extract(&sample("Bash"));
        let _: Facts = extract(&sample("Read"));
    }

    #[test]
    fn facts_default_is_constructible() {
        let _ = Facts::default();
    }
}
