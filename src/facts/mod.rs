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
/// Populated lazily as the layered rule set demands: each new fact
/// extractor (urls, paths, dataflow, …) lands as another field with its
/// own `Option<…>` so that non-Bash tools simply leave the relevant
/// shapes unset.
#[derive(Debug, Default)]
pub struct Facts {
    /// Parsed Bash command line, present only for `Bash` tool calls
    /// whose payload carries a `command` string.
    pub bash: Option<shell::Bash>,
}

/// Build a [`Facts`] view of a hook input. Pure function with no I/O.
pub fn extract(input: &HookInput) -> Facts {
    Facts {
        bash: input.bash_command().map(shell::parse),
    }
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
