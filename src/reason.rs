/// Build the canonical "Rule Feedback" reason string used by `ask` / `deny`
/// decisions. See `docs/design/decision-model.md`.
pub fn build(rule_id: &str, problem: &str, alternatives: &[&str]) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = write!(out, "Blocked by ptuf rule {rule_id}.\n\n{problem}\n");
    if !alternatives.is_empty() {
        out.push_str("\nSafer alternative:\n");
        for (i, alt) in alternatives.iter().enumerate() {
            let _ = writeln!(out, "{}. {alt}", i + 1);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_rule_id_header_and_problem() {
        let s = build("core.test.example", "Something dangerous happened.", &[]);
        assert!(s.starts_with("Blocked by ptuf rule core.test.example.\n"));
        assert!(s.contains("Something dangerous happened."));
        assert!(!s.contains("Safer alternative"));
    }

    #[test]
    fn enumerates_alternatives() {
        let s = build(
            "core.x",
            "Problem.",
            &["Do A first.", "Then ask the user.", "Finally run B."],
        );
        assert!(s.contains("\nSafer alternative:\n"));
        assert!(s.contains("1. Do A first."));
        assert!(s.contains("2. Then ask the user."));
        assert!(s.contains("3. Finally run B."));
        let snapshot = build("core.x", "Problem statement.", &["Step one.", "Step two."]);
        let expected = "Blocked by ptuf rule core.x.\n\nProblem statement.\n\nSafer alternative:\n1. Step one.\n2. Step two.\n";
        assert_eq!(snapshot, expected);
    }

    use crate::testing::proptest::{reason_text, rule_id};
    use proptest::collection::vec;
    use proptest::prelude::*;

    proptest! {
        // Header is fixed regardless of payload contents.
        #[test]
        fn pbt_starts_with_header(
            id in rule_id(),
            problem in reason_text(),
            alts in vec(reason_text(), 0..5),
        ) {
            let alt_refs: Vec<&str> = alts.iter().map(String::as_str).collect();
            let s = build(&id, &problem, &alt_refs);
            let header = format!("Blocked by ptuf rule {id}.\n\n");
            prop_assert!(s.starts_with(&header), "missing header in {s:?}");
        }

        // Empty alternatives ⇒ no "Safer alternative:" section.
        #[test]
        fn pbt_no_alternatives_section_when_empty(
            id in rule_id(),
            problem in reason_text(),
        ) {
            let s = build(&id, &problem, &[]);
            prop_assert!(!s.contains("Safer alternative:"));
        }

        // Non-empty alternatives ⇒ section present and numbered 1..n.
        #[test]
        fn pbt_alternatives_are_numbered(
            id in rule_id(),
            problem in reason_text(),
            alts in vec(reason_text(), 1..6),
        ) {
            let alt_refs: Vec<&str> = alts.iter().map(String::as_str).collect();
            let s = build(&id, &problem, &alt_refs);
            prop_assert!(s.contains("Safer alternative:"));
            for (i, _) in alts.iter().enumerate() {
                let prefix = format!("\n{}. ", i + 1);
                prop_assert!(
                    s.contains(&prefix),
                    "missing number {i}: {s:?}",
                );
            }
        }

        // `build` must not panic for any printable inputs.
        #[test]
        fn pbt_never_panics(
            id in "[ -~]{0,30}",
            problem in "[ -~]{0,80}",
            alts in vec("[ -~]{0,30}", 0..6),
        ) {
            let alt_refs: Vec<&str> = alts.iter().map(String::as_str).collect();
            let _ = build(&id, &problem, &alt_refs);
        }
    }
}
