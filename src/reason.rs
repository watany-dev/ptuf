/// Build the canonical "Rule Feedback" reason string used by `ask` / `deny`
/// decisions. See `docs/design/decision-model.md`.
pub fn build(rule_id: &str, problem: &str, alternatives: &[&str]) -> String {
    let mut out = format!("Blocked by ptuf rule {rule_id}.\n\n{problem}\n");
    if !alternatives.is_empty() {
        out.push_str("\nSafer alternative:\n");
        for (i, alt) in alternatives.iter().enumerate() {
            out.push_str(&format!("{}. {alt}\n", i + 1));
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
    }

    #[test]
    fn full_layout_snapshot() {
        let s = build("core.x", "Problem statement.", &["Step one.", "Step two."]);
        let expected = "Blocked by ptuf rule core.x.\n\nProblem statement.\n\nSafer alternative:\n1. Step one.\n2. Step two.\n";
        assert_eq!(s, expected);
    }
}
