#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(file_name: str):
    """Import scripts/<file_name> by path: its name has a hyphen."""
    path = ROOT / "scripts" / file_name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


widen_diff = load("mutants-diff.py")

SOURCE = """\
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}

#[cfg(test)]
mod tests {
    #[test]
    fn adds() {
        assert_eq!(super::add(1, 2), 3);
    }
}
"""


def section(path: str, hunk: str, body: str) -> str:
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n{hunk}\n{body}"


class WidenTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.write("src/config/merge.rs", SOURCE)
        self.write("src/config/types.rs", "pub struct Node;\n")
        self.write("src/lib.rs", "#[cfg(test)]\nmod walk_reference;\npub fn run() {}\n")
        self.write("src/walk_reference.rs", "pub fn reference() {}\n")
        self.write("tests/config_integration.rs", "#[test]\nfn builds() {}\n")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write(self, path: str, text: str) -> None:
        (self.root / path).parent.mkdir(parents=True, exist_ok=True)
        (self.root / path).write_text(text, encoding="utf-8")

    def widened(self, diff: str) -> tuple[list[str], list[str]]:
        out, report = widen_diff.widen(self.root, diff)
        files = [part.split()[0] for part in out.split("diff --git a/")[1:]]
        return files, report

    def test_a_removed_line_in_a_test_block_widens_to_the_whole_file(self) -> None:
        diff = section(
            "src/config/merge.rs",
            "@@ -9,2 +9,1 @@ mod tests {",
            "-        assert_eq!(super::add(1, 2), 3);\n-        assert_eq!(super::add(0, 0), 0);\n+        assert_eq!(super::add(1, 2), 3);\n",
        )
        out, _ = widen_diff.widen(self.root, diff)
        self.assertIn("--- /dev/null\n+++ b/src/config/merge.rs\n@@ -0,0 +1,11 @@\n+pub fn add(", out)
        self.assertNotIn("--- a/src/config/merge.rs", out)

    def test_a_test_block_deleted_whole_widens_to_the_file(self) -> None:
        self.write("src/config/merge.rs", "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n")
        diff = section(
            "src/config/merge.rs",
            "@@ -4,3 +3,0 @@",
            "-\n-#[cfg(test)]\n-mod tests {}\n",
        )
        files, _ = self.widened(diff)
        self.assertEqual(files, ["src/config/merge.rs"])
        self.assertNotIn("--- a/src/config/merge.rs", widen_diff.widen(self.root, diff)[0])

    def test_an_added_test_or_a_non_test_change_keeps_the_diff(self) -> None:
        added = section("src/config/merge.rs", "@@ -9,0 +10,1 @@ mod tests {", "+        assert!(true);\n")
        code = section("src/config/merge.rs", "@@ -2,1 +2,1 @@", "-    a + b\n+    b + a\n")
        for diff in (added, code):
            out, report = widen_diff.widen(self.root, diff)
            self.assertEqual(out, diff)
            self.assertEqual(report, [])

    def test_an_integration_test_widens_to_its_targets(self) -> None:
        diff = section("tests/config_integration.rs", "@@ -2,1 +1,0 @@", "-fn builds() {}\n")
        files, report = self.widened(diff)
        # The test's own section stays: cargo-mutants never mutates tests.
        self.assertEqual(files, ["tests/config_integration.rs", "src/config/merge.rs", "src/config/types.rs"])
        self.assertEqual(
            report,
            ["widened: tests/config_integration.rs lost lines, so all of src/config/merge.rs, src/config/types.rs"],
        )

    def test_a_test_module_file_widens_to_the_files_beside_it(self) -> None:
        diff = section("src/walk_reference.rs", "@@ -1,1 +0,0 @@", "-pub fn reference() {}\n")
        files, _ = self.widened(diff)
        self.assertEqual(files, ["src/walk_reference.rs", "src/lib.rs"])

    def test_a_test_module_file_of_a_non_mod_file_widens_to_its_declarer(self) -> None:
        self.write("src/sources.rs", "#[cfg(test)]\nmod tests;\npub fn walk() {}\n")
        self.write("src/sources/tests.rs", "#[test]\nfn walks() {}\n")
        self.write("src/sources/layout.rs", "pub fn layout() {}\n")
        diff = section("src/sources/tests.rs", "@@ -2,1 +1,0 @@", "-fn walks() {}\n")
        files, _ = self.widened(diff)
        self.assertEqual(files, ["src/sources/tests.rs", "src/sources.rs", "src/sources/layout.rs"])

    def test_an_end_to_end_or_unknown_test_and_a_fixture_are_reported(self) -> None:
        diffs = [
            section("tests/bypass_corpus.rs", "@@ -1,1 +0,0 @@", "-x\n"),
            section("tests/brand_new.rs", "@@ -1,1 +0,0 @@", "-x\n"),
            section("tests/fixtures/app/main.py", "@@ -1,1 +0,0 @@", "-import x\n"),
            section("tests/bypass/corpus.jsonl", "@@ -1,1 +0,0 @@", "-x\n"),
            section("tests/scripts/test_other.py", "@@ -1,1 +0,0 @@", "-x\n"),
        ]
        files, report = self.widened("".join(diffs))
        self.assertEqual(
            files,
            [
                "tests/bypass_corpus.rs",
                "tests/brand_new.rs",
                "tests/fixtures/app/main.py",
                "tests/bypass/corpus.jsonl",
                "tests/scripts/test_other.py",
            ],
        )
        self.assertEqual(
            report,
            [
                "not widened: tests/bypass_corpus.rs runs the whole pipeline; the nightly run checks it",
                "not widened: tests/brand_new.rs is not in TEST_TARGETS; the nightly run checks it",
                "not widened: tests/fixtures/app/main.py is a fixture; the nightly run checks it",
                "not widened: tests/bypass/corpus.jsonl is no test file this maps; the nightly run checks it",
            ],
        )

    def test_a_deleted_test_file_still_widens(self) -> None:
        diff = (
            "diff --git a/tests/config_integration.rs b/tests/config_integration.rs\n"
            "deleted file mode 100644\n--- a/tests/config_integration.rs\n+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n-#[test]\n-fn builds() {}\n"
        )
        files, _ = self.widened(diff)
        self.assertEqual(files, ["tests/config_integration.rs", "src/config/merge.rs", "src/config/types.rs"])

    def test_every_test_file_has_a_target_entry(self) -> None:
        root = ROOT
        stems = {path.stem for path in (root / "tests").glob("*.rs")}
        self.assertEqual(stems - widen_diff.TEST_TARGETS.keys(), set())
        for targets in widen_diff.TEST_TARGETS.values():
            for target in targets or ():
                self.assertTrue((root / target).exists(), target)


if __name__ == "__main__":
    unittest.main()
