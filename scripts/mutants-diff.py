#!/usr/bin/env python3
"""Widen a PR's diff so cargo-mutants also checks the code whose tests lost lines.

`cargo mutants --in-diff` mutates only the non-test lines a PR changes, so a
PR that only deletes or weakens tests runs no mutant at all. This reads the
PR's diff and writes it back with every source file whose tests lost a line
added in full, as if it were a new file, so the one `--in-diff` run mutates
all of it. Ported from watany-dev/chokkin's `scripts/mutants-diff.py`.

A removed or changed line counts; an added test cannot make a mutant survive.
Where the tests are:

- a `#[cfg(test)] mod name { ... }` block in `src/**.rs`, or a removed line
  that reads as test code (`#[cfg(test)]`, `#[test]`, an assertion), which
  also catches a block deleted whole: that file;
- a `#[cfg(test)] mod name;` file under `src/`: the file declaring it and the
  other files beside it;
- `tests/<name>.rs`: the source `TEST_TARGETS` names for it.

A test file `TEST_TARGETS` does not name (the end-to-end suites, a new file),
a fixture, and any other file under `tests/` widen nothing: the report on
stderr lists them, and the nightly full run is what checks that code.

The widened files still go through `.cargo/mutants.toml`'s `examine_globs`,
so only the decision core is ever mutated.

Usage: mutants-diff.py DIFF > widened.diff
"""

import re
import sys
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path

# What each integration test file pins, as paths under the repo root. A
# directory stands for every `.rs` file under it. `None`: the file runs the
# whole pipeline end to end, so no narrower target exists.
TEST_TARGETS: dict[str, tuple[str, ...] | None] = {
    "bypass_corpus": None,
    "cli_audit": None,
    "cli_smoke": None,
    "config_integration": ("src/config",),
    "contracts": None,
    "e2e_heavy": None,
    "rules_iter_order": ("src/rules",),
}

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
TEST_ATTR = "#[cfg(test)]"
TEST_MOD_BLOCK = re.compile(r"^(?:pub(?:\([^)]*\))? )?mod \w+ \{")
TEST_MOD_FILE = re.compile(r"^(?:pub(?:\([^)]*\))? )?mod (\w+);")
TEST_LINE = re.compile(r"^\s*(?:#\[cfg\(test\)\]|#\[test\]|(?:prop_)?assert(?:_eq|_ne)?!|proptest!)")


@dataclass
class FileDiff:
    path: str
    text: str
    # New-side line numbers a removed line sat before, and its text.
    removed_at: list[int] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)


def split_diff(diff: str) -> list[FileDiff]:
    """Each file's section of a `git diff`, with where its lines were removed."""
    sections = re.split(r"(?m)^(?=diff --git )", diff)
    files = []
    for text in sections:
        if not text.startswith("diff --git "):
            continue
        old = new = None
        removed_at: list[int] = []
        removed: list[str] = []
        line = 0
        for row in text.splitlines():
            if row.startswith("--- ") and old is None:
                old = row[4:]
            elif row.startswith("+++ ") and new is None:
                new = row[4:]
            elif match := HUNK.match(row):
                line = int(match.group(1))
            elif new is not None and row.startswith("-"):
                removed_at.append(line)
                removed.append(row[1:])
            elif new is not None and row.startswith(("+", " ")):
                line += 1
        named = new if new not in (None, "/dev/null") else old
        if named is None or named == "/dev/null":
            # A mode or rename-only change: nothing to mutate or widen.
            path = text.split()[2].removeprefix("a/")
        else:
            path = named.removeprefix("b/").removeprefix("a/")
        files.append(FileDiff(path, text, removed_at, removed))
    return files


def test_blocks(source: str) -> list[tuple[int, int]]:
    """1-based inclusive line ranges of top-level `#[cfg(test)] mod x { }` blocks."""
    lines = source.splitlines()
    blocks = []
    index = 0
    while index < len(lines) - 1:
        if lines[index] == TEST_ATTR and TEST_MOD_BLOCK.match(lines[index + 1]):
            end = next((at for at in range(index + 2, len(lines)) if lines[at] == "}"), len(lines) - 1)
            blocks.append((index + 1, end + 1))
            index = end
        index += 1
    return blocks


def test_module_files(root: Path) -> dict[str, str]:
    """`src/` files only a `#[cfg(test)] mod name;` brings in, to the declaring file."""
    found = {}
    for path in sorted((root / "src").rglob("*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for attr, declaration in pairwise(lines):
            match = TEST_MOD_FILE.match(declaration)
            if attr != TEST_ATTR or not match:
                continue
            directory = path.parent if path.name in ("mod.rs", "lib.rs", "main.rs") else path.with_suffix("")
            for candidate in (directory / f"{match.group(1)}.rs", directory / match.group(1) / "mod.rs"):
                if candidate.is_file():
                    found[candidate.relative_to(root).as_posix()] = path.relative_to(root).as_posix()
    return found


def expand(root: Path, target: str) -> list[str]:
    path = root / target
    if path.is_dir():
        return [file.relative_to(root).as_posix() for file in sorted(path.rglob("*.rs"))]
    return [target] if path.is_file() else []


def widen(root: Path, diff: str) -> tuple[str, list[str]]:
    """The widened diff and one report line per widening or skipped test change."""
    files = split_diff(diff)
    test_files = test_module_files(root)
    widened: dict[str, str] = {}
    report = []
    for file in files:
        if not file.removed_at:
            continue
        path = Path(file.path)
        if file.path in test_files:
            beside = (entry.relative_to(root).as_posix() for entry in sorted((root / path.parent).glob("*.rs")))
            siblings = [sibling for sibling in beside if sibling not in test_files]
            for source in [test_files[file.path], *siblings]:
                widened.setdefault(source, file.path)
        elif file.path.startswith("src/") and path.suffix == ".rs" and (root / path).is_file():
            blocks = test_blocks((root / path).read_text(encoding="utf-8"))
            in_block = any(start <= at <= end for at in file.removed_at for start, end in blocks)
            if in_block or any(TEST_LINE.match(text) for text in file.removed):
                widened.setdefault(file.path, file.path)
        elif path.parent.as_posix() == "tests" and path.suffix == ".rs":
            targets = TEST_TARGETS.get(path.stem, ())
            if not targets:
                why = "runs the whole pipeline" if targets is None else "is not in TEST_TARGETS"
                report.append(f"not widened: {file.path} {why}; the nightly run checks it")
                continue
            for target in targets:
                for source in expand(root, target):
                    widened.setdefault(source, file.path)
        elif file.path.startswith("tests/fixtures/"):
            report.append(f"not widened: {file.path} is a fixture; the nightly run checks it")
        elif file.path.startswith("tests/") and path.suffix != ".py":
            report.append(f"not widened: {file.path} is no test file this maps; the nightly run checks it")
    by_cause: dict[str, list[str]] = {}
    for source, cause in widened.items():
        by_cause.setdefault(cause, []).append(source)
    report.extend(
        f"widened: {cause} lost lines, so all of {', '.join(sorted(sources))}"
        for cause, sources in sorted(by_cause.items())
    )
    sections = [file.text for file in files if file.path not in widened]
    for source in sorted(widened):
        lines = (root / source).read_text(encoding="utf-8").splitlines()
        body = "".join(f"+{line}\n" for line in lines)
        sections.append(
            f"diff --git a/{source} b/{source}\n--- /dev/null\n+++ b/{source}\n@@ -0,0 +1,{len(lines)} @@\n{body}"
        )
    return "".join(sections), report


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    diff = Path(argv[1]).read_text(encoding="utf-8")
    widened, report = widen(Path.cwd(), diff)
    sys.stdout.write(widened)
    for line in report:
        print(line, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
