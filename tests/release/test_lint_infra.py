"""Tests for the repository lint infrastructure.

Scope: .ruff.toml (FlitzZip-mirrored profile), tools/lint.ps1 stage wiring,
.github/workflows/lint.yml hash pinning, and the structure of the hash-pinned
requirements file. Network use is deliberately excluded: the requirements file
is validated structurally (pin format, sha256 hash format, entry grammar)
rather than by installing from it.
"""

from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

REQ_FILE = ROOT / ".github" / "requirements" / "requirements-lint-windows.txt"


class TestRuffConfig(unittest.TestCase):
    """The ruff profile must match strmt7/FlitzZip exactly (line-length 120)."""

    def test_ruff_toml_exists_with_flitzzip_profile(self) -> None:
        """Ruff toml exists with flitzzip profile."""
        path = ROOT / ".ruff.toml"
        self.assertTrue(path.is_file(), ".ruff.toml is missing")
        config = tomllib.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(config["line-length"], 120)
        self.assertEqual(config["target-version"], "py313")
        self.assertEqual(
            config["lint"]["select"],
            ["E", "F", "I", "B", "UP", "SIM", "PLW1510", "D"],
        )
        # The D contract: documentation rules on (every module, class,
        # function and magic method carries a docstring), presentation-only
        # D2xx/D4xx rules off (see the rationale block in .ruff.toml).
        self.assertEqual(config["lint"]["ignore"], ["D203", "D205", "D212", "D213", "D401"])
        self.assertEqual(config["format"]["line-ending"], "lf")

    def test_line_length_exception_is_documented_and_dated(self) -> None:
        """Line length exception is documented and dated."""
        text = (ROOT / ".ruff.toml").read_text(encoding="utf-8")
        self.assertIn("2026-10-28", text)
        self.assertIn("exception", text.lower())
        self.assertIn("DeepSource", text)
        self.assertIn("FlitzZip", text)


class TestLintScript(unittest.TestCase):
    """tools/lint.ps1 must carry the required stages and no C++/CMake ones."""

    REQUIRED_STAGES = [
        "python-ruff-check",
        "python-ruff-format",
        "powershell-psscriptanalyzer",
        "yaml-yamllint",
        "markdown-pymarkdown",
        "workflow-actionlint",
        "workflow-zizmor",
        "deepsource-inventory-tests",
        "lint step=rust-clippy delegated=tools/local_ci.py",
    ]

    FORBIDDEN_MARKERS = ["cmake-lint", "clang-format", "CppMode"]

    def setUp(self) -> None:
        """Initialize the per-test fixture state.

        Inputs: none (unittest fixture hook). Output: none; loads the
        artifact under test into `self.text` (or the suite's fixture fields).
        """
        self.text = (ROOT / "tools" / "lint.ps1").read_text(encoding="utf-8")

    def test_required_stages_present(self) -> None:
        """Required stages present."""
        for stage in self.REQUIRED_STAGES:
            self.assertIn(stage, self.text, f"missing stage: {stage}")

    def test_no_cmake_or_cpp_stages(self) -> None:
        """No cmake or cpp stages."""
        lowered = self.text.lower()
        for marker in self.FORBIDDEN_MARKERS:
            self.assertNotIn(marker.lower(), lowered, f"forbidden marker: {marker}")

    def test_python_scope(self) -> None:
        """Python scope."""
        # 2026-10-28: scope flipped to recursive globs - the previous shallow
        # forms (training/*.py, tools/*.py) left training/tests/ and
        # tools/contract/ unenforced in "All" lint mode.
        for pathspec in ("training/**/*.py", "tools/**/*.py", "tests/**/*.py"):
            self.assertIn(pathspec, self.text, f"python scope missing {pathspec}")
        for shallow in ('"training/*.py"', '"tools/*.py"'):
            self.assertNotIn(shallow, self.text, f"stale shallow scope present: {shallow}")

    def test_powershell_scope(self) -> None:
        """Powershell scope."""
        for pathspec in (
            "tools/*.ps1",
            "tools/*.psm1",
            "scripts/*.ps1",
            "scripts/*.psm1",
            "windows/**/*.ps1",
            "windows/**/*.psm1",
        ):
            self.assertIn(pathspec, self.text, f"powershell scope missing {pathspec}")

    def test_unittest_hook_targets(self) -> None:
        """Unittest hook targets."""
        self.assertIn("tools/deepsource_inventory.py", self.text)
        self.assertIn("tests.release.test_deepsource_inventory", self.text)


class TestLintWorkflow(unittest.TestCase):
    """.github/workflows/lint.yml must keep the hash-pinned supply chain."""

    def setUp(self) -> None:
        """Initialize the per-test fixture state.

        Inputs: none (unittest fixture hook). Output: none; loads the
        artifact under test into `self.text` (or the suite's fixture fields).
        """
        self.text = (ROOT / ".github" / "workflows" / "lint.yml").read_text(encoding="utf-8")

    def test_hash_pinned_requirements_install(self) -> None:
        """Hash pinned requirements install."""
        self.assertIn("requirements-lint-windows.txt", self.text)
        self.assertIn("--require-hashes", self.text)
        self.assertIn("--only-binary=:all:", self.text)

    def test_pinned_python_linter_actions(self) -> None:
        """Pinned python linter actions."""
        self.assertIn(
            "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
            self.text,
        )
        self.assertIn("windows-2022", self.text)
        self.assertIn("contents: read", self.text)
        self.assertIn("timeout-minutes: 30", self.text)

    def test_psscriptanalyzer_hash_pin(self) -> None:
        """Psscriptanalyzer hash pin."""
        self.assertIn("PSScriptAnalyzer", self.text)
        self.assertIn("1.25.0", self.text)
        self.assertIn(
            "14E634C828EB98EFB9F40B2918BA90F139ED5ECCDF663A2A747736D996995D60",
            self.text,
        )

    def test_actionlint_hash_pin(self) -> None:
        """Actionlint hash pin."""
        self.assertIn("actionlint", self.text)
        self.assertIn("1.7.12", self.text)
        self.assertIn(
            "6E7241B51E6817EA6A047693D8E6FED13B31819C9A0DD6C5A726E1592D22F6E9",
            self.text,
        )

    def test_event_based_modes(self) -> None:
        """Event based modes."""
        self.assertIn("workflow_dispatch", self.text)
        self.assertIn("schedule", self.text)
        self.assertIn("pull_request", self.text)
        self.assertIn("-LintMode All", self.text)
        self.assertIn("-LintMode Changed", self.text)
        self.assertIn("HEAD~1", self.text)
        self.assertIn("origin/", self.text)


class TestRequirementsFile(unittest.TestCase):
    """The hash-pinned requirements file must be structurally valid.

    Network use is skipped: instead of installing, assert the pin grammar and
    that every hash is a well-formed lowercase sha256 hex digest.
    """

    PIN_RE = re.compile(r"^([a-z0-9][a-z0-9._-]*)==([^\s\\]+) \\$")
    HASH_RE = re.compile(r"^    --hash=sha256:([0-9a-f]{64})( \\)?$")

    def setUp(self) -> None:
        """Initialize the per-test fixture state.

        Inputs: none (unittest fixture hook). Output: none; loads the
        artifact under test into `self.text` (or the suite's fixture fields).
        """
        self.text = REQ_FILE.read_text(encoding="utf-8")
        self.lines = self.text.splitlines()

    def test_header(self) -> None:
        """Header."""
        self.assertTrue(self.lines[0].startswith("--index-url https://"))
        self.assertIn("--only-binary :all:", self.lines[:3])

    def test_entries_are_well_formed(self) -> None:
        """Entries are well formed."""
        pins: dict[str, str] = {}
        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            if not line or line.startswith("--"):
                i += 1
                continue
            if line.startswith(" "):
                self.fail(f"unexpected line {i + 1}: {line!r}")
            match = self.PIN_RE.match(line)
            self.assertIsNotNone(match, f"bad pin line {i + 1}: {line!r}")
            assert match is not None
            pins[match.group(1)] = match.group(2)
            hash_count = 0
            i += 1
            while i < len(self.lines) and self.lines[i].startswith("    --hash="):
                hash_match = self.HASH_RE.match(self.lines[i])
                self.assertIsNotNone(hash_match, f"bad hash line {i + 1}: {self.lines[i]!r}")
                is_continued = self.lines[i].endswith("\\")
                hash_count += 1
                i += 1
                if not is_continued:
                    break
            self.assertGreaterEqual(hash_count, 1, f"no hashes for {match.group(1)}")
        self.assertGreaterEqual(len(pins), 1)

    def test_required_tool_pins(self) -> None:
        """Required tool pins."""
        self.assertIn("ruff==0.17.2", self.text)
        self.assertIn("pymarkdownlnt==0.9.41", self.text)
        self.assertIn("yamllint==1.38.0", self.text)
        self.assertIn("zizmor==1.31.1", self.text)

    def test_no_cpp_or_cmake_tools(self) -> None:
        """No cpp or cmake tools."""
        self.assertNotIn("clang-format", self.text)
        self.assertNotIn("cmakelang", self.text)

    def test_every_hash_is_lowercase_sha256_hex(self) -> None:
        """Every hash is lowercase sha256 hex."""
        hashes = re.findall(r"--hash=sha256:(\S+)", self.text)
        self.assertGreater(len(hashes), 0)
        for digest in hashes:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


class TestLintConfigsExist(unittest.TestCase):
    """Assert the pinned lint configuration files exist and keep their contracts.

    Inputs: none (unittest case). Output: assertions over the checked-in
    lint configuration set.
    """

    def test_yamllint_and_pymarkdown_configs(self) -> None:
        """Yamllint and pymarkdown configs."""
        yamllint = (ROOT / ".yamllint").read_text(encoding="utf-8")
        self.assertIn("extends: default", yamllint)
        self.assertIn("document-start: disable", yamllint)
        pymarkdown = (ROOT / ".pymarkdown.json").read_text(encoding="utf-8")
        self.assertIn("md013", pymarkdown)
        self.assertIn("front-matter", pymarkdown)


if __name__ == "__main__":
    unittest.main()
