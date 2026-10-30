"""Repository integrity: advisory suppressions can never return.

Why: the owner-set findings policy (docs/deepsource-dispositions.md) bans
every suppression construct — scanner ignores, false-positive dispositions,
dismissals. A suppression that slips back into a config file would silently
convert a security gate to green while findings stay hidden (the exact
defect security review finding 12 removed). This test makes the construct
itself a repository defect, independent of any scanner.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Suppression constructs and the tracked files that could carry them.
BANNED = (
    (re.compile(r"^\s*ignore\s*=\s*\["), "deny.toml advisory ignore array"),
    (re.compile(r"\[\[IgnoredVulns\]\]"), "osv-scanner suppressed advisory block"),
    (re.compile(r'"\s*--ignore\s+RUSTSEC'), "cargo-audit command-line ignore"),
    (re.compile(r"ignoreUntil"), "osv-scanner ignoreUntil suppression window"),
)
FILES = (
    "deny.toml",
    "osv-scanner.toml",
    "engineering.toml",
)


class NoAdvisorySuppressions(unittest.TestCase):
    """Every tracked policy file must be free of suppression constructs."""

    def test_no_suppression_constructs_in_policy_files(self):
        """No policy file may carry an advisory suppression construct."""
        for name in FILES:
            path = ROOT / name
            text = path.read_text(encoding="utf-8")
            for pattern, label in BANNED:
                matches = pattern.findall(text)
                self.assertEqual(
                    matches,
                    [],
                    f"{name} contains a banned suppression construct ({label})",
                )

    def test_no_suppression_constructs_anywhere_in_tracked_configs(self):
        """A suppression dropped into any tracked config is a repository defect.

        The scan covers every git-tracked TOML/YAML/JSON policy surface so a
        new scanner integration cannot reintroduce an ignore quietly.
        """
        import subprocess

        pattern = re.compile(r"IgnoredVulns|--ignore\s+RUSTSEC|ignoreUntil")
        tracked = subprocess.run(
            ["git", "ls-files", "*.toml", "*.yaml", "*.yml", "*.json", "*.py"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=True,
        ).stdout.splitlines()
        offenders = []
        for name in tracked:
            path = ROOT / name
            if not path.exists():
                # Tracked but deleted on disk: a pending deletion that the
                # next commit removes from the index. Nothing to scan.
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if pattern.search(text):
                offenders.append(name)
        self.assertEqual(
            offenders,
            [],
            f"suppression constructs found in tracked configs: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()
