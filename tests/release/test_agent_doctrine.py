"""Deterministic enforcement of the agent-doctrine invariants.

Inputs: none (unittest). Output: pins the AGENTS.md size ceiling, the
no-leakage rule, and the tool-test linkage rule as executable checks —
prompt prose is not enforcement, so the enforcable doctrines live here.

Why (research-backed doctrine, 2026-10-31): instruction files decay in
adherence with size, self-reports of compliance are unreliable, and untested
tools are dead weight. These tests make the three mechanical rules
unbreakable.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

# Every email-shaped token in the tracked tree is reviewed once and pinned
# by digest: any addition (a new fixture) or removal changes the set and
# fails this test, forcing a conscious re-review — the moment where a real
# identifier would be caught. The current set is 2,166 synthetic fixture
# addresses (RFC 2606 reserved domains, platform noreply identity, test
# corpora in training/data/).
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
REVIEWED_TOKEN_SET_SHA256 = "bad2301f6ad6d52e6416229ab122b04007e34184970982c0c77094d21ae1d27c"


class AgentFileDoctrineTests(unittest.TestCase):
    """Pin the AGENTS.md structural invariants."""

    def test_agents_md_stays_at_the_instruction_budget(self):
        """Why (instruction decay): always-on instruction files dilute
        adherence per line; the documented ceiling is 200 lines and the file
        carries judgment only.
        """
        lines = (REPO / "AGENTS.md").read_text(encoding="utf-8").splitlines()
        self.assertLessEqual(
            len(lines),
            200,
            f"AGENTS.md is {len(lines)} lines; move derivable content to docs/ or skills",
        )

    def test_email_token_set_is_the_reviewed_set(self):
        """Why (owner rule: no account leakage on GitHub): the exact set of
        email-shaped tokens in the tracked tree is pinned by digest. A new
        token (fixture or otherwise) fails here and must be reviewed before
        the pin is updated — that review is the leakage checkpoint.
        """
        git = shutil.which("git")
        self.assertIsNotNone(git, "git is required for the tracked-file scan")
        listing = subprocess.run(
            [git, "ls-files"],
            capture_output=True,
            text=True,
            cwd=str(REPO),
            check=True,
        ).stdout.splitlines()
        tokens = set()
        for rel in listing:
            path = REPO / rel
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, ValueError, OSError):
                continue
            tokens.update(match.group(0) for match in EMAIL_PATTERN.finditer(text))
        digest = hashlib.sha256("\n".join(sorted(tokens)).encode("utf-8")).hexdigest()
        self.assertEqual(
            digest,
            REVIEWED_TOKEN_SET_SHA256,
            "email-shaped token set changed; review every new token for "
            "account leakage before updating REVIEWED_TOKEN_SET_SHA256",
        )


class ToolTestLinkageTests(unittest.TestCase):
    """Pin the anti-dead-tool rule."""

    def test_every_tool_module_is_tested(self):
        """Why (tool-call economy doctrine): a tool with no test rots and
        gets re-derived; every tools/*.py must be referenced by name in at
        least one test module (ambient or integration layer).
        """
        tools = sorted(p.stem for p in (REPO / "tools").glob("*.py") if p.stem != "__init__")
        corpus = ""
        for layer in ("tests/release", "tests/integration"):
            directory = REPO / layer
            if directory.is_dir():
                for test in directory.glob("*.py"):
                    corpus += test.read_text(encoding="utf-8")
        untested = [name for name in tools if name not in corpus]
        self.assertEqual(untested, [], f"tools/ modules with no test reference: {untested}")


if __name__ == "__main__":
    unittest.main()
