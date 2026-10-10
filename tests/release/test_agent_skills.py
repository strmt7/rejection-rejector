"""Offline enforcement for the repository agent-skill contracts."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILLS = ROOT / ".agents" / "skills"

REQUIRED = {
    "caveman": ["Compression rules", "Never remove"],
    "cocoindex-code-search": ["rg", "Never change code from a semantic hit"],
    "crawl4ai-research": ["scanner-secret-reviews-crawl4ai.json", "untrusted"],
}


class AgentSkillsTest(unittest.TestCase):
    """The three badge-backed skills must exist, carry discipline, and be routed."""

    def test_required_skills_exist_with_frontmatter(self):
        for name in REQUIRED:
            path = SKILLS / name / "SKILL.md"
            self.assertTrue(path.is_file(), f"missing skill {name}")
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\n"), f"{name}: frontmatter missing")
            head = text.split("---\n", 2)[1]
            self.assertIn("name:", head)
            self.assertIn("description:", head)

    def test_required_discipline_markers_present(self):
        for name, markers in REQUIRED.items():
            text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
            for marker in markers:
                self.assertIn(marker, text, f"{name}: missing marker {marker!r}")

    def test_agents_md_references_every_skill(self):
        guide = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for name in REQUIRED:
            self.assertIn(name, guide, f"AGENTS.md must reference {name}")

    def test_secret_review_ledger_is_valid(self):
        path = ROOT / ".github" / "scanner-secret-reviews-crawl4ai.json"
        ledger = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(ledger["schema"], 1)
        self.assertIsInstance(ledger["reviews"], list)


if __name__ == "__main__":
    unittest.main()
