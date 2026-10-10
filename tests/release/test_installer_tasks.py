"""Enforce the component-selectable installer contract.

The Windows installer must offer the three interface components as
independent, default-checked choices and must refuse to continue with none
selected. These tests pin that contract so the installer cannot silently
lose a component or the at-least-one rule.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISS = ROOT / "windows" / "installer.iss"


class InstallerTasksTest(unittest.TestCase):
    """The installer ships all three surfaces with user-selectable ticks."""

    def setUp(self):
        self.text = ISS.read_text(encoding="utf-8")

    def components_section(self):
        match = re.search(r"\[Components\](.*?)\n\[", self.text, re.S)
        self.assertIsNotNone(match, "missing [Components] section")
        return match.group(1)

    def test_three_interface_components_exist_and_are_user_selectable(self):
        section = self.components_section()
        for name in ('"desktop"', '"cli"', '"web"'):
            self.assertIn(f"Name: {name};", section, f"missing component {name}")
        # Fixed components cannot be unticked; the requirement is ticks the
        # user can change, so no component may carry Flags: fixed.
        for line in section.splitlines():
            if line.startswith("Name:"):
                self.assertNotIn("Flags: fixed", line, f"component not deselectable: {line}")

    def test_all_components_are_selected_by_default(self):
        section = self.components_section()
        for line in section.splitlines():
            if line.startswith("Name:"):
                self.assertIn("Types: custom", line, f"not default-checked: {line}")

    def test_at_least_one_component_rule_is_present_and_enforced_before_install(self):
        self.assertIn("function NextButtonClick", self.text)
        self.assertIn("wpSelectComponents", self.text)
        self.assertIn("Select at least one component", self.text)
        self.assertRegex(
            self.text,
            r"WizardIsComponentSelected\('desktop'\)",
            "the at-least-one rule must enumerate the desktop component",
        )

    def test_least_privilege_posture_holds(self):
        self.assertIn("PrivilegesRequired=lowest", self.text)
        self.assertRegex(self.text, r"\[Run\]\s*\n; Nothing", "install time must launch nothing")
        self.assertIn('Source: "{#SourceDir}\\rejection-rejector.exe"', self.text)
        self.assertIn('Source: "{#SourceDir}\\rr.exe"', self.text)


if __name__ == "__main__":
    unittest.main()
