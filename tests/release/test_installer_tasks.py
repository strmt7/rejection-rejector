"""Enforce the component-selectable installer contract.

The Windows installer must offer the two interface components (command-line
tools and the local web console) as independent, default-checked choices and
must refuse to continue with none selected. These tests pin that contract so
the installer cannot silently lose a component or the at-least-one rule.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISS = ROOT / "windows" / "installer.iss"


class InstallerTasksTest(unittest.TestCase):
    """The installer ships both surfaces with user-selectable ticks."""

    def setUp(self):
        """Load the installer script source once per test."""
        self.text = ISS.read_text(encoding="utf-8")

    def components_section(self):
        """Return the [Components] section body, failing when absent."""
        match = re.search(r"\[Components\](.*?)\n\[", self.text, re.S)
        self.assertIsNotNone(match, "missing [Components] section")
        return match.group(1)

    def test_two_interface_components_exist_and_are_user_selectable(self):
        """Both interface components exist and can be deselected."""
        section = self.components_section()
        for name in ('"cli"', '"web"'):
            self.assertIn(f"Name: {name};", section, f"missing component {name}")
        self.assertNotIn('"desktop"', section, "the removed desktop UI must stay gone")
        # Fixed components cannot be unticked; the requirement is ticks the
        # user can change, so no component may carry Flags: fixed.
        for line in section.splitlines():
            if line.startswith("Name:"):
                self.assertNotIn("Flags: fixed", line, f"component not deselectable: {line}")

    def test_all_components_are_selected_by_default(self):
        """Every component line is default-checked via Types: custom."""
        section = self.components_section()
        for line in section.splitlines():
            if line.startswith("Name:"):
                self.assertIn("Types: custom", line, f"not default-checked: {line}")

    def test_at_least_one_component_rule_is_present_and_enforced_before_install(self):
        """The NextButtonClick guard enforces at least one component."""
        self.assertIn("function NextButtonClick", self.text)
        self.assertIn("wpSelectComponents", self.text)
        self.assertIn("Select at least one component", self.text)
        self.assertRegex(
            self.text,
            r"WizardIsComponentSelected\('cli'\)",
            "the at-least-one rule must enumerate the cli component",
        )
        self.assertRegex(
            self.text,
            r"WizardIsComponentSelected\('web'\)",
            "the at-least-one rule must enumerate the web component",
        )

    def test_least_privilege_posture_holds(self):
        """The installer stays lowest-privilege and launches nothing."""
        self.assertIn("PrivilegesRequired=lowest", self.text)
        self.assertRegex(self.text, r"\[Run\]\s*\n; Nothing", "install time must launch nothing")
        self.assertIn('Source: "{#SourceDir}\\rr.exe"', self.text)
        self.assertIn('Source: "..\LICENSE"', self.text)


if __name__ == "__main__":
    unittest.main()
