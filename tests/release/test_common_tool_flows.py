"""CLI-flow behavior contracts for the common-action tools.

Inputs: none (unittest). Output: pins tools/commit_wave.py operation
collection and dry-run/apply flow, and tools/ci_status.py lane verdicts —
both with fully scripted subprocess seams (no network, no git writes).

Why (coverage doctrine): these tools' main() flows are the exact paths
agents execute daily; their counting and refusal rules must fail tests
when they turn subtly wrong, not merely run.
"""

from __future__ import annotations

import io
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import ci_status  # noqa: E402
import commit_wave  # noqa: E402


class CollectOperationsTests(unittest.TestCase):
    """Pin git-status classification."""

    def test_mixed_porcelain_rows_classify(self):
        """Modified/untracked/deleted rows map to set/set/delete; cache
        artifacts skip; malformed rows refuse.
        """
        exists = lambda rel: rel != "gone.txt"  # noqa: E731
        rows = " M docs/a.md\n?? new.txt\n D gone.txt\n?? __pycache__/x.py\n?? bad\x00.md\n"
        with self.assertRaisesRegex(ValueError, "malformed"):
            commit_wave.collect_operations(rows, exists)
        rows = " M docs/a.md\n?? new.txt\n D gone.txt\n?? __pycache__/x.py\n\n"
        self.assertEqual(
            commit_wave.collect_operations(rows, exists),
            [("set", "docs/a.md"), ("set", "new.txt"), ("delete", "gone.txt")],
        )

    def test_control_character_rows_refuse_at_the_first_defense_line(self):
        """Why (the CRLF lesson): a control character that acts as a line
        break is split before classification, so the garbage row refuses at
        status validation; any other control character refuses at the
        well-formed check. Either way nothing is ever uploaded.
        """
        exists = lambda rel: True  # noqa: E731
        with self.assertRaisesRegex(ValueError, "unhandled status"):
            commit_wave.collect_operations("?? bad\rcr.md\n", exists)
        with self.assertRaisesRegex(ValueError, "malformed"):
            commit_wave.collect_operations("?? bad\x07x.md\n", exists)

    def test_deletion_of_present_file_refuses(self):
        """Why (never silently re-upload): a pending deletion whose file is
        still present cannot be expressed to the connector and must refuse.
        """
        with self.assertRaisesRegex(ValueError, "still present"):
            commit_wave.collect_operations(" D still/here.txt", lambda rel: True)


class CommitWaveMainTests(unittest.TestCase):
    """Pin the commit-wave CLI flow against a scripted git seam."""

    @staticmethod
    def _scripted(status: str, connector_result: tuple[int, str, str] = (0, "sha\n", "")):
        """Purpose: Build the mocked subprocess seam. Inputs: porcelain
        status text and the connector's (code, stdout, stderr); Output: the
        mock object for subprocess.run.
        """

        def runner(command, **kwargs):
            if "status" in command:
                return mock.Mock(stdout=status, stderr="", returncode=0)
            return mock.Mock(stdout=connector_result[1], stderr=connector_result[2], returncode=connector_result[0])

        return mock.Mock(side_effect=runner)

    def _run(self, status: str, *, dry_run: bool, connector_result=(0, "sha\n", "")) -> tuple[int, str]:
        """Purpose: Drive main() with the scripted seam. Inputs: status text,
        dry-run flag, connector result; Output: (exit code, captured stdout).
        """
        with tempfile.TemporaryDirectory() as owned:
            message = pathlib.Path(owned) / "msg.txt"
            message.write_text("subject\n", encoding="utf-8")
            argv = ["--message-file", str(message)]
            if dry_run:
                argv.append("--dry-run")
            with (
                mock.patch("sys.argv", ["commit_wave.py", *argv]),
                mock.patch.object(commit_wave, "shutil") as which_mock,
                mock.patch.object(commit_wave, "subprocess") as subprocess_mock,
                mock.patch.object(commit_wave, "ROOT", pathlib.Path(owned)),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                which_mock.which.return_value = "/usr/bin/git"
                subprocess_mock.run = self._scripted(status, connector_result)
                code = commit_wave.main()
        return code, out.getvalue()

    def test_dry_run_lists_without_committing(self):
        """Dry-run prints operations and never reaches the connector."""
        code, out = self._run(" M a.md\n D old.txt\n", dry_run=True)
        self.assertEqual(code, 0)
        self.assertIn("set    a.md", out)
        self.assertIn("delete old.txt", out)

    def test_clean_tree_short_circuits(self):
        """A clean tree reports and exits 0 without invoking the connector."""
        code, out = self._run("", dry_run=False)
        self.assertEqual(code, 0)
        self.assertIn("nothing to commit", out)

    def test_connector_exit_code_is_forwarded(self):
        """The wave's exit status is exactly the connector's."""
        code, _ = self._run(" M a.md\n", dry_run=False, connector_result=(2, "", "boom"))
        self.assertEqual(code, 2)


class CiStatusVerdictTests(unittest.TestCase):
    """Pin the CI lane counting rule."""

    def test_failure_masks_running(self):
        """Why (the counting rule): a red lane is verdict 1 even while other
        lanes run — never verdict 2, never masked.
        """
        rows = [
            {"workflowName": "a", "status": "completed", "conclusion": "failure"},
            {"workflowName": "b", "status": "in_progress", "conclusion": None},
        ]
        code, summary = ci_status.verdict(rows)
        self.assertEqual(code, 1)
        self.assertIn("1 red", summary)

    def test_all_green_is_zero_and_empty_is_running(self):
        """All-completed-green is 0; no rows yet is run-creation lag (2),
        never evidence of green.
        """
        green = [{"workflowName": "a", "status": "completed", "conclusion": "success"}]
        self.assertEqual(ci_status.verdict(green)[0], 0)
        self.assertEqual(ci_status.verdict([])[0], 2)

    def test_cancelled_and_timeout_count_as_red(self):
        """Cancelled and timed-out lanes are failures for the verdict."""
        for conclusion in ("cancelled", "timed_out"):
            rows = [{"workflowName": "a", "status": "completed", "conclusion": conclusion}]
            self.assertEqual(ci_status.verdict(rows)[0], 1)


if __name__ == "__main__":
    unittest.main()
