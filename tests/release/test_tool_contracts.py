"""Behavior contracts for previously untested operator tools.

Inputs: none (unittest). Output: pins the strict-JSON decoder, the native
executable resolver, the child-memory admission, the agent-context report
helpers and the NLTK installed-runtime measurement — the five tools/ modules
that had no direct test coverage before the tool-test-linkage doctrine test
existed.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import tools.child_containment as containment  # noqa: E402
import tools.json_input as json_input  # noqa: E402
import tools.nltk_distribution as nltk_distribution  # noqa: E402
from tools import agent_context  # noqa: E402
from tools import executable_path as executable  # noqa: E402


class StrictJsonTests(unittest.TestCase):
    """Pin the ambiguity-free JSON decoder."""

    def test_duplicate_keys_and_nonfinite_values_refused(self):
        """Why (evidence integrity): merged duplicate keys and NaN silently
        change meaning; the decoder must refuse both.
        """
        with self.assertRaisesRegex(ValueError, "duplicate"):
            json_input.decode_json('{"a": 1, "a": 2}')
        for text in ('{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}'):
            with self.assertRaises(ValueError):
                json_input.decode_json(text)

    def test_accepts_bytes_and_str(self):
        """Both caller-bounded input forms decode to equal values."""
        self.assertEqual(json_input.decode_json(b'{"a": [1, 2.5]}'), {"a": [1, 2.5]})
        self.assertEqual(json_input.decode_json('{"a": true}'), {"a": True})


class ExecutablePathTests(unittest.TestCase):
    """Pin the native-executable resolver."""

    def test_absolute_program_resolves(self):
        """An absolute existing executable resolves to itself."""
        resolved = executable.executable_path(sys.executable)
        self.assertEqual(Path(resolved), Path(sys.executable))

    def test_basename_resolves_only_through_absolute_path_dirs(self):
        """Why (process-startup safety): relative PATH entries must never be
        searched; only absolute directories are admitted.
        """
        program = Path(sys.executable).name
        directory = str(Path(sys.executable).parent)
        resolved = executable.executable_path(program, search_path=directory + os.pathsep + "relative-dir")
        self.assertEqual(Path(resolved).parent, Path(sys.executable).parent)

    def test_refuses_relative_paths_scripts_and_missing(self):
        """Relative subpaths, command scripts and unavailable names refuse."""
        for bad in ("./tool", "sub/tool", "", "..", "with\x00nul"):
            with self.assertRaises(ValueError):
                executable.executable_path(bad)
        with self.assertRaises(FileNotFoundError):
            executable.executable_path(
                "definitely-not-a-real-program-xyz", search_path=str(Path(sys.executable).parent)
            )


class ChildMemoryAdmissionTests(unittest.TestCase):
    """Pin the owned-child memory admission rules."""

    def test_requested_budget_validation(self):
        """Invalid requested budgets refuse before any launch."""
        for bad in (0, -1, 1.5, "1024"):
            with self.assertRaises(ValueError):
                containment.admit_child_memory_bytes(bad)
        if os.name == "nt":
            with self.assertRaisesRegex(ValueError, "exceeds"):
                containment.admit_child_memory_bytes(2**62)

    def test_platform_contract(self):
        """Windows admits a positive integer ceiling; other platforms fail
        closed before any child is launched.
        """
        if os.name == "nt":
            admitted = containment.admit_child_memory_bytes()
            self.assertIsInstance(admitted, int)
            self.assertGreater(admitted, 0)
        else:
            with self.assertRaises(RuntimeError):
                containment.admit_child_memory_bytes()


class AgentContextReportTests(unittest.TestCase):
    """Pin the refactored report helpers."""

    def test_json_pointer_and_member_shapes(self):
        """Exact pointers and bounded member expansion."""
        doc = {"a": {"b": [10, {"c": "x"}]}}
        self.assertEqual(agent_context.json_pointer(doc, "/a/b/1/c"), "x")
        member = agent_context.json_member("/a/b/0", 10)
        self.assertTrue(member["expanded"])
        self.assertEqual(member["value"], 10)

    def test_scalar_report_refuses_page_offset(self):
        """Why (bounded reporting): a scalar selection cannot page."""
        result = {"pointer": "/a"}
        with self.assertRaisesRegex(ValueError, "page offset"):
            agent_context._report_scalar(result, 7, type("Args", (), {"offset": 1, "max_chars": 1000})())

    def test_page_report_projection_and_budget(self):
        """Field projection requires object items and the page budget must
        fit at least one member.
        """
        args = type("Args", (), {"offset": 0, "limit": 2, "pointer": "/a", "max_chars": 10000})()
        report = agent_context._report_page({"pointer": "/a"}, [{"x": 1}, {"x": 2}], args, ["x"])
        self.assertEqual(len(report["items"]), 2)
        self.assertEqual(report["items"][0]["fields"][0]["value"], 1)
        with self.assertRaisesRegex(ValueError, "object array items"):
            agent_context._report_page({"pointer": "/a"}, [7], args, ["x"])
        tight = type("Args", (), {"offset": 0, "limit": 2, "pointer": "/a", "max_chars": 10})()
        with self.assertRaisesRegex(ValueError, "cannot fit one item"):
            agent_context._report_page({"pointer": "/a"}, [{"x": "y" * 50}], tight, [])


class NltkRuntimeMeasurementTests(unittest.TestCase):
    """Pin the installed-runtime measurement refusals."""

    def _tree(self, root: Path, name: str, content: bytes) -> Path:
        package = root / "nltk"
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_bytes(b"")
        (package / "VERSION").write_bytes(b"3.10.4")
        target = package / name
        target.write_bytes(content)
        return root

    def test_digest_is_stable_and_content_sensitive(self):
        """The measurement hashes admitted source; changing content changes
        the digest.
        """
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            a = nltk_distribution.installed_runtime_sha256(self._tree(Path(first), "m.py", b"x = 1"))
            b = nltk_distribution.installed_runtime_sha256(self._tree(Path(second), "m.py", b"x = 1"))
            c = nltk_distribution.installed_runtime_sha256(self._tree(Path(second), "m.py", b"x = 2"))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_native_images_and_unreviewed_bytecode_refuse(self):
        """Why (supply-chain admission): native images and sourceless
        bytecode are outside the reviewed source set and must refuse.
        """
        with tempfile.TemporaryDirectory() as owned, self.assertRaisesRegex(ValueError, "native executable"):
            nltk_distribution.installed_runtime_sha256(self._tree(Path(owned), "m.dll", b"MZ"))
        with tempfile.TemporaryDirectory() as owned, self.assertRaisesRegex(ValueError, "sourceless bytecode"):
            nltk_distribution.installed_runtime_sha256(self._tree(Path(owned), "m.pyo", b"\x00"))
        with tempfile.TemporaryDirectory() as owned, self.assertRaisesRegex(ValueError, "sourceless bytecode"):
            nltk_distribution.installed_runtime_sha256(self._tree(Path(owned), "m.pyc", b"\x00"))


if __name__ == "__main__":
    unittest.main()
