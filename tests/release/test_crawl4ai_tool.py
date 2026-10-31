"""Behavior contracts for tools/crawl4ai_tool.py (provisioning and runner).

Inputs: none (unittest). Output: pins cache scoping, child-process
ownership (real owned children plus the output/overflow budgets), the
advisory-lock mechanics, atomic receipt publication, the provision
receipt short-circuit/contract-drift flow, the interpreter version gate
and the CLI dispatch/exit mapping.

Why (supply-chain doctrine): this module owns every third-party install;
its admission, containment and refusal rules must fail tests when they
turn subtly wrong.
"""

from __future__ import annotations

import errno
import io
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
import tools.crawl4ai_tool as crawl4ai_tool  # noqa: E402


class CacheHomeTests(unittest.TestCase):
    """Pin portable cache scoping."""

    def test_override_and_env_resolution(self):
        """Explicit and environment overrides resolve absolute; relative
        and in-checkout homes refuse.
        """
        external = (pathlib.Path.cwd().parent / "elsewhere-x").resolve()
        self.assertEqual(crawl4ai_tool.cache_home(str(external)), external)
        with self.assertRaisesRegex(ValueError, "absolute"):
            crawl4ai_tool.cache_home("relative/path")
        env_home = str(pathlib.Path(tempfile.gettempdir()) / "env-home")
        with mock.patch.dict(os.environ, {"FLITZZIP_CRAWL4AI_HOME": env_home}):
            self.assertTrue(str(crawl4ai_tool.cache_home()).endswith("env-home"))
        with self.assertRaisesRegex(ValueError, "outside the source checkout"):
            crawl4ai_tool.cache_home(str(crawl4ai_tool.ROOT))

    def test_text_identity_normalizes_line_endings(self):
        """Why (Git's portable text identity): CRLF and LF bytes of the same
        text hash identically.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            crlf = root / "crlf.txt"
            lf = root / "lf.txt"
            crlf.write_bytes(b"a\r\nb\r\n")
            lf.write_bytes(b"a\nb\n")
            self.assertEqual(crawl4ai_tool.text_identity(crlf), crawl4ai_tool.text_identity(lf))

    def test_tool_environment_scopes_child_writes(self):
        """Telemetry off, caches scoped to the tool home, UTF-8 forced."""
        home = pathlib.Path(tempfile.gettempdir()) / "tool-home"
        env = crawl4ai_tool.tool_environment(home)
        self.assertEqual(env["PLAYWRIGHT_BROWSERS_PATH"], str(home / "browsers"))
        self.assertEqual(env["CRAWL4AI_BASE_DIRECTORY"], str(home / "data"))
        self.assertEqual(env["DO_NOT_TRACK"], "1")
        self.assertEqual(env["HF_HUB_DISABLE_TELEMETRY"], "1")
        self.assertEqual(env["PYTHONNOUSERSITE"], "1")


class OutputBudgetTests(unittest.TestCase):
    """Pin the bounded setup-output capture."""

    def test_tail_is_bounded_and_overflow_trips(self):
        """The tail keeps at most 8 KiB; crossing 4 MiB sets the overflow
        event instead of buffering unboundedly.
        """
        tail = bytearray()
        overflow = threading.Event()
        crawl4ai_tool.retain_setup_output(io.BytesIO(b"x" * 20000), tail, overflow)
        self.assertEqual(len(tail), 8192)
        self.assertFalse(overflow.is_set())
        big = io.BytesIO(b"y" * (5 * 1024 * 1024))
        crawl4ai_tool.retain_setup_output(big, bytearray(), overflow)
        self.assertTrue(overflow.is_set())

    def test_finish_output_failure_and_overflow_rules(self):
        """Failed children dump their tail to stderr; overflow without
        failure raises AFTER reporting; a failed overflow only reports.
        """
        stream = io.BytesIO(b"diag")
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            crawl4ai_tool._finish_setup_output(stream, bytearray(b"boom"), threading.Event(), True)
        self.assertIn("boom", err.getvalue())
        overflow = threading.Event()
        overflow.set()
        with self.assertRaisesRegex(ValueError, "output budget"):
            crawl4ai_tool._finish_setup_output(io.BytesIO(), bytearray(), overflow, False)
        crawl4ai_tool._finish_setup_output(io.BytesIO(), bytearray(b"x"), overflow, True)


class OwnedChildTests(unittest.TestCase):
    """Pin owned-child execution with real processes."""

    def test_success_and_failure_exit_codes(self):
        """Owned children return their exact exit codes; a quiet successful
        child completes without diagnostics.
        """
        env = dict(os.environ)
        self.assertEqual(crawl4ai_tool.run_owned([sys.executable, "-c", "print('ok')"], env, 60, quiet=True), 0)
        self.assertEqual(crawl4ai_tool.run_owned([sys.executable, "-c", "raise SystemExit(3)"], env, 60, quiet=True), 3)

    def test_timeout_reaps_the_child(self):
        """An owned child that exceeds its deadline raises TimeoutExpired
        and is reaped (the finally path leaves nothing running).
        """
        sleeper = [sys.executable, "-c", "import time; time.sleep(30)"]
        with self.assertRaises(subprocess.TimeoutExpired):
            crawl4ai_tool.run_owned(sleeper, dict(os.environ), 0.3, quiet=True)

    def test_run_requires_success(self):
        """run() is the requiring wrapper: zero passes, nonzero raises
        CalledProcessError; run_source_python refuses an empty command.
        """
        env = dict(os.environ)
        self.assertIsNone(crawl4ai_tool.run([sys.executable, "-c", "pass"], env, 60))
        with self.assertRaises(subprocess.CalledProcessError):
            crawl4ai_tool.run([sys.executable, "-c", "raise SystemExit(4)"], env, 60)
        with self.assertRaisesRegex(ValueError, "interpreter command"):
            crawl4ai_tool.run_source_python([], env, 60)


class LockMechanicsTests(unittest.TestCase):
    """Pin advisory-lock contention rules."""

    def test_lock_contended_classification(self):
        """Only ownership conflicts are retryable: Windows sharing codes
        and the POSIX EACCES/EAGAIN/EDEADLK family.
        """
        windows = OSError(1, "sharing")
        windows.winerror = 32
        self.assertTrue(crawl4ai_tool.lock_contended(windows))
        for code in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
            self.assertTrue(crawl4ai_tool.lock_contended(OSError(code, "busy")))
        self.assertFalse(crawl4ai_tool.lock_contended(OSError(errno.ENOENT, "missing")))

    def test_retry_and_deadline_rules(self):
        """Retryable contention retries until success; non-retryable errors
        propagate immediately; an expired deadline raises TimeoutError.
        """
        attempts = []

        def flaky():
            """Purpose: Fail twice with contention, then succeed. Inputs:
            none; Output: the success marker.
            """
            attempts.append(1)
            if len(attempts) < 3:
                raise OSError(errno.EACCES, "busy")
            return "held"

        self.assertEqual(crawl4ai_tool._retry_cache_lock(flaky, deadline=threading.TIMEOUT_MAX), "held")
        self.assertEqual(len(attempts), 3)

        def fatal():
            """Purpose: Raise a non-retryable error. Inputs: none; Output:
            never (raises OSError).
            """
            raise OSError(errno.ENOENT, "x")

        with self.assertRaises(OSError):
            crawl4ai_tool._retry_cache_lock(fatal, deadline=threading.TIMEOUT_MAX)
        with self.assertRaises(TimeoutError):
            crawl4ai_tool._retry_cache_lock(lambda: (_ for _ in ()).throw(OSError(errno.EACCES, "busy")), deadline=-1.0)

    def test_installation_lock_roundtrip_and_refusals(self):
        """The lock serializes, auto-creates its directory, refuses
        redirected directories, and a second acquisition times out.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            directory = root / "cache"
            with crawl4ai_tool.installation_lock(directory, timeout=30):
                self.assertTrue((directory / ".install.lock").is_file())
            with crawl4ai_tool.installation_lock(directory, timeout=30):
                pass
            with (
                crawl4ai_tool.installation_lock(directory, timeout=0.2),
                self.assertRaises(TimeoutError),
                crawl4ai_tool.installation_lock(directory, timeout=0.2),
            ):
                pass
            link = root / "link"
            try:
                link.symlink_to(directory, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with (
                self.assertRaisesRegex(ValueError, "missing, special or redirected"),
                crawl4ai_tool.installation_lock(link, timeout=1),
            ):
                pass


class ReceiptAndProvisionTests(unittest.TestCase):
    """Pin atomic receipt publication and the provision short-circuit."""

    def test_receipt_publishes_atomically(self):
        """Receipts land as exact compact JSON; a failed replace leaves no
        staging litter behind.
        """
        with tempfile.TemporaryDirectory() as owned:
            receipt = pathlib.Path(owned) / "install.json"
            crawl4ai_tool.write_install_receipt(receipt, {"schema": 1, "v": 2})
            self.assertEqual(json.loads(receipt.read_text(encoding="utf-8")), {"schema": 1, "v": 2})
            with mock.patch("os.replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
                crawl4ai_tool.write_install_receipt(receipt, {"schema": 1, "v": 3})
            self.assertEqual(list(pathlib.Path(owned).glob("*.tmp")), [])

    @staticmethod
    def _receipt(directory: pathlib.Path, **overrides) -> dict:
        """Purpose: Build a matching provision receipt. Inputs: the env
        directory and field overrides; Output: the written receipt dict.
        """
        record = {
            "schema": 1,
            "version": crawl4ai_tool.VERSION,
            "lock_sha256": "identity-1",
            "platform": platform.system(),
            "model_contract_sha256": crawl4ai_tool.text_identity(
                crawl4ai_tool.ROOT / "tests/integration/test_nltk_model_security.py"
            ),
            "download_contract_sha256": crawl4ai_tool.text_identity(
                crawl4ai_tool.ROOT / "tests/integration/test_crawl4ai_downloads.py"
            ),
        }
        record.update(overrides)
        (directory / "flitzzip-install.json").write_text(json.dumps(record), encoding="utf-8")
        return record

    def test_provision_short_circuit_and_contract_drift(self):
        """A matching receipt verifies and returns without installing; a
        drifted model contract re-runs exactly that contract and re-stamps
        the receipt.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            home = root / "home"
            directory = root / "env"
            directory.mkdir()
            python = directory / "python.exe"
            python.touch()
            self._receipt(directory)
            with (
                mock.patch.object(crawl4ai_tool, "verify_versions") as verify,
                mock.patch.object(crawl4ai_tool, "run") as run_mock,
            ):
                result = crawl4ai_tool.provision(home, directory, python, "identity-1")
            self.assertEqual(result, python)
            verify.assert_called_once()
            run_mock.assert_not_called()

        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            directory = root / "env"
            directory.mkdir()
            python = directory / "python.exe"
            python.touch()
            self._receipt(directory, model_contract_sha256="0" * 64)
            with (
                mock.patch.object(crawl4ai_tool, "verify_versions"),
                mock.patch.object(crawl4ai_tool, "run") as run_mock,
            ):
                crawl4ai_tool.provision(root / "home", directory, python, "identity-1")
            self.assertEqual(run_mock.call_count, 1)
            self.assertIn("test_nltk_model_security", " ".join(run_mock.call_args.args[0]))
            updated = json.loads((directory / "flitzzip-install.json").read_text(encoding="utf-8"))
            self.assertNotEqual(updated["model_contract_sha256"], "0" * 64)


class GateAndDispatchTests(unittest.TestCase):
    """Pin the interpreter gate and CLI dispatch."""

    def test_install_refuses_unqualified_python(self):
        """Only the qualified CPython range is admitted."""
        with (
            mock.patch.object(sys, "version_info", (3, 12, 0)),
            self.assertRaisesRegex(ValueError, "3.13 or 3.14"),
        ):
            crawl4ai_tool.install(pathlib.Path(tempfile.gettempdir()))

    def test_argument_guards_and_dispatch_shapes(self):
        """Extra arguments to install/check-lock/selftest refuse at the
        parser; crawl forwards its remainder to the crawler CLI; the other
        commands route to the research tool.
        """
        for argv in (
            ["crawl4ai_tool.py", "install", "extra"],
            ["crawl4ai_tool.py", "check-lock", "extra"],
            ["crawl4ai_tool.py", "selftest", "extra"],
        ):
            with mock.patch("sys.argv", argv), self.assertRaises(SystemExit):
                crawl4ai_tool.main()

        fake_python = pathlib.Path("python")
        cases = {
            "crawl": ["-m", "crawl4ai.cli", "crawl", "--url", "x"],
            "qualify": ["-m", "tools.crawl4ai_research", "qualify"],
            "doctor": ["-m", "tools.crawl4ai_research", "doctor"],
        }
        for command, tail in cases.items():
            with (
                mock.patch("sys.argv", ["crawl4ai_tool.py", command, *tail[3:]]),
                mock.patch.object(crawl4ai_tool, "install", return_value=fake_python),
                mock.patch.object(crawl4ai_tool, "run") as run_mock,
                mock.patch.object(crawl4ai_tool, "run_source_python", return_value=0) as source_mock,
            ):
                self.assertEqual(crawl4ai_tool.main(), 0)
            self.assertEqual(source_mock.call_args.args[0], [str(fake_python), *tail])
            if command == "crawl":
                run_mock.assert_not_called()
            if command == "doctor":
                self.assertIn("pip", run_mock.call_args.args[0])

    def test_entrypoint_maps_expected_failures(self):
        """Expected failures print one diagnostic and exit 1."""
        with (
            mock.patch.object(crawl4ai_tool, "main", side_effect=ValueError("bad")),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
            self.assertRaises(SystemExit) as raised,
        ):
            crawl4ai_tool._entrypoint()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("crawl4ai: bad", err.getvalue())


if __name__ == "__main__":
    unittest.main()
