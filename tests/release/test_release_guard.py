"""Offline regression tests: no real GitHub calls, package signing or emails."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_guard", ROOT / "scripts/release_guard.py")
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
HEAD = "a" * 40
BASE = "b" * 40
REPO = "strmt7/rejection-rejector"
NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


def good_run(workflow="ci.yml", **changes):
    """Build one synthetic completed-success workflow run row."""
    value = dict(id=1, run_attempt=1, name={**gate.EXACT, **gate.DEEP}[workflow],
                 path=f".github/workflows/{workflow}", head_sha=HEAD, head_branch="main",
                 head_repository=REPO, event="push", status="completed", conclusion="success",
                 updated_at=NOW.isoformat())
    value.update(changes)
    return value


class ReleaseEvidenceTests(unittest.TestCase):
    """Every evidence acceptance boundary, offline and synthetic."""
    @staticmethod
    def test_exact_green_run_passes():
        """A green exact-commit run passes validation."""
        gate.validate_run(good_run(), "ci.yml", REPO, HEAD, NOW)

    def test_failed_cancelled_skipped_and_neutral_never_pass(self):
        """Non-success conclusions never pass, whatever the label."""
        for conclusion in ("failure", "cancelled", "skipped", "neutral", "timed_out", None):
            with self.subTest(conclusion=conclusion), self.assertRaises(gate.GateError):
                gate.validate_run(good_run(conclusion=conclusion), "ci.yml", REPO, HEAD, NOW)

    def test_running_run_is_pending_not_success(self):
        """An in-progress run is PendingEvidence, not success."""
        with self.assertRaises(gate.PendingEvidence):
            gate.validate_run(good_run(status="in_progress", conclusion=None), "ci.yml", REPO, HEAD, NOW)

    def test_identity_cannot_be_spoofed_with_a_workflow_name(self):
        """Spoofed path/branch/repo/event/id identities are rejected."""
        for field, value in (("path", ".github/workflows/fake.yml"), ("head_branch", "feature"),
                             ("head_repository", "attacker/fork"), ("event", "pull_request"),
                             ("id", True), ("run_attempt", 0), ("head_sha", "bad")):
            with self.subTest(field=field), self.assertRaises(gate.GateError):
                gate.validate_run(good_run(**{field: value}), "ci.yml", REPO, HEAD, NOW)

    def test_old_commit_cannot_satisfy_exact_gate(self):
        """Evidence from another commit cannot satisfy the exact gate."""
        with self.assertRaises(gate.GateError):
            gate.validate_run(good_run(head_sha=BASE), "ci.yml", REPO, HEAD, NOW)

    def test_bad_timestamps_fail_closed(self):
        """Missing, malformed, stale and future timestamps fail closed."""
        times = [None, "bad", "2026-10-08T00:00:00", (NOW - timedelta(days=9)).isoformat(),
                 (NOW + timedelta(hours=1)).isoformat()]
        for value in times:
            with self.subTest(value=value), self.assertRaises(gate.GateError):
                gate.validate_run(good_run(updated_at=value), "ci.yml", REPO, HEAD, NOW)

    def test_each_changed_build_input_invalidates_old_deep_evidence(self):
        """Any changed build/test input invalidates deep evidence."""
        paths = ["src/oauth.rs", "src/oauth/callback.rs", "tests/new_test.rs", "Cargo.lock", "build.rs",
                 "rust-toolchain.toml", ".cargo/config.toml", "windows/app.manifest",
                 "docs/openapi-v1.json", "scripts/release_guard.py", ".github/workflows/fuzz.yml"]
        for path in paths:
            def execute(args, path=path):
                """Return changed paths for every command except merge-base."""
                return "" if args[1] == "merge-base" else path + "\0"
            with self.subTest(path=path), self.assertRaises(gate.GateError):
                gate.assert_unchanged_inputs(BASE, HEAD, execute)

    @staticmethod
    def test_docs_only_ancestor_remains_usable():
        """Docs-only changes leave deep evidence usable."""
        def execute(args):
            """Return documentation-only changed paths."""
            return "" if args[1] == "merge-base" else "README.md\0docs/OPERATIONS.md\0"
        gate.assert_unchanged_inputs(BASE, HEAD, execute)

    def test_non_ancestor_is_rejected(self):
        """A non-ancestor comparison fails closed."""
        def execute(args):
            """Raise as if Git refused the comparison."""
            raise gate.GateError("not an ancestor")
        with self.assertRaises(gate.GateError):
            gate.assert_unchanged_inputs(BASE, HEAD, execute)

    def test_git_options_cannot_be_injected_as_commits(self):
        """Option-like revisions are rejected before any command runs."""
        with self.assertRaises(gate.GateError):
            gate.assert_unchanged_inputs("--output=owned", HEAD, lambda args: self.fail("executed git"))

    def test_workflow_scoped_query_never_filters_out_failures(self):
        """The run query is workflow-scoped and never filters to greens."""
        calls = []
        def execute(args):
            """Record the API call and return one failing run row."""
            calls.append(args)
            return json.dumps([good_run("fuzz.yml", conclusion="failure")])
        result = gate.latest_run(REPO, "fuzz.yml", HEAD, execute)
        self.assertEqual(result["conclusion"], "failure")
        endpoint = calls[0][2]
        self.assertIn("actions/workflows/fuzz.yml/runs?", endpoint)
        self.assertNotIn("status=success", endpoint)
        self.assertNotIn("head_sha=", endpoint)

    def test_missing_and_malformed_api_responses_fail_closed(self):
        """Missing or malformed API responses fail closed."""
        for raw in ("[]", "null", "{}", "[null]", "[{},{}]", "invalid"):
            with self.subTest(raw=raw), self.assertRaises(gate.GateError):
                gate.latest_run(REPO, "ci.yml", HEAD, lambda args, raw=raw: raw)

    def test_main_movement_is_detected(self):
        """A moved main ref is detected and rejected."""
        with self.assertRaises(gate.GateError):
            gate.check_main(REPO, HEAD, lambda args: HEAD if args[0] == "git" else BASE)

    def test_complete_evidence_is_bound_to_all_required_workflows(self):
        """Evidence covers all required workflows bound to the commit."""
        def execute(args):
            """Serve git and API answers from the synthetic fixture state."""
            if args[0] == "git":
                return HEAD if args[1] == "rev-parse" else ""
            if "/git/ref/" in args[2]:
                return HEAD
            workflow = args[2].split("/workflows/")[1].split("/")[0]
            return json.dumps([good_run(workflow)])
        report = gate.collect_evidence(REPO, HEAD, NOW, execute)
        self.assertEqual(len(report["automated_evidence"]), 12)
        self.assertIn("repository-integrity.yml", gate.EXACT)
        self.assertEqual(report["source_commit"], HEAD)
        self.assertIn("not established", report["owner_environment_acceptance"])

    def test_invalid_repository_never_runs_a_command(self):
        """An invalid repository name runs no command at all."""
        with self.assertRaises(gate.GateError):
            gate.collect_evidence("../attacker", HEAD, NOW, lambda args: self.fail("executed"))


    def test_native_command_failure_does_not_echo_private_output(self):
        """Command failures report the exit code, never private output."""
        command = [sys.executable, "-c", "import sys; print('PRIVATE_CANARY'); sys.exit(7)"]
        with self.assertRaises(gate.GateError) as caught:
            gate.checked_output(command)
        self.assertNotIn("PRIVATE_CANARY", str(caught.exception))
        self.assertIn("7", str(caught.exception))

    def test_checkout_encoding_config_invalidates_old_evidence(self):
        """Encoding-config changes invalidate deep evidence."""
        for path in (".gitattributes", ".gitignore", ".editorconfig"):
            self.assertTrue(gate.affects_evidence(path), path)

    def test_dirty_release_checkout_is_rejected_before_github_access(self):
        """Local source integrity is checked before any remote access."""
        calls = []
        def execute(args):
            """Answer rev-parse and fail the cleanliness diff."""
            calls.append(args)
            if args[:2] == ["git", "rev-parse"]:
                return HEAD
            if args[:2] == ["git", "diff"]:
                raise gate.GateError("modified tracked file")
            self.fail("Remote API must not run after local source integrity fails")
        with self.assertRaises(gate.GateError):
            gate.check_main(REPO, HEAD, execute)
        self.assertEqual(len(calls), 2)

    def test_no_baseline_skip_or_allow_failure_in_compatibility_workflow(self):
        """The compatibility workflow has no skip or allow-failure escapes."""
        text = (ROOT / ".github/workflows/semver.yml").read_text()
        baseline = (ROOT / ".cargo/semver-baseline.txt").read_text().strip()
        self.assertRegex(baseline, r"^[0-9a-f]{40}$")
        self.assertIn("fetch-depth: 0", text)
        self.assertIn('for baseline in "$stable" "$parent"', text)
        self.assertIn("all-features only-explicit-features", text)
        self.assertIn('git merge-base --is-ancestor "$stable" "$parent"', text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("|| true", text)

    def test_deep_triggers_cover_all_invalidation_inputs(self):
        """Deep workflow triggers cover every evidence-invalidating input."""
        required = {p + "**" for p in gate.INPUT_PREFIXES} | set(gate.INPUT_FILES)
        for workflow in gate.DEEP:
            text = (ROOT / ".github/workflows" / workflow).read_text()
            block = text.split("    paths:\n", 1)[1].split("  schedule:", 1)[0]
            paths = {json.loads(line.strip()[2:]) for line in block.splitlines() if line.strip()}
            with self.subTest(workflow=workflow):
                self.assertLessEqual(required, paths)

    def test_release_evidence_is_checked_again_before_upload(self):
        """Release evidence is rechecked immediately before upload."""
        text = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("fetch-depth: 0", text)
        self.assertEqual(text.count("python scripts/release_guard.py evidence"), 2)
        self.assertLess(text.index("Recheck release evidence"), text.index("Upload package and evidence"))
        self.assertIn("python scripts/release_guard.py audit", text)
        self.assertNotIn("cargo audit bin target/release", text)


class GitHistoryIntegrationTests(unittest.TestCase):
    """Real Git history comparisons on a synthetic repository."""
    def test_real_git_diff_distinguishes_docs_and_changed_source(self):
        """Real diffs separate docs-only changes from source changes."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def execute(args):
                """Run real Git in the synthetic repository."""
                result = subprocess.run(args, cwd=root, capture_output=True, text=True, check=False)
                if result.returncode:
                    raise gate.GateError("Synthetic Git comparison failed")
                return result.stdout
            execute(["git", "init", "--quiet"])
            execute(["git", "config", "user.name", "Synthetic Test"])
            execute(["git", "config", "user.email", "test@example.invalid"])
            (root / "README.md").write_text("Initial docs")
            execute(["git", "add", "."])
            execute(["git", "commit", "-qm", "baseline"])
            base = execute(["git", "rev-parse", "HEAD"]).strip()
            (root / "README.md").write_text("Revised docs")
            execute(["git", "add", "."])
            execute(["git", "commit", "-qm", "docs"])
            docs = execute(["git", "rev-parse", "HEAD"]).strip()
            gate.assert_unchanged_inputs(base, docs, execute)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text("// New source")
            execute(["git", "add", "."])
            execute(["git", "commit", "-qm", "source"])
            source = execute(["git", "rev-parse", "HEAD"]).strip()
            with self.assertRaises(gate.GateError):
                gate.assert_unchanged_inputs(base, source, execute)
            with self.assertRaises(gate.GateError):
                gate.assert_unchanged_inputs(source, base, execute)


class BinaryAuditTests(unittest.TestCase):
    """Per-executable audit semantics on synthetic binaries."""
    def setUp(self):
        """Create two synthetic release executables in a temp directory."""
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths = [self.root / "rejection-rejector.exe", self.root / "rr.exe"]
        for path in self.paths:
            path.write_bytes(b"synthetic")

    def test_first_failure_cannot_be_masked_by_second_success(self):
        """A first failure blocks release despite a second success."""
        calls = []
        def run(args, **kwargs):
            """Record the audit call and fail only the first invocation."""
            calls.append(args)
            return SimpleNamespace(returncode=1 if len(calls) == 1 else 0, stdout="audit failed", stderr="")
        with self.assertRaises(gate.GateError):
            gate.audit_binaries(self.paths, self.root / "out", run)
        self.assertEqual(len(calls), 1)
        self.assertEqual((self.root / "out/rejection-rejector-binary-audit.txt").read_text(), "audit failed")

    def test_second_failure_blocks_release(self):
        """A failing second audit blocks release too."""
        calls = []
        def run(args, **kwargs):
            """Record the audit call and fail from the second invocation."""
            calls.append(args)
            return SimpleNamespace(returncode=len(calls) - 1, stdout="result", stderr="")
        with self.assertRaises(gate.GateError):
            gate.audit_binaries(self.paths, self.root / "out", run)
        self.assertEqual(len(calls), 2)

    def test_success_requires_both_audits(self):
        """Both audits run with check=False and a bounded timeout."""
        calls = []
        def run(args, **kwargs):
            """Assert call options and report a clean audit."""
            calls.append(args)
            self.assertFalse(kwargs["check"])
            self.assertEqual(kwargs["timeout"], 300)
            return SimpleNamespace(returncode=0, stdout="clean", stderr="")
        gate.audit_binaries(self.paths, self.root / "out", run)
        self.assertEqual(len(calls), 2)

    def test_missing_binary_blocks_without_invoking_audit(self):
        """A missing binary blocks release before any audit runs."""
        self.paths[0].unlink()
        with self.assertRaises(gate.GateError):
            gate.audit_binaries(self.paths, self.root / "out", lambda *a, **kw: self.fail("executed"))

    def test_timeout_blocks_release(self):
        """A timed-out audit blocks release."""
        def run(args, **kwargs):
            """Raise the transport timeout the audit must survive."""
            raise subprocess.TimeoutExpired(args, 300)
        with self.assertRaises(gate.GateError):
            gate.audit_binaries(self.paths, self.root / "out", run)


if __name__ == "__main__":
    unittest.main()
