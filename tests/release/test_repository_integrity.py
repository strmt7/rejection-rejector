"""Repository integrity regressions; synthetic Git history only."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repository_integrity", ROOT / "scripts/repository_integrity.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class TextChecks(unittest.TestCase):
    def errors(self, name, content):
        return {f["code"] for f in audit.inspect_text(name, content) if f["severity"] == "error"}

    def test_mixed_utf16_append_is_rejected(self):
        content = b'[toolchain]\nchannel = "1.99.0"\n' + "# Version\r\n".encode("utf-16-le")
        self.assertIn("nul_bytes_or_utf16_fragment", self.errors("rust-toolchain.toml", content))

    def test_boms_and_invalid_utf8_are_rejected(self):
        for content in (b"\xef\xbb\xbf# docs\n", "# docs".encode("utf-16"), b"\xffbad\n"):
            with self.subTest(content=content):
                self.assertTrue(self.errors("README.md", content))

    def test_greek_utf8_is_not_a_false_positive(self):
        self.assertEqual(self.errors("README.md", "# Εφαρμογή\n".encode()), set())

    def test_control_characters_are_not_hidden_by_valid_utf8(self):
        self.assertIn("unescaped_control_character", self.errors("README.md", b"command\x08roken\n"))
        self.assertIn("bare_carriage_return", self.errors("README.md", b"command\rbroken\n"))

    def test_crlf_is_visible_but_not_confused_with_corruption(self):
        findings = audit.inspect_text("README.md", b"# Valid\r\n")
        self.assertEqual(findings, [{"path": "README.md", "code": "noncanonical_crlf", "severity": "warning"}])

    def test_structured_files_must_parse(self):
        for name, content in (("Cargo.toml", b"[broken\n"), ("config.json", b'{"x":1,"x":2}\n'),
                              ("config.json", b'{"x":NaN}\n'), ("script.py", b"def f(:\n")):
            with self.subTest(name=name):
                self.assertIn("invalid_structured_text", self.errors(name, content))

    def test_valid_structured_text(self):
        for name, content in (("Cargo.toml", b'[package]\nname="example"\n'),
                              ("config.json", b'{"x":1}\n'), ("script.py", b"x = 1\n")):
            self.assertFalse(self.errors(name, content))

    def test_commit_padding_is_not_documentation(self):
        self.assertIn("commit_count_padding", self.errors("README.md", b"# Title\n# Commit 818\n"))
        self.assertFalse(self.errors("README.md", b"Review commit 818 in the incident record.\n"))

    def test_finding_does_not_echo_file_contents(self):
        findings = audit.inspect_text("config.json", b'{"token":"PRIVATE_CANARY"\n')
        self.assertNotIn("PRIVATE_CANARY", json.dumps(findings))

    def test_binary_assets_are_not_decoded_as_source(self):
        self.assertFalse(audit.is_text("windows/icon.ico"))
        self.assertFalse(audit.is_text("screenshots/gui.png"))
        self.assertTrue(audit.is_text(".gitattributes"))
        self.assertTrue(audit.is_text("windows/app.manifest"))


class HistoryChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        audit.git(self.root, "init", "-q")
        audit.git(self.root, "config", "user.name", "Synthetic Audit Test")
        audit.git(self.root, "config", "user.email", "test@example.invalid")
        (self.root / "README.md").write_text("# Baseline\n")
        self.commit("baseline")
        (self.root / "rust-toolchain.toml").write_bytes(b'[toolchain]\nchannel="1.99.0"\n#\0 bad\n')
        self.commit("docs: add toolchain note")
        audit.git(self.root, "commit", "--allow-empty", "-qm", "empty counter commit")

    def commit(self, subject):
        audit.git(self.root, "add", ".")
        audit.git(self.root, "commit", "-qm", subject)

    def test_exact_tree_is_checked_even_when_worktree_was_repaired(self):
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel="1.99.0"\n')
        findings, count = audit.inspect_tree(self.root, audit.resolve(self.root, "HEAD"))
        self.assertEqual(count, 2)
        self.assertTrue(any(f["code"] == "nul_bytes_or_utf16_fragment" for f in findings))

    def test_history_keeps_empty_and_documentation_changes(self):
        rows = audit.audit_history(self.root, "HEAD", 3)
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[0]["empty_change"])
        self.assertEqual(rows[1]["changed_files"][0]["path"], "rust-toolchain.toml")
        self.assertEqual(rows[0]["parents"], [rows[1]["commit"]])

    def test_commit_body_preserves_evidence_of_padding(self):
        audit.git(self.root, "commit", "--allow-empty", "-qm", "test: fixture\n\nAdded only for commit counting.")
        record = audit.audit_history(self.root, "HEAD", 1)[0]
        self.assertIn("Added only", record["message"])
        self.assertTrue(record["commit_count_language"])

    def test_incomplete_history_does_not_claim_a_complete_audit(self):
        with self.assertRaises(audit.AuditError):
            audit.audit_history(self.root, "HEAD", 100)

    def test_option_injection_and_unbounded_requests_are_rejected(self):
        with self.assertRaises(audit.AuditError):
            audit.resolve(self.root, "--output=owned")
        for count in (0, -1, 101):
            with self.assertRaises(audit.AuditError):
                audit.audit_history(self.root, "HEAD", count)

    def test_cli_retains_report_patch_and_source_even_on_integrity_failure(self):
        out = self.root / "artifacts"
        result = subprocess.run([sys.executable, str(ROOT / "scripts/repository_integrity.py"),
                                 "--root", str(self.root), "--history-count", "3", "--report", str(out / "audit.json"),
                                 "--patch-file", str(out / "history.patch"), "--snapshot-file", str(out / "source.zip"), "--bundle-file", str(out / "history.bundle")],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads((out / "audit.json").read_text())
        self.assertEqual(report["history_count"], 3)
        self.assertEqual(len(report["snapshot_sha256"]), 64)
        self.assertTrue((out / "history.patch").is_file())
        self.assertTrue((out / "source.zip").is_file())
        audit.git(self.root, "bundle", "verify", str(out / "history.bundle"))
        self.assertEqual(len(report["bundle_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
