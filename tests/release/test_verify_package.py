"""Synthetic ZIPs only: never invoke an executable or a signing/provider service."""
import hashlib
import importlib.util
import json
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("verify_package", SCRIPTS / "verify_package.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
COMMIT = "a" * 40
OTHER = "b" * 40
STAMP = "2026-10-09T08:00:00+00:00"


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def checksum(value):
    return hashlib.sha256(value).hexdigest()


def fixture_files(signing="unsigned"):
    files = {name: b"Synthetic non-executable fixture\n" for name in verifier.REQUIRED - {"SHA256SUMS.txt"}}
    files["COMMIT.txt"] = (COMMIT + "\r\n").encode()
    files["Cargo.lock"] = b'version = 4\n'
    files["docs/openapi-v1.json"] = encoded({"openapi": "3.1.0"})
    files["docs/enterprise-policy.schema.json"] = encoded({"type": "object"})
    build = dict(schema_version=1, application_version="0.2.0", source_commit=COMMIT,
                 source_commit_verified=True, rustc_version="rustc 1.99.0 (synthetic)",
                 target="x86_64-pc-windows-msvc", profile="release",
                 cargo_lock_sha256=checksum(files["Cargo.lock"]))
    # Independently mirror Rust's explicitly ordered, length-prefixed identity.
    fields = [build[k].encode() for k in ("application_version", "source_commit", "rustc_version",
                                         "target", "profile", "cargo_lock_sha256")]
    identity = b"rejection-rejector-build-identity-v1\0" + b"".join(struct.pack("<Q", len(x)) + x for x in fields)
    build["identity_sha256"] = checksum(identity)
    files["build-info.json"] = encoded(build)
    files["contract-info.json"] = encoded(dict(
        schema_version=1, api_contract_sha256=checksum(files["docs/openapi-v1.json"]),
        enterprise_policy_schema_sha256=checksum(files["docs/enterprise-policy.schema.json"]),
        settings_format_version=2, database_schema_version=4, evaluation_suite_sha256="c" * 64))
    evidence = [dict(workflow=name, run_id=number, run_attempt=1, commit=COMMIT,
                     updated_at=STAMP, conclusion="success")
                for number, name in enumerate({**verifier.EXACT, **verifier.DEEP}, 1)]
    files["release-evidence.json"] = encoded(dict(
        schema_version=1, repository="strmt7/rejection-rejector", source_commit=COMMIT,
        checked_at=STAMP, automated_evidence=evidence))
    files["rejection-rejector.cdx.json"] = encoded({"bomFormat": "CycloneDX", "specVersion": "1.5"})
    signed = signing == "azure-artifact-signing"
    records = [dict(file=name, sha256=checksum(files[name]), requested_mode=signing,
                    status="Valid" if signed else "NotSigned",
                    signer_subject="CN=Synthetic Publisher" if signed else None,
                    signer_thumbprint="D" * 40 if signed else None,
                    timestamper_subject="CN=Synthetic Timestamp" if signed else None)
               for name in sorted(verifier.EXECUTABLES)]
    files["signing.json"] = encoded(dict(schema_version=1, requested_mode=signing,
                                         verified_signed=signed, files=records))
    return files


class PackageVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "package.zip"
        self.files = fixture_files()

    def write(self, manifest=None, extra=(), compression=zipfile.ZIP_DEFLATED):
        if manifest is None:
            manifest = "".join(f"{checksum(data)}  {name}\n" for name, data in sorted(self.files.items())).encode()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.path, "w", compression=compression) as archive:
                for name, data in self.files.items():
                    archive.writestr(name, data)
                archive.writestr("SHA256SUMS.txt", manifest)
                for name, data in extra:
                    archive.writestr(name, data)
        return self.path

    def verify(self, signing="unsigned", expected_hash=None):
        return verifier.verify(self.path, COMMIT, signing, expected_hash)

    def change(self, name, edit):
        value = json.loads(self.files[name])
        edit(value)
        self.files[name] = encoded(value)

    def test_valid_unsigned_archive_is_checked_without_extraction_or_execution(self):
        self.files["scripts/helper.py"] = b"raise RuntimeError('NEVER_EXECUTE')\n"
        self.write()
        before = self.path.read_bytes()
        report = self.verify(expected_hash=checksum(before))
        self.assertEqual(report["files_verified"], len(self.files))
        self.assertTrue(report["expected_archive_hash_matched"])
        self.assertFalse(report["authenticode_checked"])
        self.assertFalse(report["attestation_checked"])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_valid_signed_evidence_is_not_misreported_as_live_signature_verification(self):
        self.files = fixture_files("azure-artifact-signing")
        self.write()
        report = self.verify("azure-artifact-signing")
        self.assertFalse(report["authenticode_checked"])

    def test_wrong_expected_archive_hash_is_rejected(self):
        self.write()
        with self.assertRaises(verifier.PackageError):
            self.verify(expected_hash="0" * 64)

    def test_archive_and_member_count_limits(self):
        self.write()
        for attribute, limit in (("MAX_ARCHIVE", 8), ("MAX_ENTRIES", 1),
                                 ("MAX_MEMBER", 8), ("MAX_TOTAL", 8), ("MAX_DIRECTORY", 8)):
            with self.subTest(attribute=attribute), patch.object(verifier, attribute, limit):
                with self.assertRaises(verifier.PackageError):
                    self.verify()

    def test_metadata_limit_is_enforced(self):
        self.write()
        with patch.object(verifier, "MAX_METADATA", 8), self.assertRaises(verifier.PackageError):
            self.verify()

    def test_traversal_absolute_ads_device_and_backslash_paths_are_rejected(self):
        for name in ("../escape.txt", "/absolute.txt", "C:/drive.txt", "docs/a:stream.md",
                     "docs/CON.md", "docs/CON .md", "docs/LPT¹.md", "docs/CONOUT$.md",
                     "docs/evil. /x.md", "docs\\x.md", "docs//x.md", "docs/./x.md",
                     "docs/tab\tx.md", "docs/file.md "):
            with self.subTest(name=name):
                self.write(extra=((name, b"untrusted"),))
                with self.assertRaises(verifier.PackageError):
                    self.verify()

    def test_duplicate_and_case_aliases_fail(self):
        for name in ("README.md", "readme.MD", "DOCS/openapi-v1.json"):
            self.write(extra=((name, b"duplicate"),))
            with self.subTest(name=name), self.assertRaises(verifier.PackageError):
                self.verify()

    def test_file_directory_collision_fails(self):
        self.files["scripts/task.py"] = b"# stub\n"
        self.files["scripts/task.py/sub.py"] = b"# stub\n"
        self.write()
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_valid_explicit_directory_entry_is_permitted(self):
        self.write(extra=(("docs/", b""),))
        self.verify()

    def test_unexpected_executable_cache_or_secret_is_rejected_even_when_hashed(self):
        for name in ("unexpected.exe", "scripts/__pycache__/helper.pyc", "docs/.env", "docs/helper.exe"):
            original = self.files.copy()
            self.files[name] = b"unwanted"
            self.write()
            with self.subTest(name=name), self.assertRaises(verifier.PackageError):
                self.verify()
            self.files = original

    def test_symlink_archive_member_fails(self):
        link = zipfile.ZipInfo("docs/link.md")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write(extra=((link, b"README.md"),))
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_nonzero_directory_content_fails(self):
        self.write(extra=(("docs/", b"not empty"),))
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_missing_required_file_fails(self):
        self.files.pop("rr.exe")
        self.write()
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_manifest_requires_exact_file_set(self):
        base = "".join(f"{checksum(data)}  {name}\n" for name, data in sorted(self.files.items()))
        for manifest in (base + f"{'0' * 64}  missing.md\n",
                         "\n".join(base.splitlines()[1:]) + "\n",
                         base + f"{'0' * 64}  SHA256SUMS.txt\n",
                         base + base.splitlines()[0] + "\n"):
            self.write(manifest=manifest.encode())
            with self.assertRaises(verifier.PackageError):
                self.verify()

    def test_manifest_format_is_not_silently_normalized(self):
        for manifest in (b"", b"not a hash\n", b"\xff\n", ("0" * 64 + " *README.md\n").encode()):
            self.write(manifest=manifest)
            with self.assertRaises(verifier.PackageError):
                self.verify()

    def test_modified_member_cannot_be_hidden_by_valid_zip_crc(self):
        manifest = "".join(f"{checksum(data)}  {name}\n" for name, data in self.files.items()).encode()
        self.files["rr.exe"] = b"replacement"
        self.write(manifest=manifest)
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_checksum_rewrite_cannot_hide_inconsistent_signature_record(self):
        self.files["rr.exe"] = b"replacement"
        self.write()  # recompute every ZIP file checksum, but not signing evidence
        with self.assertRaisesRegex(verifier.PackageError, "Signature record"):
            self.verify()

    def test_build_identity_is_recomputed(self):
        self.change("build-info.json", lambda x: x.update(application_version="9.9.9"))
        self.write()
        with self.assertRaisesRegex(verifier.PackageError, "Build identity checksum"):
            self.verify()

    def test_wrong_commit_or_build_target_fails(self):
        for key, value in (("source_commit", OTHER), ("source_commit_verified", 1),
                           ("profile", "debug"), ("target", "x86_64-unknown-linux-gnu")):
            self.files = fixture_files()
            self.change("build-info.json", lambda x: x.update({key: value}))
            self.write()
            with self.subTest(key=key), self.assertRaises(verifier.PackageError):
                self.verify()

    def test_lockfile_and_contract_drift_fails(self):
        for path in ("Cargo.lock", "docs/openapi-v1.json", "docs/enterprise-policy.schema.json"):
            self.files = fixture_files()
            self.files[path] += b"\n"
            self.write()
            with self.subTest(path=path), self.assertRaises(verifier.PackageError):
                self.verify()

    def test_unsigned_only_accepts_notsigned(self):
        for status in ("Valid", "HashMismatch", "NotTrusted", "UnknownError",
                       "NotSupportedFileFormat", "Incompatible", "", None):
            self.files = fixture_files()
            self.change("signing.json", lambda x: x["files"][0].update(status=status))
            self.write()
            with self.subTest(status=status), self.assertRaises(verifier.PackageError):
                self.verify()

    def test_signed_requires_timestamp_and_publisher_evidence(self):
        for field in ("signer_subject", "signer_thumbprint", "timestamper_subject"):
            self.files = fixture_files("azure-artifact-signing")
            self.change("signing.json", lambda x: x["files"][0].update({field: None}))
            self.write()
            with self.subTest(field=field), self.assertRaises(verifier.PackageError):
                self.verify("azure-artifact-signing")

    def test_unsigned_rejects_inconsistent_certificate_metadata(self):
        self.change("signing.json", lambda x: x["files"][0].update(signer_subject="unexpected"))
        self.write()
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_missing_or_duplicate_signing_record_fails(self):
        for edit in (lambda x: x["files"].pop(), lambda x: x["files"].__setitem__(1, x["files"][0])):
            self.files = fixture_files()
            self.change("signing.json", edit)
            self.write()
            with self.assertRaises(verifier.PackageError):
                self.verify()

    def test_mode_mismatch_is_rejected(self):
        self.write()
        with self.assertRaises(verifier.PackageError):
            self.verify("azure-artifact-signing")

    def test_workflow_failure_missing_and_duplicate_evidence_fails(self):
        for edit in (lambda x: x["automated_evidence"].pop(),
                     lambda x: x["automated_evidence"][0].update(conclusion="cancelled"),
                     lambda x: x["automated_evidence"].__setitem__(1, x["automated_evidence"][0]),
                     lambda x: x["automated_evidence"][0].update(commit=OTHER),
                     lambda x: x["automated_evidence"][0].update(run_id=True),
                     lambda x: x.update(repository="attacker/fork")):
            self.files = fixture_files()
            self.change("release-evidence.json", edit)
            self.write()
            with self.assertRaises(verifier.PackageError):
                self.verify()

    def test_evidence_freshness_is_relative_to_packaging_not_verification_date(self):
        self.write()
        self.verify()  # Fixed historical date is intentionally acceptable.
        for stamp in ("2026-10-01T07:59:59Z", "2026-10-09T10:00:00Z", "invalid", "2026-10-09T08:00:00"):
            self.files = fixture_files()
            self.change("release-evidence.json", lambda x: x["automated_evidence"][0].update(updated_at=stamp))
            self.write()
            with self.subTest(stamp=stamp), self.assertRaises(verifier.PackageError):
                self.verify()

    def test_duplicate_keys_nonfinite_json_and_boolean_schema_fail(self):
        for content in (b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}',
                        b'{"schema_version":true}', b'[]', b'\xff'):
            self.files["contract-info.json"] = content
            self.write()
            with self.assertRaises(verifier.PackageError):
                self.verify()

    def test_powershell_utf8_bom_is_supported_for_generated_metadata(self):
        for name in verifier.METADATA:
            if name.endswith(".json"):
                self.files[name] = b"\xef\xbb\xbf" + self.files[name]
        self.write()
        self.verify()

    def test_nul_in_zip_filename_is_rejected(self):
        self.files["docs/nullX.md"] = b"test"
        self.write()
        raw = self.path.read_bytes().replace(b"docs/nullX.md", b"docs/null\0.md")
        self.path.write_bytes(raw)
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_trailing_garbage_and_missing_end_record_fail(self):
        self.write()
        good = self.path.read_bytes()
        for bad in (good + b"garbage", good[:-22], b"not a zip"):
            self.path.write_bytes(bad)
            with self.assertRaises(verifier.PackageError):
                self.verify()

    def test_zip_comment_is_allowed(self):
        self.write()
        with zipfile.ZipFile(self.path, "a") as archive:
            archive.comment = b"Synthetic package"
        self.verify()

    def test_forged_entry_count_rejected_before_zipfile_allocation(self):
        self.write()
        raw = bytearray(self.path.read_bytes())
        index = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", raw, index + 8, 65535, 65535)
        self.path.write_bytes(raw)
        with patch.object(verifier.zipfile, "ZipFile", side_effect=AssertionError("must not parse")):
            with self.assertRaises(verifier.PackageError):
                self.verify()

    def test_split_zip_is_rejected(self):
        self.write()
        raw = bytearray(self.path.read_bytes())
        index = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<H", raw, index + 4, 1)
        self.path.write_bytes(raw)
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_unsupported_compression_fails(self):
        self.write(compression=zipfile.ZIP_BZIP2)
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_encrypted_flag_fails(self):
        self.write()
        raw = bytearray(self.path.read_bytes())
        index = raw.find(b"PK\x01\x02")
        raw[index + 8] |= 1
        self.path.write_bytes(raw)
        with self.assertRaises(verifier.PackageError):
            self.verify()

    def test_cli_rejects_invalid_package_without_private_content_in_errors(self):
        self.files["build-info.json"] = b'{"PRIVATE_CANARY": '
        self.write()
        result = subprocess.run([sys.executable, str(SCRIPTS / "verify_package.py"), str(self.path),
                                 "--expected-commit", COMMIT, "--signing-mode", "unsigned"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("PRIVATE_CANARY", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_report_cannot_replace_the_input_zip(self):
        self.write()
        before = self.path.read_bytes()
        result = subprocess.run([sys.executable, str(SCRIPTS / "verify_package.py"), str(self.path),
                                 "--expected-commit", COMMIT, "--signing-mode", "unsigned",
                                 "--report", str(self.path)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.path.read_bytes(), before)


class WorkflowIntegrationTests(unittest.TestCase):
    def test_signature_status_is_fail_closed_and_digest_bound(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("$signature.Status -ne 'NotSigned'", workflow)
        self.assertNotIn("$signature.Status -eq 'Valid'", workflow)
        self.assertIn("-not $signature.TimeStamperCertificate", workflow)
        self.assertIn("sha256 = (Get-FileHash -LiteralPath $path", workflow)

    def test_only_tracked_scripts_and_docs_enter_package(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('git archive --format=zip "--output=$sourceArchive" HEAD -- docs scripts', workflow)
        self.assertNotIn("Copy-Item -Recurse scripts", workflow)
        self.assertNotIn("Copy-Item -Recurse docs", workflow)
        self.assertIn("Package staging directory must be fresh", workflow)

    def test_zip_verification_precedes_attestation_and_is_repeated_before_upload(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("python scripts/verify_package.py"), 2)
        self.assertLess(workflow.index("Verify final package contents"), workflow.index("Attest build provenance"))
        self.assertLess(workflow.index("Verify package bytes are unchanged"), workflow.index("Upload package and evidence"))
        self.assertIn("--expected-sha256 $report.archive_sha256", workflow)

    def test_operator_regressions_run_on_both_supported_ci_platforms(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("os: [ubuntu-latest, windows-latest]", workflow)
        self.assertIn("python -m unittest discover -s tests/release -v", workflow)


if __name__ == "__main__":
    unittest.main()
