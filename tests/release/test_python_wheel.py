"""Ordinary reproducible-wheel packaging and failed-build recovery contracts."""

from __future__ import annotations

import base64
import calendar
import csv
import hashlib
import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tools import python_wheel as packaging  # noqa: E402


class PureWheelPackagingTests(unittest.TestCase):
    """Keep packaging portable, byte-preserving and reusable after an invalid recipe."""

    def setUp(self):
        """Purpose: Own a tiny valid wheel. Inputs: Temporary directory. Outputs: Inert source and fresh destination."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "built.whl"
        self.output = self.root / "canonical.whl"
        self.prefix = "sample-1.2.3.dist-info/"
        self.files = {
            "sample/__init__.py": b"VALUE = 7\r\n",
            "sample/data,part.bin": bytes((0, 1, 127, 255)),
            self.prefix + "METADATA": b"Metadata-Version: 2.4\r\nName: sample\r\nVersion: 1.2.3\r\n\r\n",
            self.prefix + "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
            self.prefix + "licenses/LICENSE.txt": b"Test-owned licence bytes\r\n",
            self.prefix + "RECORD": b"source-generated record\n",
        }
        self.write_source(self.files)

    def write_source(self, files):
        """Purpose: Frame known valid inputs independently. Inputs: Literal members. Outputs: Small source ZIP."""
        with zipfile.ZipFile(self.source, "w") as archive:
            for name, payload in files.items():
                archive.writestr(zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0)), payload)

    def canonical(self, epoch, destination=None):
        """Purpose: Use the real shared producer. Inputs: Recipe epoch and owned path. Outputs: Canonical wheel."""
        packaging.canonical_wheel(
            self.source,
            self.output if destination is None else destination,
            {"version": "1.2.3", "source_date_epoch": epoch},
            project="sample",
        )

    def require_timestamp(self, expected, destination=None):
        """Purpose: Observe wire timestamps independently. Inputs: Literal tuple. Outputs: Every member matches."""
        with zipfile.ZipFile(self.output if destination is None else destination) as archive:
            self.assertGreater(len(archive.infolist()), 1)
            for member in archive.infolist():
                with self.subTest(member=member.filename):
                    self.assertEqual(member.date_time, expected)

    def test_epoch_before_zip_range_leaves_no_candidate(self):
        """Purpose: Reject an unsupported date before publication. Inputs: Last 1979 second. Outputs: No file."""
        with self.assertRaises(ValueError):
            self.canonical(calendar.timegm((1979, 12, 31, 23, 59, 59)))
        self.assertFalse(self.output.exists())

    def test_epoch_after_zip_range_leaves_no_candidate(self):
        """Purpose: Refuse an unrepresentable DOS year cleanly. Inputs: First 2108 second. Outputs: No file."""
        with self.assertRaises(ValueError):
            self.canonical(calendar.timegm((2108, 1, 1, 0, 0, 0)))
        self.assertFalse(self.output.exists())

    def test_both_zip_timestamp_endpoints_and_leap_day(self):
        """Purpose: Preserve legal endpoints and UTC calendar conversion. Inputs: Three dates. Outputs: Exact fields."""
        for index, expected in enumerate(
            ((1980, 1, 1, 0, 0, 0), (2000, 2, 29, 23, 59, 58), (2107, 12, 31, 23, 59, 58))
        ):
            with self.subTest(expected=expected):
                output = self.root / f"boundary-{index}.whl"
                self.canonical(calendar.timegm(expected), output)
                self.require_timestamp(expected, output)

    def test_zip_two_second_precision_is_explicit(self):
        """Purpose: Keep ZIP time precision. Inputs: Odd UTC second. Outputs: Its preceding even second."""
        self.canonical(calendar.timegm((1980, 1, 1, 0, 0, 1)))
        self.require_timestamp((1980, 1, 1, 0, 0, 0))

    def test_invalid_epoch_type_never_creates_a_candidate(self):
        """Purpose: Keep recipe integers strict. Inputs: Other scalar types. Outputs: Clean refusal."""
        for index, epoch in enumerate((True, False, 1704067200.0, "1704067200", None)):
            with self.subTest(epoch_type=type(epoch).__name__):
                output = self.root / f"invalid-type-{index}.whl"
                with self.assertRaises(ValueError):
                    self.canonical(epoch, output)
                self.assertFalse(output.exists())

    def test_unrepresentable_integral_epoch_is_a_clean_refusal(self):
        """Purpose: Bound calendar conversion without host exhaustion. Inputs: Huge integers. Outputs: No candidate."""
        for epoch in (-(1 << 100), 1 << 100):
            with self.subTest(negative=epoch < 0):
                with self.assertRaises(ValueError):
                    self.canonical(epoch)
                self.assertFalse(self.output.exists())

    def test_corrected_recipe_reuses_destination_after_refusal(self):
        """Purpose: Recover without deleting a stale wheel. Inputs: Invalid then valid recipe. Outputs: Valid reuse."""
        source = self.source.read_bytes()
        with self.assertRaises(ValueError):
            self.canonical(calendar.timegm((1979, 12, 31, 23, 59, 59)))
        self.assertFalse(self.output.exists())
        self.canonical(calendar.timegm((1980, 1, 1, 0, 0, 0)))
        self.require_timestamp((1980, 1, 1, 0, 0, 0))
        self.assertEqual(self.source.read_bytes(), source)

    def test_existing_candidate_and_source_bytes_are_preserved(self):
        """Purpose: Preserve owned existing outputs. Inputs: Normal existing candidate. Outputs: FileExistsError."""
        self.output.write_bytes(b"existing release candidate")
        source = self.source.read_bytes()
        with self.assertRaises(FileExistsError):
            self.canonical(1704067200)
        self.assertEqual(self.output.read_bytes(), b"existing release candidate")
        self.assertEqual(self.source.read_bytes(), source)

    def test_only_generated_metadata_line_endings_are_normalized(self):
        """Purpose: Preserve payload bytes. Inputs: CRLF files. Outputs: Only generated METADATA normalizes."""
        source = self.source.read_bytes()
        self.canonical(1704067200)
        with zipfile.ZipFile(self.output) as archive:
            for name, payload in self.files.items():
                if name.endswith("/RECORD"):
                    continue
                expected = payload.replace(b"\r\n", b"\n") if name.endswith("/METADATA") else payload
                with self.subTest(member=name):
                    self.assertEqual(archive.read(name), expected)
        self.assertEqual(self.source.read_bytes(), source)

    def test_record_retains_comma_filename_and_exact_binary_identity(self):
        """Purpose: Frame RECORD CSV correctly. Inputs: Comma member and binary bytes. Outputs: One exact entry."""
        self.canonical(1704067200)
        with zipfile.ZipFile(self.output) as archive:
            records = list(csv.reader(io.StringIO(archive.read(self.prefix + "RECORD").decode("utf-8"))))
        name = "sample/data,part.bin"
        expected = base64.urlsafe_b64encode(hashlib.sha256(self.files[name]).digest()).rstrip(b"=").decode("ascii")
        self.assertEqual([record for record in records if record[0] == name], [[name, "sha256=" + expected, "4"]])

    def test_canonical_members_use_portable_modes_order_and_storage(self):
        """Purpose: Keep output independent of host ZIP defaults. Inputs: Valid wheel. Outputs: Stable member fields."""
        self.canonical(1704067200)
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.namelist(), sorted(self.files))
            for member in archive.infolist():
                with self.subTest(member=member.filename):
                    self.assertEqual(member.create_system, 3)
                    self.assertEqual(member.external_attr >> 16, 0o100644)
                    self.assertEqual(member.compress_type, zipfile.ZIP_STORED)

    def test_explicit_source_directories_do_not_become_record_payloads(self):
        """Purpose: Keep directories implicit. Inputs: Empty source directories. Outputs: File members only."""
        self.write_source(self.files | {"sample/": b"", "sample/empty/": b""})
        self.canonical(1704067200)
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.namelist(), sorted(self.files))

    def test_unicode_member_name_and_payload_remain_byte_exact(self):
        """Purpose: Preserve portable Unicode resources. Inputs: One Greek filename. Outputs: Exact name and bytes."""
        name = "sample/resources/κείμενο.txt"
        payload = "Plain UTF-8 resource: κείμενο\r\n".encode()
        self.write_source(self.files | {name: payload})
        self.canonical(1704067200)
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.read(name), payload)

    def test_missing_parent_is_not_implicitly_created(self):
        """Purpose: Preserve caller directory ownership. Inputs: Absent destination parent. Outputs: No new tree."""
        output = self.root / "missing-parent" / "canonical.whl"
        source = self.source.read_bytes()
        with self.assertRaises(FileNotFoundError):
            self.canonical(1704067200, output)
        self.assertFalse(output.parent.exists())
        self.assertEqual(self.source.read_bytes(), source)

    def test_digest_and_sidecar_follow_actual_content_changes(self):
        """Purpose: Track actual bytes. Inputs: Fixed-size/mtime content changes. Outputs: Fresh hash and sidecar."""
        artifact = self.root / "artifact.bin"
        values = []
        original = None
        for payload in (b"abc", b"abd"):
            artifact.write_bytes(payload)
            if original is None:
                original = artifact.stat()
            else:
                os.utime(artifact, ns=(original.st_atime_ns, original.st_mtime_ns))
                self.assertEqual(artifact.stat().st_mtime_ns, original.st_mtime_ns)
                self.assertEqual(artifact.stat().st_size, original.st_size)
            expected = hashlib.sha256(payload).hexdigest()
            self.assertEqual(packaging.digest(artifact), expected)
            values.append(expected)
        self.assertNotEqual(*values)
        sidecar = self.root / "artifact.sha256"
        sidecar.write_text(values[-1] + "  artifact.bin\n", encoding="ascii")
        self.assertEqual(packaging.expected_digest(sidecar), values[-1])


if __name__ == "__main__":
    unittest.main()
