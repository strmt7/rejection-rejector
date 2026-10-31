"""Behavior contracts for tools/nltk_distribution.py (upstream wheel admission).

Inputs: none (unittest). Output: pins the provenance-record validator,
the wheel admission checks (digest/size/redirect, METADATA/WHEEL/notices),
the installed-runtime gates (redirects, file kinds, byte budget), the
cache-resolved wheel path against hermetic fixture wheels, and the
installed-runtime verification guards.

Why (supply-chain doctrine): this module is the admission gate for a
third-party distribution; every refusal path must fail tests when it
turns subtly wrong, and the pinned record itself must stay valid.
"""

from __future__ import annotations

import copy
import hashlib
import os
import pathlib
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
import tools.nltk_distribution as nltk_distribution  # noqa: E402

FIXTURE_VERSION = "9.9.9"


def fixture_record(size: int, sha256: str) -> dict:
    """Purpose: Build a self-consistent provenance record.

    Inputs: `size`/`sha256` -- the fixture wheel's exact identity;
    Output: the full distribution record shape.
    """
    version = FIXTURE_VERSION
    tag = f"v{version}"
    filename = f"nltk-{version}-py3-none-any.whl"
    return {
        "schema": 1,
        "project": "nltk",
        "version": version,
        "tag": tag,
        "filename": filename,
        "release_url": f"https://github.com/nltk/nltk/releases/tag/{tag}",
        "url": f"https://github.com/nltk/nltk/releases/download/{tag}/{filename}",
        "release_kind": "stable",
        "license": "Apache-2.0",
        "license_member": f"nltk-{version}.dist-info/licenses/LICENSE.txt",
        "sha256": sha256,
        "size": size,
    }


def fixture_wheel(root: pathlib.Path, *, include_init: bool = True) -> pathlib.Path:
    """Purpose: Build a minimal NLTK-shaped wheel for admission tests.

    Inputs: `root` -- directory to build in; `include_init` -- whether the
    runtime source entry exists; Output: the wheel path.
    """
    version = FIXTURE_VERSION
    prefix = f"nltk-{version}.dist-info/"
    notices = b"Apache License text placeholder " * 8
    members = {
        prefix + "METADATA": f"Metadata-Version: 2.1\nName: nltk\nVersion: {version}\n\n".encode(),
        prefix + "WHEEL": b"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
        prefix + "licenses/LICENSE.txt": notices,
        prefix + "licenses/AUTHORS.md": notices,
        "nltk/VERSION": f"{version}\n".encode(),
    }
    if include_init:
        members["nltk/__init__.py"] = b"__version__ = '9.9.9'\n"
    path = root / f"nltk-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, contents in members.items():
            archive.writestr(name, contents)
    return path


def wheel_data(path: pathlib.Path) -> dict:
    """Purpose: Compute the matching record for a fixture wheel.

    Inputs: the wheel path; Output: the record with exact size and digest.
    """
    payload = path.read_bytes()
    return fixture_record(len(payload), hashlib.sha256(payload).hexdigest())


class DistributionRecordTests(unittest.TestCase):
    """Pin the tracked provenance record validator."""

    def test_pinned_record_is_valid(self):
        """The repository's tracked NLTK record validates (regression pin:
        the record is product input).
        """
        data = nltk_distribution.distribution()
        self.assertEqual(data["project"], "nltk")
        self.assertEqual(data["license"], "Apache-2.0")

    def test_field_mutations_refuse(self):
        """Every field is load-bearing: any single mutation refuses with the
        same fail-closed error.
        """
        good = nltk_distribution.distribution()
        mutations = [
            {"schema": 2},
            {"schema": "1"},
            {"project": "nltkx"},
            {"version": "3.10"},
            {"tag": "v0.0.1"},
            {"filename": "other.whl"},
            {"release_url": "https://example.invalid/tag"},
            {"url": "https://example.invalid/f"},
            {"release_kind": "nightly"},
            {"license": "MIT"},
            {"license_member": "x.txt"},
            {"sha256": "abc"},
            {"size": 0},
            {"size": -1},
            {"size": "10"},
        ]
        for mutation in mutations:
            changed = copy.deepcopy(good)
            changed.update(mutation)
            with (
                mock.patch.object(nltk_distribution, "read_recipe", return_value=changed),
                self.assertRaisesRegex(ValueError, "Unsupported NLTK upstream distribution record", msg=mutation),
            ):
                nltk_distribution.distribution()
        for broken in ([], {"version": 3, "tag": 5}):
            with (
                mock.patch.object(nltk_distribution, "read_recipe", return_value=broken),
                self.assertRaisesRegex(ValueError, "Unsupported NLTK upstream distribution record"),
            ):
                nltk_distribution.distribution()


class WheelAdmissionTests(unittest.TestCase):
    """Pin the wheel byte/metadata admission checks."""

    def test_admission_matrix(self):
        """Digest, size, redirect, METADATA/WHEEL and notice checks each
        refuse exactly their own failure; the pristine wheel verifies.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            wheel = fixture_wheel(root)
            data = wheel_data(wheel)
            self.assertEqual(nltk_distribution.verify_wheel(wheel, data), wheel)

            wrong_digest = {**data, "sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "digest or size mismatch"):
                nltk_distribution.verify_wheel(wheel, wrong_digest)
            wrong_size = {**data, "size": data["size"] + 1}
            with self.assertRaisesRegex(ValueError, "digest or size mismatch"):
                nltk_distribution.verify_wheel(wheel, wrong_size)

        bad_members = {
            "METADATA": f"Metadata-Version: 2.1\nName: not-nltk\nVersion: {FIXTURE_VERSION}\n\n",
            "WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\n",
            "VERSION": "1.2.3\n",
        }
        for member, contents in bad_members.items():
            with tempfile.TemporaryDirectory() as owned:
                root = pathlib.Path(owned)
                wheel = fixture_wheel(root)
                _rewrite_member(wheel, member, contents.encode())
                data = wheel_data(wheel)
                with self.assertRaisesRegex(ValueError, "metadata, runtime or original notices"):
                    nltk_distribution.verify_wheel(wheel, data)

    def test_redirect_admission_refuses(self):
        """A reparse-point (symlink) asset refuses before any hashing."""
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            wheel = fixture_wheel(root)
            data = wheel_data(wheel)
            link = root / "link.whl"
            try:
                link.symlink_to(wheel)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "redirected asset"):
                nltk_distribution.verify_wheel(link, data)


class InstalledGatesTests(unittest.TestCase):
    """Pin the installed-runtime admission gates."""

    def test_redirect_and_file_kind_gates(self):
        """Entry-count overflow and links refuse; native images and
        sourceless bytecode refuse; __pycache__ bytecode is tolerated.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            real = pathlib.Path(__file__)
            info = real.lstat()
            with self.assertRaisesRegex(ValueError, "exceeds admission"):
                nltk_distribution._reject_entry_redirect(10001, info)
            try:
                (root / "link").symlink_to(real)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "exceeds admission"):
                nltk_distribution._reject_entry_redirect(1, (root / "link").lstat())
        for suffix in (".pyd", ".so", ".DLL", ".dylib"):
            with self.assertRaisesRegex(ValueError, "native executable"):
                nltk_distribution._reject_file_kind(pathlib.Path(f"nltk/mod{suffix}"))
        with self.assertRaisesRegex(ValueError, "sourceless bytecode"):
            nltk_distribution._reject_file_kind(pathlib.Path("nltk/mod.pyo"))
        with self.assertRaisesRegex(ValueError, "sourceless bytecode"):
            nltk_distribution._reject_file_kind(pathlib.Path("nltk/mod.pyc"))
        nltk_distribution._reject_file_kind(pathlib.Path("nltk/__pycache__/mod.cpython-312.pyc"))
        nltk_distribution._reject_file_kind(pathlib.Path("nltk/mod.py"))

    def test_byte_budget_overflow_refuses(self):
        """Why (bounded measurement): the source byte budget is enforced
        during measurement, not after.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned) / "nltk"
            root.mkdir()
            (root / "VERSION").write_bytes(b"9.9.9\n")
            (root / "big.py").write_bytes(b"x" * 40)
            with (
                mock.patch.object(nltk_distribution, "MAX_SOURCE_BYTES", 10),
                self.assertRaisesRegex(ValueError, "byte budget"),
            ):
                nltk_distribution.installed_runtime_sha256(root.parent)


class CacheAndVerificationTests(unittest.TestCase):
    """Pin the cache-resolved wheel path and installed-runtime verification."""

    def test_wheel_path_cache_hit_is_hermetic(self):
        """With a fixture wheel already cached and the record patched to
        match, wheel_path verifies and returns without any download.
        """
        with tempfile.TemporaryDirectory() as owned:
            home = pathlib.Path(owned)
            wheel = fixture_wheel(home)
            data = wheel_data(wheel)
            directory = home / "wheels" / ("nltk-" + data["sha256"])
            directory.mkdir(parents=True)
            destination = directory / data["filename"]
            wheel.rename(destination)
            with (
                mock.patch.object(nltk_distribution, "distribution", return_value=data),
                mock.patch("tools.crawl4ai_tool.cache_home", return_value=home),
            ):
                resolved = nltk_distribution.wheel_path(home)
            self.assertEqual(resolved, destination)

    def test_wheel_path_refuses_redirected_cache(self):
        """A redirected cache directory refuses before any lock or IO."""
        with tempfile.TemporaryDirectory() as owned:
            home = pathlib.Path(owned)
            data = fixture_record(1, "0" * 64)
            wheels = home / "wheels"
            wheels.mkdir()
            try:
                (wheels / ("nltk-" + data["sha256"])).symlink_to(home, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with (
                mock.patch.object(nltk_distribution, "distribution", return_value=data),
                mock.patch("tools.crawl4ai_tool.cache_home", return_value=home),
                self.assertRaisesRegex(ValueError, "redirected"),
            ):
                nltk_distribution.wheel_path(home)

    def test_runtime_source_requires_complete_runtime(self):
        """A wheel without nltk/__init__.py refuses as incomplete."""
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            wheel = fixture_wheel(root, include_init=False)
            with (
                mock.patch.object(nltk_distribution, "wheel_path", return_value=wheel),
                self.assertRaisesRegex(ValueError, "incomplete"),
            ):
                nltk_distribution.runtime_source_sha256()

    def test_identity_is_deterministic(self):
        """The cache identity is a stable 64-hex digest of the pinned record."""
        first = nltk_distribution.identity()
        self.assertRegex(first, r"^[a-f0-9]{64}$")
        self.assertEqual(first, nltk_distribution.identity())

    def test_installed_runtime_verification_guards(self):
        """Malformed identity, non-filesystem providers and byte drift each
        refuse; a matching tree passes.
        """
        with self.assertRaisesRegex(ValueError, "Malformed"):
            nltk_distribution.verify_installed_runtime("abc")

        class BytesPath:
            """PathLike whose filesystem representation is not text."""

            def __init__(self):
                """Purpose: Hold the bytes representation. Inputs: none;
                Output: none.
                """
                self._representation = b"nltk"

            def __fspath__(self):
                """Purpose: Satisfy PathLike. Inputs: none; Output: the bytes
                filesystem representation.
                """
                return self._representation

        fake_distribution = mock.Mock()
        fake_distribution.locate_file.return_value = object()
        with (
            mock.patch("importlib.metadata.distribution", return_value=fake_distribution),
            self.assertRaisesRegex(ValueError, "filesystem installation"),
        ):
            nltk_distribution.verify_installed_runtime("0" * 64)
        fake_distribution.locate_file.return_value = BytesPath()
        with (
            mock.patch("importlib.metadata.distribution", return_value=fake_distribution),
            self.assertRaisesRegex(ValueError, "text filesystem path"),
        ):
            nltk_distribution.verify_installed_runtime("0" * 64)

        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned) / "nltk"
            root.mkdir()
            (root / "VERSION").write_bytes(b"9.9.9\n")
            (root / "__init__.py").write_bytes(b"x = 1\n")
            expected = nltk_distribution.installed_runtime_sha256(root.parent)
            fake_distribution.locate_file.return_value = root.parent
            with mock.patch("importlib.metadata.distribution", return_value=fake_distribution):
                nltk_distribution.verify_installed_runtime(expected)
                with self.assertRaisesRegex(ValueError, "changed"):
                    nltk_distribution.verify_installed_runtime("0" * 64)


def _rewrite_member(wheel: pathlib.Path, member_suffix: str, contents: bytes) -> None:
    """Purpose: Replace one wheel member in place for mutation tests.

    Inputs: the wheel path, the member-name suffix and the new bytes;
    Output: none (the zip is rewritten).
    """
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        blobs = {name: archive.read(name) for name in names}
    target = next(name for name in names if name.endswith(member_suffix))
    blobs[target] = contents
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, blob in blobs.items():
            archive.writestr(name, blob)


if __name__ == "__main__":
    unittest.main()
