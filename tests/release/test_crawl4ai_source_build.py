"""Source acquisition, source-delta and security contracts for the portable Crawl4AI build."""

from __future__ import annotations

import hashlib
import io
import os
import sys
import tarfile
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tools import crawl4ai_download_opener as opener  # noqa: E402
from tools import crawl4ai_source_build as build  # noqa: E402


class SourceContracts(unittest.TestCase):
    """Verify exact original provenance, narrow source changes and the real platform opener."""

    def test_source_acquisition_is_exact_and_reused_outside_checkout(self):
        """Purpose: Pin cache reuse outside Git. Inputs: Source bytes and cache. Outputs: Exact file."""
        payload = b"pinned source fixture"
        digest = hashlib.sha256(payload).hexdigest()
        data = build.recipe() | {"source_bytes": len(payload)}
        with tempfile.TemporaryDirectory() as owned:
            home = Path(owned)
            with (
                patch.object(build, "recipe", return_value=data),
                patch.object(build.packaging, "expected_digest", return_value=digest),
                patch.object(build.urllib.request, "urlopen", return_value=io.BytesIO(payload)) as download,
            ):
                archive = build.source_archive(home)
                self.assertEqual(archive.read_bytes(), payload)
                self.assertEqual(build.source_archive(home), archive)
                download.assert_called_once()
            self.assertNotIn(build.ROOT, archive.parents)

    def test_source_acquisition_refuses_incomplete_excess_and_changed_cache(self):
        """Purpose: Refuse bad transport and cache bytes. Inputs: Bad source. Outputs: No admitted file."""
        digest = hashlib.sha256(b"expected").hexdigest()
        data = build.recipe() | {"source_bytes": len(b"expected")}
        with tempfile.TemporaryDirectory() as owned:
            home = Path(owned)
            for payload in (b"short", b"too many bytes", b"badbytes"):
                with (
                    self.subTest(payload=payload),
                    patch.object(build, "recipe", return_value=data),
                    patch.object(build.packaging, "expected_digest", return_value=digest),
                    patch.object(build.urllib.request, "urlopen", return_value=io.BytesIO(payload)),
                    self.assertRaises(ValueError),
                ):
                    build.source_archive(home)
                self.assertFalse((home / "source" / digest / data["source"]).exists())
                self.assertEqual(list((home / "source" / digest).glob("*.part")), [])
            cache = home / "source" / digest / data["source"]
            cache.write_bytes(b"badbytes")
            with (
                patch.object(build, "recipe", return_value=data),
                patch.object(build.packaging, "expected_digest", return_value=digest),
                patch.object(build.urllib.request, "urlopen") as download,
                self.assertRaisesRegex(ValueError, "cached source differs"),
            ):
                build.source_archive(home)
            download.assert_not_called()

    def test_source_repair_preserves_all_other_runtime_files_and_original_license(self):
        """Purpose: Bound the repair delta. Inputs: Actual source/recipe. Outputs: Exact unaffected source/notices."""
        data = build.recipe()
        with tempfile.TemporaryDirectory() as owned:
            source = build.extract_source(build.source_archive(), Path(owned) / "source")
            before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
            build.repair_source(source, data)
            changed = {
                Path("crawl4ai/async_crawler_strategy.py"),
                Path("crawl4ai/__version__.py"),
                Path("pyproject.toml"),
            }
            for path, contents in before.items():
                if path not in changed:
                    self.assertEqual((source / path).read_bytes(), contents)
            original_license = (build.ROOT / "docs/licenses/Crawl4AI-0.9.5.txt").read_text(encoding="utf-8")
            self.assertEqual((source / "LICENSE").read_text(encoding="utf-8"), original_license)
            notice = (source / "FLITZZIP_BUILD_NOTICE.txt").read_text()
            self.assertIn("downstream build", notice)
            self.assertIn("UncleCode", notice)
            self.assertEqual((source / "crawl4ai/flitzzip_download.py").read_text(), build.OPENER.read_text())
            for path, expected in build.runtime_hashes().items():
                self.assertEqual(build.packaging.digest(source / path), expected)
            with self.assertRaisesRegex(ValueError, "requires renewed review"):
                build.repair_source(source, data)

    def test_tampered_artifacts_and_unknown_source_refused(self):
        """Purpose: Refuse substituted source. Inputs: Wrong digest and changed opener. Outputs: Errors."""
        with (
            patch.object(build.packaging, "expected_digest", side_effect=ValueError("bad digest")),
            self.assertRaisesRegex(ValueError, "bad digest"),
        ):
            build.recipe()
        with tempfile.TemporaryDirectory() as owned:
            root = Path(owned)
            (root / "crawl4ai").mkdir()
            (root / "crawl4ai/async_crawler_strategy.py").write_text("# changed upstream boundary\n")
            with self.assertRaisesRegex(ValueError, "requires renewed review"):
                build.repair_source(root, build.recipe())
        original = '    safe_name = os.path.basename(filename or "")\n    return os.open(path, flags | os.O_NOFOLLOW)'
        for changed in (original.replace("safe_name =", "renamed ="), original + original):
            with self.subTest(source=changed), self.assertRaisesRegex(ValueError, "requires renewed review"):
                build.patched_strategy(changed)

    def test_recipe_and_identity_bind_every_build_input(self):
        """Purpose: Bind all provenance and repair inputs.
        Inputs: Actual recipe and semantic mutations. Outputs: Stable identity/refusal.
        """
        data = build.recipe()
        self.assertEqual(len(build.identity()), 64)
        variants = (
            data | {"source_url": "https://example.invalid/crawl4ai.tar.gz"},
            data | {"source_bytes": data["source_bytes"] + 1},
            data | {"source_date_epoch": data["source_date_epoch"] + 1},
            data | {"unreviewed": True},
        )
        for variant in variants:
            with (
                self.subTest(variant=variant),
                patch.object(build.packaging, "read_recipe", return_value=variant),
                self.assertRaisesRegex(ValueError, "Unsupported Crawl4AI"),
            ):
                build.recipe()

    def test_extraction_rejects_traversal_links_duplicates_and_size_before_writing(self):
        """Purpose: Protect owned extraction. Inputs: Hostile synthetic tar members. Outputs: No published payload."""
        with tempfile.TemporaryDirectory() as owned:
            root = Path(owned)
            for index, name in enumerate(("crawl4ai-0.9.5/../escape", "/absolute", "crawl4ai-0.9.5/name:stream")):
                archive = root / f"bad-{index}.tar.gz"
                with tarfile.open(archive, "w:gz") as output:
                    first = tarfile.TarInfo("crawl4ai-0.9.5/valid")
                    first.size = 1
                    output.addfile(first, io.BytesIO(b"x"))
                    bad = tarfile.TarInfo(name)
                    output.addfile(bad)
                destination = root / f"destination-{index}"
                with self.assertRaises(ValueError):
                    build.extract_source(archive, destination)
                self.assertFalse(destination.exists())
            for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                archive = root / "link.tar.gz"
                with tarfile.open(archive, "w:gz") as output:
                    item = tarfile.TarInfo("crawl4ai-0.9.5/link")
                    item.type = kind
                    item.linkname = "../outside"
                    output.addfile(item)
                with self.assertRaises(ValueError):
                    build.extract_source(archive, root / "link-destination")

            archive = root / "bounded.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                item = tarfile.TarInfo("crawl4ai-0.9.5/payload")
                item.size = 1
                output.addfile(item, io.BytesIO(b"x"))
            with patch.object(build.packaging, "MAX_SOURCE_BYTES", 0), self.assertRaisesRegex(ValueError, "extent"):
                build.extract_source(archive, root / "bounded-destination")
            occupied = root / "occupied"
            occupied.mkdir()
            with self.assertRaisesRegex(ValueError, "destination must be new"):
                build.extract_source(archive, occupied)

    def test_patch_contracts_and_license_failure_leave_source_unchanged(self):
        """Purpose: Refuse upstream drift before source mutation.
        Inputs: Changed contracts/version/license. Outputs: Error and unchanged tree.
        """
        strategy = '    safe_name = os.path.basename(filename or "")\n    return os.open(path, flags | os.O_NOFOLLOW)\n'
        with self.assertRaisesRegex(ValueError, "download contract changed"):
            build.patched_strategy(strategy)
        with self.assertRaisesRegex(ValueError, "version changed"):
            build.patched_version('__version__ = "9.9.9"', "1.0")
        data = build.recipe()
        with tempfile.TemporaryDirectory() as owned:
            source = build.extract_source(build.source_archive(), Path(owned) / "source")
            before = {path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()}
            config = source / "pyproject.toml"
            config.write_text(
                config.read_text(encoding="utf-8").replace('license = "Apache-2.0"', 'license = "MIT"'),
                encoding="utf-8",
            )
            before[config.relative_to(source)] = config.read_bytes()
            with self.assertRaisesRegex(ValueError, "license packaging changed"):
                build.repair_source(source, data)
            after = {path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()}
            self.assertEqual(after, before)

    def test_build_wheel_uses_owned_builder_and_canonical_output(self):
        """Purpose: Exercise offline wheel orchestration.
        Inputs: Owned cache and inert build doubles. Outputs: Exact commands/environment/output.
        """
        data = build.recipe()
        with tempfile.TemporaryDirectory() as owned:
            root = Path(owned)
            home, output = root / "home", root / "wheels"
            commands = []

            def create_builder(directory):
                python = Path(directory) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                python.parent.mkdir(parents=True)
                python.write_bytes(b"inert interpreter fixture")

            def extract(_archive, destination):
                destination.mkdir(parents=True)
                return destination

            def canonical(_built, destination, _data, *, project):
                self.assertEqual(project, "crawl4ai")
                destination.write_bytes(b"canonical wheel")

            with (
                patch("tools.crawl4ai_tool.text_identity", return_value="a" * 64),
                patch("tools.crawl4ai_tool.tool_environment", return_value={"BASE": "1"}),
                patch("tools.crawl4ai_tool.installation_lock", side_effect=lambda _path: nullcontext()),
                patch(
                    "tools.crawl4ai_tool.run",
                    side_effect=lambda command, env, *args: commands.append((command, dict(env), args)),
                ),
                patch.object(build.venv, "EnvBuilder") as builder,
                patch.object(build, "source_archive", return_value=root / "verified-source.tar.gz"),
                patch.object(build, "extract_source", side_effect=extract),
                patch.object(build, "repair_source") as repair,
                patch.object(build.packaging, "canonical_wheel", side_effect=canonical) as package,
            ):
                builder.return_value.create.side_effect = create_builder
                wheel = build.build_wheel(home, output, data)
            self.assertEqual(wheel.read_bytes(), b"canonical wheel")
            builder.assert_called_once_with(with_pip=True)
            self.assertEqual(repair.call_count, 1)
            self.assertEqual(package.call_count, 1)
            self.assertEqual(len(commands), 3)
            self.assertIn("--require-hashes", commands[0][0])
            self.assertEqual(commands[1][0][-2:], ["pip", "check"])
            self.assertIn("--no-build-isolation", commands[2][0])
            for _command, env, _args in commands:
                self.assertEqual(env["BASE"], "1")
                self.assertEqual(env["SOURCE_DATE_EPOCH"], str(data["source_date_epoch"]))
                self.assertEqual(env["PYTHONHASHSEED"], "0")

    def test_ensure_wheel_reuses_or_builds_only_exact_artifact(self):
        """Purpose: Enforce cache identity.
        Inputs: Missing, exact and changed cached wheels. Outputs: Build/reuse/refusal.
        """
        data = build.recipe()
        with tempfile.TemporaryDirectory() as owned:
            home = Path(owned)
            directory = home / ("crawl4ai-wheel-" + "b" * 16)
            wheel = directory / f"crawl4ai-{data['version']}-py3-none-any.whl"
            expected = "c" * 64
            common = (
                patch.object(build, "recipe", return_value=data),
                patch.object(build, "identity", return_value="b" * 64),
                patch.object(build.packaging, "expected_digest", return_value=expected),
                patch("tools.crawl4ai_tool.installation_lock", side_effect=lambda _path: nullcontext()),
            )
            with common[0], common[1], common[2], common[3], patch.object(build, "build_wheel") as builder:
                directory.mkdir()
                wheel.write_bytes(b"exact")
                with patch.object(build.packaging, "digest", return_value=expected):
                    self.assertEqual(build.ensure_wheel(home), wheel)
                builder.assert_not_called()
            wheel.unlink()
            with (
                patch.object(build, "recipe", return_value=data),
                patch.object(build, "identity", return_value="b" * 64),
                patch.object(build.packaging, "expected_digest", return_value=expected),
                patch("tools.crawl4ai_tool.installation_lock", side_effect=lambda _path: nullcontext()),
                patch.object(build, "build_wheel", side_effect=lambda *_args: wheel),
                patch.object(build.packaging, "digest", return_value=expected),
            ):
                self.assertEqual(build.ensure_wheel(home), wheel)
            wheel.write_bytes(b"changed")
            with (
                patch.object(build, "recipe", return_value=data),
                patch.object(build, "identity", return_value="b" * 64),
                patch.object(build.packaging, "expected_digest", return_value=expected),
                patch("tools.crawl4ai_tool.installation_lock", side_effect=lambda _path: nullcontext()),
                patch.object(build.packaging, "digest", return_value="d" * 64),
                self.assertRaisesRegex(ValueError, "digest mismatch"),
            ):
                build.ensure_wheel(home)

    def test_real_platform_open_and_failure_cleanup(self):
        """Purpose: Exercise the installed helper source. Inputs: Owned regular/unsafe file. Outputs: Exact bytes."""
        with tempfile.TemporaryDirectory() as owned:
            path = Path(owned) / "output"
            with open(path, "wb", opener=opener.open_download) as stream:
                stream.write(b"byte exact")
            self.assertEqual(path.read_bytes(), b"byte exact")
            with self.assertRaises(OSError), open(Path(owned), "wb", opener=opener.open_download):
                pass
            if os.name == "nt":
                link = Path(owned) / "hardlink"
                os.link(path, link)
                for _ in range(20):
                    with self.assertRaises(OSError), open(link, "wb", opener=opener.open_download):
                        pass
                self.assertEqual(path.read_bytes(), b"byte exact")
                link.unlink()
            path.unlink()

    def test_download_opener_rejects_windows_aliases_flags_and_unverified_handles(self):
        """Purpose: Exercise every fail-closed native handle boundary.
        Inputs: Reserved name, unsupported flags, query failure and reparse metadata. Outputs: Refusal and cleanup.
        """
        if os.name != "nt":
            self.skipTest("Windows handle contract is qualified in the Windows matrix")
        import ctypes

        with self.assertRaisesRegex(ValueError, "Reserved Windows"):
            opener.validate_download_name("CON")
        with self.assertRaisesRegex(ValueError, "Unsupported download"):
            opener.windows_handle("safe-name", 1 << 29)

        close = Mock(return_value=True)
        query = Mock(return_value=False)
        kernel = SimpleNamespace(CloseHandle=close, GetFileInformationByHandleEx=query)
        with (
            patch.object(opener, "windows_handle", return_value=123),
            patch.object(ctypes, "WinDLL", return_value=kernel),
            patch.object(ctypes, "get_last_error", return_value=5),
            self.assertRaises(OSError),
        ):
            opener.windows_descriptor("owned", os.O_WRONLY)
        close.assert_called_once_with(123)

        def mark_reparse(_handle, _kind, attributes, _size):
            """Purpose: Model handle metadata. Inputs: Query buffer. Outputs: Reparse tag and success."""
            attributes._obj[0] = 0x400
            return True

        close.reset_mock()
        query.side_effect = mark_reparse
        with (
            patch.object(opener, "windows_handle", return_value=456),
            patch.object(ctypes, "WinDLL", return_value=kernel),
            self.assertRaisesRegex(OSError, "reparse point"),
        ):
            opener.windows_descriptor("owned", os.O_WRONLY)
        close.assert_called_once_with(456)

    def test_download_opener_preserves_posix_no_follow_flag(self):
        """Purpose: Preserve the non-Windows no-follow boundary.
        Inputs: Modeled POSIX open and caller flags. Outputs: Descriptor with O_NOFOLLOW added.
        """
        opened = Mock(return_value=17)
        platform = SimpleNamespace(name="posix", O_NOFOLLOW=0x20000, open=opened)
        with patch.object(opener, "os", platform):
            self.assertEqual(opener.open_download("owned", 3), 17)
        opened.assert_called_once_with("owned", 3 | platform.O_NOFOLLOW)


class ReservedNameContracts(unittest.TestCase):
    """Pin the locally owned Windows reserved-name predicate."""

    def test_reserved_name_table(self):
        """Why (portable admission): the stdlib isreserved helper only exists on
        Python 3.13+; the documented reserved-name rule must hold identically
        on every supported interpreter.
        """
        reserved = [
            "CON",
            "con",
            "NUL",
            "PRN",
            "AUX",
            "NUL .txt",
            "nul.tar.gz",
            "COM1",
            "com9",
            "LPT1",
            "lpt9.txt",
            "CONIN$",
            "conout$",
            "COM\u00b9",
            "LPT\u00b3",
            "trailing.",
            "trailing ",
            "has:stream",
            "pipe|name",
            "wild*card",
            'quo"te',
            "a<b",
        ]
        admitted = [".", "..", "CONS", "COM0", "LPT0", "console", "x.txt", "COM10"]
        for name in reserved:
            self.assertTrue(opener._is_reserved_name(name), name)
        for name in admitted:
            self.assertFalse(opener._is_reserved_name(name), name)

    def test_reserved_name_matches_stdlib_when_available(self):
        """Where the stdlib helper exists (Python 3.13+), our predicate must
        agree with it exactly across the same table.
        """
        import os.path
        import sys

        if not hasattr(os.path, "isreserved"):
            return
        table = [
            "CON",
            "con",
            "NUL .txt",
            "COM1",
            "LPT9.txt",
            "COM\u00b9",
            "trailing.",
            "trailing ",
            "has:stream",
            "pipe|name",
            ".",
            "..",
            "CONS",
            "COM0",
            "console",
            "x.txt",
            "C:\\temp\\CON.txt",
            "C:\\temp\\y.txt",
            "C:\\temp\\sub.\\x",
            "relative\\NUL",
            "a/b/COM1.txt",
        ]
        for name in table:
            self.assertEqual(
                opener._is_reserved_path(name),
                os.path.isreserved(name),
                name,
            )
        self.assertGreaterEqual(sys.version_info, (3, 13))


if __name__ == "__main__":
    unittest.main()
