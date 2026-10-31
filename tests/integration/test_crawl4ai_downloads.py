"""Exercise installed download, image and research-result consumers without public network access."""

from __future__ import annotations

import asyncio
import base64
import importlib.metadata
import io
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


class DownloadContracts(unittest.TestCase):
    """Verify the production package, including refusal before target truncation."""

    @classmethod
    def setUpClass(cls):
        """Purpose: Admit the actual installed source build. Inputs: Runtime metadata. Outputs: Production opener."""
        from tools.crawl4ai_tool import VERSION

        if importlib.metadata.version("crawl4ai") != VERSION:
            raise AssertionError("Download regression requires the exact source-admitted Crawl4AI runtime")
        from packaging.version import Version

        if Version(importlib.metadata.version("pillow")) < Version("13.0.0"):
            raise AssertionError("Image-consumer regressions require the fixed Pillow release")
        from crawl4ai.async_crawler_strategy import _nofollow_opener, _safe_download_filepath

        cls.opener = staticmethod(_nofollow_opener)
        cls.destination = staticmethod(_safe_download_filepath)

    def test_pillow_security_floor_and_image_decoding(self):
        """Purpose: Qualify patched image decoding and JPEG draft/thumbnail behavior used by research image consumers.
        Inputs: Installed Pillow, tiny in-memory PNG/JPEG controls and truncated headers; no external images are
        opened.
        Outputs: The fixed version decodes/resizes expected pixels and refuses incomplete images without disk writes.
        """
        from PIL import Image

        for format_name in ("PNG", "JPEG"):
            encoded = io.BytesIO()
            with Image.new("RGB", (32, 24), (220, 30, 40)) as original:
                original.save(encoded, format=format_name)
            payload = encoded.getvalue()
            with self.subTest(format=format_name), Image.open(io.BytesIO(payload)) as decoded:
                self.assertEqual(decoded.size, (32, 24))
                decoded.thumbnail((8, 8), Image.Resampling.LANCZOS)
                self.assertEqual(decoded.size, (8, 6))
                pixel = decoded.getpixel((0, 0))
                self.assertGreater(pixel[0], pixel[1] + 100)
                self.assertGreater(pixel[0], pixel[2] + 100)
            with self.assertRaises(OSError):
                Image.open(io.BytesIO(payload[:8]))

    def test_jpeg_decoder_rejects_output_larger_than_declared_tile(self):
        """Purpose: Verify the patched JPEG decoder checks actual output against its allocated tile extent.
        Inputs: A locally generated tiny JPEG with deliberately undersized decoder metadata, then an intact control.
        Outputs: The decoder refuses the inconsistent layout and remains usable for a subsequent valid image.
        """
        from PIL import Image

        source = io.BytesIO()
        with Image.new("RGB", (32, 24), (220, 30, 40)) as original:
            original.save(source, format="JPEG")
        with Image.open(io.BytesIO(source.getvalue())) as inconsistent:
            inconsistent.tile = [inconsistent.tile[0]._replace(extents=(0, 0, 8, 8))]
            with self.assertRaisesRegex(OSError, "broken data stream"):
                inconsistent.load()
        with Image.open(io.BytesIO(source.getvalue())) as control:
            control.load()
            self.assertEqual(control.size, (32, 24))
            self.assertGreater(control.getpixel((0, 0))[0], 200)

    def test_installed_screenshot_image_consumer(self):
        """Purpose: Qualify the real crawler's JPEG-to-PNG screenshot stitching through the installed image library.
        Inputs: Browser-I/O doubles supplying two tiny JPEG segments; real upstream strategy and image operations.
        Outputs: Correct image extent/color order and restored viewport, rejecting the strategy's error placeholder.
        """
        from crawl4ai import BrowserConfig
        from crawl4ai.async_crawler_strategy import AsyncPlaywrightCrawlerStrategy
        from crawl4ai.async_logger import AsyncLogger
        from PIL import Image

        async def capture():
            """Purpose: Exercise actual image operations. Inputs: Owned JPEG segments. Outputs: Captured PNG bytes."""
            frames = []
            for height, color in ((4, (240, 0, 0)), (3, (0, 0, 240))):
                encoded = io.BytesIO()
                with Image.new("RGB", (32, height), color) as image:
                    image.save(encoded, format="JPEG")
                frames.append(encoded.getvalue())
            page = SimpleNamespace(
                viewport_size={"width": 32, "height": 4}, evaluate=AsyncMock(), screenshot=AsyncMock(side_effect=frames)
            )

            async def resize(viewport):
                """Purpose: Model viewport state. Inputs: Requested extent. Outputs: Updated page-owned state."""
                page.viewport_size = dict(viewport)

            page.set_viewport_size = AsyncMock(side_effect=resize)
            strategy = AsyncPlaywrightCrawlerStrategy(
                browser_config=BrowserConfig(headless=True), logger=AsyncLogger(verbose=False)
            )
            with patch.object(strategy, "get_page_dimensions", AsyncMock(return_value={"width": 32, "height": 7})):
                encoded = await strategy.take_screenshot_scroller(page, screenshot_height_threshold=4, scroll_delay=0)
            self.assertEqual(page.screenshot.await_count, 2)
            self.assertEqual(page.viewport_size, {"width": 32, "height": 4})
            return base64.b64decode(encoded, validate=True)

        with Image.open(io.BytesIO(asyncio.run(capture()))) as image:
            self.assertEqual(image.size, (32, 7))
            top, bottom = image.getpixel((16, 1)), image.getpixel((16, 5))
            self.assertGreater(top[0], top[2] + 100)
            self.assertGreater(bottom[2], bottom[0] + 100)

    def test_research_capture_handles_native_failure_and_redirected_content(self):
        """Purpose: Preserve provider results. Inputs: Error and redirected CrawlResult. Outputs: Exact evidence."""
        from crawl4ai.models import CrawlResult, MarkdownGenerationResult

        from tools.crawl4ai_research import inspect_result, retain_capture

        text = "Public documentation with substantive source text. " * 10
        results = (
            CrawlResult(url="https://example.invalid/error", html="", success=False, error_message="Connection reset"),
            CrawlResult(
                url="https://example.invalid/start",
                html="<p>Public documentation</p>",
                success=True,
                status_code=307,
                redirected_url="https://example.invalid/document",
                redirected_status_code=200,
                markdown=MarkdownGenerationResult(
                    raw_markdown=text, markdown_with_citations=text, references_markdown=""
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as owned:
            for index, result in enumerate(results):
                row = inspect_result(result, "documentation")
                path = Path(owned) / f"{index}.json"
                retain_capture(path, result.url, result, row)
                native = json.loads(path.read_text(encoding="utf-8"))["native_result"]
                self.assertEqual(native["error_message"], result.error_message)
                self.assertEqual(native["success"], result.success)
                self.assertNotIn("fit_html", native)
                if result.success:
                    self.assertTrue(row["success"])
                    self.assertEqual(native["markdown"]["raw_markdown"], text)
                    self.assertEqual(native["redirected_status_code"], 200)
                else:
                    self.assertFalse(row["success"])
                    self.assertEqual(row["failure_category"], "native_failure")

    def test_real_creation_overwrite_and_descriptor_ownership(self):
        """Purpose: Preserve normal downloads. Inputs: Owned binary file. Outputs: Exact bytes and closed handle."""
        with tempfile.TemporaryDirectory() as owned:
            path = Path(owned) / "download.json"
            for contents in (b'{"long":123456789}', b'{"ok":true}'):
                with open(path, "wb", opener=self.opener) as stream:
                    self.assertFalse(os.get_inheritable(stream.fileno()))
                    stream.write(contents)
                self.assertEqual(path.read_bytes(), contents)
            with self.assertRaises(FileExistsError), open(path, "xb", opener=self.opener):
                pass
            self.assertEqual(path.read_bytes(), b'{"ok":true}')
            path.unlink()  # Windows denies deletion when an owned handle leaked.

    def test_installed_byte_admission_refuses_a_wrong_expected_repair(self):
        """Purpose: Keep cache reuse fail-closed. Inputs: Actual runtime/wrong digest. Outputs: Admission failure."""
        from tools import crawl4ai_source_build as build
        from tools import crawl4ai_tool as tool

        expected = build.runtime_hashes()
        expected["crawl4ai/flitzzip_download.py"] = build.hashlib.sha256(b"different repair").hexdigest()
        with tempfile.TemporaryFile(mode="w+b") as diagnostics:
            with (
                patch.object(build, "runtime_hashes", return_value=expected),
                patch.object(tool.sys, "stderr", diagnostics),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                tool.verify_versions(Path(sys.executable), tool.tool_environment(tool.cache_home()))
            diagnostics.seek(0)
            self.assertIn(b"crawler repair bytes changed", diagnostics.read(8192))

    def test_reparse_target_is_not_truncated(self):
        """Purpose: Refuse links at the actual open. Inputs: Owned link/target. Outputs: Error and unchanged target."""
        with tempfile.TemporaryDirectory() as owned:
            root = Path(owned)
            target = root / "target"
            target.write_bytes(b"must survive")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError as error:
                if os.name == "nt" and error.winerror == 1314:
                    self.skipTest("Host policy does not permit unprivileged symbolic-link creation")
                raise
            with self.assertRaises(OSError), open(link, "wb", opener=self.opener):
                pass
            self.assertEqual(target.read_bytes(), b"must survive")
            self.assertTrue(link.is_symlink())

    @unittest.skipUnless(os.name == "nt", "Windows native-handle boundary")
    def test_windows_hardlink_and_reserved_destinations_refused(self):
        """Purpose: Reject unsafe Windows aliases. Inputs: Hardlink/device/stream destinations. Outputs: No writes."""
        with tempfile.TemporaryDirectory() as owned:
            target = Path(owned) / "target"
            target.write_bytes(b"preserved")
            link = Path(owned) / "hardlink"
            os.link(target, link)
            names = (
                link.name,
                "CON",
                "con.json",
                "CONIN$",
                "NUL",
                "AUX.txt",
                "LPT1",
                "COM1",
                "target:stream",
                "trailing.",
            )
            for name in names:
                with (
                    self.subTest(destination=name),
                    self.assertRaises((OSError, ValueError)),
                    open(self.destination(owned, name), "wb", opener=self.opener),
                ):
                    pass
            self.assertEqual(target.read_bytes(), b"preserved")
            link.unlink()
            target.unlink()

    @unittest.skipUnless(os.name == "nt", "Windows reserved-name admission")
    def test_http_reserved_headers_refused_before_opening(self):
        """Purpose: Protect the complete download consumer. Inputs: Remote reserved names. Outputs: No file opens."""
        import aiofiles
        from aiohttp import web
        from aiohttp.test_utils import TestServer
        from crawl4ai import CrawlerRunConfig, HTTPCrawlerConfig
        from crawl4ai.async_crawler_strategy import AsyncHTTPCrawlerStrategy, HTTPCrawlerError

        async def respond(request):
            """Purpose: Supply a hostile download name. Inputs: Owned request. Outputs: Typed named response."""
            return web.Response(
                body=b"reserved filename must not be written",
                content_type="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="{request.query["name"]}"'},
            )

        async def consume(root: str):
            """Purpose: Exercise admission before file I/O. Inputs: Owned root. Outputs: Verified refusals."""
            app = web.Application()
            app.router.add_get("/reserved", respond)
            async with TestServer(app) as server:
                self.assertTrue(ipaddress.ip_address(server.host).is_loopback)
                async with AsyncHTTPCrawlerStrategy(browser_config=HTTPCrawlerConfig(downloads_path=root)) as strategy:
                    # The real admission must reject before aiofiles or CPython can select WindowsConsoleIO.
                    with patch("crawl4ai.async_crawler_strategy.aiofiles.open", wraps=aiofiles.open) as opened:
                        for name in ("CON", "CON.txt", "CONIN$", "NUL", "AUX.txt", "target:stream", "trailing."):
                            url = server.make_url("/reserved").with_query(name=name)
                            with (
                                self.subTest(filename=name),
                                self.assertRaisesRegex(HTTPCrawlerError, "Reserved Windows download destination"),
                            ):
                                await asyncio.wait_for(
                                    strategy.crawl(str(url), CrawlerRunConfig(page_timeout=5000)), 10
                                )
                        opened.assert_not_called()
            self.assertEqual(list(Path(root).iterdir()), [])

        with tempfile.TemporaryDirectory() as owned:
            asyncio.run(consume(owned))

    def test_confined_http_consumer_preserves_complete_download_and_content(self):
        """Purpose: Exercise the failing HTTP path. Inputs: Owned JSON response. Outputs: Exact file/content."""
        from aiohttp import web
        from aiohttp.test_utils import TestServer
        from crawl4ai import CrawlerRunConfig, HTTPCrawlerConfig
        from crawl4ai.async_crawler_strategy import AsyncHTTPCrawlerStrategy

        payload = b'{"crawler_download_contract":"byte exact","value":123}'

        async def respond(request):
            """Purpose: Supply the owned JSON fixture. Inputs: TestServer request. Outputs: Exact typed response."""
            return web.Response(body=payload, content_type="application/json")

        async def consume(root: str):
            """Purpose: Exercise the upstream HTTP consumer. Inputs: Owned root. Outputs: Verified native result."""
            app = web.Application()
            app.router.add_get("/contract.json", respond)
            # Reuse aiohttp's owned loopback test fixture and its actual allocated URL.
            async with TestServer(app) as server:
                self.assertTrue(ipaddress.ip_address(server.host).is_loopback)
                async with AsyncHTTPCrawlerStrategy(browser_config=HTTPCrawlerConfig(downloads_path=root)) as strategy:
                    result = await asyncio.wait_for(
                        strategy.crawl(str(server.make_url("/contract.json")), CrawlerRunConfig(page_timeout=5000)), 10
                    )
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.html.encode(), payload)
                self.assertEqual(len(result.downloaded_files), 1)
                path = Path(result.downloaded_files[0])
                self.assertEqual(path.parent.resolve(), Path(root).resolve())
                self.assertEqual(path.read_bytes(), payload)

        with tempfile.TemporaryDirectory() as owned:
            asyncio.run(consume(owned))


if __name__ == "__main__":
    unittest.main()
