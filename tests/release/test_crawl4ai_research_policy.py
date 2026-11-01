"""Why (security review): crawl4ai_research.py's admission policy is the
SSRF boundary for untrusted remote research — plain public HTTPS only, no
credentials/query/fragment, no numeric hosts, distinct named origins, a
strict manifest envelope and a 20-100 reviewed-site budget. Every arm of
that boundary is pinned here; a regression is a security defect.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import crawl4ai_research as cr  # noqa: E402


class SiteTextPolicyTests(unittest.TestCase):
    """Manifest-row text bound admissions."""

    def test_url_and_marker_bounds(self) -> None:
        """Why: every text bound is a separate admission rule."""
        self.assertTrue(cr._site_text_ok("https://a.example/x", "marker"))
        self.assertFalse(cr._site_text_ok(7, "marker"))
        self.assertFalse(cr._site_text_ok("x" * 2049, "marker"))
        self.assertFalse(cr._site_text_ok("https://a.example/x", ""))
        self.assertFalse(cr._site_text_ok("https://a.example/x", "  padded  "))
        self.assertFalse(cr._site_text_ok("https://a.example/x", "m" * 201))
        self.assertFalse(cr._site_text_ok("https://a.example/x", "line\nbreak"))


class TransportPolicyTests(unittest.TestCase):
    """Origin transport admissions (the SSRF core)."""

    def test_plain_https_only(self) -> None:
        """Why: the transport arm forbids non-HTTPS, credentials, and
        query/fragment smuggling — the SSRF core.
        """
        self.assertTrue(cr._origin_transport_ok(urlsplit("https://a.example/x"), None))
        self.assertTrue(cr._origin_transport_ok(urlsplit("https://a.example/x"), 443))
        self.assertFalse(cr._origin_transport_ok(urlsplit("http://a.example/x"), 80))
        self.assertFalse(cr._origin_transport_ok(urlsplit("https://u:p@a.example/x"), None))
        self.assertFalse(cr._origin_transport_ok(urlsplit("https://a.example/x?q=1"), None))
        self.assertFalse(cr._origin_transport_ok(urlsplit("https://a.example/x#f"), None))
        self.assertFalse(cr._origin_transport_ok(urlsplit("https://a.example/x"), 8443))


class HostPolicyTests(unittest.TestCase):
    """Origin host admissions: named, public, distinct."""

    def test_named_public_distinct_hosts(self) -> None:
        """Why: numeric hosts (IP literals) and duplicates are refused;
        this blocks direct-to-IP SSRF and host-pool reuse.
        """
        self.assertTrue(cr._origin_host_ok("a.example", set()))
        self.assertFalse(cr._origin_host_ok("127.0.0.1", set()))
        self.assertFalse(cr._origin_host_ok("::1", set()))
        self.assertFalse(cr._origin_host_ok("localhost", set()))
        self.assertFalse(cr._origin_host_ok("a.example", {"a.example"}))
        self.assertFalse(cr._origin_host_ok("a_b.example", set()))
        self.assertFalse(cr._origin_host_ok("x" * 254 + ".example", set()))


class AdmitSitePolicyTests(unittest.TestCase):
    """Per-site admission refusals and host pooling."""

    def test_field_set_is_exact(self) -> None:
        """Why: unknown or missing fields are refused outright."""
        with self.assertRaises(ValueError):
            cr._admit_site({"url": "https://a.example/"}, set())
        with self.assertRaises(ValueError):
            cr._admit_site({"url": "https://a.example/", "marker": "m", "extra": 1}, set())
        with self.assertRaises(ValueError):
            cr._admit_site("not-a-dict", set())

    def test_bad_port_refused(self) -> None:
        """Why: an ambiguous port is its own refusal message."""
        with self.assertRaises(ValueError):
            cr._admit_site({"url": "https://a.example:99999/", "marker": "m"}, set())

    def test_transport_and_host_violations_refused(self) -> None:
        """Why: the transport/host arms surface as one admission refusal."""
        with self.assertRaises(ValueError):
            cr._admit_site({"url": "http://a.example/", "marker": "m"}, set())
        with self.assertRaises(ValueError):
            cr._admit_site({"url": "https://10.0.0.1/", "marker": "m"}, set())

    def test_admission_mutates_host_set(self) -> None:
        """Why: admitted hosts are pooled for the distinctness rule."""
        hosts: set[str] = set()
        row = cr._admit_site({"url": "https://a.example/x", "marker": "m"}, hosts)
        self.assertEqual(row, {"url": "https://a.example/x", "marker": "m"})
        self.assertIn("a.example", hosts)


class ManifestPolicyTests(unittest.TestCase):
    """Manifest envelope, content budget and read_sites pipeline."""

    def _manifest(self, count: int = 20) -> dict:
        return {
            "schema": 1,
            "purpose": "Reviewed research targets for the crawler qualification run.",
            "sites": [{"url": f"https://site{i}.example/x", "marker": f"unique marker {i}"} for i in range(count)],
        }

    def test_shape_refusals(self) -> None:
        """Why: the envelope's exact key set and schema version are
        admission rules.
        """
        with self.assertRaises(ValueError):
            cr._manifest_shape({"schema": 1})
        with self.assertRaises(ValueError):
            cr._manifest_shape({"schema": 2, "purpose": "p", "sites": []})
        with self.assertRaises(ValueError):
            cr._manifest_shape({"schema": True, "purpose": "p", "sites": []})

    def test_content_refusals(self) -> None:
        """Why: the purpose bound and the 20-100 site budget are enforced."""
        with self.assertRaises(ValueError):
            cr._manifest_content({"purpose": "  ", "sites": []})
        with self.assertRaises(ValueError):
            cr._manifest_content({"purpose": "p" * 1001, "sites": []})
        with self.assertRaises(ValueError):
            cr._manifest_content({"purpose": "p", "sites": []})
        with self.assertRaises(ValueError):
            cr._manifest_content({"purpose": "p", "sites": list(range(101))})

    def test_read_sites_admits_reviewed_manifest(self) -> None:
        """Why: the full pipeline — budget, decode, shape, content, per-site
        admission — runs end to end on a valid manifest.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sites.json"
            path.write_text(json.dumps(self._manifest()), encoding="utf-8")
            rows = cr.read_sites(path)
        self.assertEqual(len(rows), 20)

    def test_read_sites_refusals(self) -> None:
        """Why: empty, oversized, ambiguous-JSON and duplicate-key
        manifests are refused before any network work.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sites.json"
            path.write_bytes(b"")
            with self.assertRaises(ValueError):
                cr.read_sites(path)
            path.write_bytes(b"x" * (65537))
            with self.assertRaises(ValueError):
                cr.read_sites(path)
            path.write_bytes(b"{broken")
            with self.assertRaises(ValueError):
                cr.read_sites(path)
            path.write_bytes(b'{"schema": 1, "schema": 1, "purpose": "p", "sites": []}')
            with self.assertRaises(ValueError):
                cr.read_sites(path)


if __name__ == "__main__":
    unittest.main()
