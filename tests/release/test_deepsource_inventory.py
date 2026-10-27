"""Exercise complete finding retrieval and refusal of misleading API snapshots."""

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import deepsource_inventory as inventory

REPOSITORY = "fixture/project"
COMMIT = "a" * 40


def page(ids: range, total: int, more: bool = False, cursor: str | None = None) -> dict:
    """Generate distinct native IDs at deliberately identical file/line positions."""
    nodes = [
        {
            "node": {
                "id": str(number),
                "path": "source.cpp",
                "beginLine": 7,
                "endLine": 7,
                "beginColumn": number,
                "endColumn": number,
                "title": "Reported operation",
                "issue": {
                    "shortcode": "CXX-W2045",
                    "category": "BUG_RISK",
                    "severity": "MAJOR",
                    "shortDescription": "Review operand width",
                    "analyzer": {"name": "C++", "shortcode": "cxx"},
                },
            }
        }
        for number in ids
    ]
    return {
        "data": {
            "run": {"id": "analysis-identity", "commitOid": COMMIT, "status": "FAILURE", "finishedAt": "completed"},
            "repository": {
                "id": "repository-identity",
                "name": "project",
                "vcsUrl": f"https://github.com/{REPOSITORY}",
                "vcsProvider": "GITHUB",
                "defaultBranch": "main",
                "latestCommitOid": COMMIT,
                "configJson": {"version": 1, "analyzers": [{"name": "cxx", "enabled": True}]},
                "issueOccurrences": {
                    "totalCount": total,
                    "edges": nodes,
                    "pageInfo": {"hasNextPage": more, "endCursor": cursor},
                },
            },
        }
    }


class InventoryTests(unittest.TestCase):
    """The oracle is the provider's native count/IDs, never a locally truncated list."""

    def setUp(self):
        """Own an isolated evidence directory and retain the request sequence."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name) / "capture"
        self.requests = []

    def capture(self, pages, **kwargs):
        """Deliver controlled native pages through the production traversal."""
        responses = iter(pages)

        def fetch(variables, destination):
            """Persist each native test response before the collector interprets it."""
            self.requests.append(dict(variables))
            try:
                response = next(responses)
            except StopIteration:
                self.fail("Collector requested an unexpected additional response page")
            raw = json.dumps(response).encode()
            destination.write_bytes(raw)
            return raw

        return inventory.capture(fetch, REPOSITORY, COMMIT, self.output, **kwargs)

    def assert_incomplete(self):
        """Require failure evidence without a published findings snapshot."""
        self.assertFalse(json.loads((self.output / "manifest.json").read_text())["complete"])
        self.assertFalse((self.output / "findings.json").exists())

    def test_complete_cursor_traversal_preserves_same_line_occurrences(self):
        """Recover reports beyond the first hundred without merging distinct same-line IDs."""
        result = self.capture([page(range(100), 109, True, "next"), page(range(100, 109), 109), page(range(1), 109)])
        findings = json.loads((self.output / "findings.json").read_text())
        self.assertEqual([item["id"] for item in findings], [str(number) for number in range(109)])
        self.assertEqual(result["total_count"], 109)
        self.assertEqual(result["categories"], {"BUG_RISK": 109})
        self.assertTrue(result["complete"])
        self.assertEqual([query["after"] for query in self.requests], [None, "next", None])
        self.assertEqual([query["first"] for query in self.requests], [100, 100, 1])
        self.assertEqual(len(result["pages"]), 2)

    def test_empty_inventory_requires_final_observation(self):
        """Accept zero only after two consistent observations of a valid connection."""
        result = self.capture([page(range(0), 0), page(range(0), 0)])
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_count"], 0)
        self.assertEqual(len(self.requests), 2)

    def test_missing_nested_page_cannot_be_reported_complete(self):
        """Reject the exact silent truncation observed in the upstream CLI."""
        with self.assertRaisesRegex(inventory.InventoryError, "native totalCount"):
            self.capture([page(range(100), 109)])
        self.assert_incomplete()
        self.assertTrue((self.output / "page-0001.json").exists())

    def test_duplicate_native_id_cannot_inflate_count(self):
        """Reject repeated IDs even when the apparent row count matches the total."""
        with self.assertRaisesRegex(inventory.InventoryError, "Duplicate occurrence ID"):
            self.capture([page(range(2), 3, True, "next"), page(range(1, 2), 3)])
        self.assert_incomplete()

    def test_no_progress_and_budget_exhaustion_remain_failed(self):
        """Refuse looping, missing and inconsistent cursors or exhausted traversal budgets."""
        cases = [
            ([page(range(0), 5, True, "next")], {}, "consistent progress"),
            ([page(range(2), 5, True, "next"), page(range(2, 3), 5, True, "next")], {}, "consistent progress"),
            ([page(range(2), 5, True, "next")], {"max_pages": 1}, "page budget"),
            ([page(range(2), 2, True, "next")], {}, "consistent progress"),
            ([page(range(2), 3, True)], {}, "continuation cursor"),
        ]
        for index, (pages, kwargs, message) in enumerate(cases):
            with self.subTest(index=index):
                self.output = self.output.parent / str(index)
                with self.assertRaisesRegex(inventory.InventoryError, message):
                    self.capture(pages, **kwargs)
                self.assert_incomplete()

    def test_reanalysis_and_wrong_repository_reject_the_snapshot(self):
        """Require unchanged source and repository identities through final observation."""
        mutations = [
            ("latestCommitOid", "b" * 40),
            ("vcsUrl", "https://github.com/fixture/another"),
            ("defaultBranch", "changed"),
            ("id", "changed-identity"),
            ("configJson", {"version": 1, "analyzers": []}),
        ]
        for index, (field, value) in enumerate(mutations):
            with self.subTest(field=field):
                self.output = self.output.parent / str(index)
                final = page(range(1), 2)
                final["data"]["repository"][field] = value
                with self.assertRaises(inventory.InventoryError):
                    self.capture([page(range(2), 2), final])
                self.assert_incomplete()

    def test_count_changes_during_and_after_traversal_are_rejected(self):
        """Detect reanalysis during pagination and immediately after its completion."""
        for index, pages in enumerate(
            [
                [page(range(1), 2, True, "next"), page(range(1, 2), 3)],
                [page(range(2), 2), page(range(1), 3)],
            ]
        ):
            self.output = self.output.parent / str(index)
            with self.assertRaisesRegex(inventory.InventoryError, "changed"):
                self.capture(pages)
            self.assert_incomplete()

    def test_unfinished_analysis_is_not_a_complete_inventory(self):
        """Reject temporarily empty issue lists while analysis is pending or unavailable."""
        for status in ("PENDING", "READY", "CANCEL", "TIMEOUT", "SKIPPED", None):
            response = page(range(0), 0)
            response["data"]["run"]["status"] = status
            with self.subTest(status=status), self.assertRaisesRegex(inventory.InventoryError, "unfinished"):
                inventory.parse_page(json.dumps(response).encode(), REPOSITORY, COMMIT)

    def test_reanalysis_identity_must_remain_stable(self):
        """An equal finding count cannot conceal replacement of the analyzed run."""
        final = page(range(1), 1)
        final["data"]["run"]["id"] = "another-analysis"
        with self.assertRaisesRegex(inventory.InventoryError, "changed at final"):
            self.capture([page(range(1), 1), final])
        self.assert_incomplete()

    def test_malformed_and_partial_graphql_responses_are_not_clean(self):
        """Reject malformed pagination and partial GraphQL success without losing evidence."""
        cases = [
            ("totalCount", None),
            ("totalCount", True),
            ("edges", None),
            ("pageInfo", {}),
            ("pageInfo", {"hasNextPage": "false"}),
        ]
        for index, (field, value) in enumerate(cases):
            self.output = self.output.parent / str(index)
            response = page(range(1), 1)
            response["data"]["repository"]["issueOccurrences"][field] = value
            with self.assertRaises(inventory.InventoryError):
                self.capture([response])
            self.assert_incomplete()
        partial = page(range(0), 0)
        partial["errors"] = [{"message": "access denied"}]
        with self.assertRaisesRegex(inventory.InventoryError, "GraphQL errors"):
            inventory.parse_page(json.dumps(partial).encode(), REPOSITORY, COMMIT)
        for raw in (b"{}", b'{"data":{},"data":{}}', b'{"data":NaN}', b"not JSON"):
            with self.assertRaises(inventory.InventoryError):
                inventory.parse_page(raw, REPOSITORY, COMMIT)

    def test_failure_and_existing_output_preserve_prior_evidence(self):
        """Preserve interrupted captures and refuse to overwrite an existing review."""

        def interrupted(_variables, destination):
            """Model a transport interruption after retaining received bytes."""
            destination.write_bytes(b"partial response")
            raise TimeoutError("interrupted request")

        with self.assertRaises(TimeoutError):
            inventory.capture(interrupted, REPOSITORY, COMMIT, self.output)
        self.assert_incomplete()
        before = (self.output / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.capture([])
        self.assertEqual((self.output / "manifest.json").read_bytes(), before)


class HttpResponse(io.BytesIO):
    """An owned in-memory HTTP body with the status used by urllib."""

    status = 200


class TransportTests(unittest.TestCase):
    """Verify real request construction at the HTTP boundary without network access."""

    def test_transport_identifies_itself_and_bounds_requests(self):
        """Inspect the actual urllib request, deadline and closed response owner."""
        with tempfile.TemporaryDirectory() as directory:
            client = inventory.ApiClient("fixture")
            response = HttpResponse(b'{"data": {}}')
            response.status = 200
            client.opener = Mock()
            client.opener.open.return_value = response
            destination = Path(directory) / "page.json"
            self.assertEqual(client({"after": None}, destination), b'{"data": {}}')
            request = client.opener.open.call_args.args[0]
            self.assertEqual(request.full_url, inventory.ENDPOINT)
            self.assertEqual(request.get_header("User-agent"), inventory.USER_AGENT)
            self.assertEqual(request.get_header("Authorization"), "Bearer fixture")
            self.assertEqual(client.opener.open.call_args.kwargs["timeout"], 45)
            self.assertEqual(json.loads(request.data)["query"], inventory.QUERY)
            self.assertTrue(response.closed)

    def test_http_errors_are_retained_without_retry_or_token_exposure(self):
        """Keep provider refusal visible while redacting an echoed credential."""
        with tempfile.TemporaryDirectory() as directory:
            for status in (401, 403, 429):
                client = inventory.ApiClient("fixture")
                response = urllib.error.HTTPError(inventory.ENDPOINT, status, "refused", {}, io.BytesIO(b"fixture"))
                client.opener = Mock()
                client.opener.open.side_effect = response
                path = Path(directory) / f"{status}.json"
                with self.assertRaisesRegex(inventory.InventoryError, str(status)):
                    client({}, path)
                self.assertEqual(path.read_bytes(), b"[redacted]")
                self.assertEqual(client.opener.open.call_count, 1)

    def test_oversize_pages_and_redirects_are_rejected(self):
        """Bound incoming data and prevent authorization from following redirects."""
        with tempfile.TemporaryDirectory() as directory:
            client = inventory.ApiClient("fixture")
            response = HttpResponse(b"x" * (inventory.MAX_PAGE_BYTES + 2))
            response.status = 200
            client.opener = Mock()
            client.opener.open.return_value = response
            path = Path(directory) / "large.json"
            with self.assertRaisesRegex(inventory.InventoryError, "byte budget"):
                client({}, path)
            self.assertEqual(path.stat().st_size, inventory.MAX_PAGE_BYTES + 1)
        with self.assertRaisesRegex(inventory.InventoryError, "redirect refused"):
            inventory.NoRedirects().redirect_request(None, None, 302, "", {}, "https://example.invalid/")

    def test_existing_cli_authentication_and_explicit_environment(self):
        """Reuse legitimate login state without forwarding private-server credentials."""
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {}, clear=True):
            config = Path(directory) / "config.toml"
            config.write_text('host = "deepsource.com"\ntoken = "fixture"\n')
            self.assertEqual(inventory.authentication(config), "fixture")
            config.write_text('host = "private.example.invalid"\ntoken = "fixture"\n')
            with self.assertRaisesRegex(inventory.InventoryError, "cloud endpoint"):
                inventory.authentication(config)
            with patch.dict("os.environ", {"DEEPSOURCE_TOKEN": "explicit"}):
                self.assertEqual(inventory.authentication(config), "explicit")
            with (
                patch.dict(
                    "os.environ", {"DEEPSOURCE_TOKEN": "explicit", "DEEPSOURCE_HOST": "private.example.invalid"}
                ),
                self.assertRaisesRegex(inventory.InventoryError, "cloud endpoint"),
            ):
                inventory.authentication(config)


if __name__ == "__main__":
    unittest.main()
