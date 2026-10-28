"""Capture the complete default-branch DeepSource occurrence connection.

This read-only client uses the documented cloud GraphQL API. It never ignores
findings or changes provider settings. Raw pages remain in a new local directory;
only a fully reconciled traversal receives a complete manifest. The API does not
provide snapshot isolation, so commit/count checks detect, but cannot rule out
every possible concurrent reanalysis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from .json_input import decode_json
else:
    from json_input import decode_json

ENDPOINT = "https://api.deepsource.com/graphql/"
USER_AGENT = "RejectionRejector-DeepSource-Audit/1.0"
MAX_PAGE_BYTES = 4 * 1024 * 1024
QUERY = """query Inventory($owner: String!, $name: String!, $commit: String!,
  $after: String, $first: Int!) {
  run(commitOid: $commit) { id commitOid status finishedAt }
  repository(login: $owner, name: $name, vcsProvider: GITHUB) {
    id name vcsUrl vcsProvider defaultBranch latestCommitOid configJson
    issueOccurrences(first: $first, after: $after) {
      totalCount pageInfo { hasNextPage endCursor }
      edges { node {
        id path beginLine beginColumn endLine endColumn title
        issue { shortcode category severity shortDescription analyzer { name shortcode } }
      } }
    }
  }
}"""


class InventoryError(ValueError):
    """An actionable diagnostic containing no credentials or provider-controlled text."""


def object_value(value: object, label: str) -> dict[str, object]:
    """Reject absent or malformed API objects before interpreting their fields."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InventoryError(f"Invalid {label} object")
    return value


def text_value(value: object, label: str) -> str:
    """Require a nonempty textual API identity or metadata field."""
    if not isinstance(value, str) or not value:
        raise InventoryError(f"Missing {label}")
    return value


def count_value(value: object, label: str) -> int:
    """Require an exact nonnegative integer, excluding JSON booleans."""
    if type(value) is not int or value < 0:
        raise InventoryError(f"Invalid {label}")
    return value


def authentication(config_path: Path) -> str:
    """Use an explicit environment token or the official CLI's existing login.

    Never copy credentials into reports or accept a token on the command line.
    A configured private server needs its own reviewed endpoint; its credentials
    must not be forwarded to the cloud by accident.
    """
    if token := os.environ.get("DEEPSOURCE_TOKEN"):
        host = os.environ.get("DEEPSOURCE_HOST", "deepsource.com")
    else:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
        token = config.get("token")
        host = config.get("host", "deepsource.com")
    if host not in ("deepsource.com", "deepsource.io", "app.deepsource.com"):
        raise InventoryError("Configured DeepSource server is not the reviewed cloud endpoint")
    if not isinstance(token, str) or not token or any(char.isspace() for char in token):
        raise InventoryError("Run the official 'deepsource auth login' or set DEEPSOURCE_TOKEN")
    return token


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Keep the authorization header confined to the selected HTTPS endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Refuse redirect handling before urllib can construct another request."""
        raise InventoryError("DeepSource API redirect refused; no redirect target was contacted")


class ApiClient:
    """One authenticated, bounded HTTP request per page; no automatic retries."""

    def __init__(self, token: str):
        """Bind the client to one API token.

        Inputs: `token` -- the DeepSource API bearer token. Output: none;
        stores the token and a no-redirect URL opener.
        """
        self._token = token
        self.opener = urllib.request.build_opener(NoRedirects())

    def __call__(self, variables: dict[str, object], destination: Path) -> bytes:
        """Retain a bounded response and reject failed or credential-echoing requests."""
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps({"query": QUERY, "variables": variables}).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "Cache-Control": "no-cache",
            },
        )
        try:
            response = self.opener.open(request, timeout=45)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(MAX_PAGE_BYTES + 1)
            status = response.status
        # An unexpected server echo must not persist the authentication secret.
        retained = raw.replace(self._token.encode("utf-8"), b"[redacted]")
        destination.write_bytes(retained)
        if status != 200:
            raise InventoryError(f"DeepSource HTTP {status}; inspect the retained response")
        if len(raw) > MAX_PAGE_BYTES:
            raise InventoryError("DeepSource response exceeds the page byte budget")
        if retained != raw:
            raise InventoryError("DeepSource response echoed a credential; retained response was redacted")
        return raw


def parse_page(raw: bytes, repository: str, commit: str) -> tuple[dict[str, object], dict[str, object]]:
    """Decode one native response and require the requested repository and source."""
    try:
        decoded = decode_json(raw)
    except (ValueError, RecursionError):
        raise InventoryError("DeepSource returned invalid JSON; inspect the retained response") from None
    envelope = object_value(decoded, "GraphQL response")
    if envelope.get("errors"):
        raise InventoryError("DeepSource returned GraphQL errors; inspect the retained response")
    data = object_value(envelope.get("data"), "GraphQL data")
    analysis = object_value(data.get("run"), "analysis run")
    if analysis.get("commitOid") != commit or analysis.get("status") not in ("SUCCESS", "FAILURE"):
        raise InventoryError(
            "DeepSource analysis is unfinished or unavailable; retain the response and wait for completion"
        )
    text_value(analysis.get("id"), "analysis identity")
    text_value(analysis.get("finishedAt"), "analysis completion time")
    repo = object_value(data.get("repository"), "repository")
    if (
        repo.get("vcsUrl") != f"https://github.com/{repository}"
        or repo.get("vcsProvider") != "GITHUB"
        or repo.get("name") != repository.split("/")[1]
        or repo.get("latestCommitOid") != commit
    ):
        raise InventoryError("DeepSource repository or default-branch commit does not match the requested source")
    text_value(repo.get("id"), "repository identity")
    text_value(repo.get("defaultBranch"), "default branch")
    object_value(repo.get("configJson"), "analyzer configuration")
    repo["analysis"] = analysis
    connection = object_value(repo.pop("issueOccurrences", None), "occurrence connection")
    return repo, connection


def occurrence(value: object) -> dict[str, object]:
    """Preserve native occurrence IDs and columns, including same-line reports."""
    item = object_value(value, "occurrence")
    for field in ("id", "path", "title"):
        text_value(item.get(field), field)
    for field in ("beginLine", "endLine", "beginColumn", "endColumn"):
        count_value(item.get(field), field)
    rule = object_value(item.get("issue"), "issue")
    for field in ("shortcode", "category", "severity"):
        text_value(rule.get(field), field)
    analyzer = object_value(rule.get("analyzer"), "analyzer")
    text_value(analyzer.get("shortcode"), "analyzer shortcode")
    return item


def page_entries(connection: dict[str, object]) -> tuple[list[dict[str, object]], bool, str | None]:
    """Validate the page and its continuation signal independently of accumulated state."""
    edges = connection.get("edges")
    if not isinstance(edges, list) or len(edges) > 100:
        raise InventoryError("Invalid occurrence page size")
    entries = [occurrence(object_value(edge, "edge").get("node")) for edge in edges]
    page = object_value(connection.get("pageInfo"), "pageInfo")
    more = page.get("hasNextPage")
    if type(more) is not bool:
        raise InventoryError("Missing pagination completion flag")
    cursor = text_value(page.get("endCursor"), "continuation cursor") if more else None
    return entries, more, cursor


def verify_final_observation(
    raw: bytes,
    repository: str,
    commit: str,
    identity: dict[str, object],
    total: int,
    first_id: object,
) -> None:
    """Check the final count, source and first occurrence against the captured traversal."""
    final, connection = parse_page(raw, repository, commit)
    entries, _, _ = page_entries(connection)
    if (
        final != identity
        or count_value(connection.get("totalCount"), "final totalCount") != total
        or len(entries) != min(1, total)
        or (entries and entries[0]["id"] != first_id)
    ):
        raise InventoryError("DeepSource inventory changed at final observation")


def collect_pages(
    fetch: Callable[[dict[str, object], Path], bytes],
    repository: str,
    commit: str,
    output: Path,
    max_pages: int,
) -> dict[str, object]:
    """Traverse native cursors; reject gaps, duplicates, drift and exhausted budgets."""
    identity: dict[str, object] = {}
    total = 0
    after = None
    cursors: set[str] = set()
    ids: set[str] = set()
    findings: list[dict[str, object]] = []
    pages = []
    variables: dict[str, object] = dict(
        zip(("owner", "name"), repository.split("/"), strict=True), first=100, commit=commit
    )
    for number in range(1, max_pages + 1):
        variables["after"] = after
        path = output / f"page-{number:04d}.json"
        raw = fetch(variables, path)
        current, connection = parse_page(raw, repository, commit)
        count = count_value(connection.get("totalCount"), "totalCount")
        if not identity:
            identity, total = current, count
        if current != identity or count != total:
            raise InventoryError("DeepSource identity or occurrence count changed during retrieval")
        entries, more, next_cursor = page_entries(connection)
        for item in entries:
            item_id = text_value(item["id"], "occurrence ID")
            if item_id in ids:
                raise InventoryError("Duplicate occurrence ID across pages")
            ids.add(item_id)
            findings.append(item)
        pages.append(
            {
                "file": path.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "count": len(entries),
            }
        )
        if not more:
            if len(findings) != total:
                raise InventoryError("Collected occurrence count differs from native totalCount")
            break
        after = text_value(next_cursor, "continuation cursor")
        if not entries or after in cursors or len(findings) >= count:
            raise InventoryError("Occurrence pagination made no consistent progress")
        cursors.add(after)
    else:
        raise InventoryError("Occurrence retrieval exceeded its page budget; inventory is incomplete")
    # A final observation detects changes after the last page, including empty inventories.
    variables.update(first=1, after=None)
    raw = fetch(variables, output / "final-observation.json")
    verify_final_observation(raw, repository, commit, identity, total, findings[0]["id"] if findings else None)
    (output / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    categories = Counter(text_value(object_value(item["issue"], "issue")["category"], "category") for item in findings)
    return {
        "complete": True,
        "repository": identity,
        "total_count": total,
        "pages": pages,
        "categories": dict(sorted(categories.items())),
        "final_observation_sha256": hashlib.sha256(raw).hexdigest(),
        "findings_sha256": hashlib.sha256((output / "findings.json").read_bytes()).hexdigest(),
        "consistency": ("cursor traversal with stable commit/count; provider does not promise snapshot isolation"),
    }


def capture(
    fetch: Callable[[dict[str, object], Path], bytes],
    repository: str,
    commit: str,
    output: Path,
    max_pages: int = 1000,
) -> dict[str, object]:
    """Create fresh evidence; failed runs retain pages and an incomplete manifest."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise InventoryError("Use owner/repository and a complete lowercase Git commit SHA")
    if type(max_pages) is not int or not 1 <= max_pages <= 1000:
        raise InventoryError("Page budget must be between 1 and 1000")
    output.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, object] = {
        "schema_version": 1,
        "complete": False,
        "endpoint": ENDPOINT,
        "user_agent": USER_AGENT,
        "requested_repository": repository,
        "requested_commit": commit,
        "started_at": datetime.now(UTC).isoformat(),
        "query_sha256": hashlib.sha256(QUERY.encode()).hexdigest(),
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    try:
        manifest.update(collect_pages(fetch, repository, commit, output, max_pages))
        return manifest
    except InventoryError as error:
        manifest["failure"] = str(error)
        raise
    finally:
        manifest["finished_at"] = datetime.now(UTC).isoformat()
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Capture the requested repository, reporting sanitized failure diagnostics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="GitHub owner/repository")
    parser.add_argument("--commit", required=True, help="Expected complete default-branch SHA")
    parser.add_argument("--output", required=True, type=Path, help="New local evidence directory")
    parser.add_argument("--config", type=Path, default=Path.home() / ".deepsource" / "config.toml")
    parser.add_argument("--max-pages", type=int, default=1000)
    args = parser.parse_args()
    try:
        result = capture(
            ApiClient(authentication(args.config)),
            args.repository,
            args.commit,
            args.output,
            args.max_pages,
        )
    except InventoryError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, RecursionError):
        # Do not echo arbitrary provider/config content or credentials in exceptions.
        print(
            "DeepSource inventory failed; inspect retained pages/manifest and authentication configuration.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps({key: result[key] for key in ("complete", "total_count", "categories")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
