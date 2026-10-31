"""Bounded local research crawling; remote content is untrusted source material.

This product includes software developed by UncleCode (https://x.com/unclecode)
as part of the Crawl4AI project (https://github.com/unclecode/crawl4ai).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import ipaddress
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

from tools.crawl4ai_tool import ATTRIBUTION, ROOT, VERSION, text_identity
from tools.json_input import decode_json

MAX_MARKDOWN_BYTES = 2 * 1024 * 1024
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_SITES_BYTES = 64 * 1024
CAPTURE_FIELDS = frozenset(
    {
        "url",
        "html",
        "success",
        "status_code",
        "redirected_url",
        "redirected_status_code",
        "response_headers",
        "error_message",
        "metadata",
        "crawl_stats",
    }
)
SITES = ROOT / "tools/crawl4ai_sites.json"


def _site_text_ok(url: object, marker: object) -> bool:
    """
    Purpose: Validate one manifest row's text fields.
    Inputs: Candidate url and marker;
    Output: True when both texts are admissible.
    """
    return (
        isinstance(url, str)
        and len(url) <= 2048
        and isinstance(marker, str)
        and bool(marker.strip())
        and marker == marker.strip()
        and len(marker) <= 200
        and not any(ord(character) < 32 for character in marker)
    )


def _origin_transport_ok(parsed: SplitResult, port: int | None) -> bool:
    """
    Purpose: Validate one site origin's transport shape.
    Inputs: Parsed URL and its resolved port;
    Output: True for plain HTTPS without credentials, query or fragment.
    """
    return (
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and port in (None, 443)
        and not parsed.query
        and not parsed.fragment
    )


def _origin_host_ok(host: str, hosts: set[str]) -> bool:
    """
    Purpose: Validate one site origin's host shape.
    Inputs: Lowercased hostname and the already-admitted hosts;
    Output: True for a distinct named public DNS host.
    """
    labels = host.split(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        numeric_host = False
    else:
        numeric_host = True
    return (
        not numeric_host
        and len(host) <= 253
        and len(labels) >= 2
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        and host not in hosts
    )


def _admit_site(site: object, hosts: set[str]) -> dict[str, str]:
    """
    Purpose: Validate and admit one manifest site row.
    Inputs: Candidate row and the admitted-host set (mutated on success);
    Output: The admitted url/marker row; raises ValueError on any violation with the original messages.
    """
    if not isinstance(site, dict) or set(site) != {"url", "marker"}:
        raise ValueError("Crawler site fields are missing or unknown")
    url, marker = site["url"], site["marker"]
    if not _site_text_ok(url, marker):
        raise ValueError("Crawler site URL or marker is invalid")
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Crawler sites require unambiguous public HTTPS URLs") from error
    host = (parsed.hostname or "").casefold()
    if not _origin_transport_ok(parsed, port) or not _origin_host_ok(host, hosts):
        raise ValueError("Crawler sites require distinct named public HTTPS origins")
    hosts.add(host)
    return {"url": url, "marker": marker}


def _manifest_shape(document: object) -> None:
    """
    Purpose: Validate the manifest envelope.
    Inputs: Parsed manifest document;
    Output: None; raises ValueError when the fields or schema are invalid.
    """
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "purpose", "sites"}
        or type(document["schema"]) is not int
        or document["schema"] != 1
    ):
        raise ValueError("Crawler site manifest fields or schema are invalid")


def _manifest_content(document: dict) -> tuple[str, list]:
    """
    Purpose: Validate the manifest contents.
    Inputs: Shape-checked manifest document;
    Output: The (purpose, sites) pair; raises ValueError when either is invalid.
    """
    purpose, sites = document["purpose"], document["sites"]
    if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 1000:
        raise ValueError("Crawler site manifest purpose is absent or too long")
    if not isinstance(sites, list) or not 20 <= len(sites) <= 100:
        raise ValueError("Crawler qualification requires 20-100 reviewed sites")
    return purpose, sites


def read_sites(path: Path) -> list[dict[str, str]]:
    """Purpose: Admit reviewed public crawl targets. Inputs: Bounded site manifest. Outputs: Exact safe site rows."""
    with path.open("rb") as source:
        payload = source.read(MAX_SITES_BYTES + 1)
    if not payload or len(payload) > MAX_SITES_BYTES:
        raise ValueError("Crawler site manifest must contain 1..65536 bytes")
    try:
        document = decode_json(payload)
    except (ValueError, RecursionError) as error:
        raise ValueError("Crawler site manifest must be unambiguous UTF-8 JSON") from error
    _manifest_shape(document)
    _purpose, sites = _manifest_content(document)
    admitted, hosts = [], set()
    for site in sites:
        admitted.append(_admit_site(site, hosts))
    return admitted


def crawler():
    """Purpose: Construct the source-admitted upstream crawler. Inputs: Installed package. Outputs: Crawler owner."""
    if importlib.metadata.version("crawl4ai") != VERSION:
        raise ValueError("Crawler version does not match the reviewed integration")
    from crawl4ai import AsyncWebCrawler

    return AsyncWebCrawler()


def inspect_result(result, marker: str = "") -> dict:
    """Purpose: Classify native access/content evidence. Inputs: Result and marker. Outputs: Honest acceptance/cause."""
    markdown = str(result.markdown.raw_markdown) if result.markdown else ""
    content = markdown.encode("utf-8")
    status = int(result.status_code or 0)
    final_status = int(getattr(result, "redirected_status_code", None) or status)
    headers = {key.casefold(): str(value) for key, value in (result.response_headers or {}).items()}
    error = str(result.error_message or "")
    expected = not marker or marker.casefold() in markdown.casefold()
    # Use the provider's access diagnosis and documented response headers, not
    # words in an article that might itself explain anti-bot mechanisms.
    outcomes = (
        (headers.get("x-robots-status") == "Blocked by robots.txt", "robots_denied"),
        (error == "Access denied by robots.txt", "robots_denied"),
        (error.startswith("Blocked by anti-bot protection:"), "access_challenge"),
        (headers.get("cf-mitigated", "").casefold() == "challenge", "access_challenge"),
        (final_status in (401, 403), "access_denied"),
        (final_status == 429, "rate_limited"),
        (bool(final_status) and not 200 <= final_status < 300, "http_error"),
        (not result.success, "native_failure"),
        (not 200 <= final_status < 300, "http_error"),
        (len(content) > MAX_MARKDOWN_BYTES, "content_too_large"),
        (len(content) < 200, "insufficient_content"),
        (not expected, "unexpected_content"),
    )
    category = next((name for failed, name in outcomes if failed), "")
    return {
        "success": not category,
        "native_success": bool(result.success),
        "http_status": status,
        "final_http_status": final_status,
        "markdown_bytes": len(content),
        "markdown_sha256": hashlib.sha256(content).hexdigest(),
        "expected_content": expected,
        "failure_category": category,
        "error": error[:500],
    }


def retain_capture(path: Path, url: str, result, row: dict) -> dict:
    """Purpose: Retain inspectable native evidence. Inputs: New file/result/diagnosis. Outputs: File identity."""
    capture = {
        "schema": 1,
        "requested_url": url,
        "provider_version": importlib.metadata.version("crawl4ai"),
        "diagnosis": row,
        # The public serializer adds Markdown. Limit other fields to the
        # research contract, excluding deprecated properties and binary artifacts.
        "native_result": result.model_dump(mode="json", include=CAPTURE_FIELDS) if result is not None else None,
    }
    content = (json.dumps(capture, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(content) > MAX_CAPTURE_BYTES:
        raise ValueError("Native research capture exceeds the evidence byte budget")
    with path.open("xb") as output:
        output.write(content)
    return {"capture": path.name, "capture_sha256": hashlib.sha256(content).hexdigest()}


async def fetch(owner, url: str, marker: str = "", capture: Path | None = None) -> dict:
    """Purpose: Crawl with finite lifetime. Inputs: Owner/URL/marker/new capture. Outputs: Diagnosis and evidence."""
    from crawl4ai import CacheMode, CrawlerRunConfig

    started = time.monotonic()
    row = {"url": url, "success": False}
    result = None
    try:
        config = CrawlerRunConfig(cache_mode=CacheMode.BYPASS, check_robots_txt=True)
        result = await asyncio.wait_for(owner.arun(url=url, config=config), timeout=45)
        row.update(inspect_result(result, marker))
    except TimeoutError as error:
        row.update(failure_category="timeout", error=str(error)[:500] or "Page exceeded the 45-second deadline")
    except (ValueError, OSError) as error:
        row.update(failure_category="request_error", error=f"{type(error).__name__}: {error}"[:500])
    row["seconds"] = round(time.monotonic() - started, 3)
    if capture is not None:
        row.update(retain_capture(capture, url, result, row))
    return row


def source_identity() -> dict[str, str]:
    """Purpose: Bind qualification to integration bytes. Inputs: Repository sources. Outputs: Exact source digests."""
    from tools import crawl4ai_source_build, nltk_distribution

    paths = (
        "tools/crawl4ai_tool.py",
        "tools/crawl4ai_research.py",
        "tools/requirements/crawl4ai.txt",
        "tools/crawl4ai_sites.json",
        "tools/nltk_distribution.py",
        "tools/python_wheel.py",
        "tests/integration/test_nltk_model_security.py",
        "tools/requirements/python-build.txt",
        "tools/crawl4ai_source_build.py",
        "tools/crawl4ai_download_opener.py",
        "tests/integration/test_crawl4ai_downloads.py",
    )
    identities = {path: text_identity(ROOT / path) for path in paths}
    record = nltk_distribution.SOURCE_ROOT / "distribution.json"
    identities[record.relative_to(ROOT).as_posix()] = text_identity(record)
    identities["nltk_upstream_wheel"] = nltk_distribution.digest(nltk_distribution.wheel_path())
    identities["crawl4ai_source_build"] = crawl4ai_source_build.identity()
    return identities


async def execute(args) -> int:
    """Purpose: Run the requested local lane. Inputs: Parsed CLI. Outputs: Exit status and bounded evidence."""
    if args.command == "doctor":
        from crawl4ai import CacheMode, CrawlerRunConfig

        async with crawler() as owner:
            result = await asyncio.wait_for(
                owner.arun(
                    url=("raw:<html><body><h1>FlitzZip crawler contract</h1><p>Local extraction.</p></body></html>"),
                    config=CrawlerRunConfig(cache_mode=CacheMode.DISABLED, word_count_threshold=0),
                ),
                timeout=45,
            )
        passed = result.success and "FlitzZip crawler contract" in str(result.markdown)
        print(
            json.dumps({"doctor_passed": bool(passed), "version": VERSION, "browser_configuration": "upstream-default"})
        )
        return 0 if passed else 1
    sites = read_sites(SITES)
    if args.receipt.exists():
        raise FileExistsError("Research receipt already exists; select a new evidence destination")
    captures = args.receipt.with_suffix(args.receipt.suffix + ".captures")
    captures.mkdir(parents=True, exist_ok=False)
    rows = []
    before = source_identity()
    async with crawler() as owner:
        for index, site in enumerate(sites):
            row = await fetch(owner, site["url"], site["marker"], captures / f"{index:04d}.json")
            rows.append(row)
            print(json.dumps(row), flush=True)
    successful_domains = {urlsplit(row["url"]).hostname for row in rows if row["success"]}
    qualified = len(successful_domains) >= 20 and before == source_identity()
    receipt = {
        "schema": 2,
        "completed_utc": datetime.now(UTC).isoformat(),
        "version": VERSION,
        "browser_configuration": "upstream-default",
        "robots_checked": True,
        "custom_browser_overrides": False,
        "source_identity": before,
        "capture_directory": captures.name,
        "attempted": len(rows),
        "successful_domains": len(successful_domains),
        "qualified": qualified,
        "results": rows,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(json.dumps({key: receipt[key] for key in ("attempted", "successful_domains", "qualified")}), flush=True)
    return 0 if qualified else 1


def main() -> int:
    """Purpose: Parse explicit crawler lanes. Inputs: CLI. Outputs: Selected lane status."""
    parser = argparse.ArgumentParser(description=__doc__, epilog=ATTRIBUTION)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor")
    qualify = commands.add_parser("qualify")
    qualify.add_argument("--receipt", type=Path, required=True, help="New local JSON evidence file; never overwrite")
    return asyncio.run(execute(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
