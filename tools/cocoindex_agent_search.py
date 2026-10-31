"""Local, external-mirror CocoIndex Code routing for development agents.

This tool is never imported by scanner runtime. Install and index explicitly;
search refuses stale source bytes. Exact source reads remain authoritative.
Adapted from strmt7/VulnerabilityScreener scripts/cocoindex_agent_search.py (MIT).
Original notice: third_party/notices/VulnerabilityScreener-MIT.txt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from functools import partial
from pathlib import Path, PurePosixPath

if __package__:
    from .agent_context import relative_source_path, safe_path
    from .executable_path import executable_path
else:
    from agent_context import relative_source_path, safe_path
    from executable_path import executable_path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.2.42"
MODEL = "Snowflake/snowflake-arctic-embed-xs"
INDEX_SUFFIXES = (
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".rs",
    ".go",
    ".c",
    ".h",
    ".hpp",
    ".hh",
    ".cpp",
    ".cc",
    ".cxx",
    ".cs",
    ".java",
    ".rb",
    ".php",
    ".sh",
    ".ps1",
    ".psm1",
    ".cjs",
    ".html",
    ".css",
)
SETTINGS = (
    "embedding:\n  provider: sentence-transformers\n"
    f"  model: {MODEL}\n  device: cpu\n"
    "daemon:\n  idle_timeout_minutes: 1\n"
    "  keep_alive_with_mcp: false\n"
)
PROJECT_SETTINGS_V1 = (
    "include_patterns:\n  - '*'\nexclude_patterns:\n  - '.cocoindex_code/**'\n  - '**/.cocoindex_code/**'\n"
)
PROJECT_SETTINGS = (
    "include_patterns:\n" + "".join(f"  - '**/*{suffix}'\n" for suffix in INDEX_SUFFIXES) + "  - '**/CMakeLists.txt'\n"
    "exclude_patterns:\n  - 'tests/**'\n"
    "  - 'third_party/**'\n"
    "  - '.cocoindex_code/**'\n  - '**/.cocoindex_code/**'\n"
)
CONFIG_DIGEST = hashlib.sha256((SETTINGS + PROJECT_SETTINGS).encode("utf-8")).hexdigest()


def home() -> Path:
    """Purpose: Select external agent state. Inputs: environment. Outputs: safe absolute cache path."""
    override = os.environ.get("AGENT_CODE_HOME")
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise ValueError("AGENT_CODE_HOME must be an absolute path")
        selected = path.resolve()
    else:
        base = (
            os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        )
        selected = (Path(base) / "FlitzZip" / "agent-code").resolve()
    if selected.is_relative_to(ROOT):
        raise ValueError("agent index state must remain outside the checkout")
    return selected


def paths(base: Path, repo: Path = ROOT) -> tuple[Path, Path, Path, Path]:
    """Purpose: Scope tool, mirror, and runtime state. Inputs: base/repo. Outputs: four external paths."""
    digest = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:16]
    return (
        base / f"venv-{VERSION}",
        base / "mirrors" / digest,
        base / "config" / digest,
        base / "runtime" / VERSION / digest,
    )


def ccc_path(venv: Path) -> Path:
    """Purpose: Locate the pinned CLI. Inputs: virtual environment. Outputs: platform executable path."""
    return venv / ("Scripts/ccc.exe" if os.name == "nt" else "bin/ccc")


def _run(
    args: list[str], *, cwd: Path | None = None, timeout: int, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Purpose: Run a bounded child. Inputs: argv/cwd/timeout/env. Outputs: captured result or failure."""
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        timeout=timeout,
        check=True,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        errors="replace",
    )


def install(base: Path) -> None:
    """Purpose: Install pinned development CLI. Inputs: external base. Outputs: verified environment or error."""
    venv = paths(base)[0]
    command = ccc_path(venv)
    if command.is_file():
        version = _run([str(command), "version"], timeout=30).stdout.strip()
        if version != VERSION:
            raise RuntimeError(f"existing CocoIndex version {version}; expected {VERSION}")
        print(f"CocoIndex Code {version} already installed")
        return
    venv.parent.mkdir(parents=True, exist_ok=True)
    _run([sys.executable, "-m", "venv", str(venv)], timeout=300)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    requirement = f"cocoindex-code[full]=={VERSION}"
    uv = shutil.which("uv")
    if uv:
        _run([uv, "pip", "install", "--python", str(python), requirement], timeout=3600)
    else:
        _run(
            [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", requirement],
            timeout=3600,
        )
    version = _run([str(command), "version"], timeout=30).stdout.strip()
    if version != VERSION:
        raise RuntimeError(f"CocoIndex version verification failed: {version}")
    print(f"Installed CocoIndex Code {version} in {venv}")


def tracked_files(repo: Path) -> list[tuple[str, Path]]:
    """Purpose: Inventory live code. Inputs: checkout. Outputs: safe paths without Git-confirmed deletions."""
    raw = subprocess.run(
        [executable_path("git"), "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--deduplicate"],
        cwd=repo,
        timeout=30,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    result = []
    deleted: set[str] | None = None
    for name in (part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part):
        rel = relative_source_path(name)
        if rel.parts[0] in ("tests", "third_party"):
            continue
        if rel.suffix.lower() not in INDEX_SUFFIXES and rel.name != "CMakeLists.txt":
            continue
        source = safe_path(repo, name)
        if not source.exists() and not source.is_symlink():
            if deleted is None:
                removed = subprocess.run(
                    [executable_path("git"), "ls-files", "-z", "--deleted"],
                    cwd=repo,
                    timeout=30,
                    check=True,
                    stdout=subprocess.PIPE,
                ).stdout
                deleted = {part.decode("utf-8", "surrogateescape") for part in removed.split(b"\0") if part}
            if name in deleted:
                continue
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"source is not a regular file: {name}")
        if source.stat().st_size > 32 * 1024 * 1024:
            raise ValueError(f"source exceeds 32 MiB index bound: {name}")
        result.append((name, source))
    return result


def source_digest(entries: list[tuple[str, Path]]) -> str:
    """Purpose: Fingerprint indexable bytes.
    Inputs: live path/source entries in any Git inventory order.
    Outputs: canonical SHA-256, unchanged by staging alone.
    """
    digest = hashlib.sha256()
    for name, source in sorted(entries, key=lambda entry: entry[0]):
        digest.update(name.encode("utf-8", "surrogateescape") + b"\0")
        with source.open("rb") as stream:
            for block in iter(partial(stream.read, 1024 * 1024), b""):
                digest.update(block)
        digest.update(b"\0")
    return digest.hexdigest()


def prepare_mirror(mirror: Path, entries: list[tuple[str, Path]]) -> None:
    """Purpose: Synchronize private source mirror. Inputs: mirror/entries. Outputs: exact safe copies."""
    mirror.mkdir(parents=True, exist_ok=True)
    resolved = mirror.resolve()
    wanted = set()
    for name, source in entries:
        target = mirror.joinpath(*PurePosixPath(name).parts)
        if not target.parent.resolve().is_relative_to(resolved):
            raise ValueError(f"mirror path escapes target: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise ValueError(f"mirror path is a link: {name}")
        wanted.add(target.resolve())
        if not target.is_file() or target.read_bytes() != source.read_bytes():
            shutil.copyfile(source, target)
    for stale in mirror.rglob("*"):
        if not stale.is_file() or ".cocoindex_code" in stale.parts:
            continue
        if stale.resolve() not in wanted:
            if not stale.resolve().is_relative_to(resolved):
                raise ValueError("stale mirror path escapes target")
            stale.unlink()


def _environment(base: Path, config: Path, runtime: Path) -> dict[str, str]:
    """Purpose: Isolate CLI state. Inputs: external paths. Outputs: child environment without telemetry."""
    result = dict(os.environ)
    result.update(
        {
            "COCOINDEX_CODE_DIR": str(config),
            "COCOINDEX_CODE_RUNTIME_DIR": str(runtime),
            "COCOINDEX_DISABLE_USAGE_TRACKING": "1",
            "HF_HOME": str(base / "hf-cache"),
        }
    )
    return result


def index(base: Path, repo: Path = ROOT) -> None:
    """Purpose: Refresh semantic index. Inputs: external base/checkout. Outputs: fresh marker or error."""
    venv, mirror, config, runtime = paths(base, repo)
    command = ccc_path(venv)
    if not command.is_file():
        raise RuntimeError("run install before indexing")
    entries = tracked_files(repo)
    digest = source_digest(entries)
    prepare_mirror(mirror, entries)
    settings = config / "global_settings.yml"
    settings.parent.mkdir(parents=True, exist_ok=True)
    if settings.exists() and settings.read_text(encoding="utf-8") != SETTINGS:
        raise RuntimeError("CocoIndex settings changed; inspect before indexing")
    settings.write_text(SETTINGS, encoding="utf-8")
    project = mirror / ".cocoindex_code" / "settings.yml"
    project.parent.mkdir(parents=True, exist_ok=True)
    previous = project.read_text(encoding="utf-8") if project.exists() else None
    if previous not in (None, PROJECT_SETTINGS, PROJECT_SETTINGS_V1):
        raise RuntimeError("CocoIndex project settings changed; inspect before indexing")
    project.write_text(PROJECT_SETTINGS, encoding="utf-8")
    runtime.mkdir(parents=True, exist_ok=True)
    if previous == PROJECT_SETTINGS_V1:
        # This private runtime was created by our v1 index. Reload the
        # narrower settings before reindexing; other projects have own dirs.
        _run([str(command), "daemon", "stop"], cwd=mirror, timeout=30, env=_environment(base, config, runtime))
    output = _run([str(command), "index"], cwd=mirror, timeout=3600, env=_environment(base, config, runtime)).stdout
    match = re.search(r"Indexing: .*?error: (\d+)", output)
    if match is None or int(match.group(1)) != 0 or source_digest(tracked_files(repo)) != digest:
        raise RuntimeError("index errors or source changed during indexing; no active marker written")
    marker = base / "active" / (mirror.name + ".json")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps(
            {
                "schema": 1,
                "source_digest": digest,
                "config_digest": CONFIG_DIGEST,
                "cocoindex_code": VERSION,
                "files": len(entries),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Indexed {len(entries)} Git-visible source files; source SHA-256 {digest[:16]}")
    print(output[-2000:])


def record_search_use(base: Path, repo: Path, digest: str, query: str, hit_count: int) -> None:
    """Purpose: Record real successful routing.
    Inputs: verified search metadata.
    Outputs: atomic local receipt, no query text.
    """
    mirror = paths(base, repo)[1]
    target = base / "active" / (mirror.name + ".usage.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": 1,
        "source_digest": digest,
        "config_digest": CONFIG_DIGEST,
        "cocoindex_code": VERSION,
        "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "hit_count": hit_count,
        "completed_at": datetime.now(UTC).isoformat(),
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".search-", delete=False) as output:
            temporary = Path(output.name)
            output.write((json.dumps(receipt) + "\n").encode("utf-8"))
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate_search_results(payload: object, maximum: int) -> list[dict]:
    """Purpose: Admit bounded provider output. Inputs: Parsed JSON/fetch limit. Outputs: Typed safe search hits."""
    if not isinstance(payload, dict):
        raise RuntimeError("CocoIndex search returned a non-object response")
    if payload.get("success") is not True:
        raise RuntimeError(f"CocoIndex search failed: {str(payload.get('message', 'unknown error'))[:500]}")
    hits = payload.get("results")
    if not isinstance(hits, list) or len(hits) > maximum:
        raise RuntimeError("CocoIndex search returned an invalid result collection")
    admitted = []
    for hit in hits:
        if not isinstance(hit, dict):
            raise RuntimeError("CocoIndex search returned a malformed result")
        file_path = hit.get("file_path")
        start, end, score, content = (
            hit.get("start_line"),
            hit.get("end_line"),
            hit.get("score"),
            hit.get("content"),
        )
        if (
            not isinstance(file_path, str)
            or relative_source_path(file_path).as_posix() != file_path
            or type(start) is not int
            or type(end) is not int
            or start < 1
            or end < start
            or isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(score)
            or not isinstance(content, str)
            or len(content.encode("utf-8")) > 1024 * 1024
        ):
            raise RuntimeError("CocoIndex search returned an invalid result field")
        admitted.append(hit)
    return admitted


def search(base: Path, query: str, limit: int, repo: Path = ROOT, path: str | None = None) -> None:
    """Purpose: Route a conceptual query. Inputs: fresh index/query/limit/path. Outputs: bounded hints."""
    if path and any(mark in path for mark in "*?["):
        raise ValueError(
            "wildcard path filters are outside this wrapper's exact-path contract; "
            "search broadly, then validate files with rg"
        )
    venv, mirror, config, runtime = paths(base, repo)
    marker = base / "active" / (mirror.name + ".json")
    if not marker.is_file():
        raise RuntimeError("no active index; run index explicitly")
    recorded = json.loads(marker.read_text(encoding="utf-8"))
    current = source_digest(tracked_files(repo))
    if (
        recorded.get("source_digest") != current
        or recorded.get("config_digest") != CONFIG_DIGEST
        or recorded.get("cocoindex_code") != VERSION
    ):
        raise RuntimeError("index is stale; run index before semantic search")
    command = ccc_path(venv)
    fetch = max(20, limit * 5)
    args = [str(command), "search", "--limit", str(fetch), "--json"]
    if path:
        args += ["--path", path]
    output = _run(args + [query], cwd=mirror, timeout=180, env=_environment(base, config, runtime)).stdout
    payload = json.loads(output)
    hits = validate_search_results(payload, fetch)
    distinct = []
    seen = set()
    for hit in hits:
        if hit["file_path"] not in seen:
            distinct.append(hit)
            seen.add(hit["file_path"])
        if len(distinct) == limit:
            break
    hits = distinct
    if source_digest(tracked_files(repo)) != current:
        raise RuntimeError("source changed during semantic search; refresh index before using results")
    record_search_use(base, repo, current, query, len(hits))
    for hit in hits:
        excerpt = " ".join(hit["content"].split())[:160]
        print(f"{hit['file_path']}:{hit['start_line']}-{hit['end_line']} score={hit['score']:.3f} {excerpt}")
    print(f"results={len(hits)}; confirm exact paths with rg")


def main(argv: list[str] | None = None) -> int:
    """Purpose: Dispatch CLI actions. Inputs: optional argv. Outputs: zero or an actionable failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("install")
    sub.add_parser("index")
    find = sub.add_parser("search")
    find.add_argument("query")
    find.add_argument("--limit", type=int, default=5)
    find.add_argument("--path", help="exact repository-relative file after initial routing; wildcards are rejected")
    args = parser.parse_args(argv)
    base = home()
    if args.action == "install":
        install(base)
    elif args.action == "index":
        index(base)
    else:
        if not 1 <= args.limit <= 10 or not args.query.strip():
            parser.error("search requires a query and limit between 1 and 10")
        search(base, args.query, args.limit, path=args.path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        if isinstance(exc, subprocess.CalledProcessError) and exc.stdout:
            print(exc.stdout[-3000:], file=sys.stderr)
        print(f"error: CocoIndex agent search: {exc}", file=sys.stderr)
        raise SystemExit(3) from None
