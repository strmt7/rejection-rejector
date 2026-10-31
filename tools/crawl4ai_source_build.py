"""Build an identified, portable Crawl4AI revision from immutable published source."""

from __future__ import annotations

import hashlib
import os
import tarfile
import tempfile
import urllib.request
import venv
from pathlib import Path, PurePosixPath

from tools import python_wheel as packaging

ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOT = ROOT / "third_party/upstream/crawl4ai/0.9.5"
OPENER = ROOT / "tools/crawl4ai_download_opener.py"
BUILD_LOCK = packaging.BUILD_LOCK


def recipe() -> dict:
    """Purpose: Admit original source. Inputs: Pinned recipe/archive. Outputs: Verified build recipe or refusal."""
    data = packaging.read_recipe(SOURCE_ROOT / "build.json")
    if (
        set(data)
        != {
            "schema",
            "project",
            "upstream_version",
            "version",
            "source",
            "source_bytes",
            "source_date_epoch",
            "source_url",
        }
        or type(data.get("schema")) is not int
        or data["schema"] != 1
        or data.get("project") != "crawl4ai"
        or data.get("upstream_version") != "0.9.5"
        or data.get("version") != "0.9.5+rejection.rejector.portable2"
        or data.get("source") != "crawl4ai-0.9.5.tar.gz"
        or type(data.get("source_bytes")) is not int
        or data["source_bytes"] != 577411
        or data.get("source_date_epoch") != 1791973529
        or data.get("source_url")
        != "https://files.pythonhosted.org/packages/ea/ad/44b57b650c3c0afaeea917bd7e6b87a64cd1108be53431690483cde0eb2d/crawl4ai-0.9.5.tar.gz"
    ):
        raise ValueError("Unsupported Crawl4AI source build recipe")
    packaging.expected_digest(SOURCE_ROOT / (data["source"] + ".sha256"))
    return data


def source_archive(home: Path | None = None) -> Path:
    """Purpose: Acquire pinned upstream source outside Git. Inputs: Tool cache. Outputs: Verified regular archive."""
    from tools.crawl4ai_tool import cache_home, installation_lock

    data = recipe()
    home = cache_home(str(home) if home is not None else None)
    expected = packaging.expected_digest(SOURCE_ROOT / (data["source"] + ".sha256"))
    directory = home / "source" / expected
    if any(path.is_symlink() or path.is_junction() for path in (directory.parent, directory)):
        raise ValueError("Crawl4AI source cache is redirected")
    with installation_lock(directory, timeout=180):
        destination = directory / data["source"]
        if destination.exists() or destination.is_symlink():
            if destination.stat().st_size != data["source_bytes"] or packaging.digest(destination) != expected:
                raise ValueError("Crawl4AI cached source differs from pinned provenance")
            return destination
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(prefix="source-", suffix=".part", dir=directory, delete=False) as stage:
                temporary = Path(stage.name)
                request = urllib.request.Request(data["source_url"], headers={"Accept": "application/octet-stream"})
                with urllib.request.urlopen(request, timeout=60) as response:
                    remaining = data["source_bytes"]
                    while chunk := response.read(min(65536, remaining + 1)):
                        remaining -= len(chunk)
                        if remaining < 0:
                            raise ValueError("Crawl4AI source download exceeds pinned length")
                        stage.write(chunk)
                    if remaining != 0:
                        raise ValueError("Crawl4AI source download is incomplete")
            if packaging.digest(temporary) != expected:
                raise ValueError("Crawl4AI source download differs from pinned digest")
            os.replace(temporary, destination)
            return destination
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def identity() -> str:
    """Purpose: Reuse exact artifacts. Inputs: Source/repair/build/wheel identities. Outputs: Cache digest."""
    from tools.crawl4ai_tool import text_identity

    data = recipe()
    values = [packaging.expected_digest(SOURCE_ROOT / (data["source"] + ".sha256"))]
    values.extend(
        text_identity(path)
        for path in (
            SOURCE_ROOT / "build.json",
            SOURCE_ROOT / (data["source"] + ".sha256"),
            SOURCE_ROOT / "crawl4ai-wheel.sha256",
            OPENER,
            BUILD_LOCK,
        )
    )
    return hashlib.sha256("\n".join(values).encode("ascii")).hexdigest()


def extract_source(archive: Path, destination: Path) -> Path:
    """Purpose: Extract owned bounded regular source. Inputs: Verified tar/destination. Outputs: Source tree."""
    if destination.exists() or destination.is_symlink():
        raise ValueError("Crawl4AI source destination must be new and unredirected")
    with tarfile.open(archive, "r:gz") as source:
        entries: list[tarfile.TarInfo] = []
        total = 0
        for item in source:
            total += item.size
            if item.size < 0 or len(entries) >= 2000 or total > packaging.MAX_SOURCE_BYTES or len(item.name) > 4096:
                raise ValueError("Crawl4AI source exceeds its reviewed extent")
            entries.append(item)
        seen = set()
        # Validate the complete archive before publishing any member to the owned tree.
        for item in entries:
            path = PurePosixPath(item.name)
            if (
                path.is_absolute()
                or not path.parts
                or path.parts[0] != "crawl4ai-0.9.5"
                or ".." in path.parts
                or "\\" in item.name
                or ":" in item.name
                or "\0" in item.name
                or not (item.isfile() or item.isdir())
                or item.name.casefold() in seen
            ):
                raise ValueError("Unsafe or duplicate Crawl4AI source member")
            seen.add(item.name.casefold())
        for item in entries:
            target = destination.joinpath(*PurePosixPath(item.name).parts[1:])
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(item) as stream:
                    target.write_bytes(stream.read())
    return destination


def patched_strategy(original: str) -> str:
    """Purpose: Bind the repaired boundary. Inputs: Original strategy text. Outputs: Modified source or refusal."""
    previous = "    return os.open(path, flags | os.O_NOFOLLOW)"
    basename = '    safe_name = os.path.basename(filename or "")'
    if original.count(previous) != 1 or original.count(basename) != 1:
        raise ValueError("Upstream download opener changed; repair requires renewed review")
    repaired = original.replace(
        previous,
        "    # FlitzZip portable source repair: preserve no-follow checks on Windows.\n"
        "    from .flitzzip_download import open_download\n"
        "    return open_download(path, flags)",
    )
    repaired = repaired.replace(
        basename,
        basename + "\n    # Validate before normalization or Python's console I/O selection.\n"
        "    from .flitzzip_download import validate_download_name\n"
        "    validate_download_name(safe_name)",
    )
    contracts = (
        (
            '    """Resolve a download destination confined to ``downloads_path``.',
            '    """Purpose: Confine and admit downloads. Inputs: Root/remote name. Outputs: Safe path or refusal.\n\n'
            "    Resolve a download destination confined to ``downloads_path``.",
        ),
        (
            '    """Opener for ``open``/``aiofiles.open`` that refuses to follow a symlink at',
            '    """Purpose: Open without following links. Inputs: Admitted path/flags. Outputs: Owned descriptor.\n\n'
            "    Opener for ``open``/``aiofiles.open`` that refuses to follow a symlink at",
        ),
    )
    for old, new in contracts:
        if repaired.count(old) != 1:
            raise ValueError("Upstream download contract changed; repair requires renewed review")
        repaired = repaired.replace(old, new)
    return repaired


def patched_version(original: str, version: str) -> str:
    """Purpose: Identify the modified package. Inputs: Original version text/identity. Outputs: Source or refusal."""
    if original.count('__version__ = "0.9.5"') != 1:
        raise ValueError("Upstream Crawl4AI version changed")
    return original.replace('__version__ = "0.9.5"', f'__version__ = "{version}"')


def runtime_hashes() -> dict[str, str]:
    """Purpose: Refuse changed installed repairs. Inputs: Source/local repair. Outputs: Exact runtime digests."""
    data = recipe()
    with tarfile.open(source_archive(), "r:gz") as source:
        strategy = source.extractfile("crawl4ai-0.9.5/crawl4ai/async_crawler_strategy.py").read().decode("utf-8")
        version = source.extractfile("crawl4ai-0.9.5/crawl4ai/__version__.py").read().decode("utf-8")
    files = {
        "crawl4ai/async_crawler_strategy.py": patched_strategy(strategy),
        "crawl4ai/__version__.py": patched_version(version, data["version"]),
        "crawl4ai/flitzzip_download.py": OPENER.read_text(encoding="utf-8"),
    }
    return {
        name: hashlib.sha256(contents.replace("\r\n", "\n").encode("utf-8")).hexdigest()
        for name, contents in files.items()
    }


def repair_source(source: Path, data: dict) -> None:
    """Purpose: Repair the actual download boundary. Inputs: Owned exact source/recipe. Outputs: Identified source."""
    strategy = source / "crawl4ai/async_crawler_strategy.py"
    version = source / "crawl4ai/__version__.py"
    repaired_strategy = patched_strategy(strategy.read_text(encoding="utf-8"))
    repaired_version = patched_version(version.read_text(encoding="utf-8"), data["version"])
    config = source / "pyproject.toml"
    contents = config.read_text(encoding="utf-8")
    if contents.count('license = "Apache-2.0"') != 1:
        raise ValueError("Upstream license packaging changed")
    notice = (
        "FlitzZip Crawl4AI development-tool source build\n\n"
        "Upstream: https://github.com/unclecode/crawl4ai/releases/tag/v0.9.5\n"
        f"Downstream version: {data['version']}\n"
        "Modified 25 October 2026: async_crawler_strategy.py delegates its download opener\n"
        "and pre-open filename validation to the included Apache-2.0 flitzzip_download.py.\n"
        "Reserved Windows basenames are rejected before path normalization and opening.\n"
        "Windows uses a native no-follow\n"
        "handle, validates it before truncation and transfers ownership to Python.\n"
        "POSIX retains O_NOFOLLOW. __version__.py and license packaging identify this build.\n"
        "Modified 26 October 2026: annotate optional handle ownership without changing I/O behavior.\n"
        "No browser, URL, robots, request, extraction or dependency rules were changed.\n"
        "This is a downstream build, not a published Crawl4AI release.\n\n"
        "This product includes software developed by UncleCode (https://x.com/unclecode)\n"
        "as part of the Crawl4AI project (https://github.com/unclecode/crawl4ai).\n"
    )
    (source / "FLITZZIP_BUILD_NOTICE.txt").write_text(notice, encoding="utf-8", newline="\n")
    strategy.write_text(repaired_strategy, encoding="utf-8", newline="\n")
    (source / "crawl4ai/flitzzip_download.py").write_text(
        OPENER.read_text(encoding="utf-8"), encoding="utf-8", newline="\n"
    )
    version.write_text(repaired_version, encoding="utf-8", newline="\n")
    config.write_text(
        contents.replace(
            'license = "Apache-2.0"', 'license = "Apache-2.0"\nlicense-files = ["LICENSE", "FLITZZIP_BUILD_NOTICE.txt"]'
        ),
        encoding="utf-8",
        newline="\n",
    )


def builder_python(home: Path) -> Path:
    """Purpose: Provide the pinned pip-capable builder interpreter.

    Inputs: external cache root;
    Output: interpreter path inside the builder venv, created on first use.
    The ambient interpreter is not assumed to carry pip; the builder venv is
    always created with one.
    """
    from tools.crawl4ai_tool import installation_lock, text_identity

    builder = home / ("python-builder-" + text_identity(BUILD_LOCK)[:16])
    python = builder / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    with installation_lock(builder):
        if not python.exists():
            venv.EnvBuilder(with_pip=True).create(builder)
    return python


def build_wheel(home: Path, output: Path, data: dict) -> Path:
    """Purpose: Use the pinned standard builder. Inputs: External cache/output/recipe. Outputs: Canonical wheel."""
    from tools.crawl4ai_tool import installation_lock, run, text_identity, tool_environment

    builder = home / ("python-builder-" + text_identity(BUILD_LOCK)[:16])
    python = builder / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    env = tool_environment(home)
    env.update(SOURCE_DATE_EPOCH=str(data["source_date_epoch"]), PYTHONHASHSEED="0")
    with installation_lock(builder):
        if not python.exists():
            venv.EnvBuilder(with_pip=True).create(builder)
        run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--quiet",
                "--require-hashes",
                "--only-binary=:all:",
                "-r",
                str(BUILD_LOCK),
            ],
            env,
        )
        run([str(python), "-m", "pip", "check"], env, 60)
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="crawl4ai-source-", dir=output) as owned:
            source = extract_source(source_archive(home), Path(owned) / "source")
            repair_source(source, data)
            # Upstream setup.py prepares/removes a cache. Confine that build-only side effect to this owned tree.
            env["CRAWL4_AI_BASE_DIRECTORY"] = str(source)
            built = Path(owned) / "built"
            run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "wheel",
                    "--no-index",
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(built),
                    str(source),
                ],
                env,
                180,
            )
            filename = f"crawl4ai-{data['version']}-py3-none-any.whl"
            destination = output / filename
            packaging.canonical_wheel(built / filename, destination, data, project="crawl4ai")
    return destination


def ensure_wheel(home: Path) -> Path:
    """Purpose: Admit only the exact repaired wheel. Inputs: External cache. Outputs: Hash-verified wheel."""
    from tools.crawl4ai_tool import installation_lock

    data = recipe()
    directory = home / ("crawl4ai-wheel-" + identity()[:16])
    wheel = directory / f"crawl4ai-{data['version']}-py3-none-any.whl"
    expected = packaging.expected_digest(SOURCE_ROOT / "crawl4ai-wheel.sha256")
    with installation_lock(directory):
        if not wheel.exists():
            wheel = build_wheel(home, directory, data)
        if packaging.digest(wheel) != expected:
            raise ValueError("Crawl4AI repaired wheel digest mismatch; installation refused")
    return wheel
