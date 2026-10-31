"""Admit the unmodified official NLTK wheel and verify its installed runtime."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from email.parser import BytesParser
from pathlib import Path

from tools.python_wheel import MAX_SOURCE_BYTES, digest, read_recipe, wheel_files

ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOT = ROOT / "third_party/upstream/nltk/3.10.4"


def distribution() -> dict:
    """Purpose: Validate exact upstream provenance. Inputs: Tracked record. Outputs: Admitted metadata."""
    data = read_recipe(SOURCE_ROOT / "distribution.json")
    if not isinstance(data, dict) or not isinstance(data.get("version"), str) or not isinstance(data.get("tag"), str):
        raise ValueError("Unsupported NLTK upstream distribution record")
    version = data.get("version", "")
    filename = f"nltk-{version}-py3-none-any.whl"
    tag = data.get("tag", "")
    if (
        type(data.get("schema")) is not int
        or data["schema"] != 1
        or data.get("project") != "nltk"
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
        or not re.fullmatch(re.escape("v" + version) + r"(?:-rc[1-9][0-9]*)?", tag)
        or data.get("filename") != filename
        or data.get("release_url") != f"https://github.com/nltk/nltk/releases/tag/{tag}"
        or data.get("url") != f"https://github.com/nltk/nltk/releases/download/{tag}/{filename}"
        or data.get("release_kind") != ("release_candidate" if "-rc" in tag else "stable")
        or data.get("license") != "Apache-2.0"
        or data.get("license_member") != f"nltk-{version}.dist-info/licenses/LICENSE.txt"
        or not isinstance(data.get("sha256"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", data.get("sha256", ""))
        or type(data.get("size")) is not int
        or not 0 < data["size"] <= MAX_SOURCE_BYTES
    ):
        raise ValueError("Unsupported NLTK upstream distribution record")
    return data


def verify_wheel(path: Path, data: dict) -> Path:
    """Purpose: Admit original upstream bytes. Inputs: Asset and provenance. Outputs: Verified wheel or refusal."""
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        or info.st_size != data["size"]
        or digest(path) != data["sha256"]
    ):
        raise ValueError("NLTK upstream wheel digest or size mismatch, or redirected asset")
    files = wheel_files(path)
    prefix = f"nltk-{data['version']}.dist-info/"
    metadata = BytesParser().parsebytes(files[prefix + "METADATA"])
    wheel = BytesParser().parsebytes(files[prefix + "WHEEL"])
    if (
        metadata.get_all("Name") != ["nltk"]
        or metadata.get_all("Version") != [data["version"]]
        or files["nltk/VERSION"].decode("ascii").strip() != data["version"]
        or wheel.get_all("Root-Is-Purelib") != ["true"]
        or wheel.get_all("Tag") != ["py3-none-any"]
        or len(files[prefix + "licenses/LICENSE.txt"]) < 100
        or len(files[prefix + "licenses/AUTHORS.md"]) < 100
    ):
        raise ValueError("NLTK wheel metadata, runtime or original notices disagree with provenance")
    return path


def wheel_path(home: Path | None = None) -> Path:
    """Purpose: Cache the official asset outside Git. Inputs: Optional tool home. Outputs: Verified wheel.
    Downloads use pip's normal HTTPS transport and hash admission; package installation still resolves dependencies.
    """
    from tools.crawl4ai_source_build import builder_python
    from tools.crawl4ai_tool import cache_home, installation_lock, run, tool_environment

    data = distribution()
    home = cache_home(str(home) if home is not None else None)
    directory = home / "wheels" / ("nltk-" + data["sha256"])
    if directory.is_symlink() or directory.is_junction():
        raise ValueError("NLTK wheel cache is redirected")
    with installation_lock(directory, timeout=180):
        destination = directory / data["filename"]
        if destination.exists() or destination.is_symlink():
            return verify_wheel(destination, data)
        with tempfile.TemporaryDirectory(prefix="download-", dir=directory) as temporary:
            stage = Path(temporary)
            requirements = stage / "asset.txt"
            requirements.write_text(f"nltk @ {data['url']} --hash=sha256:{data['sha256']}\n", encoding="utf-8")
            run(
                [
                    str(builder_python(home)),
                    "-m",
                    "pip",
                    "download",
                    "--disable-pip-version-check",
                    "--require-hashes",
                    "--only-binary=:all:",
                    "--no-deps",
                    "--timeout",
                    "30",
                    "--retries",
                    "2",
                    "--dest",
                    str(stage),
                    "-r",
                    str(requirements),
                ],
                tool_environment(home),
                180,
            )
            verified = verify_wheel(stage / data["filename"], data)
            os.replace(verified, destination)
        return verify_wheel(destination, data)


def identity() -> str:
    """Purpose: Isolate the pinned distribution. Inputs: Validated provenance. Outputs: Cache identity."""
    from tools.crawl4ai_tool import text_identity

    data = distribution()
    return hashlib.sha256(
        (text_identity(SOURCE_ROOT / "distribution.json") + data["sha256"]).encode("ascii")
    ).hexdigest()


def runtime_source_sha256(home: Path | None = None) -> str:
    """Purpose: Bind installed runtime to upstream bytes. Inputs: Official wheel. Outputs: Canonical source digest."""
    files = wheel_files(wheel_path(home))
    hashes = {
        name: hashlib.sha256(contents.replace(b"\r\n", b"\n")).hexdigest()
        for name, contents in files.items()
        if name.startswith("nltk/") and (name.lower().endswith(".py") or name == "nltk/VERSION")
    }
    if "nltk/__init__.py" not in hashes or "nltk/VERSION" not in hashes:
        raise ValueError("NLTK runtime source is incomplete")
    return hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def _reject_entry_redirect(entries: int, info: os.stat_result) -> None:
    """Purpose: Refuse redirected or excessive tree entries.

    Inputs: Entry count and its lstat result;
    Output: None; raises ValueError on any redirect or overflow.
    """
    if (
        entries > 10000
        or stat.S_ISLNK(info.st_mode)
        or (getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    ):
        raise ValueError("NLTK installed runtime exceeds admission or contains a redirect")


def _reject_file_kind(path: Path) -> None:
    """Purpose: Refuse unreviewed executable or bytecode files.

    Inputs: Candidate file path;
    Output: None; raises ValueError on native images or unreviewed bytecode.
    """
    if path.suffix.lower() in (".pyd", ".so", ".dll", ".dylib"):
        raise ValueError("NLTK admitted runtime contains a native executable file")
    if path.suffix.lower() == ".pyo" or (path.suffix.lower() == ".pyc" and path.parent.name != "__pycache__"):
        raise ValueError("NLTK admitted runtime contains unreviewed sourceless bytecode")


def installed_runtime_sha256(root: Path) -> str:
    """Purpose: Measure installed source without importing it. Inputs: Package directory. Outputs: Bounded digest."""
    root_info = root.lstat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or getattr(root_info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError("NLTK installed runtime is missing or redirected")
    hashes = {}
    total = entries = 0
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                entries += 1
                info = child.stat(follow_symlinks=False)
                _reject_entry_redirect(entries, info)
                path = Path(child.path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                    continue
                name = path.relative_to(root).as_posix()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("NLTK installed runtime contains a special file")
                _reject_file_kind(path)
                if path.suffix.lower() != ".py" and name != "VERSION":
                    continue
                with path.open("rb") as stream:
                    contents = stream.read(MAX_SOURCE_BYTES - total + 1)
                total += len(contents)
                if total > MAX_SOURCE_BYTES:
                    raise ValueError("NLTK installed runtime exceeds its source byte budget")
                hashes["nltk/" + name] = hashlib.sha256(contents.replace(b"\r\n", b"\n")).hexdigest()
    return hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def verify_installed_runtime(expected_sha256: str) -> None:
    """Verify installed filesystem source before importing any NLTK code.

    Archive-backed metadata providers cannot supply the no-follow filesystem
    checks required by admission. Refuse them instead of interpreting their
    display names as paths. Invalid identity, location or bytes raise ValueError.
    """
    import importlib.metadata

    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("Malformed NLTK runtime source identity")
    location = importlib.metadata.distribution("nltk").locate_file("nltk")
    if not isinstance(location, (str, os.PathLike)):
        raise ValueError("NLTK runtime requires a filesystem installation")
    path = os.fspath(location)
    if not isinstance(path, str):
        raise ValueError("NLTK runtime requires a text filesystem path")
    root = Path(path)
    if installed_runtime_sha256(root) != expected_sha256:
        raise ValueError("NLTK installed runtime source changed; upstream dependency refused")
