"""Read-only Windows ZIP verification. Never extract or execute packaged files.

Run this script from a trusted source checkout, not from an unverified download.
Checksums and embedded metadata establish consistency, not publisher identity.
Verify the GitHub attestation and Windows Authenticode signature separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any, BinaryIO

from release_guard import DEEP, EXACT, GateError, parse_time

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_MEMBER = 256 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_METADATA = 8 * 1024 * 1024
MAX_DIRECTORY = 2 * 1024 * 1024
CHUNK = 64 * 1024
EXECUTABLES = frozenset({"rejection-rejector.exe", "rr.exe"})
REQUIRED = EXECUTABLES | frozenset({
    "README.md", "LICENSE", "SECURITY.md", "CHANGELOG.md", "Cargo.lock",
    "COMMIT.txt", "toolchain.txt", "build-info.json", "contract-info.json",
    "signing.json", "rejection-rejector.cdx.json", "release-evidence.json", "SHA256SUMS.txt",
    "docs/openapi-v1.json", "docs/enterprise-policy.schema.json",
})
METADATA = frozenset({
    "COMMIT.txt", "build-info.json", "contract-info.json", "signing.json",
    "rejection-rejector.cdx.json", "release-evidence.json", "SHA256SUMS.txt",
})
RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "123456789¹²³"
}


class PackageError(RuntimeError):
    """An invalid or incomplete package must not be deployed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageError(message)


def safe_name(name: str, directory: bool = False) -> str:
    require(isinstance(name, str) and bool(name) and len(name) <= 1024, "Invalid archive path")
    require(not any(ord(c) < 32 or ord(c) == 127 or c in '\\<>:"|?*' for c in name),
            "Unsafe Windows archive path")
    if directory:
        require(name.endswith("/"), "Invalid directory entry")
        name = name[:-1]
    parts = name.split("/")
    for part in parts:
        require(part not in {"", ".", ".."} and not part.endswith((".", " ")),
                "Archive path is absolute, traversing or ambiguous")
        require(part.split(".")[0].rstrip(" ").upper() not in RESERVED, "Archive path uses a Windows device name")
    return name


def preflight_directory(handle: BinaryIO, size: int) -> None:
    """Bound central-directory allocation before zipfile creates member objects.

    Release packages fit ordinary single-disk ZIP. ZIP64 and prepended executable
    stubs are intentionally unsupported, not silently handled as a different format.
    """
    require(size >= 22, "Truncated ZIP end record")
    handle.seek(max(0, size - 65557))
    tail = handle.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    require(offset >= 0 and len(tail) - offset >= 22, "Missing ZIP end record")
    fields = struct.unpack_from("<4s4H2LH", tail, offset)
    _, disk, directory_disk, disk_entries, entries, directory_size, directory_offset, comment = fields
    require(offset + 22 + comment == len(tail), "Ambiguous ZIP end record or trailing data")
    require(disk == directory_disk == 0 and disk_entries == entries, "Split ZIP archives are unsupported")
    require(0 < entries <= MAX_ENTRIES, "Archive entry count exceeds policy")
    require(0 < directory_size <= MAX_DIRECTORY, "ZIP directory exceeds size policy")
    end_position = size - len(tail) + offset
    require(directory_offset + directory_size == end_position, "ZIP64 or inconsistent directory offsets")
    handle.seek(0)
    require(handle.read(4) == b"PK\x03\x04", "ZIP has an unsupported prefix")
    handle.seek(0)


def allowed_payload(name: str) -> bool:
    if name in REQUIRED:
        return True
    parts = name.split("/")
    if any(part.startswith(".") or part == "__pycache__" for part in parts):
        return False
    suffix = Path(name).suffix.lower()
    return (parts[0] == "docs" and suffix in {".md", ".json"}
            or parts[0] == "scripts" and suffix in {".py", ".ps1", ".sh"})


def inventory(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    entries = archive.infolist()
    require(0 < len(entries) <= MAX_ENTRIES, "Archive entry count exceeds policy")
    files: dict[str, zipfile.ZipInfo] = {}
    names: dict[str, bool] = {}
    total = 0
    for entry in entries:
        name = safe_name(entry.orig_filename, entry.is_dir())
        require(entry.orig_filename == entry.filename, "Archive filename was truncated or rewritten")
        key = name.casefold()
        require(key not in names, "Duplicate or case-colliding archive entry")
        names[key] = entry.is_dir()
        mode = stat.S_IFMT(entry.external_attr >> 16)
        expected = stat.S_IFDIR if entry.is_dir() else stat.S_IFREG
        require(mode in {0, expected}, "Archive contains a symlink or special file")
        require(not entry.flag_bits & 1, "Encrypted ZIP entries are not supported")
        require(entry.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
                "Unsupported ZIP compression")
        require(0 <= entry.file_size <= MAX_MEMBER, "Archive member exceeds size policy")
        total += entry.file_size
        require(total <= MAX_TOTAL, "Expanded archive exceeds size policy")
        if entry.is_dir():
            require(entry.file_size == 0, "Directory entry contains file data")
        else:
            require(allowed_payload(name), "Unexpected file type or location in release package")
            files[name] = entry
    for key in names:
        parts = key.split("/")
        for length in range(1, len(parts)):
            require(names.get("/".join(parts[:length]), True), "File/directory path collision")
    require(REQUIRED <= files.keys(), "Required release files are missing")
    return files


def read_member(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, limit: int) -> bytes:
    require(entry.file_size <= limit, "Metadata exceeds size policy")
    with archive.open(entry) as stream:
        data = stream.read(limit + 1)
    require(len(data) == entry.file_size and len(data) <= limit, "Invalid metadata size")
    return data


def checksum_manifest(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeError as error:
        raise PackageError("Checksum manifest must be ASCII") from error
    result = {}
    aliases = set()
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "Invalid checksum manifest line")
        digest, name = match.groups()
        name = safe_name(name)
        require(name != "SHA256SUMS.txt", "Checksum manifest cannot include itself")
        require(name.casefold() not in aliases, "Duplicate checksum manifest entry")
        aliases.add(name.casefold())
        result[name] = digest
    require(bool(result), "Checksum manifest is empty")
    return result


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON metadata key")
        result[key] = value
    return result


def read_json(data: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_object,
                         parse_constant=lambda _: require(False, "Non-finite JSON metadata"))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise PackageError("Invalid package JSON metadata") from error
    require(isinstance(obj, dict), "Package metadata must be a JSON object")
    return obj


def positive_integer(value: Any) -> bool:
    return type(value) is int and value > 0


def schema_one(value: dict[str, Any]) -> bool:
    return type(value.get("schema_version")) is int and value["schema_version"] == 1


def signing_check(signature: dict[str, Any], hashes: dict[str, str], signing: str) -> None:
    signed = signing == "azure-artifact-signing"
    require(schema_one(signature) and signature.get("requested_mode") == signing,
            "Signing mode differs from requested package flavor")
    require(signature.get("verified_signed") is signed, "Inconsistent signing metadata")
    records = signature.get("files")
    require(isinstance(records, list) and len(records) == 2, "Invalid executable signing records")
    seen = set()
    for record in records:
        require(isinstance(record, dict), "Invalid executable signing record")
        name = record.get("file")
        require(isinstance(name, str) and name in EXECUTABLES and name not in seen,
                "Missing or duplicate executable signing record")
        seen.add(name)
        require(record.get("sha256") == hashes[name], "Signature record does not describe packaged executable")
        require(record.get("requested_mode") == signing, "Inconsistent executable signing mode")
        require(record.get("status") == ("Valid" if signed else "NotSigned"),
                "Executable signature status does not match package flavor")
        for key in ("signer_subject", "signer_thumbprint", "timestamper_subject"):
            value = record.get(key)
            if signed:
                require(isinstance(value, str) and bool(value.strip()),
                        "Signed package lacks publisher/timestamp evidence")
            else:
                require(value is None, "Unsigned package carries inconsistent certificate evidence")


def evidence_check(evidence: dict[str, Any], commit: str) -> None:
    require(schema_one(evidence) and evidence.get("source_commit") == commit,
            "Release evidence does not match expected source")
    require(evidence.get("repository") == "strmt7/rejection-rejector", "Unexpected release-evidence repository")
    try:
        checked_at = parse_time(evidence.get("checked_at"))
    except GateError as error:
        raise PackageError("Invalid release-evidence timestamp") from error
    rows = evidence.get("automated_evidence")
    expected = set(EXACT) | set(DEEP)
    require(isinstance(rows, list) and len(rows) == len(expected), "Incomplete automated release evidence")
    seen = set()
    for row in rows:
        require(isinstance(row, dict), "Invalid automated evidence record")
        workflow = row.get("workflow")
        require(isinstance(workflow, str) and workflow in expected and workflow not in seen,
                "Duplicate or unexpected workflow evidence")
        seen.add(workflow)
        require(positive_integer(row.get("run_id")) and positive_integer(row.get("run_attempt")),
                "Invalid workflow run identity")
        source = row.get("commit")
        require(isinstance(source, str) and bool(COMMIT.fullmatch(source)), "Invalid workflow source identity")
        require(row.get("conclusion") == "success", "Unsuccessful workflow in release evidence")
        if workflow in EXACT:
            require(source == commit, "Exact-commit evidence describes a different source")
        try:
            age = checked_at - parse_time(row.get("updated_at"))
        except GateError as error:
            raise PackageError("Invalid workflow evidence timestamp") from error
        # Freshness is evaluated at packaging time, not the later download date.
        require(-300 <= age.total_seconds() <= 8 * 86400, "Evidence was stale or future-dated when packaged")


def build_identity(build: dict[str, Any]) -> str:
    digest = hashlib.sha256(b"rejection-rejector-build-identity-v1\0")
    for key in ("application_version", "source_commit", "rustc_version", "target", "profile", "cargo_lock_sha256"):
        value = build.get(key)
        require(isinstance(value, str) and 0 < len(value) <= 256
                and not any(ord(c) < 32 or ord(c) == 127 for c in value), "Invalid build-identity field")
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    return digest.hexdigest()


def metadata_check(data: dict[str, bytes], hashes: dict[str, str], commit: str, signing: str) -> None:
    require(data["COMMIT.txt"].decode("ascii").strip() == commit, "COMMIT.txt does not match expected source")
    build = read_json(data["build-info.json"])
    require(schema_one(build), "Unsupported build metadata schema")
    require(build.get("source_commit") == commit and build.get("source_commit_verified") is True,
            "Build metadata does not match expected source")
    require(build.get("target") == "x86_64-pc-windows-msvc" and build.get("profile") == "release",
            "Build metadata is not a Windows x64 release")
    require(build.get("cargo_lock_sha256") == hashes["Cargo.lock"], "Packaged Cargo.lock differs from build metadata")
    require(build.get("identity_sha256") == build_identity(build), "Build identity checksum is inconsistent")
    contract = read_json(data["contract-info.json"])
    require(schema_one(contract), "Unsupported compatibility metadata schema")
    require(contract.get("api_contract_sha256") == hashes["docs/openapi-v1.json"],
            "Packaged API contract differs from embedded-contract metadata")
    require(contract.get("enterprise_policy_schema_sha256") == hashes["docs/enterprise-policy.schema.json"],
            "Packaged policy contract differs from embedded-contract metadata")
    require(positive_integer(contract.get("settings_format_version"))
            and positive_integer(contract.get("database_schema_version")), "Invalid persistence versions")
    evaluation = contract.get("evaluation_suite_sha256")
    require(isinstance(evaluation, str) and bool(SHA256.fullmatch(evaluation)), "Invalid evaluation fingerprint")
    evidence_check(read_json(data["release-evidence.json"]), commit)
    sbom = read_json(data["rejection-rejector.cdx.json"])
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.5",
            "Unsupported SBOM format")
    signing_check(read_json(data["signing.json"]), hashes, signing)


def verify(path: Path, commit: str, signing: str, expected_sha256: str | None = None) -> dict[str, Any]:
    require(bool(COMMIT.fullmatch(commit)), "Expected a lowercase 40-character source commit")
    require(signing in {"unsigned", "azure-artifact-signing"}, "Invalid signing mode")
    require(expected_sha256 is None or bool(SHA256.fullmatch(expected_sha256)), "Invalid expected ZIP checksum")
    require(path.is_file() and not path.is_symlink(), "Expected a regular package file")
    require(0 < path.stat().st_size <= MAX_ARCHIVE, "Archive exceeds size policy")
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_ARCHIVE,
                    "Opened package is not a bounded regular file")
            preflight_directory(handle, before.st_size)
            digest = hashlib.sha256()
            size = 0
            while chunk := handle.read(CHUNK):
                size += len(chunk)
                require(size <= MAX_ARCHIVE, "Archive grew beyond size policy")
                digest.update(chunk)
            require(size == before.st_size, "Archive changed while being hashed")
            archive_hash = digest.hexdigest()
            require(expected_sha256 is None or archive_hash == expected_sha256, "ZIP checksum mismatch")
            handle.seek(0)
            with zipfile.ZipFile(handle) as archive:
                files = inventory(archive)
                manifest = checksum_manifest(read_member(archive, files["SHA256SUMS.txt"], MAX_METADATA))
                require(manifest.keys() == files.keys() - {"SHA256SUMS.txt"},
                        "Checksum manifest does not cover the exact archive file set")
                data = {}
                total = 0
                for name, entry in files.items():
                    digest = hashlib.sha256()
                    count = 0
                    saved = bytearray() if name in METADATA else None
                    with archive.open(entry) as stream:
                        while chunk := stream.read(CHUNK):
                            count += len(chunk)
                            total += len(chunk)
                            require(count <= MAX_MEMBER and total <= MAX_TOTAL, "Expanded data exceeds size policy")
                            digest.update(chunk)
                            if saved is not None:
                                require(count <= MAX_METADATA, "Metadata exceeds size policy")
                                saved.extend(chunk)
                    require(count == entry.file_size, "Expanded member size differs from directory")
                    if name != "SHA256SUMS.txt":
                        require(digest.hexdigest() == manifest[name], "Packaged file checksum mismatch")
                    if saved is not None:
                        data[name] = bytes(saved)
                metadata_check(data, manifest, commit, signing)
            after = os.fstat(handle.fileno())
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "Archive changed during verification")
        return {"schema_version": 1, "source_commit": commit, "archive_sha256": archive_hash,
                "expected_archive_hash_matched": expected_sha256 is not None,
                "files_verified": len(manifest), "expanded_bytes": total, "signing_mode": signing,
                "authenticode_checked": False, "attestation_checked": False,
                "scope": "Internal package consistency only; publisher identity requires independent signature/attestation verification."}
    except PackageError:
        raise
    except (OSError, UnicodeError, zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError, EOFError, KeyError, TypeError) as error:
        raise PackageError("Package could not be read and verified safely") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--signing-mode", required=True, choices=("unsigned", "azure-artifact-signing"))
    parser.add_argument("--expected-sha256")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.package, args.expected_commit, args.signing_mode, args.expected_sha256)
        text = json.dumps(report, indent=2) + "\n"
        if args.report:
            require(args.report.resolve() != args.package.resolve(), "Report cannot overwrite the package")
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(text, encoding="utf-8")
        print(text, end="")
        return 0
    except (PackageError, OSError) as error:
        print(f"Package verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
