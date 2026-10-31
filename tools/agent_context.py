"""Bounded source reads and explicit, provenance-aware development notes.

No model, network, transcript capture, global memory or acceptance cache is used.
State is disposable and stays under the checkout's ignored out/agent-context tree.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
MAX_FILE_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
SKILLS = ("caveman", "cocoindex-code-search")
KEY = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


def relative_source_path(name: str) -> PurePosixPath:
    """Purpose: Apply one portable non-secret path policy to context reads and code mirroring.
    Inputs: Repository-relative name. Outputs: Parsed path or refusal before filesystem access.
    """
    relative = PurePosixPath(name)
    if (
        not name
        or not relative.parts
        or relative.is_absolute()
        or "\\" in name
        or any(
            part != part.rstrip(" .") or part.lower() in (".", "..", ".git", "secrets") or ":" in part
            for part in relative.parts
        )
        or relative.name.lower().startswith(".env")
        or relative.suffix.lower() in (".pem", ".key", ".p12", ".pfx")
    ):
        raise ValueError("expected a repository-relative, non-secret path")
    return relative


def safe_path(root: Path, name: str) -> Path:
    """Purpose: Contain local paths.
    Inputs: root/relative name.
    Outputs: path or rejection, including reparse points.
    """
    relative = relative_source_path(name)
    selected = root.resolve()
    for part in relative.parts:
        selected /= part
        if selected.is_symlink() or (selected.exists() and getattr(selected.lstat(), "st_file_attributes", 0) & 0x400):
            raise ValueError("reparse points are not admitted")
    if not selected.resolve().is_relative_to(root.resolve()):
        raise ValueError("path escapes checkout")
    return selected


def read_source(root: Path, name: str, *, max_bytes: int = MAX_FILE_BYTES) -> tuple[str, str]:
    """Purpose: Read bounded exact text.
    Inputs: root/path and byte budget.
    Outputs: UTF-8 text and SHA-256; rejects binary/large input.
    """
    path = safe_path(root, name)
    with path.open("rb") as source:
        raw = source.read(max_bytes + 1)
    if len(raw) > max_bytes or b"\0" in raw:
        raise ValueError(f"source exceeds {max_bytes} bytes or contains binary data")
    return raw.decode("utf-8-sig"), hashlib.sha256(raw).hexdigest()


def load_state(root: Path, name: str) -> dict:
    """Purpose: Load optional disposable state. Inputs: local path. Outputs: schema-1 object or explicit failure."""
    path = safe_path(root, name)
    if not path.exists():
        return {"schema": 1}
    text, _ = read_source(root, name)
    value = json.loads(
        text,
        object_pairs_hook=unique_json_object,
        parse_constant=reject_json_constant,
        parse_float=finite_json_float,
    )
    if not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("unsupported context state; use a new session/key")
    return value


def write_state(root: Path, name: str, value: dict, *, exclusive: bool = False) -> None:
    """Purpose: Publish local state.
    Inputs: contained path/object.
    Outputs: atomic file, refusing exclusive collisions.
    """
    path = safe_path(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_path(root, name)
    payload = (json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError("context state exceeds 1 MiB; use a new session/key")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".context-", delete=False) as output:
            temporary = Path(output.name)
            output.write(payload)
        if exclusive:
            # Linking publishes a complete file without replacing an existing note.
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def state_name(category: str, key: str) -> str:
    """Purpose: Scope explicit state identifiers. Inputs: fixed category/key. Outputs: ignored relative JSON path."""
    if not KEY.fullmatch(key):
        raise ValueError("key/session must contain 1-64 lowercase letters, digits or hyphens")
    return f"out/agent-context/{category}/{key}.json"


def headings(text: str) -> list[dict]:
    """Purpose: Map ATX sections.
    Inputs: Markdown.
    Outputs: heading spans with descendants, ignoring fenced examples.
    """
    result = []
    fence = None
    lines = text.splitlines(keepends=True)
    for number, line in enumerate(lines, 1):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = (run[0], len(run))
            elif run[0] == fence[0] and len(run) >= fence[1] and not line[marker.end() :].strip():
                fence = None
            continue
        match = re.match(r"^ {0,3}(#{1,6})[ \t]+(.+?)\s*$", line)
        if fence is None and match:
            title = re.sub(r"[ \t]+#+[ \t]*$", "", match.group(2))
            result.append({"title": title, "level": len(match.group(1)), "start": number})
    for index, heading in enumerate(result):
        heading["end"] = next(
            (other["start"] - 1 for other in result[index + 1 :] if other["level"] <= heading["level"]),
            len(lines),
        )
    return result


def source_window(text: str, section: str | None, start: int, end: int | None) -> tuple[int, int]:
    """Purpose: Select exact source extent.
    Inputs: heading or line range.
    Outputs: inclusive span; ambiguous/missing fails.
    """
    length = len(text.splitlines())
    if section is not None:
        selected = [item for item in headings(text) if item["title"] == section]
        if len(selected) != 1:
            raise ValueError("section must match exactly one heading; inspect outline or use line bounds")
        return selected[0]["start"], selected[0]["end"]
    last = length if end is None else end
    if start < 1 or last < start or last > length:
        raise ValueError("line range lies outside source")
    return start, last


def read_window(root: Path, args: argparse.Namespace) -> dict:
    """Purpose: Reduce repeated context.
    Inputs: source/window/budget/explicit session.
    Outputs: lines and unread extent.
    """
    text, digest = read_source(root, args.path)
    start, end = source_window(text, args.section, args.start, args.end)
    record = {"path": args.path, "sha256": digest, "start": start, "end": end}
    state = {"schema": 1, "reads": []}
    cache_name = state_name("sessions", args.session) if args.session else None
    if cache_name:
        state = load_state(root, cache_name)
        if not isinstance(state.get("reads", []), list) or len(state.get("reads", [])) > 200:
            raise ValueError("invalid/oversized read history; use a new session")
        if not args.force and record in state.get("reads", []):
            return {**record, "status": "unchanged_in_explicit_session", "content": "", "unread": None}
    selected = text.splitlines(keepends=True)[start - 1 : end]
    emitted = []
    used = 0
    for number, line in enumerate(selected, start):
        value = f"{number}: {line.rstrip(chr(10)).rstrip(chr(13))}\n"
        if used + len(value) > args.max_chars:
            break
        emitted.append(value)
        used += len(value)
    complete = len(emitted) == len(selected)
    result = {
        **record,
        "status": "complete" if complete else "partial",
        "content": "".join(emitted),
        "unread": None if complete else {"start": start + len(emitted), "end": end},
        "content_chars": used,
    }
    if cache_name and complete:
        reads = state.setdefault("reads", [])
        if record not in reads:
            if len(reads) >= 200:
                raise ValueError("session read history is full; use a new session")
            reads.append(record)
            write_state(root, cache_name, state)
    return result


def unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Purpose: Refuse ambiguous evidence. Inputs: Decoded JSON members. Outputs: Unique-key object or error."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member; evidence selection is ambiguous")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    """Purpose: Reject non-JSON numbers. Inputs: Decoder constant. Outputs: Explicit refusal."""
    raise ValueError(f"non-finite JSON number is not evidence: {value}")


def finite_json_float(value: str) -> float:
    """Purpose: Reject overflowing JSON numbers. Inputs: Numeric text. Outputs: Finite float or explicit refusal."""
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON number exceeds the finite float range")
    return number


def json_pointer(value: object, pointer: str) -> object:
    """Purpose: Select exact evidence. Inputs: JSON value and RFC 6901 pointer. Outputs: Selected value or error."""
    if not pointer:
        return value
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValueError("expected an RFC 6901 JSON pointer")
    for encoded in pointer[1:].split("/"):
        key = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value[key]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", key):
            value = value[int(key)]
        else:
            raise ValueError("JSON pointer does not identify an object member or array item")
    return value


def json_shape(value: object) -> dict:
    """Purpose: Describe omitted payloads honestly. Inputs: JSON value. Outputs: Type and exact extent."""
    if isinstance(value, dict):
        return {"kind": "object", "count": len(value)}
    if isinstance(value, list):
        return {"kind": "array", "count": len(value)}
    if isinstance(value, str):
        return {"kind": "string", "characters": len(value)}
    return {"kind": "scalar"}


def compact_json(value: object) -> str:
    """Purpose: Measure the actual emitted representation. Inputs: JSON value. Outputs: Compact ASCII JSON."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def json_member(pointer: str, value: object) -> dict:
    """Purpose: Bound one displayed value. Inputs: Exact pointer/value. Outputs: Scalar or explicit omitted shape."""
    result = {"pointer": pointer, **json_shape(value), "expanded": False}
    if not isinstance(value, (dict, list)) and len(compact_json(value)) <= 512:
        result.update(expanded=True, value=value)
    return result


def _report_scalar(result: dict, selected: object, args: argparse.Namespace) -> dict:
    """
    Purpose: Expand a scalar JSON selection under budget.
    Inputs: Base report, the scalar value and the invocation arguments;
    Output: The finished scalar report; raises ValueError when a page offset was requested or the report overflows.
    """
    if args.offset:
        raise ValueError("scalar JSON selection has no page offset")
    full = {**result, "expanded": True, "value": selected}
    return full if len(compact_json(full)) <= args.max_chars else {**result, "expanded": False}


def _page_member(base_pointer: str, key: object, item: object, fields: list[str]) -> dict:
    """
    Purpose: Build one paged member entry.
    Inputs: The selection pointer, the member key, the member value and optional field names;
    Output: The member entry with its exact pointer; raises ValueError when projection targets a non-object.
    """
    pointer = base_pointer + "/" + str(key).replace("~", "~0").replace("/", "~1")
    entry = json_member(pointer, item)
    if fields:
        if not isinstance(item, dict):
            raise ValueError("field projection requires object array items")
        entry["fields"] = [
            json_member(pointer + "/" + field.replace("~", "~0").replace("/", "~1"), item[field]) for field in fields
        ]
    return entry


def _report_page(result: dict, selected: dict | list, args: argparse.Namespace, fields: list[str]) -> dict:
    """
    Purpose: Page a container JSON selection under budget.
    Inputs: Base report, the selected container, the invocation arguments and optional field names;
    Output: The finished paged report; raises ValueError when a page cannot fit or the report overflows.
    """
    if args.offset > len(selected):
        raise ValueError("JSON page offset exceeds the selected container")
    members = list(selected.items()) if isinstance(selected, dict) else list(enumerate(selected))
    result.update(offset=args.offset, items=[], next_offset=args.offset, omitted_values=0)
    for index, (key, item) in enumerate(members[args.offset : args.offset + args.limit], args.offset):
        entry = _page_member(args.pointer, key, item, fields)
        candidate = {
            **result,
            "items": [*result["items"], entry],
            "next_offset": index + 1 if index + 1 < len(members) else None,
            "omitted_values": result["omitted_values"] + int(not entry["expanded"]),
        }
        if len(compact_json(candidate)) > args.max_chars:
            break
        result = candidate
    if args.offset == len(members):
        result["next_offset"] = None
    if result["next_offset"] == args.offset:
        raise ValueError("JSON page budget cannot fit one item; select a narrower pointer or increase the budget")
    return result


def json_report(root: Path, args: argparse.Namespace) -> dict:
    """Purpose: Inspect evidence without flooding context.
    Inputs: Bounded JSON, exact pointer and page/output budgets. Outputs: Source-bound page and explicit omissions.
    """
    text, digest = read_source(root, args.path, max_bytes=MAX_REPORT_BYTES)
    value = json.loads(
        text,
        object_pairs_hook=unique_json_object,
        parse_constant=reject_json_constant,
        parse_float=finite_json_float,
    )
    selected = json_pointer(value, args.pointer)
    fields = args.field
    if fields and (not isinstance(selected, list) or len(fields) > 16 or len(fields) != len(set(fields))):
        raise ValueError("field projection requires an array and 1-16 unique member names")
    shape = json_shape(selected)
    result = {
        "path": args.path,
        "sha256": digest,
        "pointer": args.pointer,
        **shape,
        "acceptance": "not_established_by_context_tool",
    }
    if not isinstance(selected, (dict, list)):
        result = _report_scalar(result, selected, args)
    else:
        result = _report_page(result, selected, args, fields)
    if len(compact_json(result)) > args.max_chars:
        raise ValueError("JSON metadata exceeds the output budget; use a larger explicit budget")
    return result


def python_symbols(text: str) -> list[dict]:
    """Purpose: Route Python reads without importing code.
    Inputs: Exact source text. Outputs: Ordered qualified definition names and inclusive source spans.
    """
    result = []

    def visit(node: ast.AST, prefix: str) -> None:
        """Purpose: Retain lexical scope. Inputs: AST node and parent name. Outputs: Appended definition spans."""
        for child in ast.iter_child_nodes(node):
            scope = prefix
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = prefix + child.name
                result.append(
                    {
                        "name": scope,
                        "kind": "class" if isinstance(child, ast.ClassDef) else "function",
                        "start": min([child.lineno, *(item.lineno for item in child.decorator_list)]),
                        "end": child.end_lineno,
                    }
                )
                scope += "."
            visit(child, scope)

    visit(ast.parse(text), "")
    return result


def source_outline(root: Path, args: argparse.Namespace) -> dict:
    """Purpose: Bound source navigation output.
    Inputs: Source path and page/output budgets. Outputs: Exact heading or Python definition page and continuation.
    """
    text, digest = read_source(root, args.path)
    key = "symbols" if Path(args.path).suffix in (".py", ".pyi") else "headings"
    entries = python_symbols(text) if key == "symbols" else headings(text)
    if args.offset > len(entries):
        raise ValueError("outline offset exceeds its entry count")
    result = {
        "path": args.path,
        "sha256": digest,
        "count": len(entries),
        "offset": args.offset,
        key: [],
        "next_offset": args.offset if args.offset < len(entries) else None,
    }
    for index, entry in enumerate(entries[args.offset : args.offset + args.limit], args.offset):
        candidate = {
            **result,
            key: [*result[key], entry],
            "next_offset": index + 1 if index + 1 < len(entries) else None,
        }
        if len(compact_json(candidate)) > args.max_chars:
            break
        result = candidate
    if result["next_offset"] == args.offset or len(compact_json(result)) > args.max_chars:
        raise ValueError("outline budget cannot fit an entry and metadata; increase the explicit budget")
    return result


def remember(root: Path, args: argparse.Namespace) -> dict:
    """Purpose: Persist explicit synthesis.
    Inputs: summary file/kind/source paths/TTL.
    Outputs: new cited note, no overwrite.
    """
    summary, _ = read_source(root, args.summary_file)
    if not summary.strip() or len(summary) > 4000:
        raise ValueError("note summary must contain 1-4000 characters")
    sources = []
    for name in dict.fromkeys(args.source):
        _, digest = read_source(root, name)
        sources.append({"path": name, "sha256": digest})
    if not 1 <= len(sources) <= 32:
        raise ValueError("note requires 1-32 explicit evidence paths")
    now = datetime.now(UTC)
    note = {
        "schema": 1,
        "kind": args.kind,
        "summary": summary,
        "sources": sources,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=args.expires_hours)).isoformat(),
        "acceptance": "not_established_by_context_tool",
    }
    name = state_name("notes", args.key)
    write_state(root, name, note, exclusive=True)
    return {"note": name, "sources": sources, "expires_at": note["expires_at"], "acceptance": note["acceptance"]}


def recall(root: Path, key: str) -> dict:
    """Purpose: Validate cited note freshness.
    Inputs: existing key.
    Outputs: synthesis only when declared evidence/TTL match.
    """
    name = state_name("notes", key)
    note = load_state(root, name)
    if not isinstance(note.get("sources"), list) or not 1 <= len(note["sources"]) <= 32:
        raise ValueError("note has no bounded source provenance")
    reasons = []
    for source in note["sources"]:
        try:
            _, current = read_source(root, source["path"])
            if current != source["sha256"]:
                reasons.append({"path": source["path"], "reason": "source_changed"})
        except (OSError, ValueError):
            reasons.append({"path": source["path"], "reason": "source_unavailable"})
    expiry = datetime.fromisoformat(note["expires_at"])
    if expiry.tzinfo is None:
        raise ValueError("note expiry requires an explicit timezone")
    if datetime.now(UTC) >= expiry:
        reasons.append({"reason": "expired"})
    return {
        "note": name,
        "status": "stale" if reasons else "declared_sources_unchanged",
        "kind": note["kind"],
        "summary": None if reasons else note["summary"],
        "sources": note["sources"],
        "reasons": reasons,
        "acceptance": "not_established_by_context_tool",
    }


def startup(root: Path) -> dict:
    """Purpose: Expose mandatory skills and the authoritative research route.
    Inputs: checkout.
    Outputs: current instructions and source hashes; no installation or network activity.
    """
    agents, agents_hash = read_source(root, "AGENTS.md")
    if not re.search(r"caveman\s+and\s+cocoindex\s+are\s+mandatory", agents, re.IGNORECASE):
        raise ValueError("AGENTS.md must declare Caveman and CocoIndex mandatory")
    instructions = []
    for skill in SKILLS:
        name = f".agents/skills/{skill}/SKILL.md"
        if name not in agents:
            raise ValueError("AGENTS.md must declare mandatory Caveman and CocoIndex routing")
        text, digest = read_source(root, name)
        instructions.append({"path": name, "sha256": digest, "instructions": text})
    research = re.findall(
        r"(?m)^- [^\n]*\[Crawl4AI research tool\]\(docs/crawl4ai\.md\)[^\n]*\n(?:[ \t]+[^\n]*\n)*", agents
    )
    if len(research) != 1 or not research[0].startswith("- Use the self-hosted "):
        raise ValueError("AGENTS.md must declare the mandatory self-hosted Crawl4AI research route")
    launcher = "tools/crawl4ai_tool.py"
    _, launcher_hash = read_source(root, launcher)
    return {
        "skills": instructions,
        "agents_sha256": agents_hash,
        "research": {
            "path": "AGENTS.md",
            "sha256": agents_hash,
            "instructions": research[0].rstrip(),
            "launcher": launcher,
            "launcher_sha256": launcher_hash,
        },
        "next": "Apply the AGENTS.md reading map; index/search for broad concepts, then verify exact source.",
        "acceptance": "instruction_delivery_only_not_proof_of_model_behavior",
    }


def main(argv: list[str] | None = None) -> int:
    """Purpose: Dispatch bounded context operations.
    Inputs: CLI argv.
    Outputs: JSON, explicit failures or stale exit 3.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("startup")
    outline = commands.add_parser("outline")
    outline.add_argument("path")
    report = commands.add_parser("json")
    report.add_argument("path")
    report.add_argument("--pointer", default="")
    report.add_argument("--field", action="append", default=[])
    for command, limit in ((outline, 40), (report, 12)):
        command.add_argument("--offset", type=int, default=0)
        command.add_argument("--limit", type=int, default=limit)
        command.add_argument("--max-chars", type=int, default=4000)
    read = commands.add_parser("read")
    read.add_argument("path")
    read.add_argument("--section")
    read.add_argument("--start", type=int, default=1)
    read.add_argument("--end", type=int)
    read.add_argument("--max-chars", type=int, default=8000)
    read.add_argument("--session")
    read.add_argument("--force", action="store_true")
    save = commands.add_parser("remember")
    save.add_argument("key")
    save.add_argument("--summary-file", required=True)
    save.add_argument("--source", action="append", required=True)
    save.add_argument("--kind", choices=("observation", "decision", "hypothesis"), required=True)
    save.add_argument("--expires-hours", type=int, default=24)
    retrieve = commands.add_parser("recall")
    retrieve.add_argument("key")
    args = parser.parse_args(argv)
    try:
        if args.action == "startup":
            result = startup(ROOT)
        elif args.action in ("outline", "json"):
            if not 512 <= args.max_chars <= 32000 or not 1 <= args.limit <= 100 or args.offset < 0:
                raise ValueError("pages need 512-32000 characters, 1-100 items and a nonnegative offset")
            result = source_outline(ROOT, args) if args.action == "outline" else json_report(ROOT, args)
        elif args.action == "read":
            if not 1 <= args.max_chars <= 32000 or (args.section and (args.start != 1 or args.end is not None)):
                raise ValueError("read needs a 1-32000 character budget and either section or line bounds")
            result = read_window(ROOT, args)
        elif args.action == "remember":
            if not 1 <= args.expires_hours <= 168:
                raise ValueError("note expiry must be 1-168 hours; refresh volatile external state before reuse")
            result = remember(ROOT, args)
        else:
            result = recall(ROOT, args.key)
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 3 if result.get("status") == "stale" else 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError, SyntaxError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
