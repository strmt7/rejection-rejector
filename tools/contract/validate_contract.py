#!/usr/bin/env python3
"""Read-only reference validator for this report's proposed engineering contract.

Requires Python >=3.11. Never imports project code or executes declared commands.
Hashes establish local byte consistency, not truthful logs or remote authenticity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath

PACKAGE = Path(__file__).resolve().parent
PREFIXES = {
    "strmt7/FlitzZip": "FZ",
    "strmt7/rejection-rejector": "RR",
    "strmt7/ome-zarr-C": "OZC",
    "strmt7/VulnerabilityScreener": "VS",
    "strmt7/TextForensics": "TF",
    "strmt7/model-protocol-lab": "MPL",
    "strmt7/simple_ai_trading": "SAT",
    "strmt7/smart-job-seeker": "SJS",
    "strmt7/ai_skills_collection_benchmarked": "AISC",
    "ZMB-UZH/omero-docker-extended": "OMERO",
    "strmt7/qfales_fc_website": "QFALES",
    "strmt7/imaris-zmb-omero-connector-ui": "IMARIS-UI",
    "strmt7/project_air_defense": "AIR-DEFENSE",
}
STANDARD_IDS = {f"S{i:02d}" for i in range(1, 16)}
LIMITATIONS = [
    "Reference contract only; no command is executed and no repository or remote setting is changed.",
    "Target source/profile SHAs are caller-supplied trusted CI inputs; this tool "
    "does not query Git, GitHub, a registry or the remote profile.",
    "Local hashes and metadata do not prove log truthfulness, producer identity, "
    "workflow trust, remote authenticity or scientific correctness.",
    "Declared source/coverage scope and input digests are checked for "
    "consistency; this is not exhaustive source inventory or independent "
    "measurement of coverage percentages.",
    "Exceptions are documentary and require passing alternatives; they never waive a failed or blocked requirement.",
    "Synthetic examples cannot produce a production PASS. No cryptographic "
    "signature, attestation or hostile-concurrent-filesystem protection is "
    "implemented.",
]


class ContractError(ValueError):
    """Contract validation failure: malformed, unsafe or contradictory input."""


def duplicate_free(pairs):
    """Build a dict that rejects duplicate JSON keys.

    Inputs: `pairs` -- (key, value) pairs in document order. Output: `dict` --
    the mapping; raises [`ContractError`] on any duplicate key.
    """
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path):
    """Load one bounded contract JSON document with duplicate-key rejection.

    Inputs: `path` -- the file to read. Output: the parsed JSON document;
    raises [`ContractError`] over 2 MiB or on malformed text.
    """
    raw = Path(path).read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ContractError("contract JSON exceeds 2 MiB")
    return json.loads(
        raw,
        object_pairs_hook=duplicate_free,
        parse_constant=lambda x: (_ for _ in ()).throw(ContractError(f"invalid JSON constant {x}")),
    )


def check_shape(value, schema, where="$", depth=0):
    """Only the explicit keywords used by the bundled schemas; not a general engine.

    Inputs: `value` -- the document node; `schema` -- the schema node; `where`
    -- JSON-pointer-ish location for findings; `depth` -- recursion depth.
    Output: none; raises [`ContractError`] on the first inconsistency.
    """
    if depth > 64:
        raise ContractError("contract nesting exceeds 64")
    if set(schema) - SUPPORTED_KEYWORDS:
        raise ContractError(f"unsupported schema keyword at {where}")
    _check_constant(value, schema, where)
    _check_type(value, schema, where)
    if isinstance(value, dict):
        _check_object(value, schema, where, depth)
    elif isinstance(value, list):
        _check_array(value, schema, where, depth)
    elif isinstance(value, str):
        _check_string(value, schema, where)
    elif type(value) is int and value < schema.get("minimum", value):
        raise ContractError(f"{where}: below minimum")


SUPPORTED_KEYWORDS = {
    "$schema",
    "$id",
    "title",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "uniqueItems",
    "minLength",
    "pattern",
    "enum",
    "const",
    "minimum",
}


def _check_constant(value, schema, where):
    """Enforce const/enum constraints.

    Inputs: `value` -- the node; `schema` -- the schema node; `where` --
    location for findings. Output: none; raises [`ContractError`].
    """
    if "const" in schema and value != schema["const"]:
        raise ContractError(f"{where}: wrong constant")
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError(f"{where}: unsupported value")


def _check_type(value, schema, where):
    """Enforce the node's declared type.

    Inputs: `value` -- the node; `schema` -- the schema node; `where` --
    location for findings. Output: none; raises [`ContractError`].
    """
    predicates = {
        "object": lambda x: type(x) is dict,
        "array": lambda x: type(x) is list,
        "string": lambda x: type(x) is str,
        "integer": lambda x: type(x) is int,
        "boolean": lambda x: type(x) is bool,
        "null": lambda x: x is None,
    }
    types = schema.get("type", [])
    types = [types] if isinstance(types, str) else types
    if types and not any(predicates[t](value) for t in types):
        raise ContractError(f"{where}: wrong type")


def _check_object(value, schema, where, depth):
    """Validate an object node's fields against its properties.

    Inputs: `value` -- the object node; `schema` -- the schema node; `where` --
    location for findings; `depth` -- recursion depth. Output: none; raises
    [`ContractError`].
    """
    missing = set(schema.get("required", [])) - set(value)
    if missing:
        raise ContractError(f"{where}: missing fields {sorted(missing)}")
    properties = schema.get("properties", {})
    additional = schema.get("additionalProperties", True)
    for key, item in value.items():
        if key in properties:
            check_shape(item, properties[key], f"{where}/{key}", depth + 1)
        elif additional is False:
            raise ContractError(f"{where}: unexpected field {key}")
        elif isinstance(additional, dict):
            check_shape(item, additional, f"{where}/{key}", depth + 1)


def _check_array(value, schema, where, depth):
    """Validate an array node's items and bounds.

    Inputs: `value` -- the array node; `schema` -- the schema node; `where` --
    location for findings; `depth` -- recursion depth. Output: none; raises
    [`ContractError`].
    """
    if len(value) < schema.get("minItems", 0):
        raise ContractError(f"{where}: too few items")
    if schema.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
        raise ContractError(f"{where}: duplicate item")
    for i, item in enumerate(value):
        check_shape(item, schema.get("items", {}), f"{where}/{i}", depth + 1)


def _check_string(value, schema, where):
    """Validate a string node's length and pattern.

    Inputs: `value` -- the string node; `schema` -- the schema node; `where` --
    location for findings. Output: none; raises [`ContractError`].
    """
    if len(value) < schema.get("minLength", 0):
        raise ContractError(f"{where}: empty string")
    if "pattern" in schema and not re.search(schema["pattern"], value):
        raise ContractError(f"{where}: pattern mismatch")


def digest_file(path):
    """Hash one file's bytes in streaming fashion.

    Inputs: `path` -- the file to read. Output: `str` -- lowercase hex SHA-256.
    """
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative_path(value):
    """Parse one portable, containment-safe relative path.

    Inputs: `value` -- forward-slash relative path text. Output:
    `PurePosixPath` -- the validated path; raises [`ContractError`] for
    absolute, parent, dot or drive-qualified paths.
    """
    if "\\" in value:
        raise ContractError("use portable forward-slash relative paths")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("..", ".") for p in value.split("/")) or ":" in value:
        raise ContractError("absolute, parent, dot or drive paths are not permitted")
    if not path.parts:
        raise ContractError("empty path")
    return path


class _Validation:
    """Mutable state and shared helpers for one receipt-consistency run.

    Inputs (constructor): `policy_path` -- engineering policy TOML;
    `receipt_path` -- the receipt JSON; `evidence_root` -- containment root for
    referenced files; `repo`/`target_sha`/`profile_sha` -- identity the receipt
    must bind; `now` -- timezone-aware validation clock. Output: none; run the
    `check_*` phases in order and read `build_result()`.
    """

    def __init__(self, policy_path, receipt_path, evidence_root, repo, target_sha, profile_sha, now):
        self.repo = repo
        self.target_sha = target_sha
        self.profile_sha = profile_sha
        self.now = now or datetime.now(UTC)
        if self.now.tzinfo is None:
            raise ContractError("validation clock must be timezone-aware")
        self.now = self.now.astimezone(UTC)
        self.policy_path = policy_path
        self.receipt_path = receipt_path
        self.evidence_root = Path(evidence_root).resolve()
        self.issues = []
        self.aborted = False
        self.policy = None
        self.receipt = None
        self.raw = None
        self.synthetic = False
        self.created = None
        self.p = {}
        self.r = {}
        self.expected_tasks = set()
        self.valid_evidence = set()
        self.valid_artifacts = set()
        self.valid_inputs = set()
        self.file_paths = set()
        self.physical_files = set()
        self.available = set()
        self.passed_commands = set()
        self.passed_families = set()
        self.command_finished = {}
        self.qualified_artifacts = set()
        self.valid_kinds = set()

    def issue(self, level, code, field, message):
        """Record one finding.

        Inputs: `level` -- finding level; `code` -- stable finding code;
        `field` -- offending field; `message` -- operator text. Output: none
        (appends to the collected findings).
        """
        self.issues.append({"level": level, "code": code, "field": field, "message": message})

    def fail(self, code, field, message):
        """Record one FAIL finding. Inputs: `code`/`field`/`message` -- as
        [`issue`]. Output: none.
        """
        self.issue("FAIL", code, field, message)

    def block(self, code, field, message):
        """Record one BLOCKED finding. Inputs: `code`/`field`/`message` -- as
        [`issue`]. Output: none.
        """
        self.issue("BLOCKED", code, field, message)

    def output(self):
        """Build the final validation result.

        Inputs: `synthetic` -- whether the receipt declares itself a synthetic
        example. Output: `dict` -- consistency result, qualification and the
        collected findings.
        """
        consistency = "FAIL" if any(i["level"] == "FAIL" for i in self.issues) else "BLOCKED" if self.issues else "PASS"
        result = "BLOCKED" if self.synthetic and consistency == "PASS" else consistency
        return {
            "validator": "portfolio-reference-1.0",
            "result": result,
            "consistency_result": consistency,
            "qualification": "synthetic_example_only" if self.synthetic else "local_contract_only",
            "checked_at": self.now.isoformat().replace("+00:00", "Z"),
            "repo": self.repo,
            "target_sha": self.target_sha,
            "profile_sha": self.profile_sha,
            "issues": self.issues,
            "limitations": LIMITATIONS,
        }

    def parsed_date(self, value, field):
        """Parse one ISO calendar date, failing closed into a finding.

        Inputs: `value` -- date text; `field` -- field name for findings.
        Output: `date` -- the parsed date (a DATE finding is recorded on
        failure).
        """
        try:
            return date.fromisoformat(value)
        except ValueError:
            self.fail("DATE", field, "invalid calendar date")
            return self.now.date()

    def timestamp(self, value, field):
        """Parse one strict UTC RFC 3339 timestamp, failing closed into a finding.

        Inputs: `value` -- timestamp text; `field` -- field name for findings.
        Output: `datetime` -- the parsed UTC instant (a TIMESTAMP finding is
        recorded on failure).
        """
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
                raise ValueError()
        except ValueError:
            self.fail("TIMESTAMP", field, "expected valid UTC timestamp")
            return self.now
        if result > self.now:
            self.fail("FUTURE_EVIDENCE", field, "timestamp is later than the validation clock")
        return result

    def index(self, records, field):
        """Index records by id, rejecting duplicates.

        Inputs: `records` -- record list; `field` -- field name for findings.
        Output: `dict` -- id to record (a DUPLICATE_ID finding is recorded on
        duplicates).
        """
        ids = [row["id"] for row in records]
        if len(ids) != len(set(ids)):
            self.fail("DUPLICATE_ID", field, "record IDs must be unique within the collection")
        return {row["id"]: row for row in records}

    def verify_file(self, item, field, time_field, kind_field):
        """Verify one referenced local file's identity bindings.

        Inputs: `item` -- the evidence or artifact record; `field` -- field name
        for findings; `time_field`/`kind_field` -- the record's time and kind
        fields. Output: `bool` -- whether the file fully verified.
        """
        good = True
        before = len(self.issues)
        if not self._verify_file_identity(item, field):
            good = False
        when = self.timestamp(item[time_field], f"{field}/{time_field}")
        if when > self.created:
            self.fail("EVIDENCE_ORDER", field, "evidence/artifact postdates receipt creation")
            good = False
        if not self._verify_file_bytes(item, field):
            good = False
        if self.receipt["mode"] == "production" and item[kind_field] == "synthetic":
            self.block("SYNTHETIC_EVIDENCE", field, "synthetic evidence cannot qualify a production requirement")
        return good and len(self.issues) == before

    def _verify_file_identity(self, item, field):
        """Check the source/profile identity pair against the trusted targets.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        good = True
        for key, expected in [("source_sha", self.target_sha), ("profile_sha", self.profile_sha)]:
            if item[key] != expected:
                self.fail(
                    "FILE_IDENTITY", f"{field}/{key}", "evidence/artifact identity differs from the current target"
                )
                good = False
        return good

    def _verify_file_bytes(self, item, field):
        """Resolve and hash one referenced file's physical bytes.

        Inputs: `item` -- the evidence or artifact record; `field` -- field name.
        Output: `bool` -- whether the bytes verified.
        """
        good = True
        try:
            rel = relative_path(item["path"])
            resolved = (self.evidence_root / rel).resolve()
            if not resolved.is_relative_to(self.evidence_root):
                raise ContractError("resolved path escapes evidence root")
            key = (field.split("/")[0], str(resolved))
            if key in self.file_paths:
                raise ContractError("duplicate physical file within this collection")
            self.file_paths.add(key)
            if not resolved.is_file():
                self.block("MISSING_FILE", field, "referenced local file is unavailable")
                return False
            stat = resolved.stat()
            if not stat.st_ino:
                self.block("FILE_IDENTITY_UNAVAILABLE", field, "filesystem supplies no stable inode/file identity")
                return False
            physical = (field.split("/")[0], stat.st_dev, stat.st_ino)
            if physical in self.physical_files:
                self.fail("DUPLICATE_PHYSICAL_FILE", field, "hard-linked or aliased file cannot inflate the collection")
                return False
            self.physical_files.add(physical)
            if digest_file(resolved) != item["sha256"]:
                self.fail("FILE_HASH", field, "actual file SHA-256 differs from receipt")
                good = False
        except (OSError, RuntimeError, ContractError) as error:
            self.fail("FILE_PATH", field, str(error))
            good = False
        return good

    def references(self, ids, field, nonempty=False):
        """Check one evidence-id reference list against verified evidence.

        Inputs: `ids` -- referenced evidence ids; `field` -- field name for
        findings; `nonempty` -- require at least one verified id. Output:
        `bool` -- whether every reference resolves to verified evidence.
        """
        if nonempty and not ids:
            self.fail("NO_EVIDENCE", field, "at least one verified local evidence record is required")
            return False
        unknown = set(ids) - set(self.r["evidence"])
        if unknown:
            self.fail("EVIDENCE_REF", field, f"unknown evidence IDs: {sorted(unknown)}")
        return bool(ids) and set(ids) <= self.valid_evidence

    def applicability(self, declared, actual, field):
        """Validate one policy-exception applicability claim.

        Inputs: `declared` -- the exception's claim; `actual` -- the computed
        requirement status; `field` -- field name for findings. Output: none
        (records findings).
        """
        if not declared["reason"].strip():
            self.fail("APPLICABILITY_REASON", field, "policy needs a factual applicability reason")
        if not declared["applicable"]:
            if actual["status"] != "not_applicable":
                self.fail("NOT_APPLICABLE", field, "policy-declared N/A must be represented as N/A")
            if actual["reason"] != declared["reason"]:
                self.fail("NA_REASON", field, "N/A reason must match the reviewed factual policy reason")
            self.references(actual["evidence_ids"], field, True)
            return False
        if actual["status"] == "not_applicable":
            self.fail("UNDECLARED_NA", field, "applicable requirement cannot become N/A in the receipt")
            return False
        return True

    def load_inputs(self):
        """Load and shape-check the policy and receipt documents.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        try:
            self.raw = Path(self.policy_path).read_bytes()
            if len(self.raw) > 2 * 1024 * 1024:
                raise ContractError("policy exceeds 2 MiB")
            self.policy = tomllib.loads(self.raw.decode("utf-8"))
            self.receipt = load_json(self.receipt_path)
            check_shape(self.policy, load_json(PACKAGE / "engineering-policy.schema.json"))
            check_shape(self.receipt, load_json(PACKAGE / "execution-receipt.schema.json"))
        except (OSError, ValueError, RecursionError) as error:
            self.fail("STRUCTURE", "$", str(error))
            self.aborted = True
            return
        self.synthetic = (
            self.receipt["mode"] == "synthetic_example"
            or any(e["kind"] == "synthetic" for e in self.receipt["evidence"])
            or any(a["evidence_kind"] == "synthetic" for a in self.receipt["artifacts"])
        )

    def check_identity(self):
        """Bind the receipt to the trusted repository, source, profile and policy bytes.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        if self.repo not in PREFIXES:
            self.fail("REPO", "repo", "repository is outside the 13 canonical report identities")
            return self.output()
        if not re.fullmatch("[0-9a-f]{40}", self.target_sha) or not re.fullmatch("[0-9a-f]{40}", self.profile_sha):
            self.fail(
                "TARGET", "target", "trusted current source/profile inputs must be full lowercase 40-character SHAs"
            )
        if self.policy["repo"] != self.repo or self.receipt["repo"] != self.repo:
            self.fail("REPO", "repo", "policy, receipt and trusted target repository differ")
        if self.receipt["source_sha"] != self.target_sha:
            self.fail("STALE_SOURCE", "source_sha", "receipt does not describe the trusted current source target")
        if self.receipt["audit_baseline_sha"] != self.policy["audit_baseline_sha"]:
            self.fail("AUDIT_BASELINE", "audit_baseline_sha", "receipt and policy audit baselines differ")
        if self.policy["profile"]["sha"] != self.profile_sha or self.receipt["profile_sha"] != self.profile_sha:
            self.fail("STALE_PROFILE", "profile_sha", "policy/receipt does not identify the trusted immutable profile")
        if hashlib.sha256(self.raw).hexdigest() != self.receipt["policy_sha256"]:
            self.fail("POLICY_DIGEST", "policy_sha256", "receipt does not bind the exact engineering.toml bytes")
        if not self.policy["owner"].strip():
            self.fail("OWNER", "owner", "policy requires a named owner")
        if self.profile_sha not in self.policy["profile"]["source_url"]:
            self.fail(
                "PROFILE_REF",
                "profile/source_url",
                "profile locator must contain its immutable SHA; remote existence remains unverified",
            )

    def check_review_dates(self):
        """Validate the policy review date pair against the validation clock.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        reviewed = self.parsed_date(self.policy["reviewed_on"], "reviewed_on")
        due = self.parsed_date(self.policy["review_due"], "review_due")
        if reviewed > self.now.date():
            self.fail("FUTURE_REVIEW", "reviewed_on", "review date is in the future")
        if due < reviewed:
            self.fail("REVIEW_ORDER", "review_due", "review deadline precedes review")
        if due < self.now.date():
            self.block("EXPIRED_REVIEW", "review_due", "policy review has expired")

    def build_indexes(self):
        """Build the created-at stamp, id indexes and required/record ID sets.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        self.created = self.timestamp(self.receipt["created_at"], "created_at")

        self.p = {
            k: self.index(self.policy[k], f"policy/{k}")
            for k in (
                "environments",
                "standards",
                "tasks",
                "commands",
                "test_families",
                "artifact_kinds",
                "coverage_scopes",
                "input_files",
                "exceptions",
            )
        }
        self.r = {
            k: self.index(self.receipt[k], f"receipt/{k}")
            for k in (
                "environments",
                "standards",
                "tasks",
                "commands",
                "test_families",
                "artifacts",
                "coverage_scopes",
                "input_files",
                "evidence",
                "exceptions",
            )
        }
        self.expected_tasks = {f"{PREFIXES[self.repo]}-{i:02d}" for i in range(1, 7)}
        for side, data in [("policy", self.p), ("receipt", self.r)]:
            for key, expected in [("standards", STANDARD_IDS), ("tasks", self.expected_tasks)]:
                if set(data[key]) != expected:
                    self.fail("REQUIRED_IDS", f"{side}/{key}", f"exact IDs required: {sorted(expected)}")
        for key in ("environments", "commands", "test_families", "coverage_scopes", "input_files", "exceptions"):
            if set(self.p[key]) != set(self.r[key]):
                self.fail("RECORD_SET", key, "policy and receipt must have exactly the same declared records")

    def check_roots_and_environments(self):
        """Validate source roots and environment/tool declarations.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        self._check_root_list()
        self._check_environments()

    def _check_root_list(self):
        """Validate source-root path containment and mutual overlap.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        roots = []
        for kind, paths in self.policy["roots"].items():
            for path in paths:
                try:
                    relative = relative_path(path)
                    roots.append((kind, relative))
                except ContractError as error:
                    self.fail("ROOT_PATH", f"roots/{kind}", str(error))
        for i, (kind, path) in enumerate(roots):
            for other_kind, other in roots[i + 1 :]:
                if path == other or path in other.parents or other in path.parents:
                    self.fail("ROOT_OVERLAP", "roots", f"{kind}:{path} overlaps {other_kind}:{other}")

    def _check_environments(self):
        """Validate environment and tool declarations against the receipt.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        if not any(e["required"] for e in self.p["environments"].values()):
            self.fail("ENVIRONMENT", "environments", "at least one required environment must be declared")
        self.available = set()
        for key, declared in self.p["environments"].items():
            self._check_one_environment(key, declared)

    def _check_one_environment(self, key, declared):
        """Validate one environment record against its policy declaration.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        actual = self.r["environments"].get(key)
        if not declared["tools"]:
            self.fail("TOOLS", f"environments/{key}", "declare at least one exact supported tool version")
        if any(not name.strip() for name in declared["tools"]):
            self.fail("TOOL_IDENTITY", f"environments/{key}/tools", "policy tool names must be nonblank")
        if actual is None:
            return
        if any(not name.strip() for name in actual["tools"]):
            self.fail("TOOL_IDENTITY", f"environments/{key}/tools", "receipt tool names must be nonblank")
        if actual["status"] == "blocked":
            if declared["required"]:
                self.block("ENVIRONMENT_BLOCKED", f"environments/{key}", actual["reason"])
            return
        valid = True
        for name, allowed in declared["tools"].items():
            if actual["tools"].get(name) not in allowed:
                self.fail("TOOL_VERSION", f"environments/{key}/tools/{name}", "missing or unsupported tool version")
                valid = False
        if valid:
            self.available.add(key)

    def verify_local_files(self):
        """Verify every referenced evidence, input and artifact file.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        for key, item in self.r["evidence"].items():
            if self.verify_file(item, f"evidence/{key}", "captured_at", "kind"):
                self.valid_evidence.add(key)
        self._verify_policy_records()

    def _verify_policy_records(self):
        """Verify policy-bound input files and declared artifact receipts.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        for key, item in self.r["input_files"].items():
            if key not in self.p["input_files"]:
                continue
            if item != self.p["input_files"][key]:
                self.fail("INPUT_IDENTITY", f"input_files/{key}", "input path/kind/digest differs from reviewed policy")
                continue
            bound = {
                **item,
                "source_sha": self.target_sha,
                "profile_sha": self.profile_sha,
                "captured_at": self.receipt["created_at"],
                "classification": "synthetic" if self.receipt["mode"] == "synthetic_example" else "real",
            }
            if self.verify_file(bound, f"input_files/{key}", "captured_at", "classification"):
                self.valid_inputs.add(key)
        for key, item in self.r["artifacts"].items():
            if item["kind"] not in self.p["artifact_kinds"]:
                self.fail("ARTIFACT_KIND", f"artifacts/{key}", "undeclared artifact kind")
                continue
            if item["environment"] != self.p["artifact_kinds"][item["kind"]]["environment"]:
                self.fail("ARTIFACT_ENV", f"artifacts/{key}", "artifact environment differs from policy")
                continue
            if self.verify_file(item, f"artifacts/{key}", "created_at", "evidence_kind"):
                self.valid_artifacts.add(key)

    def check_commands(self):
        """Validate declared commands against their policy and evidence.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        self.passed_commands = set()
        self.command_finished = {}
        for key, declared in self.p["commands"].items():
            self._check_one_command(key, declared)

    def check_test_families(self):
        """Validate test families: counts, required tests and skip policy.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        self.passed_families = set()
        for key, declared in self.p["test_families"].items():
            self._check_one_family(key, declared)

    def check_artifact_qualification(self):
        """Validate artifact qualification dependencies and timing.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        self.qualified_artifacts = set()
        for key, item in self.r["artifacts"].items():
            self._check_one_qualification(key, item)

    def _check_one_qualification(self, key, item):
        """Validate one artifact's qualification command and test evidence.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        if item["kind"] not in self.p["artifact_kinds"]:
            return
        declared = self.p["artifact_kinds"][item["kind"]]
        actual = item["qualification"]
        field = f"artifacts/{key}/qualification"
        if set(actual["command_ids"]) != set(declared["qualification_command_ids"]) or set(
            actual["test_family_ids"]
        ) != set(declared["qualification_test_family_ids"]):
            self.fail("QUALIFICATION_IDENTITY", field, "qualification dependencies differ from policy")
            return
        if not self.applicability(declared, actual, field):
            return
        if actual["status"] == "failed":
            self.fail("ARTIFACT_QUALIFICATION_FAILED", field, actual["reason"])
        if actual["status"] == "blocked":
            self.block("ARTIFACT_QUALIFICATION_BLOCKED", field, actual["reason"])
        self._qualification_passed_checks(key, item, declared, actual, field)

    def _qualification_passed_checks(self, key, item, declared, actual, field):
        """Validate one passed qualification's timing and dependency claims.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        if actual["status"] == "passed":
            before = len(self.issues)
            has_evidence = self.references(actual["evidence_ids"], field, True)
            artifact_created = self.timestamp(item["created_at"], field + "/artifact_created_at")
            qualification_commands = set(actual["command_ids"])
            qualification_commands.update(
                self.p["test_families"][family_id]["command_id"]
                for family_id in actual["test_family_ids"]
                if family_id in self.p["test_families"]
            )
            for command_id in qualification_commands:
                if command_id in self.command_finished and artifact_created > self.command_finished[command_id]:
                    self.fail(
                        "ARTIFACT_QUALIFICATION_TIME",
                        field,
                        "artifact cannot be created after a command asserted to have qualified it finished",
                    )
            if (
                not set(actual["command_ids"]) <= self.passed_commands
                or not set(actual["test_family_ids"]) <= self.passed_families
            ):
                self.fail(
                    "FALSE_PASS_QUALIFICATION",
                    field,
                    "artifact requires passing declared qualification commands/families",
                )
            elif has_evidence and key in self.valid_artifacts and len(self.issues) == before:
                self.qualified_artifacts.add(key)

    def check_artifact_kinds(self):
        """Validate artifact-kind policies and required artifact counts.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        self.valid_kinds = set()
        for key, declared in self.p["artifact_kinds"].items():
            self._check_one_kind(key, declared)

    def _check_one_kind(self, key, declared):
        """Validate one artifact-kind policy record and its receipts.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        if declared["environment"] not in self.p["environments"]:
            self.fail("ENVIRONMENT_REF", f"artifact_kinds/{key}", "undeclared artifact environment")
        count = sum(a["kind"] == key and aid in self.qualified_artifacts for aid, a in self.r["artifacts"].items())
        if declared["applicable"]:
            if not declared["qualification_command_ids"]:
                self.fail(
                    "QUALIFICATION_POLICY",
                    f"artifact_kinds/{key}",
                    "applicable artifact needs a qualification command",
                )
            if not set(declared["qualification_command_ids"]) <= set(self.p["commands"]) or not set(
                declared["qualification_test_family_ids"]
            ) <= set(self.p["test_families"]):
                self.fail("QUALIFICATION_REF", f"artifact_kinds/{key}", "undeclared qualification dependency")
            if declared["minimum_count"] < 1:
                self.fail("ARTIFACT_POLICY", f"artifact_kinds/{key}", "applicable kind requires a positive count")
            if declared["environment"] not in self.available:
                self.block(
                    "ARTIFACT_ENV_BLOCKED",
                    f"artifact_kinds/{key}",
                    "required artifact host is unavailable or unsupported",
                )
            if count < declared["minimum_count"]:
                self.block("MISSING_ARTIFACT", f"artifact_kinds/{key}", "too few verified required artifacts")
            elif declared["environment"] in self.available:
                self.valid_kinds.add(key)
        elif declared["minimum_count"] != 0:
            self.fail("NA_ARTIFACT_POLICY", f"artifact_kinds/{key}", "N/A kind must have zero required count")

    def check_coverage_scopes(self):
        """Validate coverage scopes, their identities and report artifacts.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        for key, declared in self.p["coverage_scopes"].items():
            self._check_one_coverage(key, declared)

    def check_requirements(self):
        """Validate standards/tasks acceptance dependencies.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        for category in ("standards", "tasks"):
            self._check_category_requirements(category)

    def _check_category_requirements(self, category):
        """Validate every standard/task requirement in one category.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        for key, declared in self.p[category].items():
            self._check_one_requirement(category, key, declared)

    def _check_one_requirement(self, category, key, declared):
        """Validate one standard/task requirement record.

        Inputs: `category`/`key`/`declared` -- the record coordinates and
        policy. Output: none; findings are recorded on the run state.
        """
        actual = self.r[category].get(key)
        field = f"{category}/{key}"
        for name, collection in [
            ("command_ids", "commands"),
            ("test_family_ids", "test_families"),
            ("artifact_kinds", "artifact_kinds"),
        ]:
            if set(declared[name]) - set(self.p[collection]):
                self.fail("DEPENDENCY_REF", field, "requirement refers to undeclared dependencies")
        if actual is None:
            return
        if not self.applicability(declared, actual, field):
            return
        if not any(declared[k] for k in ("command_ids", "test_family_ids", "artifact_kinds")):
            self.fail("NO_ACCEPTANCE", field, "applicable requirement needs explicit acceptance dependencies")
        if actual["status"] == "failed":
            self.fail("REQUIREMENT_FAILED", field, actual["reason"])
        if actual["status"] == "blocked":
            self.block("REQUIREMENT_BLOCKED", field, actual["reason"])
        if actual["status"] == "passed":
            self.references(actual["evidence_ids"], field, True)
            if not (
                set(declared["command_ids"]) <= self.passed_commands
                and set(declared["test_family_ids"]) <= self.passed_families
                and set(declared["artifact_kinds"]) <= self.valid_kinds
            ):
                self.fail("FALSE_PASS_DEPENDENCY", field, "claimed passing requirement has an unresolved dependency")

    def check_exceptions(self):
        """Validate policy exceptions and their proven alternatives.

        Inputs: none beyond the run state. Output: none; findings are
        recorded on the run state.
        """
        requirements = set(self.p["standards"]) | set(self.p["tasks"])
        for key, declared in self.p["exceptions"].items():
            field = f"exceptions/{key}"
            actual = self.r["exceptions"].get(key)
            if declared["requirement_id"] not in requirements:
                self.fail("EXCEPTION_REF", field, "unknown canonical requirement")
            if self.parsed_date(declared["expires_on"], field + "/expires_on") < self.now.date():
                self.fail("EXPIRED_EXCEPTION", field, "expired exception cannot support acceptance")
            if (
                not set(declared["alternative_command_ids"]) <= self.passed_commands
                or not set(declared["alternative_test_family_ids"]) <= self.passed_families
            ):
                self.fail(
                    "UNPROVEN_ALTERNATIVE",
                    field,
                    "exception requires supported passing alternative commands and test families",
                )
            if actual:
                self.references(actual["evidence_ids"], field, True)
            # Deliberately no removal or suppression of any earlier FAIL/BLOCKED issue.

    def build_result(self):
        """Cross-check the producer label and assemble the final result.

        Inputs: none beyond the run state. Output: `dict` -- the validation
        result (status, findings, verified counts); the producer label is
        checked against the independently computed result and never trusted.
        Aborted runs return the plain consistency output exactly like the
        original early exits.
        """
        if self.aborted:
            return self.output()
        computed = self.output()["consistency_result"]
        if self.receipt["overall_status"] != computed:
            self.fail(
                "OVERALL_STATUS_MISMATCH",
                "overall_status",
                "producer label contradicts the independently computed result; it cannot be silently upgraded",
            )
        result = self.output()
        result["declared_overall_status"] = self.receipt["overall_status"]
        result["declared_label_used_as_authority"] = False
        result["declared_label_consistency_checked"] = True
        result["verified_counts"] = {
            "evidence_files": len(self.valid_evidence),
            "artifacts": len(self.valid_artifacts),
            "input_files": len(self.valid_inputs),
            "qualified_artifacts": len(self.qualified_artifacts),
            "passing_commands": len(self.passed_commands),
            "passing_test_families": len(self.passed_families),
            "canonical_tasks": len(self.expected_tasks),
            "canonical_standards": len(STANDARD_IDS),
        }
        return result

    def _check_one_command(self, key, declared):
        """Validate one command record against its policy declaration.

        Inputs: `key`/declared record state
        from the run indexes. Output: none; findings are recorded on the
        run state.
        """
        actual = self.r["commands"].get(key)
        field = f"commands/{key}"
        before = len(self.issues)
        if declared["environment"] not in self.p["environments"]:
            self.fail("ENVIRONMENT_REF", field, "undeclared command environment")
        if actual is None:
            return
        if actual["command"] != declared["command"]:
            self.fail("COMMAND_IDENTITY", field, "recorded command text differs from the policy declaration")
        start = self.timestamp(actual["started_at"], field + "/started_at")
        end = self.timestamp(actual["finished_at"], field + "/finished_at")
        self.command_finished[key] = end
        if start > end or end > self.created:
            self.fail("COMMAND_TIME", field, "command times must be ordered and precede receipt creation")
        applies = self.applicability(declared, actual, field)
        if not applies:
            if actual["exit_code"] is not None:
                self.fail("NA_EXIT", field, "N/A command must not claim an execution exit code")
            return
        self._command_record_status(key, declared, actual, field, before, end)

    def _command_evidence_order(self, actual, field, end):
        """Check command evidence timestamps against completion.

        Inputs: `actual` -- the command record; `field` -- field name;
        `end` -- command completion time. Output: none.
        """
        for evidence_id in actual["evidence_ids"]:
            if (
                evidence_id in self.r["evidence"]
                and self.timestamp(self.r["evidence"][evidence_id]["captured_at"], field + "/evidence_time") < end
            ):
                self.fail("LOG_TIME", field, "command evidence cannot predate command completion")

    def _command_record_status(self, key, declared, actual, field, before, end):
        """Validate one applicable command record's status claims.

        Inputs: `key`/`declared`/`actual` -- the record and its policy;
        `field` -- field name; `before`/`end` -- issue baseline and
        completion time. Output: none.
        """
        status = actual["status"]
        has_evidence = self.references(actual["evidence_ids"], field, status in ("passed", "failed"))
        self._command_evidence_order(actual, field, end)
        if status == "failed":
            self.fail("COMMAND_FAILED", field, actual["reason"])
        if status == "blocked":
            self.block("COMMAND_BLOCKED", field, actual["reason"])
        if status == "passed":
            if actual["exit_code"] != 0:
                self.fail("FALSE_PASS_EXIT", field, "passed command requires exit code 0")
            if declared["environment"] not in self.available:
                self.fail("FALSE_PASS_ENV", field, "passed command requires its supported available environment")
            if (
                actual["exit_code"] == 0
                and declared["environment"] in self.available
                and has_evidence
                and len(self.issues) == before
            ):
                self.passed_commands.add(key)
        if status == "blocked" and actual["exit_code"] is not None:
            self.fail("BLOCKED_EXIT", field, "blocked command cannot claim an execution exit code")

    def _check_one_family(self, key, declared):
        """Validate one test-family record against its policy declaration.

        Inputs: `key`/`declared` -- the record id and its policy. Output:
        none; findings are recorded on the run state.
        """
        actual = self.r["test_families"].get(key)
        field = f"test_families/{key}"
        before = len(self.issues)
        allowed = self._family_declared_checks(declared, field)
        if actual is None:
            return
        tests, computed = self._family_test_records(actual, field)
        applies = self.applicability(declared, actual, field)
        if not applies:
            if actual["tests"]:
                self.fail("NA_TESTS", field, "N/A family cannot claim executed test records")
            if declared["minimum_executed"] or declared["required_test_ids"] or declared["allowed_skips"]:
                self.fail(
                    "NA_TEST_POLICY", field, "N/A family must not retain contradictory execution or skip requirements"
                )
            return
        self.references(actual["evidence_ids"], field, actual["status"] in ("passed", "failed"))
        self._family_execution_checks(key, declared, actual, field, computed, tests, allowed, before)

    def _family_declared_checks(self, declared, field):
        """Validate one family's declared policy references and skip rules.

        Inputs: `declared` -- the policy record; `field` -- field name.
        Output: `dict` -- the policy-allowed skip map.
        """
        if declared["command_id"] not in self.p["commands"]:
            self.fail("COMMAND_REF", field, "undeclared test command")
        elif self.p["commands"][declared["command_id"]]["environment"] != declared["environment"]:
            self.fail("TEST_ENV", field, "test and command environments differ")
        if declared["environment"] not in self.p["environments"]:
            self.fail("ENVIRONMENT_REF", field, "undeclared test environment")
        allowed = self.index(declared["allowed_skips"], field + "/allowed_skips")
        if set(allowed) & set(declared["required_test_ids"]):
            self.fail("REQUIRED_SKIP", field, "required tests cannot also be policy-allowed skips")
        return allowed

    def _family_test_records(self, actual, field):
        """Recompute a family's test counts from its individual records.

        Inputs: `actual` -- the receipt record; `field` -- field name.
        Output: `(tests, computed)` -- the test index and recomputed counts.
        """
        tests = self.index(actual["tests"], field + "/tests")
        counts = Counter(t["status"] for t in actual["tests"])
        computed = {
            "collected": len(actual["tests"]),
            "executed": counts["passed"] + counts["failed"],
            **{k: counts[k] for k in ("passed", "failed", "skipped", "blocked")},
        }
        if computed != actual["counts"]:
            self.fail("TEST_COUNTS", field, "declared counts do not equal individual test records")
        return tests, computed

    def _family_execution_checks(self, key, declared, actual, field, computed, tests, allowed, before):
        """Validate one applicable family's execution and test outcomes.

        Inputs: `declared`/`actual` -- policy and receipt records; `field` --
        field name; `computed`/`tests` -- recomputed state; `allowed` --
        policy-allowed skips; `before` -- issue baseline. Output: none.
        """
        if declared["minimum_executed"] < 1 or not declared["required_test_ids"]:
            self.fail(
                "TEST_POLICY", field, "applicable family requires a positive executed floor and named required tests"
            )
        unmet = self.block if actual["status"] == "blocked" else self.fail
        if computed["executed"] < declared["minimum_executed"]:
            unmet("ZERO_OR_FEW_TESTS", field, "too few tests actually executed")
        self._family_required_tests(declared, actual, field, tests, allowed, unmet)
        for test_id, test in tests.items():
            self._family_test_outcomes(test_id, test, allowed, field, actual)
        self._family_status_checks(key, declared, actual, field, before)

    def _family_status_checks(self, key, declared, actual, field, before):
        """Validate one family's recorded status against its issue history.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        if actual["status"] == "failed":
            self.fail("FAMILY_FAILED", field, actual["reason"])
        if actual["status"] == "blocked":
            self.block("FAMILY_BLOCKED", field, actual["reason"])
        if actual["status"] == "passed":
            if declared["command_id"] not in self.passed_commands:
                self.fail("FALSE_PASS_TEST_COMMAND", field, "passing family requires its passing command")
            if declared["environment"] not in self.available:
                self.fail("FALSE_PASS_TEST_ENV", field, "passing family requires its available supported environment")
            if len(self.issues) == before and set(actual["evidence_ids"]) <= self.valid_evidence:
                self.passed_families.add(key)

    def _family_test_outcomes(self, test_id, test, allowed, field, actual):
        """Validate each family test record's outcome and skip legitimacy.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        if test["status"] == "failed":
            self.fail("TEST_FAILED", field + "/" + test_id, test["reason"])
        if test["status"] == "blocked":
            self.block("TEST_BLOCKED", field + "/" + test_id, test["reason"])
        if test["status"] == "skipped" and (test_id not in allowed or test["reason"] != allowed[test_id]["reason"]):
            self.fail(
                "UNEXPECTED_SKIP",
                field + "/" + test_id,
                "skip is not explicitly policy-declared with its factual reason",
            )

    def _family_required_tests(self, declared, actual, field, tests, allowed, unmet):
        """Validate required tests and unexpected skips.

        Inputs: `declared`/`actual` -- policy and receipt records; `field` --
        field name; `tests` -- the test index; `allowed` -- policy-allowed
        skips. Output: none.
        """
        for test_id in declared["required_test_ids"]:
            if test_id not in tests:
                unmet("MISSING_TEST", field, f"required test {test_id} absent")
            elif tests[test_id]["status"] != "passed":
                blocked = tests[test_id]["status"] == "blocked" and actual["status"] == "blocked"
                report = self.block if blocked else self.fail
                report("REQUIRED_TEST_NOT_PASSED", field, f"required test {test_id} did not pass")

    def _check_one_coverage(self, key, declared):
        """Validate one coverage-scope record against its policy declaration.

        Inputs: `key`/`declared` -- the record id and its policy. Output:
        none; findings are recorded on the run state.
        """
        actual = self.r["coverage_scopes"].get(key)
        field = f"coverage_scopes/{key}"
        self._coverage_declared_checks(declared, field)
        if actual is None:
            return
        for name in ("environment", "command_id", "measurement", "included_roots", "excluded_roots"):
            if actual[name] != declared[name]:
                self.fail("COVERAGE_IDENTITY", field, "recorded coverage scope/mode differs from policy")
        if not self.applicability(declared, actual, field):
            return
        self._coverage_actual_checks(key, declared, actual, field)

    def _coverage_actual_checks(self, key, declared, actual, field):
        """Validate one applicable coverage's measurement and artifact claims.

        Inputs: named record state from the run. Output: none;
        findings are recorded on the run state.
        """
        if declared["measurement"] == "none" or not declared["included_roots"]:
            self.fail(
                "COVERAGE_POLICY", field, "applicable coverage needs a measurement mode and explicit source scope"
            )
        if actual["status"] == "failed":
            self.fail("COVERAGE_FAILED", field, actual["reason"])
        if actual["status"] == "blocked":
            self.block("COVERAGE_BLOCKED", field, actual["reason"])
        if actual["status"] == "passed":
            self.references(actual["evidence_ids"], field, True)
            if declared["command_id"] not in self.passed_commands or declared["environment"] not in self.available:
                self.fail("FALSE_PASS_COVERAGE", field, "coverage requires supported execution")
            if not actual["artifact_ids"]:
                self.fail("NO_COVERAGE_ARTIFACT", field, "coverage needs a qualified report artifact")
            for artifact_id in actual["artifact_ids"]:
                if (
                    artifact_id not in self.qualified_artifacts
                    or self.r["artifacts"][artifact_id]["kind"] != declared["artifact_kind"]
                ):
                    self.fail("COVERAGE_ARTIFACT", field, "coverage references missing/unqualified/wrong-kind artifact")

    def _coverage_declared_checks(self, declared, field):
        """Validate one coverage scope's declared references and paths.

        Inputs: `declared` -- the policy record; `field` -- field name.
        Output: none.
        """
        if (
            declared["environment"] not in self.p["environments"]
            or declared["command_id"] not in self.p["commands"]
            or declared["artifact_kind"] not in self.p["artifact_kinds"]
        ):
            self.fail("COVERAGE_REF", field, "coverage references undeclared environment/command/artifact kind")
        if (
            declared["command_id"] in self.p["commands"]
            and self.p["commands"][declared["command_id"]]["environment"] != declared["environment"]
        ):
            self.fail("COVERAGE_ENV", field, "coverage command and scope environments differ")
        if (
            declared["artifact_kind"] in self.p["artifact_kinds"]
            and self.p["artifact_kinds"][declared["artifact_kind"]]["environment"] != declared["environment"]
        ):
            self.fail("COVERAGE_ENV", field, "coverage report and scope environments differ")
        for value in declared["included_roots"] + declared["excluded_roots"]:
            try:
                relative_path(value)
            except ContractError as error:
                self.fail("COVERAGE_PATH", field, str(error))


def validate(policy_path, receipt_path, evidence_root, *, repo, target_sha, profile_sha, now=None):
    """Run the full receipt-consistency validation.

    Inputs: `policy_path` -- engineering policy TOML; `receipt_path` -- the
    receipt JSON; `evidence_root` -- containment root for referenced files;
    `repo`/`target_sha`/`profile_sha` -- identity the receipt must bind;
    `now` -- timezone-aware validation clock (default: current time).
    Output: the result dict (status plus findings); findings never echo
    receipt values.
    """
    run = _Validation(policy_path, receipt_path, evidence_root, repo, target_sha, profile_sha, now)
    for phase in (
        run.load_inputs,
        run.check_identity,
        run.check_review_dates,
        run.build_indexes,
        run.check_roots_and_environments,
        run.verify_local_files,
        run.check_commands,
        run.check_test_families,
        run.check_artifact_qualification,
        run.check_artifact_kinds,
        run.check_coverage_scopes,
        run.check_requirements,
        run.check_exceptions,
    ):
        if run.aborted:
            break
        phase()
    return run.build_result()


def main(argv=None):
    """CLI entry point for the contract validator.

    Inputs: `argv` -- argument list (default `sys.argv[1:]`). Output: `int` --
    process exit code (0 pass, 1 FAIL, 2 BLOCKED).
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--repo", required=True, help="Trusted repository identity, not read from the receipt.")
    parser.add_argument("--target-sha", required=True, help="Trusted current source SHA from CI/checkout context.")
    parser.add_argument("--profile-sha", required=True, help="Trusted immutable shared-profile SHA.")
    args = parser.parse_args(argv)
    try:
        result = validate(
            args.policy,
            args.receipt,
            args.evidence_root,
            repo=args.repo,
            target_sha=args.target_sha,
            profile_sha=args.profile_sha,
        )
    except (OSError, ValueError, RecursionError) as error:
        result = {"result": "FAIL", "issues": [{"code": "INPUT", "message": str(error)}], "limitations": LIMITATIONS}
    print(json.dumps(result, indent=2))
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[result["result"]]


if __name__ == "__main__":
    raise SystemExit(main())
