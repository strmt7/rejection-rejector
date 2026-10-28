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

    pass


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
    """Only the explicit keywords used by the bundled schemas; not a general engine."""
    if depth > 64:
        raise ContractError("contract nesting exceeds 64")
    supported = {
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
    if set(schema) - supported:
        raise ContractError(f"unsupported schema keyword at {where}")
    if "const" in schema and value != schema["const"]:
        raise ContractError(f"{where}: wrong constant")
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError(f"{where}: unsupported value")
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
    if isinstance(value, dict):
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
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ContractError(f"{where}: too few items")
        if schema.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
            raise ContractError(f"{where}: duplicate item")
        for i, item in enumerate(value):
            check_shape(item, schema.get("items", {}), f"{where}/{i}", depth + 1)
    elif isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ContractError(f"{where}: empty string")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise ContractError(f"{where}: pattern mismatch")
    elif type(value) is int and value < schema.get("minimum", value):
        raise ContractError(f"{where}: below minimum")


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


def validate(policy_path, receipt_path, evidence_root, *, repo, target_sha, profile_sha, now=None):
    """Run the full receipt-consistency validation.

    Inputs: `policy_path` -- engineering policy TOML; `receipt_path` -- the
    receipt JSON; `evidence_root` -- containment root for referenced files;
    `repo`/`target_sha`/`profile_sha` -- identity the receipt must bind;
    `now` -- timezone-aware validation clock (default: current time).
    Output: the result dict (status plus findings); findings never echo
    receipt values.
    """
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ContractError("validation clock must be timezone-aware")
    now = now.astimezone(UTC)
    issues = []

    def issue(level, code, field, message):
        issues.append({"level": level, "code": code, "field": field, "message": message})

    def fail(code, field, message):
        issue("FAIL", code, field, message)

    def block(code, field, message):
        issue("BLOCKED", code, field, message)

    def output(synthetic=False):
        consistency = "FAIL" if any(i["level"] == "FAIL" for i in issues) else "BLOCKED" if issues else "PASS"
        result = "BLOCKED" if synthetic and consistency == "PASS" else consistency
        return {
            "validator": "portfolio-reference-1.0",
            "result": result,
            "consistency_result": consistency,
            "qualification": "synthetic_example_only" if synthetic else "local_contract_only",
            "checked_at": now.isoformat().replace("+00:00", "Z"),
            "repo": repo,
            "target_sha": target_sha,
            "profile_sha": profile_sha,
            "issues": issues,
            "limitations": LIMITATIONS,
        }

    try:
        raw = Path(policy_path).read_bytes()
        if len(raw) > 2 * 1024 * 1024:
            raise ContractError("policy exceeds 2 MiB")
        policy = tomllib.loads(raw.decode("utf-8"))
        receipt = load_json(receipt_path)
        check_shape(policy, load_json(PACKAGE / "engineering-policy.schema.json"))
        check_shape(receipt, load_json(PACKAGE / "execution-receipt.schema.json"))
    except (OSError, ValueError, RecursionError) as error:
        fail("STRUCTURE", "$", str(error))
        return output()
    synthetic = (
        receipt["mode"] == "synthetic_example"
        or any(e["kind"] == "synthetic" for e in receipt["evidence"])
        or any(a["evidence_kind"] == "synthetic" for a in receipt["artifacts"])
    )
    if repo not in PREFIXES:
        fail("REPO", "repo", "repository is outside the 13 canonical report identities")
        return output(synthetic)
    if not re.fullmatch("[0-9a-f]{40}", target_sha) or not re.fullmatch("[0-9a-f]{40}", profile_sha):
        fail("TARGET", "target", "trusted current source/profile inputs must be full lowercase 40-character SHAs")
    if policy["repo"] != repo or receipt["repo"] != repo:
        fail("REPO", "repo", "policy, receipt and trusted target repository differ")
    if receipt["source_sha"] != target_sha:
        fail("STALE_SOURCE", "source_sha", "receipt does not describe the trusted current source target")
    if receipt["audit_baseline_sha"] != policy["audit_baseline_sha"]:
        fail("AUDIT_BASELINE", "audit_baseline_sha", "receipt and policy audit baselines differ")
    if policy["profile"]["sha"] != profile_sha or receipt["profile_sha"] != profile_sha:
        fail("STALE_PROFILE", "profile_sha", "policy/receipt does not identify the trusted immutable profile")
    if hashlib.sha256(raw).hexdigest() != receipt["policy_sha256"]:
        fail("POLICY_DIGEST", "policy_sha256", "receipt does not bind the exact engineering.toml bytes")
    if not policy["owner"].strip():
        fail("OWNER", "owner", "policy requires a named owner")
    if profile_sha not in policy["profile"]["source_url"]:
        fail(
            "PROFILE_REF",
            "profile/source_url",
            "profile locator must contain its immutable SHA; remote existence remains unverified",
        )

    def parsed_date(value, field):
        try:
            return date.fromisoformat(value)
        except ValueError:
            fail("DATE", field, "invalid calendar date")
            return now.date()

    reviewed = parsed_date(policy["reviewed_on"], "reviewed_on")
    due = parsed_date(policy["review_due"], "review_due")
    if reviewed > now.date():
        fail("FUTURE_REVIEW", "reviewed_on", "review date is in the future")
    if due < reviewed:
        fail("REVIEW_ORDER", "review_due", "review deadline precedes review")
    if due < now.date():
        block("EXPIRED_REVIEW", "review_due", "policy review has expired")

    def timestamp(value, field):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
                raise ValueError()
        except ValueError:
            fail("TIMESTAMP", field, "expected valid UTC timestamp")
            return now
        if result > now:
            fail("FUTURE_EVIDENCE", field, "timestamp is later than the validation clock")
        return result

    created = timestamp(receipt["created_at"], "created_at")

    def index(records, field):
        ids = [r["id"] for r in records]
        if len(ids) != len(set(ids)):
            fail("DUPLICATE_ID", field, "record IDs must be unique within the collection")
        return {r["id"]: r for r in records}

    p = {
        k: index(policy[k], f"policy/{k}")
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
    r = {
        k: index(receipt[k], f"receipt/{k}")
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
    expected_tasks = {f"{PREFIXES[repo]}-{i:02d}" for i in range(1, 7)}
    for side, data in [("policy", p), ("receipt", r)]:
        for key, expected in [("standards", STANDARD_IDS), ("tasks", expected_tasks)]:
            if set(data[key]) != expected:
                fail("REQUIRED_IDS", f"{side}/{key}", f"exact IDs required: {sorted(expected)}")
    for key in ("environments", "commands", "test_families", "coverage_scopes", "input_files", "exceptions"):
        if set(p[key]) != set(r[key]):
            fail("RECORD_SET", key, "policy and receipt must have exactly the same declared records")
    roots = []
    for kind, paths in policy["roots"].items():
        for path in paths:
            try:
                relative = relative_path(path)
                roots.append((kind, relative))
            except ContractError as error:
                fail("ROOT_PATH", f"roots/{kind}", str(error))
    for i, (kind, path) in enumerate(roots):
        for other_kind, other in roots[i + 1 :]:
            if path == other or path in other.parents or other in path.parents:
                fail("ROOT_OVERLAP", "roots", f"{kind}:{path} overlaps {other_kind}:{other}")
    if not any(e["required"] for e in p["environments"].values()):
        fail("ENVIRONMENT", "environments", "at least one required environment must be declared")
    available = set()
    for key, declared in p["environments"].items():
        actual = r["environments"].get(key)
        if not declared["tools"]:
            fail("TOOLS", f"environments/{key}", "declare at least one exact supported tool version")
        if any(not name.strip() for name in declared["tools"]):
            fail("TOOL_IDENTITY", f"environments/{key}/tools", "policy tool names must be nonblank")
        if actual is None:
            continue
        if any(not name.strip() for name in actual["tools"]):
            fail("TOOL_IDENTITY", f"environments/{key}/tools", "receipt tool names must be nonblank")
        if actual["status"] == "blocked":
            if declared["required"]:
                block("ENVIRONMENT_BLOCKED", f"environments/{key}", actual["reason"])
            continue
        valid = True
        for name, allowed in declared["tools"].items():
            if actual["tools"].get(name) not in allowed:
                fail("TOOL_VERSION", f"environments/{key}/tools/{name}", "missing or unsupported tool version")
                valid = False
        if valid:
            available.add(key)
    # Every referenced local evidence/artifact file is actually hashed within the supplied root.
    evidence_root = Path(evidence_root).resolve()
    valid_evidence = set()
    valid_artifacts = set()
    file_paths = set()
    physical_files = set()
    valid_inputs = set()

    def verify_file(item, field, time_field, kind_field):
        good = True
        before = len(issues)
        for key, expected in [("source_sha", target_sha), ("profile_sha", profile_sha)]:
            if item[key] != expected:
                fail("FILE_IDENTITY", f"{field}/{key}", "evidence/artifact identity differs from the current target")
                good = False
        when = timestamp(item[time_field], f"{field}/{time_field}")
        if when > created:
            fail("EVIDENCE_ORDER", field, "evidence/artifact postdates receipt creation")
            good = False
        try:
            rel = relative_path(item["path"])
            resolved = (evidence_root / rel).resolve()
            if not resolved.is_relative_to(evidence_root):
                raise ContractError("resolved path escapes evidence root")
            key = (field.split("/")[0], str(resolved))
            if key in file_paths:
                raise ContractError("duplicate physical file within this collection")
            file_paths.add(key)
            if not resolved.is_file():
                block("MISSING_FILE", field, "referenced local file is unavailable")
                return False
            stat = resolved.stat()
            if not stat.st_ino:
                block("FILE_IDENTITY_UNAVAILABLE", field, "filesystem supplies no stable inode/file identity")
                return False
            physical = (field.split("/")[0], stat.st_dev, stat.st_ino)
            if physical in physical_files:
                fail("DUPLICATE_PHYSICAL_FILE", field, "hard-linked or aliased file cannot inflate the collection")
                return False
            physical_files.add(physical)
            if digest_file(resolved) != item["sha256"]:
                fail("FILE_HASH", field, "actual file SHA-256 differs from receipt")
                good = False
        except (OSError, RuntimeError, ContractError) as error:
            fail("FILE_PATH", field, str(error))
            good = False
        if receipt["mode"] == "production" and item[kind_field] == "synthetic":
            block("SYNTHETIC_EVIDENCE", field, "synthetic evidence cannot qualify a production requirement")
        return good and len(issues) == before

    for key, item in r["evidence"].items():
        if verify_file(item, f"evidence/{key}", "captured_at", "kind"):
            valid_evidence.add(key)
    for key, item in r["input_files"].items():
        if key not in p["input_files"]:
            continue
        if item != p["input_files"][key]:
            fail("INPUT_IDENTITY", f"input_files/{key}", "input path/kind/digest differs from reviewed policy")
            continue
        bound = {
            **item,
            "source_sha": target_sha,
            "profile_sha": profile_sha,
            "captured_at": receipt["created_at"],
            "classification": "synthetic" if receipt["mode"] == "synthetic_example" else "real",
        }
        if verify_file(bound, f"input_files/{key}", "captured_at", "classification"):
            valid_inputs.add(key)
    for key, item in r["artifacts"].items():
        if item["kind"] not in p["artifact_kinds"]:
            fail("ARTIFACT_KIND", f"artifacts/{key}", "undeclared artifact kind")
            continue
        if item["environment"] != p["artifact_kinds"][item["kind"]]["environment"]:
            fail("ARTIFACT_ENV", f"artifacts/{key}", "artifact environment differs from policy")
            continue
        if verify_file(item, f"artifacts/{key}", "created_at", "evidence_kind"):
            valid_artifacts.add(key)

    def references(ids, field, nonempty=False):
        if nonempty and not ids:
            fail("NO_EVIDENCE", field, "at least one verified local evidence record is required")
            return False
        unknown = set(ids) - set(r["evidence"])
        if unknown:
            fail("EVIDENCE_REF", field, f"unknown evidence IDs: {sorted(unknown)}")
        return bool(ids) and set(ids) <= valid_evidence

    def applicability(declared, actual, field):
        if not declared["reason"].strip():
            fail("APPLICABILITY_REASON", field, "policy needs a factual applicability reason")
        if not declared["applicable"]:
            if actual["status"] != "not_applicable":
                fail("NOT_APPLICABLE", field, "policy-declared N/A must be represented as N/A")
            if actual["reason"] != declared["reason"]:
                fail("NA_REASON", field, "N/A reason must match the reviewed factual policy reason")
            references(actual["evidence_ids"], field, True)
            return False
        if actual["status"] == "not_applicable":
            fail("UNDECLARED_NA", field, "applicable requirement cannot become N/A in the receipt")
            return False
        return True

    passed_commands = set()
    command_finished = {}
    for key, declared in p["commands"].items():
        actual = r["commands"].get(key)
        field = f"commands/{key}"
        before = len(issues)
        if declared["environment"] not in p["environments"]:
            fail("ENVIRONMENT_REF", field, "undeclared command environment")
        if actual is None:
            continue
        if actual["command"] != declared["command"]:
            fail("COMMAND_IDENTITY", field, "recorded command text differs from the policy declaration")
        start = timestamp(actual["started_at"], field + "/started_at")
        end = timestamp(actual["finished_at"], field + "/finished_at")
        command_finished[key] = end
        if start > end or end > created:
            fail("COMMAND_TIME", field, "command times must be ordered and precede receipt creation")
        applies = applicability(declared, actual, field)
        if not applies:
            if actual["exit_code"] is not None:
                fail("NA_EXIT", field, "N/A command must not claim an execution exit code")
            continue
        status = actual["status"]
        has_evidence = references(actual["evidence_ids"], field, status in ("passed", "failed"))
        for evidence_id in actual["evidence_ids"]:
            if (
                evidence_id in r["evidence"]
                and timestamp(r["evidence"][evidence_id]["captured_at"], field + "/evidence_time") < end
            ):
                fail("LOG_TIME", field, "command evidence cannot predate command completion")
        if status == "failed":
            fail("COMMAND_FAILED", field, actual["reason"])
        if status == "blocked":
            block("COMMAND_BLOCKED", field, actual["reason"])
        if status == "passed":
            if actual["exit_code"] != 0:
                fail("FALSE_PASS_EXIT", field, "passed command requires exit code 0")
            if declared["environment"] not in available:
                fail("FALSE_PASS_ENV", field, "passed command requires its supported available environment")
            if (
                actual["exit_code"] == 0
                and declared["environment"] in available
                and has_evidence
                and len(issues) == before
            ):
                passed_commands.add(key)
        if status == "blocked" and actual["exit_code"] is not None:
            fail("BLOCKED_EXIT", field, "blocked command cannot claim an execution exit code")
    passed_families = set()
    for key, declared in p["test_families"].items():
        actual = r["test_families"].get(key)
        field = f"test_families/{key}"
        before = len(issues)
        if declared["command_id"] not in p["commands"]:
            fail("COMMAND_REF", field, "undeclared test command")
        elif p["commands"][declared["command_id"]]["environment"] != declared["environment"]:
            fail("TEST_ENV", field, "test and command environments differ")
        if declared["environment"] not in p["environments"]:
            fail("ENVIRONMENT_REF", field, "undeclared test environment")
        allowed = index(declared["allowed_skips"], field + "/allowed_skips")
        if set(allowed) & set(declared["required_test_ids"]):
            fail("REQUIRED_SKIP", field, "required tests cannot also be policy-allowed skips")
        if actual is None:
            continue
        tests = index(actual["tests"], field + "/tests")
        counts = Counter(t["status"] for t in actual["tests"])
        computed = {
            "collected": len(actual["tests"]),
            "executed": counts["passed"] + counts["failed"],
            **{k: counts[k] for k in ("passed", "failed", "skipped", "blocked")},
        }
        if computed != actual["counts"]:
            fail("TEST_COUNTS", field, "declared counts do not equal individual test records")
        applies = applicability(declared, actual, field)
        if not applies:
            if actual["tests"]:
                fail("NA_TESTS", field, "N/A family cannot claim executed test records")
            if declared["minimum_executed"] or declared["required_test_ids"] or declared["allowed_skips"]:
                fail("NA_TEST_POLICY", field, "N/A family must not retain contradictory execution or skip requirements")
            continue
        references(actual["evidence_ids"], field, actual["status"] in ("passed", "failed"))
        if declared["minimum_executed"] < 1 or not declared["required_test_ids"]:
            fail("TEST_POLICY", field, "applicable family requires a positive executed floor and named required tests")
        unmet = block if actual["status"] == "blocked" else fail
        if computed["executed"] < declared["minimum_executed"]:
            unmet("ZERO_OR_FEW_TESTS", field, "too few tests actually executed")
        for test_id in declared["required_test_ids"]:
            if test_id not in tests:
                unmet("MISSING_TEST", field, f"required test {test_id} absent")
            elif tests[test_id]["status"] != "passed":
                report = block if tests[test_id]["status"] == "blocked" and actual["status"] == "blocked" else fail
                report("REQUIRED_TEST_NOT_PASSED", field, f"required test {test_id} did not pass")
        for test_id, test in tests.items():
            if test["status"] == "failed":
                fail("TEST_FAILED", field + "/" + test_id, test["reason"])
            if test["status"] == "blocked":
                block("TEST_BLOCKED", field + "/" + test_id, test["reason"])
            if test["status"] == "skipped" and (test_id not in allowed or test["reason"] != allowed[test_id]["reason"]):
                fail(
                    "UNEXPECTED_SKIP",
                    field + "/" + test_id,
                    "skip is not explicitly policy-declared with its factual reason",
                )
        if actual["status"] == "failed":
            fail("FAMILY_FAILED", field, actual["reason"])
        if actual["status"] == "blocked":
            block("FAMILY_BLOCKED", field, actual["reason"])
        if actual["status"] == "passed":
            if declared["command_id"] not in passed_commands:
                fail("FALSE_PASS_TEST_COMMAND", field, "passing family requires its passing command")
            if declared["environment"] not in available:
                fail("FALSE_PASS_TEST_ENV", field, "passing family requires its available supported environment")
            if len(issues) == before and set(actual["evidence_ids"]) <= valid_evidence:
                passed_families.add(key)
    qualified_artifacts = set()
    for key, item in r["artifacts"].items():
        if item["kind"] not in p["artifact_kinds"]:
            continue
        declared = p["artifact_kinds"][item["kind"]]
        actual = item["qualification"]
        field = f"artifacts/{key}/qualification"
        if set(actual["command_ids"]) != set(declared["qualification_command_ids"]) or set(
            actual["test_family_ids"]
        ) != set(declared["qualification_test_family_ids"]):
            fail("QUALIFICATION_IDENTITY", field, "qualification dependencies differ from policy")
            continue
        if not applicability(declared, actual, field):
            continue
        if actual["status"] == "failed":
            fail("ARTIFACT_QUALIFICATION_FAILED", field, actual["reason"])
        if actual["status"] == "blocked":
            block("ARTIFACT_QUALIFICATION_BLOCKED", field, actual["reason"])
        if actual["status"] == "passed":
            before = len(issues)
            has_evidence = references(actual["evidence_ids"], field, True)
            artifact_created = timestamp(item["created_at"], field + "/artifact_created_at")
            qualification_commands = set(actual["command_ids"])
            qualification_commands.update(
                p["test_families"][family_id]["command_id"]
                for family_id in actual["test_family_ids"]
                if family_id in p["test_families"]
            )
            for command_id in qualification_commands:
                if command_id in command_finished and artifact_created > command_finished[command_id]:
                    fail(
                        "ARTIFACT_QUALIFICATION_TIME",
                        field,
                        "artifact cannot be created after a command asserted to have qualified it finished",
                    )
            if (
                not set(actual["command_ids"]) <= passed_commands
                or not set(actual["test_family_ids"]) <= passed_families
            ):
                fail(
                    "FALSE_PASS_QUALIFICATION",
                    field,
                    "artifact requires passing declared qualification commands/families",
                )
            elif has_evidence and key in valid_artifacts and len(issues) == before:
                qualified_artifacts.add(key)
    valid_kinds = set()
    for key, declared in p["artifact_kinds"].items():
        if declared["environment"] not in p["environments"]:
            fail("ENVIRONMENT_REF", f"artifact_kinds/{key}", "undeclared artifact environment")
        count = sum(a["kind"] == key and aid in qualified_artifacts for aid, a in r["artifacts"].items())
        if declared["applicable"]:
            if not declared["qualification_command_ids"]:
                fail(
                    "QUALIFICATION_POLICY", f"artifact_kinds/{key}", "applicable artifact needs a qualification command"
                )
            if not set(declared["qualification_command_ids"]) <= set(p["commands"]) or not set(
                declared["qualification_test_family_ids"]
            ) <= set(p["test_families"]):
                fail("QUALIFICATION_REF", f"artifact_kinds/{key}", "undeclared qualification dependency")
            if declared["minimum_count"] < 1:
                fail("ARTIFACT_POLICY", f"artifact_kinds/{key}", "applicable kind requires a positive count")
            if declared["environment"] not in available:
                block(
                    "ARTIFACT_ENV_BLOCKED",
                    f"artifact_kinds/{key}",
                    "required artifact host is unavailable or unsupported",
                )
            if count < declared["minimum_count"]:
                block("MISSING_ARTIFACT", f"artifact_kinds/{key}", "too few verified required artifacts")
            elif declared["environment"] in available:
                valid_kinds.add(key)
        elif declared["minimum_count"] != 0:
            fail("NA_ARTIFACT_POLICY", f"artifact_kinds/{key}", "N/A kind must have zero required count")
    for key, declared in p["coverage_scopes"].items():
        actual = r["coverage_scopes"].get(key)
        field = f"coverage_scopes/{key}"
        if (
            declared["environment"] not in p["environments"]
            or declared["command_id"] not in p["commands"]
            or declared["artifact_kind"] not in p["artifact_kinds"]
        ):
            fail("COVERAGE_REF", field, "coverage references undeclared environment/command/artifact kind")
        if (
            declared["command_id"] in p["commands"]
            and p["commands"][declared["command_id"]]["environment"] != declared["environment"]
        ):
            fail("COVERAGE_ENV", field, "coverage command and scope environments differ")
        if (
            declared["artifact_kind"] in p["artifact_kinds"]
            and p["artifact_kinds"][declared["artifact_kind"]]["environment"] != declared["environment"]
        ):
            fail("COVERAGE_ENV", field, "coverage report and scope environments differ")
        for value in declared["included_roots"] + declared["excluded_roots"]:
            try:
                relative_path(value)
            except ContractError as error:
                fail("COVERAGE_PATH", field, str(error))
        if actual is None:
            continue
        for name in ("environment", "command_id", "measurement", "included_roots", "excluded_roots"):
            if actual[name] != declared[name]:
                fail("COVERAGE_IDENTITY", field, "recorded coverage scope/mode differs from policy")
        if not applicability(declared, actual, field):
            continue
        if declared["measurement"] == "none" or not declared["included_roots"]:
            fail("COVERAGE_POLICY", field, "applicable coverage needs a measurement mode and explicit source scope")
        if actual["status"] == "failed":
            fail("COVERAGE_FAILED", field, actual["reason"])
        if actual["status"] == "blocked":
            block("COVERAGE_BLOCKED", field, actual["reason"])
        if actual["status"] == "passed":
            references(actual["evidence_ids"], field, True)
            if declared["command_id"] not in passed_commands or declared["environment"] not in available:
                fail("FALSE_PASS_COVERAGE", field, "coverage requires supported execution")
            if not actual["artifact_ids"]:
                fail("NO_COVERAGE_ARTIFACT", field, "coverage needs a qualified report artifact")
            for artifact_id in actual["artifact_ids"]:
                if (
                    artifact_id not in qualified_artifacts
                    or r["artifacts"][artifact_id]["kind"] != declared["artifact_kind"]
                ):
                    fail("COVERAGE_ARTIFACT", field, "coverage references missing/unqualified/wrong-kind artifact")
    for category in ("standards", "tasks"):
        for key, declared in p[category].items():
            actual = r[category].get(key)
            field = f"{category}/{key}"
            for name, collection in [
                ("command_ids", "commands"),
                ("test_family_ids", "test_families"),
                ("artifact_kinds", "artifact_kinds"),
            ]:
                if set(declared[name]) - set(p[collection]):
                    fail("DEPENDENCY_REF", field, "requirement refers to undeclared dependencies")
            if actual is None:
                continue
            if not applicability(declared, actual, field):
                continue
            if not any(declared[k] for k in ("command_ids", "test_family_ids", "artifact_kinds")):
                fail("NO_ACCEPTANCE", field, "applicable requirement needs explicit acceptance dependencies")
            if actual["status"] == "failed":
                fail("REQUIREMENT_FAILED", field, actual["reason"])
            if actual["status"] == "blocked":
                block("REQUIREMENT_BLOCKED", field, actual["reason"])
            if actual["status"] == "passed":
                references(actual["evidence_ids"], field, True)
                if not (
                    set(declared["command_ids"]) <= passed_commands
                    and set(declared["test_family_ids"]) <= passed_families
                    and set(declared["artifact_kinds"]) <= valid_kinds
                ):
                    fail("FALSE_PASS_DEPENDENCY", field, "claimed passing requirement has an unresolved dependency")
    requirements = set(p["standards"]) | set(p["tasks"])
    for key, declared in p["exceptions"].items():
        field = f"exceptions/{key}"
        actual = r["exceptions"].get(key)
        if declared["requirement_id"] not in requirements:
            fail("EXCEPTION_REF", field, "unknown canonical requirement")
        if parsed_date(declared["expires_on"], field + "/expires_on") < now.date():
            fail("EXPIRED_EXCEPTION", field, "expired exception cannot support acceptance")
        if (
            not set(declared["alternative_command_ids"]) <= passed_commands
            or not set(declared["alternative_test_family_ids"]) <= passed_families
        ):
            fail(
                "UNPROVEN_ALTERNATIVE",
                field,
                "exception requires supported passing alternative commands and test families",
            )
        if actual:
            references(actual["evidence_ids"], field, True)
        # Deliberately no removal or suppression of any earlier FAIL/BLOCKED issue.
    computed = output(synthetic)["consistency_result"]
    if receipt["overall_status"] != computed:
        fail(
            "OVERALL_STATUS_MISMATCH",
            "overall_status",
            "producer label contradicts the independently computed result; it cannot be silently upgraded",
        )
    result = output(synthetic)
    result["declared_overall_status"] = receipt["overall_status"]
    result["declared_label_used_as_authority"] = False
    result["declared_label_consistency_checked"] = True
    result["verified_counts"] = {
        "evidence_files": len(valid_evidence),
        "artifacts": len(valid_artifacts),
        "input_files": len(valid_inputs),
        "qualified_artifacts": len(qualified_artifacts),
        "passing_commands": len(passed_commands),
        "passing_test_families": len(passed_families),
        "canonical_tasks": len(expected_tasks),
        "canonical_standards": len(STANDARD_IDS),
    }
    return result


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
