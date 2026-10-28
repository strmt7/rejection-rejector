"""Generate the two small, closed contract schemas. No third-party dependency."""

import json
from pathlib import Path

ROOT = Path(__file__).parent


def string(pattern=None):
    """Build one JSON Schema string node.

    Inputs: `pattern` -- regex the value must match (default: non-blank).
    Output: `dict` -- the schema node.
    """
    result = {"type": "string", "minLength": 1}
    result["pattern"] = pattern or r"\S"
    return result


def array(item, minimum=0, unique=False):
    """Build one JSON Schema array node.

    Inputs: `item` -- item schema; `minimum` -- minimum item count;
    `unique` -- require unique items. Output: `dict` -- the schema node.
    """
    value = {"type": "array", "items": item, "minItems": minimum}
    if unique:
        value["uniqueItems"] = True
    return value


def obj(properties, optional=()):
    """Build one JSON Schema object node.

    Inputs: `properties` -- property name to schema map; `optional` -- names
    exempt from `required`. Output: `dict` -- the schema node.
    """
    return {
        "type": "object",
        "properties": properties,
        "required": [p for p in properties if p not in optional],
        "additionalProperties": False,
    }


ID = string(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
SHA = string(r"^[0-9a-f]{40}$")
DIGEST = string(r"^[0-9a-f]{64}$")
DATE = string(r"^\d{4}-\d{2}-\d{2}$")
TIME = string(r"^\d{4}-\d{2}-\d{2}T.+(?:Z|\+00:00)$")
BOOL = {"type": "boolean"}
INT = {"type": "integer", "minimum": 0}
REFS = array(ID, unique=True)
STATUS = {"enum": ["passed", "failed", "blocked", "not_applicable"]}
APPLICABILITY = {"applicable": BOOL, "reason": string()}
requirement = obj({"id": ID, **APPLICABILITY, "command_ids": REFS, "test_family_ids": REFS, "artifact_kinds": REFS})
input_file = obj(
    {"id": ID, "kind": {"enum": ["lock", "asset", "configuration", "dataset"]}, "path": string(), "sha256": DIGEST}
)
MEASUREMENT = {"enum": ["line", "branch", "line_and_branch", "none"]}
coverage_identity = {
    "environment": ID,
    "command_id": ID,
    "measurement": MEASUREMENT,
    "included_roots": array(string(), unique=True),
    "excluded_roots": array(string(), unique=True),
}

policy = obj(
    {
        "schema_version": {"const": "1.0"},
        "repo": string(),
        "audit_baseline_sha": SHA,
        "profile": obj({"id": ID, "sha": SHA, "source_url": string()}),
        "owner": string(),
        "lifecycle": {"enum": ["maintained", "maintenance-only", "experiment", "superseded"]},
        "reviewed_on": DATE,
        "review_due": DATE,
        "roots": obj({k: array(string(), unique=True) for k in ("authored", "generated", "vendor", "fixture")}),
        "input_files_reason": string(),
        "input_files": array(input_file),
        "environments": array(
            obj(
                {
                    "id": ID,
                    "description": string(),
                    "required": BOOL,
                    "tools": {"type": "object", "additionalProperties": array(string(), 1, True)},
                }
            ),
            1,
        ),
        "standards": array(requirement, 15),
        "tasks": array(requirement, 6),
        "commands": array(obj({"id": ID, "command": string(), "environment": ID, **APPLICABILITY}), 1),
        "test_families": array(
            obj(
                {
                    "id": ID,
                    "environment": ID,
                    "command_id": ID,
                    **APPLICABILITY,
                    "minimum_executed": INT,
                    "required_test_ids": REFS,
                    "allowed_skips": array(obj({"id": ID, "reason": string()})),
                }
            ),
            1,
        ),
        "artifact_kinds": array(
            obj(
                {
                    "id": ID,
                    "environment": ID,
                    **APPLICABILITY,
                    "minimum_count": INT,
                    "qualification_command_ids": REFS,
                    "qualification_test_family_ids": REFS,
                }
            ),
            1,
        ),
        "coverage_scopes": array(obj({"id": ID, **APPLICABILITY, **coverage_identity, "artifact_kind": ID}), 1),
        "exceptions": array(
            obj(
                {
                    "id": ID,
                    "requirement_id": ID,
                    "owner": string(),
                    "reason": string(),
                    "expires_on": DATE,
                    "alternative_command_ids": array(ID, 1, True),
                    "alternative_test_family_ids": array(ID, 1, True),
                }
            )
        ),
    }
)

requirement_result = obj({"id": ID, "status": STATUS, "reason": string(), "evidence_ids": REFS})
receipt = obj(
    {
        "schema_version": {"const": "1.0"},
        "repo": string(),
        "mode": {"enum": ["production", "synthetic_example"]},
        "source_sha": SHA,
        "audit_baseline_sha": SHA,
        "profile_sha": SHA,
        "policy_sha256": DIGEST,
        "created_at": TIME,
        "overall_status": {"enum": ["PASS", "FAIL", "BLOCKED"]},
        "input_files": array(input_file),
        "environments": array(
            obj(
                {
                    "id": ID,
                    "status": {"enum": ["available", "blocked"]},
                    "reason": string(),
                    "tools": {"type": "object", "additionalProperties": string()},
                }
            ),
            1,
        ),
        "commands": array(
            obj(
                {
                    "id": ID,
                    "command": string(),
                    "status": STATUS,
                    "exit_code": {"type": ["integer", "null"]},
                    "started_at": TIME,
                    "finished_at": TIME,
                    "reason": string(),
                    "evidence_ids": REFS,
                }
            ),
            1,
        ),
        "test_families": array(
            obj(
                {
                    "id": ID,
                    "status": STATUS,
                    "reason": string(),
                    "evidence_ids": REFS,
                    "tests": array(
                        obj(
                            {
                                "id": ID,
                                "status": {"enum": ["passed", "failed", "blocked", "skipped"]},
                                "reason": string(),
                            }
                        )
                    ),
                    "counts": obj(
                        {k: INT for k in ("collected", "executed", "passed", "failed", "skipped", "blocked")}
                    ),
                }
            ),
            1,
        ),
        "artifacts": array(
            obj(
                {
                    "id": ID,
                    "kind": ID,
                    "environment": ID,
                    "path": string(),
                    "sha256": DIGEST,
                    "created_at": TIME,
                    "source_sha": SHA,
                    "profile_sha": SHA,
                    "evidence_kind": {"enum": ["real", "synthetic"]},
                    "qualification": obj(
                        {
                            "status": STATUS,
                            "reason": string(),
                            "command_ids": REFS,
                            "test_family_ids": REFS,
                            "evidence_ids": REFS,
                        }
                    ),
                }
            )
        ),
        "coverage_scopes": array(
            obj(
                {
                    "id": ID,
                    "status": STATUS,
                    "reason": string(),
                    **coverage_identity,
                    "artifact_ids": REFS,
                    "evidence_ids": REFS,
                }
            ),
            1,
        ),
        "evidence": array(
            obj(
                {
                    "id": ID,
                    "path": string(),
                    "sha256": DIGEST,
                    "captured_at": TIME,
                    "source_sha": SHA,
                    "profile_sha": SHA,
                    "kind": {"enum": ["real", "synthetic"]},
                    "description": string(),
                }
            )
        ),
        "standards": array(requirement_result, 15),
        "tasks": array(requirement_result, 6),
        "exceptions": array(obj({"id": ID, "evidence_ids": array(ID, 1, True)})),
    }
)

for name, schema in [("engineering-policy.schema.json", policy), ("execution-receipt.schema.json", receipt)]:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"urn:portfolio-engineering-manual:2026-10-27:{name}",
        "title": name.removesuffix(".schema.json"),
        **schema,
    }
    (ROOT / name).write_text(json.dumps(schema, indent=2) + "\n")

if __name__ == "__main__":
    print("Wrote policy and receipt JSON Schemas.")
