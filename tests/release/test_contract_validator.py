"""Behavior contracts for tools/contract/validate_contract.py core.

Inputs: none (unittest). Output: pins the bundled schema engine (strict
keywords, exact type predicates, object/array/string constraints), the
portable-path and digest primitives, and the _Validation finding/file/
reference/applicability helpers — the reusable core of the release
contract validator, exercised here without any network or full receipt
fixtures.

Why (coverage doctrine): this validator is the release gate's evidence
checker; every acceptance/refusal rule must fail tests when it turns
subtly wrong.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "contract"))
import validate_contract as vc  # noqa: E402


class LoadJsonTests(unittest.TestCase):
    """Pin bounded, ambiguity-free contract loading."""

    def test_duplicate_keys_constants_and_size_refuse(self):
        """Duplicate keys, non-finite constants and oversized documents all
        raise ContractError before any rule runs.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "dup.json").write_text('{"a": 1, "a": 2}', encoding="utf-8")
            (root / "nan.json").write_text('{"a": NaN}', encoding="utf-8")
            (root / "big.json").write_bytes(b"0" * (2 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(vc.ContractError, "duplicate"):
                vc.load_json(root / "dup.json")
            with self.assertRaisesRegex(vc.ContractError, "constant"):
                vc.load_json(root / "nan.json")
            with self.assertRaisesRegex(vc.ContractError, "2 MiB"):
                vc.load_json(root / "big.json")
            (root / "ok.json").write_text('{"a": [1, true, null]}', encoding="utf-8")
            self.assertEqual(vc.load_json(root / "ok.json"), {"a": [1, True, None]})


class SchemaEngineTests(unittest.TestCase):
    """Pin the strict schema keyword behavior."""

    def test_unsupported_keyword_refuses(self):
        """The engine is deliberately not general: unknown schema keywords
        refuse instead of being silently ignored.
        """
        with self.assertRaisesRegex(vc.ContractError, "unsupported schema keyword"):
            vc.check_shape(1, {"type": "integer", "maxLength": 3})

    def test_const_and_enum_enforcement(self):
        """Exact constants and closed value sets."""
        with self.assertRaisesRegex(vc.ContractError, "wrong constant"):
            vc.check_shape("b", {"const": "a"})
        with self.assertRaisesRegex(vc.ContractError, "unsupported value"):
            vc.check_shape("c", {"enum": ["a", "b"]})
        vc.check_shape("a", {"const": "a", "enum": ["a"]})

    def test_type_predicates_are_exact(self):
        """Why (exact types): bool is NOT integer and bool/int are NOT
        interchangeable — the predicate table uses exact type checks.
        """
        with self.assertRaisesRegex(vc.ContractError, "wrong type"):
            vc.check_shape(True, {"type": "integer"})
        with self.assertRaisesRegex(vc.ContractError, "wrong type"):
            vc.check_shape(1, {"type": "boolean"})
        with self.assertRaisesRegex(vc.ContractError, "wrong type"):
            vc.check_shape(1.5, {"type": "integer"})
        vc.check_shape(1, {"type": ["integer", "string"]})
        vc.check_shape(None, {"type": "null"})

    def test_object_rules(self):
        """Required fields, closed objects and typed additional properties."""
        schema = {
            "type": "object",
            "required": ["a"],
            "properties": {"a": {"type": "integer"}},
            "additionalProperties": False,
        }
        with self.assertRaisesRegex(vc.ContractError, "missing fields"):
            vc.check_shape({}, schema)
        with self.assertRaisesRegex(vc.ContractError, "unexpected field"):
            vc.check_shape({"a": 1, "z": 2}, schema)
        vc.check_shape({"a": 1}, schema)
        open_schema = {"type": "object", "additionalProperties": {"type": "integer"}}
        with self.assertRaisesRegex(vc.ContractError, "wrong type"):
            vc.check_shape({"x": "no"}, open_schema)

    def test_array_rules(self):
        """minItems, uniqueItems and per-item recursion."""
        schema = {"type": "array", "minItems": 2, "uniqueItems": True, "items": {"type": "integer"}}
        with self.assertRaisesRegex(vc.ContractError, "too few items"):
            vc.check_shape([1], schema)
        with self.assertRaisesRegex(vc.ContractError, "duplicate item"):
            vc.check_shape([1, 1], schema)
        with self.assertRaisesRegex(vc.ContractError, "wrong type"):
            vc.check_shape([1, "x"], schema)
        vc.check_shape([1, 2], schema)

    def test_string_and_minimum_rules(self):
        """minLength, pattern and integer minimum; bool never trips minimum."""
        with self.assertRaisesRegex(vc.ContractError, "empty string"):
            vc.check_shape("", {"type": "string", "minLength": 1})
        with self.assertRaisesRegex(vc.ContractError, "pattern mismatch"):
            vc.check_shape("ZZ-9", {"type": "string", "pattern": r"^[a-z]+$", "minLength": 1})
        vc.check_shape("abc", {"type": "string", "pattern": r"^[a-z]+$"})
        with self.assertRaisesRegex(vc.ContractError, "below minimum"):
            vc.check_shape(3, {"type": "integer", "minimum": 5})
        vc.check_shape(True, {"type": "boolean", "minimum": 5})

    def test_depth_limit(self):
        """Nesting beyond 64 refuses (recursion guard)."""
        deep = value_cursor = {}
        schema = schema_cursor = {}
        for _ in range(70):
            value_cursor["n"] = {}
            value_cursor = value_cursor["n"]
            schema_cursor["type"] = "object"
            schema_cursor["additionalProperties"] = {}
            schema_cursor = schema_cursor["additionalProperties"]
        with self.assertRaisesRegex(vc.ContractError, "nesting exceeds 64"):
            vc.check_shape(deep, schema)


class PrimitivesTests(unittest.TestCase):
    """Pin digest and portable-path helpers."""

    def test_digest_file_matches_hashlib(self):
        """Streaming digest equals the standard hash of the same bytes."""
        with tempfile.TemporaryDirectory() as owned:
            path = pathlib.Path(owned) / "f.bin"
            payload = b"x" * (3 * 1024 * 1024) + b"\x00\xff"
            path.write_bytes(payload)
            self.assertEqual(vc.digest_file(path), hashlib.sha256(payload).hexdigest())

    def test_relative_path_rules(self):
        """Forward-slash relative paths only: no separators, absolutes,
        parents, dots or drive qualification.
        """
        self.assertEqual(str(vc.relative_path("docs/a.txt")), "docs/a.txt")
        for bad in ("docs\\a.txt", "/abs/a", "C:/a", "a/../b", "a/./b", ""):
            with self.assertRaises(vc.ContractError, msg=bad):
                vc.relative_path(bad)


def make_validation(root: pathlib.Path) -> vc._Validation:
    """Purpose: Build a validation run with dummy identity.

    Inputs: `root` -- evidence root directory; Output: a `_Validation`
    ready for primitive-level tests.
    """
    now = datetime.datetime(2026, 6, 1, 12, 0, 0, tzinfo=datetime.UTC)
    run = vc._Validation("policy.toml", "receipt.json", root, "owner/repo", "target-sha", "profile-sha", now)
    run.created = now - datetime.timedelta(hours=1)
    run.receipt = {"mode": "review"}
    run.r = {"evidence": {"e1": {}}}
    run.valid_evidence = {"e1"}
    return run


class ValidationPrimitiveTests(unittest.TestCase):
    """Pin the finding-closed parse and verification helpers."""

    def test_date_and_timestamp_failure_closed(self):
        """Invalid dates/timestamps record findings and return safe values;
        future timestamps record FUTURE_EVIDENCE; naive/non-UTC refuse.
        """
        with tempfile.TemporaryDirectory() as owned:
            run = make_validation(pathlib.Path(owned))
            self.assertEqual(run.parsed_date("2026-01-02", "f"), datetime.date(2026, 1, 2))
            fallback = run.parsed_date("not-a-date", "f")
            self.assertEqual(fallback, run.now.date())
            self.assertEqual(run.issues[-1]["code"], "DATE")

            self.assertEqual(run.timestamp("2026-06-01T11:00:00Z", "f").hour, 11)
            run.timestamp("2026-06-01T11:00:00", "f")
            self.assertEqual(run.issues[-1]["code"], "TIMESTAMP")
            run.timestamp("2026-06-01T11:00:00+02:00", "f")
            self.assertEqual(run.issues[-1]["code"], "TIMESTAMP")
            run.timestamp("2026-07-01T11:00:00Z", "f")
            self.assertEqual(run.issues[-1]["code"], "FUTURE_EVIDENCE")

    def test_index_rejects_duplicate_ids(self):
        """Record collections must have unique ids."""
        with tempfile.TemporaryDirectory() as owned:
            run = make_validation(pathlib.Path(owned))
            indexed = run.index([{"id": "a"}, {"id": "b"}], "col")
            self.assertEqual(set(indexed), {"a", "b"})
            run.index([{"id": "a"}, {"id": "a"}], "col")
            self.assertEqual(run.issues[-1]["code"], "DUPLICATE_ID")

    def test_verify_file_full_pass_and_refusals(self):
        """The happy path verifies identity, order and bytes; wrong hash,
        wrong identity, postdating, synthetic-in-production, missing files
        and path escapes each record exactly their own finding.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            payload = b"evidence bytes"
            (root / "ev.bin").write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            when = "2026-06-01T11:00:00Z"

            def item(**overrides):
                base = {
                    "path": "ev.bin",
                    "sha256": digest,
                    "source_sha": "target-sha",
                    "profile_sha": "profile-sha",
                    "observed_at": when,
                    "kind": "measured",
                }
                base.update(overrides)
                return base

            run = make_validation(root)
            self.assertTrue(run.verify_file(item(), "evidence/x", "observed_at", "kind"))

            run = make_validation(root)
            self.assertFalse(run.verify_file(item(sha256="0" * 64), "evidence/x", "observed_at", "kind"))
            self.assertEqual(run.issues[-1]["code"], "FILE_HASH")

            run = make_validation(root)
            self.assertFalse(run.verify_file(item(source_sha="other"), "evidence/x", "observed_at", "kind"))
            self.assertEqual(run.issues[-1]["code"], "FILE_IDENTITY")

            run = make_validation(root)
            late = item(observed_at="2026-06-01T12:30:00Z")
            self.assertFalse(run.verify_file(late, "evidence/x", "observed_at", "kind"))
            self.assertEqual(run.issues[-1]["code"], "EVIDENCE_ORDER")

            run = make_validation(root)
            run.receipt = {"mode": "production"}
            run.verify_file(item(kind="synthetic"), "evidence/x", "observed_at", "kind")
            self.assertEqual(run.issues[-1]["code"], "SYNTHETIC_EVIDENCE")
            self.assertEqual(run.issues[-1]["level"], "BLOCKED")

            run = make_validation(root)
            self.assertFalse(run.verify_file(item(path="absent.bin"), "evidence/x", "observed_at", "kind"))
            self.assertEqual(run.issues[-1]["code"], "MISSING_FILE")

            run = make_validation(root)
            self.assertFalse(run.verify_file(item(path="../escape.bin"), "evidence/x", "observed_at", "kind"))
            self.assertEqual(run.issues[-1]["code"], "FILE_PATH")

    def test_references_and_applicability_rules(self):
        """Unknown/empty references and every applicability-mismatch class
        record their own finding; the happy paths return clean.
        """
        with tempfile.TemporaryDirectory() as owned:
            run = make_validation(pathlib.Path(owned))
            self.assertFalse(run.references([], "req", True))
            self.assertEqual(run.issues[-1]["code"], "NO_EVIDENCE")
            self.assertFalse(run.references(["ghost"], "req"))
            self.assertEqual(run.issues[-1]["code"], "EVIDENCE_REF")
            self.assertTrue(run.references(["e1"], "req", True))

            run = make_validation(pathlib.Path(owned))
            actual_na = {"status": "not_applicable", "reason": "no GPU on target", "evidence_ids": ["e1"]}
            self.assertFalse(run.applicability({"applicable": False, "reason": "no GPU on target"}, actual_na, "req"))
            self.assertEqual(len(run.issues), 0)

            run = make_validation(pathlib.Path(owned))
            run.applicability({"applicable": False, "reason": " "}, {**actual_na, "reason": " "}, "req")
            self.assertEqual(run.issues[-1]["code"], "APPLICABILITY_REASON")

            run = make_validation(pathlib.Path(owned))
            run.applicability({"applicable": False, "reason": "other"}, {**actual_na, "status": "pass"}, "req")
            self.assertEqual(run.issues[0]["code"], "NOT_APPLICABLE")

            run = make_validation(pathlib.Path(owned))
            run.applicability({"applicable": False, "reason": "a"}, {**actual_na, "reason": "b"}, "req")
            self.assertEqual(run.issues[-1]["code"], "NA_REASON")

            run = make_validation(pathlib.Path(owned))
            run.applicability({"applicable": True, "reason": "a"}, actual_na, "req")
            self.assertEqual(run.issues[-1]["code"], "UNDECLARED_NA")

            run = make_validation(pathlib.Path(owned))
            actual_pass = {"status": "pass", "reason": "a", "evidence_ids": []}
            self.assertTrue(run.applicability({"applicable": True, "reason": "a"}, actual_pass, "req"))

    def test_output_qualification_rules(self):
        """FAIL dominates, BLOCKED follows any issue, and a synthetic PASS
        is downgraded to BLOCKED with synthetic-only qualification.
        """
        with tempfile.TemporaryDirectory() as owned:
            run = make_validation(pathlib.Path(owned))
            self.assertEqual(run.output()["result"], "PASS")
            run.fail("X", "f", "m")
            self.assertEqual(run.output()["result"], "FAIL")
            run2 = make_validation(pathlib.Path(owned))
            run2.block("X", "f", "m")
            self.assertEqual(run2.output()["result"], "BLOCKED")
            run3 = make_validation(pathlib.Path(owned))
            run3.synthetic = True
            self.assertEqual(run3.output()["result"], "BLOCKED")
            self.assertEqual(run3.output()["qualification"], "synthetic_example_only")


if __name__ == "__main__":
    unittest.main()
