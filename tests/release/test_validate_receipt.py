"""Offline tests for the execution-receipt validator (tools/validate_receipt.py).

The validator is the S15 closure-record check: it must reject every
contradictory, stale, fabricated-shape or escaping receipt while accepting one
internally consistent record, and it must never echo receipt values (a receipt
that accidentally carries a secret must not leak it through findings). These
tests pin every decision boundary; none of them runs a real gate or touches
the network.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))

import validate_receipt as vr  # noqa: E402

NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
HEAD = "a" * 40


def stamp(offset_minutes: int, base: datetime = NOW) -> str:
    """Build one ISO timestamp offset from the given test clock."""
    return (base + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def gate(gate_id: str, exit_code: int = 0, status: str = "passed", **changes):
    """Build one gate record with canonical command and coherent times."""
    value = {
        "id": gate_id,
        "command": vr.REQUIRED_GATES[gate_id],
        "exit_code": exit_code,
        "status": status,
        "started_at": stamp(-30),
        "finished_at": stamp(-25),
    }
    if gate_id in vr.FAMILY_GATES:
        value["test_family"] = {
            "collected": 10,
            "executed": 10,
            "passed": 10,
            "failed": 0,
            "skipped": 0,
        }
    value.update(changes)
    return value


def good_receipt(**changes):
    """Build one fully consistent passing receipt for the whole gate set."""
    value = {
        "schema_version": 1,
        "repository": vr.REPOSITORY,
        "source_commit": HEAD,
        "toolchain": {"rustc": "1.99.1", "cargo": "1.99.1", "python": "3.14.9"},
        "generated_at": stamp(-20),
        "gates": [gate(gate_id) for gate_id in vr.REQUIRED_GATES],
        "artifacts": [],
        "exceptions": [],
        "overall_status": "PASS",
    }
    value.update(changes)
    return value


class ConsistencyTests(unittest.TestCase):
    """Positive controls: a coherent receipt must pass untouched."""

    def test_consistent_receipt_is_pass(self):
        """Why: the validator must not invent findings in a clean record."""
        verdict = vr.validate(good_receipt(), Path("."), NOW)
        self.assertEqual(verdict["result"], "PASS")
        self.assertEqual(verdict["findings"], [])

    def test_honest_blocked_gate_yields_blocked_not_fail(self):
        """Why: an unavailable environment is BLOCKED with a reason, never PASS."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[-1] = gate(
            "release-suites", exit_code=3, status="blocked", reason="Windows runner unavailable in this environment"
        )
        verdict = vr.validate(good_receipt(gates=gates, overall_status="BLOCKED"), Path("."), NOW)
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertEqual(verdict["findings"], [])


class ContradictionTests(unittest.TestCase):
    """The producer label and gate records must never contradict the math."""

    def test_false_pass_label_over_failed_gate_is_rejected(self):
        """Why: a FAIL/BLOCKED outcome must not be laundered into PASS."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[0] = gate("fmt", exit_code=1, status="failed")
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("result.label_contradiction", verdict["findings"])

    def test_exit_code_and_status_contradiction_is_rejected(self):
        """Why: exit 7 recorded as passed is exactly the manual's false-pass case."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[0] = gate("fmt", exit_code=7, status="passed")
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("gate.exit_status_contradiction:fmt", verdict["findings"])

    def test_failed_gate_without_label_still_fails(self):
        """Why: a coherent failed gate forces FAIL even when the label says FAIL."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[0] = gate("fmt", exit_code=2, status="failed")
        verdict = vr.validate(good_receipt(gates=gates, overall_status="FAIL"), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertEqual(verdict["findings"], [])

    def test_blocked_gate_without_reason_is_rejected(self):
        """Why: BLOCKED must state what environment is missing, not hide skips."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[-1] = gate("release-suites", exit_code=3, status="blocked")
        verdict = vr.validate(good_receipt(gates=gates, overall_status="BLOCKED"), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("gate.blocked_without_reason:release-suites", verdict["findings"])


class CoverageAndCountTests(unittest.TestCase):
    """Gate vocabulary and test-family arithmetic must be exact."""

    def test_missing_required_gate_is_rejected(self):
        """Why: a receipt that drops a gate cannot claim the suite ran."""
        gates = [gate(g) for g in vr.REQUIRED_GATES if g != "cargo-test"]
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("gate.missing:cargo-test", verdict["findings"])

    def test_unknown_and_duplicate_gate_ids_are_rejected(self):
        """Why: invented ids must not silently satisfy the required set."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates.append(gate("fmt", exit_code=0, status="passed"))
        gates.append(
            {
                "id": "mystery",
                "command": "x",
                "exit_code": 0,
                "status": "passed",
                "started_at": stamp(-30),
                "finished_at": stamp(-25),
            }
        )
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("gate.duplicate_id:fmt", verdict["findings"])
        self.assertIn("gate.unknown_id:mystery", verdict["findings"])

    def test_command_mismatch_is_rejected(self):
        """Why: the receipt must record the canonical gate, not a lookalike."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[1] = gate("clippy", command="cargo clippy")
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("gate.command_mismatch:clippy", verdict["findings"])

    def test_family_count_mismatch_and_zero_tests_are_rejected(self):
        """Why: fabricated or empty inventories must not pass as evidence."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[-1] = gate(
            "release-suites", test_family={"collected": 5, "executed": 4, "passed": 4, "failed": 1, "skipped": 0}
        )
        gates[-2] = gate(
            "cargo-test", test_family={"collected": 0, "executed": 0, "passed": 0, "failed": 0, "skipped": 0}
        )
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("family.release-suites:collected_count_mismatch", verdict["findings"])
        self.assertIn("family.cargo-test:zero_tests_discovered", verdict["findings"])

    def test_missing_family_on_a_family_gate_is_rejected(self):
        """Why: the Rust and release suites must report discovered counts."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[-2] = gate("cargo-test", test_family=None)
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("family.cargo-test:missing", verdict["findings"])


class TimeTests(unittest.TestCase):
    """Timestamps must be ordered, timezone-aware and not in the future."""

    def test_future_and_disordered_timestamps_are_rejected(self):
        """Why: impossible times betray a manufactured record."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[0] = gate("fmt", started_at=stamp(-25), finished_at=stamp(-30))
        gates[1] = gate("clippy", started_at=stamp(60), finished_at=stamp(61))
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("gate.time_order:fmt", verdict["findings"])
        self.assertIn("gate.future_timestamp:clippy:started", verdict["findings"])

    def test_naive_timestamp_is_rejected(self):
        """Why: without a timezone the ordering checks are meaningless."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[0] = gate("fmt", started_at="2026-10-28T11:30:00")
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")


class ArtifactTests(unittest.TestCase):
    """Declared evidence bytes must hash correctly and stay under the root."""

    def test_digest_match_passes_and_mismatch_fails(self):
        """Why: the receipt must bind to the actual evidence bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "logs"
            log.mkdir()
            (log / "tests.txt").write_bytes(b"test result: ok")
            import hashlib

            good = hashlib.sha256(b"test result: ok").hexdigest()
            receipt = good_receipt(artifacts=[{"path": "logs/tests.txt", "sha256": good}])
            self.assertEqual(vr.validate(receipt, root, NOW)["result"], "PASS")
            receipt = good_receipt(artifacts=[{"path": "logs/tests.txt", "sha256": "b" * 64}])
            verdict = vr.validate(receipt, root, NOW)
            self.assertEqual(verdict["result"], "FAIL")
            self.assertIn("artifact.digest_mismatch:0", verdict["findings"])

    def test_path_escape_absolute_and_duplicate_paths_are_rejected(self):
        """Why: no receipt field may read outside the declared evidence root."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.txt").write_bytes(b"x")
            import hashlib

            digest = hashlib.sha256(b"x").hexdigest()
            for bad in ("../outside.txt", str(root / "ok.txt"), "a/../../x"):
                receipt = good_receipt(artifacts=[{"path": bad, "sha256": digest}])
                verdict = vr.validate(receipt, root, NOW)
                self.assertEqual(verdict["result"], "FAIL", bad)
            receipt = good_receipt(
                artifacts=[{"path": "ok.txt", "sha256": digest}, {"path": "ok.txt", "sha256": digest}]
            )
            verdict = vr.validate(receipt, root, NOW)
            self.assertIn("artifact.duplicate_path:1", verdict["findings"])


class ArtifactBudgetTests(unittest.TestCase):
    """why (security review finding 10): receipt-controlled artifacts are
    hashed incrementally under hard budgets instead of read fully into
    memory.
    """

    @staticmethod
    def _sparse(path: Path, size: int) -> None:
        """Create a sparse file of `size` bytes without allocating it."""
        with path.open("wb") as handle:
            handle.seek(size - 1)
            handle.write(b"\0")

    def test_oversized_artifact_fails_without_large_allocation(self):
        """A sparse artifact above the per-file cap fails closed and fast."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._sparse(root / "huge.bin", 65 * 1024 * 1024)
            receipt = good_receipt(artifacts=[{"path": "huge.bin", "sha256": "a" * 64}])
            verdict = vr.validate(receipt, root, NOW)
            self.assertEqual(verdict["result"], "FAIL")
            self.assertIn("artifact.too_large:0", verdict["findings"])

    def test_artifact_count_budget_fails_closed(self):
        """More artifacts than the count budget fail before any hashing."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts = [
                {"path": f"file{index}.txt", "sha256": "a" * 64}
                for index in range(vr.bounded_hash.MAX_ARTIFACT_COUNT + 1)
            ]
            verdict = vr.validate(good_receipt(artifacts=artifacts), root, NOW)
            self.assertEqual(verdict["result"], "FAIL")
            self.assertIn("artifact.count_budget", verdict["findings"])

    def test_aggregate_byte_budget_fails_closed(self):
        """Sparse artifacts summing past the aggregate cap fail closed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts = []
            size = 60 * 1024 * 1024
            for index in range(5):
                name = f"part{index}.bin"
                self._sparse(root / name, size)
                artifacts.append({"path": name, "sha256": "a" * 64})
            verdict = vr.validate(good_receipt(artifacts=artifacts), root, NOW)
            self.assertEqual(verdict["result"], "FAIL")
            self.assertTrue(
                any(f.startswith("artifact.aggregate_budget:") for f in verdict["findings"]),
                verdict["findings"],
            )

    def test_bounded_artifacts_still_validate_digests(self):
        """Contained, budget-respecting artifacts keep digest validation."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.txt").write_bytes(b"evidence")
            import hashlib

            digest = hashlib.sha256(b"evidence").hexdigest()
            receipt = good_receipt(artifacts=[{"path": "ok.txt", "sha256": digest}])
            self.assertEqual(vr.validate(receipt, root, NOW)["result"], "PASS")

    def test_replacement_during_hashing_fails_closed(self):
        """why: identity is compared before and after streaming, so a file
        swapped mid-hash is rejected rather than digesting mixed bytes.
        """
        from unittest import mock

        import bounded_hash

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "swap.bin"
            target.write_bytes(b"original")
            with (
                mock.patch.object(bounded_hash.os, "fstat", return_value=os.stat_result((0,) * 10)),
                self.assertRaises(bounded_hash.HashBudgetError),
            ):
                bounded_hash.bounded_sha256(target)

    def test_unmodified_artifact_hashes_to_its_digest(self):
        """The streamed digest equals the classic one-shot digest."""
        import hashlib

        import bounded_hash

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "plain.bin"
            payload = b"x" * (2 * 1024 * 1024)
            target.write_bytes(payload)
            self.assertEqual(
                bounded_hash.bounded_sha256(target),
                hashlib.sha256(payload).hexdigest(),
            )


class ExceptionTests(unittest.TestCase):
    """Exceptions are records, never an upgrade path for failures."""

    def test_expired_exception_is_rejected(self):
        """Why: a stale waiver must not linger silently."""
        receipt = good_receipt(
            exceptions=[
                {"id": "EX-1", "gate": "cargo-test", "reason": "old env", "owner": "strmt7", "expires": "2026-01-01"}
            ]
        )
        verdict = vr.validate(receipt, Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertIn("exception.expired:EX-1", verdict["findings"])

    def test_valid_exception_cannot_rescue_a_failed_gate(self):
        """Why: S15 - exceptions never delete or downgrade a FAIL."""
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[0] = gate("fmt", exit_code=1, status="failed")
        receipt = good_receipt(
            gates=gates,
            overall_status="FAIL",
            exceptions=[
                {
                    "id": "EX-2",
                    "gate": "fmt",
                    "reason": "formatter pinned elsewhere",
                    "owner": "strmt7",
                    "expires": "2027-01-01",
                }
            ],
        )
        self.assertEqual(vr.validate(receipt, Path("."), NOW)["result"], "FAIL")


class InputHardeningTests(unittest.TestCase):
    """Strict decoding, size caps and value-free failure output."""

    def test_duplicate_json_keys_are_rejected(self):
        """Why: duplicate properties are ambiguous and must fail closed."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            path.write_text('{"repository": "x", "repository": "y"}', encoding="utf-8")
            with self.assertRaises(vr.ReceiptError):
                vr.load_receipt(path)

    def test_oversize_receipt_is_rejected(self):
        """Why: bounded input keeps the validator a cheap local check."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            path.write_bytes(b" " * (vr.MAX_RECEIPT_BYTES + 1))
            with self.assertRaises(vr.ReceiptError):
                vr.load_receipt(path)

    def test_findings_never_echo_receipt_values(self):
        """Why: a receipt carrying a secret must not leak it via error text."""
        secret = "SECRET_TOKEN_9f2c"
        gates = [gate(g) for g in vr.REQUIRED_GATES]
        gates[0] = gate("fmt", command=f"cargo fmt {secret}")
        verdict = vr.validate(good_receipt(gates=gates), Path("."), NOW)
        self.assertEqual(verdict["result"], "FAIL")
        for finding in verdict["findings"]:
            self.assertNotIn(secret, finding)

    def test_cli_exit_codes_match_the_documented_contract(self):
        """Why: exit 0/1/2 for PASS/FAIL/BLOCKED is the operator interface."""
        # The CLI uses the real machine clock, so build this receipt's times
        # against that clock rather than the fixed test clock.
        real_now = datetime.now(UTC).replace(microsecond=0)

        def cli_gate(gate_id, **changes):
            """One gate record whose times sit near the real current time."""
            value = {
                "id": gate_id,
                "command": vr.REQUIRED_GATES[gate_id],
                "exit_code": 0,
                "status": "passed",
                "started_at": stamp(-30, real_now),
                "finished_at": stamp(-25, real_now),
            }
            if gate_id in vr.FAMILY_GATES:
                value["test_family"] = {
                    "collected": 10,
                    "executed": 10,
                    "passed": 10,
                    "failed": 0,
                    "skipped": 0,
                }
            value.update(changes)
            return value

        def cli_receipt(status, gates=None):
            """One receipt whose generated_at sits near the real current time."""
            return {
                "schema_version": 1,
                "repository": vr.REPOSITORY,
                "source_commit": HEAD,
                "toolchain": {"rustc": "1.99.1", "cargo": "1.99.1", "python": "3.14.9"},
                "generated_at": stamp(-20, real_now),
                "gates": gates or [cli_gate(g) for g in vr.REQUIRED_GATES],
                "artifacts": [],
                "exceptions": [],
                "overall_status": status,
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for label, expected in (("PASS", 0), ("FAIL", 1)):
                receipt = cli_receipt(label)
                if label == "FAIL":
                    receipt["gates"][0] = cli_gate("fmt", exit_code=1, status="failed")
                path = root / f"{label}.json"
                path.write_text(json.dumps(receipt), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()):
                    code = vr.main(["--receipt", str(path), "--evidence-root", str(root)])
                self.assertEqual(code, expected, label)
            gates = [cli_gate(g) for g in vr.REQUIRED_GATES]
            gates[-1] = cli_gate("release-suites", exit_code=3, status="blocked", reason="runner missing")
            path = root / "BLOCKED.json"
            path.write_text(json.dumps(cli_receipt("BLOCKED", gates)), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = vr.main(["--receipt", str(path), "--evidence-root", str(root)])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
