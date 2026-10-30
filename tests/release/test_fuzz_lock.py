"""Fuzz workspace dependency integrity (security review finding 6).

why: the fuzz workspace is an independent Cargo graph whose build executes
dependency build scripts and proc macros on the release-gating CI runner.
Without a tracked lock, a newly resolvable compromised semver-compatible
crate can execute code there and falsify the fuzz evidence the release
guard consumes. These tests are offline and structural: the tracked lock
must exist, pin the expected graph shape, and match the digest recorded in
engineering.toml's pinned inputs.
"""

import hashlib
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
LOCK = ROOT / "fuzz" / "Cargo.lock"
MANIFEST = ROOT / "fuzz" / "Cargo.toml"
POLICY = ROOT / "engineering.toml"


class FuzzLockTests(unittest.TestCase):
    """The standalone fuzz workspace resolves only its tracked lock."""

    def _lock(self) -> dict:
        """Load the tracked fuzz lock. Output: parsed lock document."""
        self.assertTrue(LOCK.is_file(), "fuzz/Cargo.lock must be tracked")
        return tomllib.loads(LOCK.read_text(encoding="utf-8"))

    def test_lock_pins_the_expected_package_graph(self):
        """The lock carries the fuzz crate, the exact libfuzzer pin and the
        local parent crate, and no git-sourced packages.
        """
        lock = self._lock()
        packages = {entry["name"]: entry for entry in lock.get("package", [])}
        self.assertIn("rejection-rejector-fuzz", packages)
        self.assertIn("rejection-rejector", packages)
        self.assertIn("libfuzzer-sys", packages)
        self.assertEqual(packages["libfuzzer-sys"]["version"], "0.4.13")
        # The parent crate is a path dependency: no registry source record.
        self.assertNotIn("source", packages["rejection-rejector"])
        for entry in packages.values():
            source = entry.get("source", "")
            self.assertFalse(
                source.startswith("git+"),
                f"unexpected git source in fuzz lock: {entry['name']}",
            )

    def test_manifest_pins_the_fuzzer_dependency_exactly(self):
        """The fuzzer runtime stays on its exact version pin."""
        manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["dependencies"]["libfuzzer-sys"], "=0.4.13")

    def test_lock_digest_matches_the_pinned_input_record(self):
        """engineering.toml binds the exact tracked lock bytes."""
        digest = hashlib.sha256(LOCK.read_bytes()).hexdigest()
        policy = tomllib.loads(POLICY.read_text(encoding="utf-8"))
        records = {entry["id"]: entry.get("sha256") for entry in policy.get("input_files", [])}
        self.assertEqual(
            records.get("fuzz-cargo-lock"),
            digest,
            "fuzz/Cargo.lock digest must match engineering.toml's pinned input",
        )


if __name__ == "__main__":
    unittest.main()
