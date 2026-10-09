"""Prevent verification workflows from becoming an alternative release path."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ReleaseRoutingTests(unittest.TestCase):
    def test_rust_ci_does_not_publish_a_deployable_package(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        for forbidden in ('package_windows', 'Collect Windows package', 'Compress-Archive',
                          'Copy-Item target/release', 'Build Windows release binaries'):
            self.assertNotIn(forbidden, text)
        self.assertIn('workflow_dispatch:', text)
        self.assertIn('cargo build --locked --bins', text)
        self.assertIn('cargo test --locked --all-features', text)
        self.assertIn('rejection-rejector-source.zip', text)

    def test_user_facing_release_remains_explicit_and_fully_gated(self):
        text = (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8')
        self.assertIn("if: inputs.confirmation == 'PACKAGE'", text)
        self.assertEqual(text.count('python scripts/release_guard.py evidence'), 2)
        self.assertEqual(text.count('python scripts/verify_package.py'), 2)
        self.assertIn('Audit each shipped executable independently', text)
        self.assertIn('Verify generated provenance and SBOM attestations', text)
        self.assertNotIn('continue-on-error:', text)

    def test_local_and_reproducibility_builds_are_preserved(self):
        local = (ROOT / 'scripts/build-windows.ps1').read_text(encoding='utf-8')
        repro = (ROOT / '.github/workflows/reproducibility.yml').read_text(encoding='utf-8')
        self.assertIn('cargo build --locked --release --bins', local)
        self.assertIn('cargo auditable build --locked --release --bins', repro)
        self.assertIn('if ($hashA -ne $hashB)', repro)


if __name__ == '__main__':
    unittest.main()
