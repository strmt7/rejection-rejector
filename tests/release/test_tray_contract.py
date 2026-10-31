"""Pin the Windows tray shell's shipping contract.

The `rr-tray` shell must stay a declared `[[bin]]` target in Cargo.toml, the
Windows installer must ship `rr-tray.exe`, and the tray source must contain no
raw-FFI token (the workspace forbids it outright). These tests pin that
contract so the tray cannot silently disappear from the build or installer and
so no native-call block can creep into its source.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CARGO = ROOT / "Cargo.toml"
ISS = ROOT / "windows" / "installer.iss"
TRAY = ROOT / "src" / "bin" / "rr-tray.rs"


class TrayContractTest(unittest.TestCase):
    """The tray shell ships as a binary and its source stays safe-only."""

    def test_cargo_declares_the_rr_tray_bin(self):
        """Cargo.toml declares rr-tray as a [[bin]] target."""
        text = CARGO.read_text(encoding="utf-8")
        self.assertIn("[[bin]]", text, "explicit bin targets are declared")
        self.assertIn('name = "rr-tray"', text, "the rr-tray target is named")
        self.assertIn('path = "src/bin/rr-tray.rs"', text, "the rr-tray target maps its source")

    def test_installer_ships_the_tray_binary(self):
        """installer.iss ships rr-tray.exe in the tray component."""
        text = ISS.read_text(encoding="utf-8")
        self.assertIn(
            'rr-tray.exe"; DestDir: "{app}"; Components: tray',
            text,
            "the tray binary is installed with its component",
        )

    def test_tray_source_contains_no_unsafe_token(self):
        """No raw-FFI token appears anywhere in the tray source."""
        text = TRAY.read_text(encoding="utf-8")
        tokens = set(re.split(r"[^A-Za-z_0-9]+", text))
        self.assertNotIn(
            "unsafe",
            tokens,
            "src/bin/rr-tray.rs must contain no raw-FFI token anywhere",
        )


if __name__ == "__main__":
    unittest.main()
