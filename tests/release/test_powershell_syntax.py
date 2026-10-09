"""Parse operator scripts and inline PowerShell without executing their bodies."""
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PWSH = shutil.which("pwsh")
PARSER = r'''
$ErrorActionPreference = 'Stop'
$cases = [Console]::In.ReadToEnd() | ConvertFrom-Json
foreach ($case in $cases) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput(
        $case.source, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        foreach ($error in $errors) {
            [Console]::Error.WriteLine("$($case.name): $($error.Message)")
        }
        exit 1
    }
}
'''


def inline_powershell(path):
    shell = None
    block = None
    chunks = []
    for line in path.read_text(encoding="utf-8").splitlines() + ["      - end"]:
        if block is not None:
            if line.startswith("          ") or not line.strip():
                block.append(line[10:] if line else "")
                continue
            chunks.append(re.sub(r"\$\{\{.*?\}\}", "synthetic_value", "\n".join(block)))
            block = None
        if line.startswith("      - "):
            shell = None
        if line.strip() == "shell: pwsh":
            shell = "pwsh"
        if line == "        run: |" and shell == "pwsh":
            block = []
    return chunks


class PowerShellSyntaxTests(unittest.TestCase):
    def test_release_workflow_blocks_are_discovered(self):
        blocks = inline_powershell(ROOT / ".github/workflows/release.yml")
        self.assertGreaterEqual(len(blocks), 10)
        self.assertTrue(any("Unsigned packaging requires NotSigned" in block for block in blocks))

    @unittest.skipUnless(PWSH, "PowerShell parser is exercised on the Windows CI runner")
    def test_operator_and_release_powershell_parse_without_execution(self):
        cases = [{"name": str(path.relative_to(ROOT)), "source": path.read_text(encoding="utf-8")}
                 for path in (ROOT / "scripts").glob("*.ps1")]
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            cases.extend({"name": f"{path.name}: block {index}", "source": block}
                         for index, block in enumerate(inline_powershell(path), 1))
        result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", PARSER],
                                input=json.dumps(cases), text=True, encoding="utf-8",
                                capture_output=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
