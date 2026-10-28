param(
    [ValidateSet("Changed", "All", "Off")]
    [string]$LintMode = "Changed",
    [string]$BaseRef = "",
    [string]$HeadRef = "HEAD",
    [switch]$IncludeUntracked,
    [string]$LintVenvPath = ""
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($LintVenvPath)) {
    $LintVenvPath = Join-Path $repo ".venv-lint"
}
$localModuleRoot = Join-Path $repo ".psmodules"
if (Test-Path -LiteralPath $localModuleRoot) {
    $env:PSModulePath = "$localModuleRoot;$env:PSModulePath"
}

# Purpose: Resolve a linter executable from the repo-local virtual environment before PATH.
# Inputs: `Name` is the command name and `VenvPath` is the local Python virtual environment root.
# Outputs: Returns a concrete executable path when present, otherwise the original command name.
function Resolve-LintToolPath {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$VenvPath
    )

    $scripts = Join-Path $VenvPath "Scripts"
    foreach ($candidate in @("$Name.exe", $Name)) {
        $toolPath = Join-Path $scripts $candidate
        if (Test-Path -LiteralPath $toolPath) {
            return $toolPath
        }
    }
    return $Name
}

# Purpose: Invoke a native command and fail when it returns a non-zero exit code.
# Inputs: `FilePath` is the executable, `Arguments` is argv, and `Label` describes the lint step.
# Outputs: Throws on lint failure; otherwise returns normally.
function Invoke-LintCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Write-Output "lint step=$Label"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

# Purpose: Return tracked files matching one or more git pathspecs.
# Inputs: `Pathspec` is passed directly to `git ls-files`.
# Outputs: Returns repository-relative file paths using slash separators.
function Get-TrackedLintFile {
    param([Parameter(Mandatory = $true)][string[]]$Pathspec)

    Push-Location $repo
    try {
        return @(& git ls-files -- @Pathspec)
    } finally {
        Pop-Location
    }
}

# Purpose: Return changed files for language lint targeting.
# Inputs: `BaseRef` and `HeadRef` optionally define a git diff range; `IncludeUntracked` adds new local files.
# Outputs: Returns repository-relative file paths using slash separators.
function Get-ChangedLintFile {
    param(
        [string]$BaseRef,
        [string]$HeadRef,
        [switch]$IncludeUntracked
    )

    Push-Location $repo
    try {
        $paths = @()
        if (-not [string]::IsNullOrWhiteSpace($BaseRef)) {
            if ($BaseRef -match '^0{40}$') {
                $paths += & git ls-files
            } else {
                $gitArgs = @("diff", "--name-only", "--diff-filter=ACMRTUX", $BaseRef)
                if (-not [string]::IsNullOrWhiteSpace($HeadRef)) {
                    $gitArgs += $HeadRef
                }
                $paths += & git @gitArgs
            }
        } else {
            $paths += & git diff --name-only --diff-filter=ACMRTUX
            $paths += & git diff --cached --name-only --diff-filter=ACMRTUX
            if ($IncludeUntracked.IsPresent) {
                $paths += & git ls-files --others --exclude-standard
            }
        }
        return @($paths | Sort-Object -Unique)
    } finally {
        Pop-Location
    }
}

# Purpose: Select files whose repository-relative path matches any regular expression.
# Inputs: `Path` is a path list and `Pattern` is one or more anchored regular expressions.
# Outputs: Returns unique matching paths in stable order.
function Select-LintFile {
    param(
        [string[]]$Path,
        [string[]]$Pattern
    )

    $selected = foreach ($pathItem in @($Path)) {
        foreach ($patternItem in @($Pattern)) {
            if ($pathItem -match $patternItem) {
                $pathItem
                break
            }
        }
    }
    return @($selected | Sort-Object -Unique)
}

# Purpose: Detect whether any changed path requires a whole-language lint pass.
# Inputs: `Path` is a changed path list and `Pattern` names linter config files.
# Outputs: Returns true when a config change should expand the lint scope.
function Test-LintConfigChange {
    param(
        [string[]]$Path,
        [string[]]$Pattern
    )

    return (Select-LintFile -Path $Path -Pattern $Pattern).Count -gt 0
}

# Purpose: Recheck existing consumers when their linter or routing changes.
# Inputs: Repository-relative changed paths, including new files.
# Outputs: True for shared linter installation, version, workflow or routing inputs.
function Test-LintToolchainChange {
    param([string[]]$Path)

    return Test-LintConfigChange -Path $Path -Pattern @(
        '^\.github/requirements/requirements-lint-windows\.(in|txt)$',
        '^\.github/workflows/lint\.yml$',
        '^tools/(bootstrap_lint_env|lint)\.ps1$')
}

# Purpose: Build a lint target set from changed files, or all tracked files when requested.
# Inputs: Changed paths, all-file pathspecs, file patterns, config patterns, and `ForceAll`.
# Outputs: Returns unique targets, retaining new changed files even when the scope expands to all tracked files.
function Get-LintTargetFile {
    param(
        [string[]]$ChangedPath,
        [string[]]$AllPathspec,
        [string[]]$FilePattern,
        [string[]]$ConfigPattern = @(),
        [switch]$ForceAll
    )

    if ($ForceAll.IsPresent -or (Test-LintConfigChange -Path $ChangedPath -Pattern $ConfigPattern)) {
        $targets = @(Get-TrackedLintFile -Pathspec $AllPathspec)
        $targets += @(Select-LintFile -Path $ChangedPath -Pattern $FilePattern)
        return @($targets | Sort-Object -Unique)
    }
    return Select-LintFile -Path $ChangedPath -Pattern $FilePattern
}

# Purpose: Reject PowerShell grammar errors before linting or running a script.
# Inputs: Path identifies one owned script/module. Outputs: Throws with parser diagnostics; never executes its contents.
function Assert-PowerShellSyntax {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $parseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        $parseErrors | ForEach-Object { Write-Output $_.ToString() }
        throw "PowerShell syntax errors in ${Path}: $($parseErrors.Count)."
    }
}

# Purpose: Parse PowerShell and run PSScriptAnalyzer, failing on either error class.
# Inputs: `Path` contains PowerShell script/module files to inspect.
# Outputs: Throws when syntax parsing or PSScriptAnalyzer returns findings.
function Invoke-PowerShellLint {
    param([Parameter(Mandatory = $true)][string[]]$Path)

    Write-Output "lint step=powershell-psscriptanalyzer"
    Import-Module PSScriptAnalyzer -ErrorAction Stop
    $findings = foreach ($scriptPath in @($Path)) {
        Assert-PowerShellSyntax -Path $scriptPath
        Invoke-ScriptAnalyzer -Path $scriptPath -Severity Error, Warning
    }
    if ($findings.Count -gt 0) {
        $findings | Format-Table -AutoSize | Out-String | Write-Output
        throw "powershell-psscriptanalyzer found $($findings.Count) issue(s)."
    }
}

Push-Location $repo
try {
    $changedFiles = Get-ChangedLintFile -BaseRef $BaseRef -HeadRef $HeadRef -IncludeUntracked:$IncludeUntracked
    $lintAll = $LintMode -eq "All" -or (Test-LintToolchainChange -Path $changedFiles)

    $pythonFiles = Get-LintTargetFile `
        -ChangedPath $changedFiles `
        -AllPathspec @("training/*.py", "tools/*.py", "tests/**/*.py") `
        -FilePattern @("^(training|tools|tests)/.*\.py$") `
        -ConfigPattern @("^\.ruff\.toml$") `
        -ForceAll:$lintAll
    if ($pythonFiles.Count -gt 0) {
        Invoke-LintCommand -FilePath (Resolve-LintToolPath -Name "ruff" -VenvPath $LintVenvPath) -Arguments (@("check") + $pythonFiles) -Label "python-ruff-check"
        Invoke-LintCommand -FilePath (Resolve-LintToolPath -Name "ruff" -VenvPath $LintVenvPath) -Arguments (@("format", "--check") + $pythonFiles) -Label "python-ruff-format"
        if (@($pythonFiles | Where-Object { $_ -in @("tools/deepsource_inventory.py", "tests/release/test_deepsource_inventory.py") }).Count -gt 0) {
            Invoke-LintCommand -FilePath "python" -Arguments @("-m", "unittest", "tests.release.test_deepsource_inventory") -Label "deepsource-inventory-tests"
        }
    } else {
        Write-Output "lint step=python-ruff skipped=no-python-files"
    }

    $powershellFiles = Get-LintTargetFile `
        -ChangedPath $changedFiles `
        -AllPathspec @("tools/*.ps1", "tools/*.psm1", "scripts/*.ps1", "scripts/*.psm1", "windows/**/*.ps1", "windows/**/*.psm1") `
        -FilePattern @("^(tools|scripts|windows)/.*\.(ps1|psm1)$") `
        -ForceAll:$lintAll
    if ($powershellFiles.Count -gt 0) {
        Invoke-PowerShellLint -Path $powershellFiles
    } else {
        Write-Output "lint step=powershell-psscriptanalyzer skipped=no-powershell-files"
    }

    $yamlFiles = Get-LintTargetFile `
        -ChangedPath $changedFiles `
        -AllPathspec @(".github/*.yml", ".github/*.yaml", ".github/**/*.yml", ".github/**/*.yaml") `
        -FilePattern @("^\.github/.*\.ya?ml$") `
        -ConfigPattern @("^\.yamllint$") `
        -ForceAll:$lintAll
    if ($yamlFiles.Count -gt 0) {
        Invoke-LintCommand -FilePath (Resolve-LintToolPath -Name "yamllint" -VenvPath $LintVenvPath) -Arguments (@("-c", ".yamllint") + $yamlFiles) -Label "yaml-yamllint"
    } else {
        Write-Output "lint step=yaml-yamllint skipped=no-yaml-files"
    }

    $markdownFiles = Get-LintTargetFile `
        -ChangedPath $changedFiles `
        -AllPathspec @("*.md") `
        -FilePattern @("^.*\.md$") `
        -ConfigPattern @("^\.pymarkdown\.json$") `
        -ForceAll:$lintAll
    if ($markdownFiles.Count -gt 0) {
        Invoke-LintCommand -FilePath (Resolve-LintToolPath -Name "pymarkdown" -VenvPath $LintVenvPath) -Arguments (@("--config", ".pymarkdown.json", "scan") + $markdownFiles) -Label "markdown-pymarkdown"
    } else {
        Write-Output "lint step=markdown-pymarkdown skipped=no-markdown-files"
    }

    $workflowFiles = Get-LintTargetFile `
        -ChangedPath $changedFiles `
        -AllPathspec @(".github/workflows/*.yml", ".github/workflows/*.yaml") `
        -FilePattern @("^\.github/workflows/.*\.ya?ml$") `
        -ForceAll:$lintAll
    if ($workflowFiles.Count -gt 0) {
        # actionlint is a Go binary with no PyPI artifact: the lint workflow
        # downloads a pinned release and verifies its SHA256 (same pattern as
        # PSScriptAnalyzer), then puts it on PATH; locally it resolves from the
        # lint venv or PATH via Resolve-LintToolPath.
        Invoke-LintCommand -FilePath (Resolve-LintToolPath -Name "actionlint" -VenvPath $LintVenvPath) -Arguments (@("-color=false") + $workflowFiles) -Label "workflow-actionlint"
        # zizmor is installed hash-pinned from PyPI alongside the Python linters.
        Invoke-LintCommand -FilePath (Resolve-LintToolPath -Name "zizmor" -VenvPath $LintVenvPath) -Arguments (@("--no-online-audits") + $workflowFiles) -Label "workflow-zizmor"
    } else {
        Write-Output "lint step=workflow-actionlint skipped=no-workflow-files"
    }

    # Rust clippy is already gated by tools/local_ci.py and .github/workflows/ci.yml.
    # This stage only records the delegation; it must never duplicate the build.
    Write-Output "lint step=rust-clippy delegated=tools/local_ci.py"
} finally {
    Pop-Location
}
