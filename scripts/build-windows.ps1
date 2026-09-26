$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'Install Rust and Microsoft C++ Build Tools with Windows SDK.' }
& cargo test --locked --lib --no-default-features
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
& cargo build --locked --release --bins
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
Write-Host 'Built target\release\rejection-rejector.exe and rr.exe. Safe preview: rejection-rejector.exe --demo'
