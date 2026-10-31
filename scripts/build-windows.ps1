$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'Install Rust through rustup and Microsoft C++ Build Tools with the Windows SDK first. The repository pins its Rust toolchain.'
}
& cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed.' }
& cargo test --locked --all-features
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
& cargo clippy --locked --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) { throw 'Clippy failed.' }
& cargo build --locked --release --bins
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
Write-Host 'Built target\release\rr.exe and target\release\rr-tray.exe.'
Write-Host 'Safe preview: .\target\release\rr.exe demo'
