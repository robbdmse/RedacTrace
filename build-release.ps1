# Build a standalone release of the anonymizer into .\dist
#   powershell -NoProfile -ExecutionPolicy Bypass -File build-release.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    $local = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path $local) { $cargo = $local } else { throw "cargo not found - install Rust from https://rustup.rs" }
}

& $cargo test --release
if ($LASTEXITCODE -ne 0) { throw "tests failed" }
& $cargo build --release
if ($LASTEXITCODE -ne 0) { throw "build failed" }

New-Item -ItemType Directory -Force dist | Out-Null
Copy-Item target\release\redactrace.exe dist\ -Force
Copy-Item anonymizer.toml, README.md dist\ -Force
Write-Host ""
Write-Host "Ready: dist\redactrace.exe  (with anonymizer.toml and README.md)"
Write-Host "Copy the dist folder anywhere; drag capture files onto the .exe to anonymize them."
