# Build STUNScope Windows executables with PyInstaller.
# Produces:
#   dist\STUNScope\STUNScope.exe          (windowed GUI)
#   dist\stunscope-cli\stunscope-cli.exe  (console CLI)
# Run from the repository root: .\scripts\build_windows.ps1

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Step($message) {
    Write-Host ""
    Write-Host "==> $message" -ForegroundColor Magenta
}

Step "Checking for PyInstaller"
$found = python -m PyInstaller --version 2>$null
if (-not $found -or $LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller not found; installing requirements-dev.txt..."
    python -m pip install -r requirements-dev.txt --quiet
}

Step "Cleaning previous builds"
if (Test-Path "dist")   { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build")  { Remove-Item -Recurse -Force "build" }

Step "Building the CLI executable (console app)"
python -m PyInstaller `
    --noconfirm --clean `
    --name stunscope-cli `
    --paths src `
    --paths src/stunscope `
    --console `
    src/stunscope/__main__.py
if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }

Step "Building the GUI executable (windowed app)"
python -m PyInstaller `
    --noconfirm --clean `
    --name STUNScope `
    --paths src `
    --paths src/stunscope `
    --windowed `
    src/stunscope/gui/main.py
if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }

Step "Build complete"
Write-Host "Output:" -ForegroundColor Green
Get-ChildItem "dist" -Directory | ForEach-Object {
    Write-Host "  dist\$($_.Name)\$($_.Name).exe" -ForegroundColor Green
}
Write-Host ""
Write-Host "Note: the built executables still require Npcap on the target machine"
Write-Host "for live capture, and usually an Administrator shell. See"
Write-Host "docs\installation-windows.md and docs\troubleshooting.md."
