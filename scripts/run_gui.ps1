# Launch the STUNScope desktop GUI from the repository's virtual environment.
# Usage: .\scripts\run_gui.ps1

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (Test-Path ".venv\Scripts\Activate.ps1") {
    & ".\.venv\Scripts\Activate.ps1"
} else {
    Write-Host "No .venv found. Run .\scripts\setup_windows.ps1 first." -ForegroundColor Yellow
}

Write-Host "Starting STUNScope GUI..."
Write-Host "Live capture may require an Administrator terminal; only analyze traffic you are authorized to inspect."
python -m stunscope.gui
exit $LASTEXITCODE
