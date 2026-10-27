# Run the STUNScope CLI from the repository's virtual environment.
# Usage examples:
#   .\scripts\run_cli.ps1 info
#   .\scripts\run_cli.ps1 list-interfaces
#   .\scripts\run_cli.ps1 capture -i 1 --duration 30 --csv out.csv
#   .\scripts\run_cli.ps1 parse-file examples\fixtures.txt --verbose

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (Test-Path ".venv\Scripts\Activate.ps1") {
    & ".\.venv\Scripts\Activate.ps1"
} else {
    Write-Host "No .venv found. Run .\scripts\setup_windows.ps1 first." -ForegroundColor Yellow
    Write-Host "Trying the system Python anyway..." -ForegroundColor Yellow
}

if ($args.Count -eq 0) {
    python -m stunscope
} else {
    python -m stunscope @args
}
exit $LASTEXITCODE
