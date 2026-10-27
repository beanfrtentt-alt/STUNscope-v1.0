# STUNScope Windows setup script.
# Checks prerequisites, creates a virtual environment, installs dependencies,
# and verifies the installation. Run from the repository root:
#   .\scripts\setup_windows.ps1

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Step($message) {
    Write-Host ""
    Write-Host "==> $message" -ForegroundColor Magenta
}

Write-Host "STUNScope setup" -ForegroundColor Magenta
Write-Host "================"

# --- Python ---------------------------------------------------------------
Step "Checking Python"
try {
    $version = python --version 2>&1
    Write-Host "Found $version"
    $majorMinor = ($version -replace "Python ", "") -split "\."
    if ([int]$majorMinor[0] -lt 3 -or ([int]$majorMinor[0] -eq 3 -and [int]$majorMinor[1] -lt 11)) {
        Write-Host "ERROR: Python 3.11 or newer is required (found $($version -replace 'Python ', ''))." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "ERROR: Python was not found on PATH. Install it from https://www.python.org/downloads/windows/ and enable 'Add python.exe to PATH'." -ForegroundColor Red
    exit 1
}

# --- Npcap ----------------------------------------------------------------
Step "Checking Npcap (optional for live capture)"
$npcap = Test-Path "C:\Windows\System32\Npcap"
if ($npcap) {
    Write-Host "Npcap detected."
} else {
    Write-Host "Npcap was NOT detected. Live capture will be unavailable until you install it:" -ForegroundColor Yellow
    Write-Host "  https://npcap.com/#download  (keep the 'WinPcap API-compatible Mode' option)" -ForegroundColor Yellow
    Write-Host "The offline 'parse-file' command works without Npcap."
}

# --- Virtual environment ----------------------------------------------------
Step "Creating virtual environment (.venv)"
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "Created .venv"
} else {
    Write-Host ".venv already exists, reusing it"
}

Step "Activating virtual environment"
& "$repoRoot\.venv\Scripts\Activate.ps1"

Step "Upgrading pip"
python -m pip install --upgrade pip --quiet

Step "Installing requirements.txt (Scapy + PySide6)"
python -m pip install -r requirements.txt --quiet

Step "Installing requirements-dev.txt (pytest, ruff, pyinstaller)"
python -m pip install -r requirements-dev.txt --quiet

Step "Installing the stunscope package (editable)"
python -m pip install -e . --quiet

# --- Verification -----------------------------------------------------------
Step "Verifying installation"
python -m stunscope info

Step "Running the offline smoke check (no Npcap needed)"
python -m stunscope parse-file examples\fixtures.txt | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Offline parsing works." -ForegroundColor Green
} else {
    Write-Host "Offline parsing failed; see the output above." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  .\scripts\run_cli.ps1 list-interfaces   (may need an Administrator terminal)"
Write-Host "  .\scripts\run_cli.ps1 capture -i 1 --duration 30"
Write-Host "  .\scripts\run_gui.ps1"
Write-Host "  python -m pytest                        (run the test suite)"
