# Installing on Windows

Step-by-step, from a clean machine to a working STUNScope.

## 1. Install Python 3.11+

1. Download the installer from <https://www.python.org/downloads/windows/>.
2. On the first page, check **“Add python.exe to PATH”** (important).
3. Install with defaults.

Verify in PowerShell:

```powershell
python --version
```

## 2. Install Npcap

Live capture on Windows needs Npcap with the WinPcap-compatible API:

1. Download from <https://npcap.com/#download>.
2. Run the installer and keep the default options — especially
   **“Install Npcap in WinPcap API-compatible Mode”**, which Scapy requires.
3. If you previously had WinPcap, let Npcap replace it.

Without Npcap, STUNScope still runs: the CLI reports the problem clearly,
`parse-file` works offline, and the GUI shows an error banner instead of an
interface list.

## 3. Get the code

Either download and extract the repository ZIP, or clone it:

```powershell
git clone https://github.com/YOUR-USERNAME/stunscope.git
cd stunscope
```

## 4. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the activation script, run once:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 5. Install dependencies and the package

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Or the all-in-one helper:

```powershell
.\scripts\setup_windows.ps1
```

## 6. Verify

```powershell
python -m stunscope info
python -m stunscope parse-file examples\fixtures.txt --verbose
python -m stunscope list-interfaces
```

The first two work unprivileged. `list-interfaces` needs Npcap; opening most
physical devices additionally needs an **elevated** terminal.

## Administrator privileges and capture

Opening a capture device on Windows generally requires elevation. When you
plan to capture:

1. Right-click PowerShell/Windows Terminal → **Run as administrator**.
2. Activate the environment and start STUNScope there.

Elevation is only needed for live capture. The GUI, offline parsing, CSV
export, and all tests run fine as a normal user.

## Antivirus note

Some antivirus products flag packet-capture libraries or PyInstaller-built
executables. Building from source (`scripts\build_windows.ps1`) usually avoids
false positives; if not, add an exclusion for the project folder after
reviewing the code — it is all on GitHub.

## Uninstall

```powershell
# Remove the Python package (inside the venv)
python -m pip uninstall stunscope
# Remove persisted settings and logs (also available in the GUI Settings page)
Remove-Item -Recurse "$env:APPDATA\STUNScope"
# Delete the repository folder when done
```
