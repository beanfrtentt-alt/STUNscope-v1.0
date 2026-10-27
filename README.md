# STUNScope

**STUNScope** is a STUN (RFC 8489) packet analyzer for Windows (and Linux) with a
command-line interface and a polished dark-themed desktop GUI. Both interfaces
share one protocol engine: the same parser, the same filters, and the same CSV
exporter.

It is built for **authorized network diagnostics and test sessions** — analyzing
STUN traffic on networks you own or are explicitly permitted to test. It is not
a tool for identifying other people's addresses, bypassing the privacy
protections of calling applications, or inspecting traffic without permission.

---

## Features

- **Shared protocol engine** — a single RFC 8489 parser used by both the CLI and
  the GUI, with structured data objects flowing from parser to display to export.
- **Full STUN header decode** — message type, method and class, message length,
  magic cookie, and the 96-bit transaction ID.
- **Attribute decoding** — MAPPED-ADDRESS, XOR-MAPPED-ADDRESS (IPv4 and IPv6),
  USERNAME, MESSAGE-INTEGRITY, ERROR-CODE, REALM, NONCE, SOFTWARE, FINGERPRINT,
  plus a registry of ICE/TURN attributes; unknown attributes are kept with their
  raw bytes and clearly labeled.
- **Structural traffic detection** — STUN messages are recognized by protocol
  structure and valid message boundaries, not by port numbers. A port list
  (3478, 19302, …) is available as an optional convenience pre-filter.
- **Live capture** — Scapy + Npcap on Windows, safe start/stop, worker thread in
  the GUI so the interface stays responsive, bounded memory during long captures.
- **Malformed-packet tolerance** — truncated headers, invalid lengths, bad
  address families, and attribute overruns produce readable diagnostics instead
  of crashes, and malformed messages stay visible and exportable.
- **Filtering** — message type/class, source and destination IP (exact, CIDR, or
  `prefix*`), transaction ID (prefix match), valid vs. malformed, free-text
  search.
- **CSV export** — UTF-8, one row per attribute with packet metadata repeated,
  atomic writes that never leave half-written files, and an optional privacy
  mode that masks IP addresses.
- **Modern desktop GUI** — PySide6 dark theme with sidebar navigation: Dashboard,
  Live Capture, Packet Inspector, Filters, Export, and Settings pages.

## Screenshots

> **Note:** the repository does not ship pre-rendered screenshots yet. This
> section uses placeholders — real captures will be added after the first
> public release. Do not read the absence of screenshots as a missing feature.
>
> | Dashboard | Live Capture | Packet Inspector |
> |---|---|---|
> | *(placeholder)* | *(placeholder)* | *(placeholder)* |
>
> Planned files: `docs/screenshots/dashboard.png`,
> `docs/screenshots/live-capture.png`, `docs/screenshots/inspector.png`.

## Requirements

- **Windows 10/11** (recommended) or a modern Linux distribution
- **Python 3.11 or newer**
- **[Npcap](https://npcap.com/)** with the *“Install Npcap in WinPcap
  API-compatible Mode”* option (for live capture on Windows)
- **Administrator privileges** to capture on most physical interfaces
- Optional: [Git](https://git-scm.com/) for publishing your own copy

The GUI additionally needs **PySide6** (installed by default with the
requirements below). Linux users need Qt runtime libraries
(`libegl1`, `libgl1`).

## Windows installation

### 1. Install Python

Install Python 3.11+ from [python.org](https://www.python.org/downloads/windows/).
On the first installer screen, enable **“Add python.exe to PATH”**.

Verify in PowerShell:

```powershell
python --version   # should print 3.11.x or newer
```

### 2. Install Npcap

Download and run the [Npcap installer](https://npcap.com/#download). During
setup, keep the default **“Install Npcap in WinPcap API-compatible Mode”**
option — Scapy depends on it.

> If Npcap is missing, `python -m stunscope list-interfaces` will say so, and
> the offline `parse-file` command still works. Capture permission failures on
> real devices usually mean the terminal is not elevated.

### 3. Create a virtual environment

In the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If script execution is blocked, allow it once for your user:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 4. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .            # installs the stunscope package
```

Or use the helper script that does all of the above:

```powershell
.\scripts\setup_windows.ps1
```

### 5. Verify the installation

```powershell
python -m stunscope info               # environment report
python -m stunscope list-interfaces    # needs Npcap; may need Administrator
```

## CLI usage

Open the repository in an **elevated** PowerShell for live capture:

```powershell
# Enumerate capture interfaces (Scapy name, description, addresses)
python -m stunscope list-interfaces

# Capture on interface 1 for 30 seconds, export to CSV when done
python -m stunscope capture -i 1 --duration 30 --csv out.csv

# Capture only Binding Success Responses from a documentation subnet
python -m stunscope capture -i "Wi-Fi" --message-type binding-success --src 198.51.100.0/24

# Stop after 200 STUN messages; show fully decoded output
python -m stunscope capture -i 2 --max-packets 200 --verbose

# Optional convenience port pre-filter (STUN is still detected structurally)
python -m stunscope capture -i 1 --ports 3478,19302

# Offline: parse hex-encoded STUN messages from a text file (no Npcap needed)
python -m stunscope parse-file examples\fixtures.txt --verbose

# Redact IP addresses in an export (privacy mode)
python -m stunscope parse-file examples\fixtures.txt --csv out.csv --redact

# Environment report, and launch the desktop GUI
python -m stunscope info
python -m stunscope gui
```

`Ctrl+C` stops a live capture cleanly and finalizes any requested CSV export.
Exit codes: `0` success, `1` unexpected error, `2` usage or environment
problems (missing Scapy/Npcap, bad interface, unknown filter).

Full reference: [docs/usage-cli.md](docs/usage-cli.md).

## GUI launch

```powershell
python -m stunscope gui          # via the CLI
python -m stunscope.gui          # directly
.\scripts\run_gui.ps1            # helper script
```

The GUI includes a Dashboard with live counters, a Live Capture page with
start/stop controls and a pause-display button, a Packet Inspector with decoded
header/attributes/raw bytes, a Filters page, an Export page, and Settings.
See [docs/usage-gui.md](docs/usage-gui.md).

## CSV export

The shared exporter writes **one row per decoded attribute**, repeating packet
metadata on every row (messages without attributes produce a single
message-level row). Fields that do not apply to a row are written as `n/a`;
genuinely empty values remain empty strings.

Columns include: timestamp, interface, protocol, source/destination IP and
port, message type, method, class, transaction ID, attribute name/type/length/
value/raw hex, MAPPED-ADDRESS, XOR-MAPPED-ADDRESS, decoded mapped port,
address family, parse status, and error-or-warning.

Exports are UTF-8, quote-comma safe, and written atomically (a `.tmp` file is
moved into place on success, so interrupted exports never leave partial CSVs).
Privacy mode (`--redact`, or the Export page checkbox) masks IPv4 addresses to
their `/24` and IPv6 addresses to their `/64` network. Nothing is ever uploaded
anywhere — exports only touch your local disk.

A sample export built from synthetic fixtures: [examples/sample_capture.csv](examples/sample_capture.csv).

## Running tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

The suite covers binding request/success/error parsing, IPv4 and IPv6
XOR-MAPPED-ADDRESS decoding (against hand-computed RFC vectors), attribute
padding, truncated/malformed messages, filters, CSV escaping and redaction,
CLI argument validation, and GUI import smoke tests. All fixtures are
synthetic and use RFC 5737/3849 documentation address ranges. No test needs
Npcap, Administrator privileges, or a real call from any third-party app.

Static checks:

```powershell
ruff check src tests conftest.py
```

## Building a Windows executable

With the dev requirements installed:

```powershell
.\scripts\build_windows.ps1
```

This uses PyInstaller to produce `dist\STUNScope\STUNScope.exe` (windowed GUI)
and `dist\stunscope-cli\stunscope-cli.exe` (console CLI). The executable still
needs **Npcap installed on the target machine** and, for most interfaces,
Administrator privileges. Some antivirus products flag PyInstaller one-file
builds; this repo builds in one-directory mode to reduce false positives. The
same build runs in CI (`.github/workflows/build-windows.yml`).

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `list-interfaces` says Npcap is missing | Install Npcap with the WinPcap API-compatible option |
| `could not open the capture device` | Run the terminal as Administrator |
| Interface list is empty | Npcap installed without WinPcap mode, or no permission |
| GUI does not start | PySide6 missing: `python -m pip install PySide6` |
| No packets appear | Capture a STUN-using app, or test with the offline `parse-file` command; verify the right interface |
| Antivirus flags the build | Use the Python source instead, or build from source yourself |

More detail: [docs/troubleshooting.md](docs/troubleshooting.md).

## Known limitations

- **UDP only.** STUN over TCP uses a 4-byte length framing not analyzed here.
- **RFC 8489 framing only.** Legacy RFC 3489 messages (no magic cookie) are
  reported as malformed/unsupported, not decoded.
- **MESSAGE-INTEGRITY and FINGERPRINT are never verified** — STUNScope has no
  credentials and only reports their presence.
- **Addresses are observed, not attributed.** See the next section.
- **Display cap.** The GUI keeps a bounded number of packets in memory
  (configurable in Settings); older packets are dropped during very long
  captures, so export before starting marathon runs if you need everything.
- **Windows-first.** Capture works on Linux too, but docs, packaging, and CI
  builds target Windows.

## Privacy and authorization notice

**Use STUNScope only on networks you own or are explicitly authorized to
test.** Capturing traffic without authorization is illegal in most
jurisdictions.

Important protocol distinctions — please read before drawing conclusions:

- A **mapped address** (XOR-MAPPED-ADDRESS or MAPPED-ADDRESS) in a Binding
  Success Response is the address the **STUN server observed for the request
  sender** — typically the NAT binding of the *local* network. It is not
  automatically anyone else's address.
- A **local interface address** is an address configured on the capture
  machine. A **remote packet endpoint** is simply the far side of one datagram
  — often a STUN/TURN server. A **TURN relay endpoint** is a server allocated
  by TURN, not the other call party.
- Third-party calling applications may use direct connections, TURN relays,
  media servers, or other architectures. **STUNScope cannot and does not claim
  to always identify a remote caller's public IP address**, and it makes no
  attempt to defeat the privacy protections of calling apps. It shows what the
  wire shows, with honest labels.

Privacy controls: optional export redaction, no telemetry, no data leaving the
machine, and a Settings action that wipes persisted settings and logs.
Full policy: [docs/privacy-and-security.md](docs/privacy-and-security.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports:
[SECURITY.md](SECURITY.md). Changelog: [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE). The license file includes an intended-use notice:
this project must not be used to inspect traffic without authorization, to
identify communications participants without consent, or to bypass the
security or privacy protections of any application.

## Publishing your copy to GitHub

```powershell
cd stunscope-repo
git init -b main
git add -A
git commit -m "Initial release: STUNScope 1.0.0"
# Create an empty repository named e.g. stunscope on github.com first, then:
git remote add origin https://github.com/YOUR-USERNAME/stunscope.git
git push -u origin main
```

Replace `YOUR-USERNAME` (also in `pyproject.toml`, `.github/ISSUE_TEMPLATE/config.yml`)
with your GitHub account name. GitHub will prompt you for credentials — none
are needed to generate this repository.
