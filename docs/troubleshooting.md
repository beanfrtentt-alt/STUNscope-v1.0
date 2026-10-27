# Troubleshooting

Collect symptoms here first; most problems are environment-related and take
a minute to fix.

## Capture setup

### “Scapy is not installed” (CLI exit 2, GUI banner)

The virtual environment isn't activated or dependencies aren't installed.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m stunscope info      # Scapy: available?
```

### “No capture interfaces were found” / empty interface list

On Windows this almost always means Npcap is missing or was installed
without the **WinPcap API-compatible Mode** option. Reinstall Npcap from
<https://npcap.com/> and keep that option enabled. On Linux, Scapy uses raw
sockets — run from an account with `CAP_NET_RAW`, or use
`sudo -E python -m stunscope list-interfaces`.

### “could not open the capture device” / access denied

Most physical interfaces require elevation:

1. Close the terminal.
2. Right-click PowerShell/Windows Terminal → **Run as administrator**.
3. Re-activate the venv and retry.

The Wi-Fi device may also be held exclusively by another capture app (close
Wireshark, etc.).

### Capture starts but no packets appear

- Are you capturing on the right interface? Check the addresses listed by
  `list-interfaces`.
- Is there actually STUN traffic? Try generating some on your own test
  setup, or verify with the offline path first:
  `python -m stunscope parse-file examples\fixtures.txt --verbose`.
- If you used the `--ports` convenience filter, confirm the traffic uses
  those ports; without it, detection is structural and port-independent.
- Remember **STUNScope only displays STUN-bearing UDP datagrams**; other
  traffic is deliberately not shown.

### GUI does not start

```powershell
python -m stunscope info    # PySide6: available?
python -m pip install PySide6
python -m stunscope gui
```

If it still fails, capture the console output and file a bug — the GUI prints
a readable message for missing dependencies.

## Protocol decode questions

### “Malformed” messages that surprise you

Common real-world causes, all rendered as readable diagnostics rather than
crashes:

- **missing magic cookie** → legacy RFC 3489 traffic (out of scope),
- **length not a multiple of 4** → truncated or corrupted datagram,
- **attribute overruns the message body** → middlebox mangling or non-STUN
  payload that happens to carry the cookie,
- **unknown comprehension-required attribute** → newer RFC/vendor extension;
  the message stays visible with a warning.

Filter for them with `--validity malformed` (CLI) or *Malformed messages
only* (GUI), and inspect the raw bytes in the Packet Inspector.

### MESSAGE-INTEGRITY / FINGERPRINT “not verified”

By design. STUNScope has no credentials and performs no key derivation; it
reports presence and the raw value. See [stun-protocol.md](stun-protocol.md).

### IPv6 addresses look strange

IPv6 XOR-MAPPED-ADDRESS decoding uses the cookie **plus the transaction ID**
mask; tests pin this behavior with hand-computed vectors. If a decode looks
wrong, compare against `tests/test_ipv6.py` before filing an issue.

## Exports

### “destination directory does not exist”

Create it, or export into an existing folder. The CLI can create parent
directories for `--csv`; the GUI validates before writing.

### Partial or empty CSV

Exports are atomic — an interrupted write never leaves a partial file at the
chosen path. An empty CSV (header only) means the filters matched nothing;
check the “Active: …” description on the Filters page or rerun without
`--message-type`/`--src`/`--dst`.

### Privacy mode surprises

Privacy mode masks addresses only: IPv4 → `/24`, IPv6 → `/64`. Ports,
transaction IDs, and timestamps are retained because they are not personal
addresses; see [privacy-and-security.md](privacy-and-security.md).

## Performance

- During very long captures the table keeps only the newest N packets
  (Settings → *Max packets in memory*). The count of dropped packets is
  reported in the footer and dashboard.
- Pause display to scroll back comfortably — capture continues in the
  background.
- Export *before* long unattended runs if you need every packet.

## Build problems

### PyInstaller executables flagged by antivirus

Known false-positive territory. Build from source yourself with
`.\scripts\build_windows.ps1`, or prefer running from the Python source.

### PyInstaller build fails on imports

Install the package itself (`python -m pip install -e .`) *before*
building; the build script uses `--paths src` as a fallback.

## Still stuck?

Run `python -m stunscope info`, collect the output, and open a bug report
with the GitHub template — including only synthetic/sanitized packet data.
