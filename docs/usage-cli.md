# CLI usage

Everything runs through `python -m stunscope` (or the installed `stunscope`
script). Global options `--verbose` and `--no-log-file` may be placed before
or after the subcommand. `--version` prints the version; no subcommand prints
help.

Exit codes: **0** success, **1** unexpected error, **2** usage/environment
problems (missing Scapy/Npcap, unknown interface, invalid filter).

## list-interfaces

```powershell
python -m stunscope list-interfaces      # aliases: interfaces, li
```

Prints a numbered list with Scapy names, descriptions, and addresses. Use the
index or a unique description substring for `-i`. If Scapy or Npcap is
missing, a clear error explains what to install.

## capture

```powershell
python -m stunscope capture -i <IFACE> [options]
```

`-i` accepts the Scapy name, the 1-based index from `list-interfaces`, or a
unique substring of the description (e.g. `-i Wi-Fi`).

| Option | Meaning |
|---|---|
| `--duration SEC` | auto-stop after N seconds (default: until Ctrl+C) |
| `--max-packets N` | auto-stop after N parsed STUN messages |
| `--ports LIST` | optional BPF port pre-filter, e.g. `3478,19302` |
| `--message-type T` | see tokens below |
| `--src IP` / `--dst IP` | source/destination IP: exact, CIDR, or `prefix*` |
| `--transaction-id HEX` | 24-hex transaction ID; a unique prefix is enough |
| `--validity any\|valid\|malformed` | keep only well-formed (or broken) messages |
| `--search TEXT` | free-text match across every displayed field |
| `--csv PATH` | export the filtered results when the capture stops |
| `--redact` | mask IP addresses in the export |
| `--verbose` | print fully decoded header and attributes per packet |

Message-type tokens: `binding-request`, `binding-success`,
`binding-success-response`, `binding-error`, `binding-error-response`,
`binding-indication`, `binding` (all binding messages), class tokens
`request`, `indication`, `success`, `error`, or any raw hex type like
`0x0111`.

Examples:

```powershell
# 30-second capture on the first interface, export filtered results
python -m stunscope capture -i 1 --duration 30 --csv results.csv

# Only Binding Success Responses seen on port 3478 or 19302
python -m stunscope capture -i 3 --ports 3478,19302 --message-type binding-success

# Everything involving 198.51.100.0/24, with full decode, redacted export
python -m stunscope capture -i "Ethernet" --src 198.51.100.0/24 --verbose --csv out.csv --redact
```

While capturing, one line is printed per STUN message:

```
14:22:07.331  192.0.2.10:50000 -> 198.51.100.20:3478  Binding Request              txn=00112233…aabb  attrs=1
```

Malformed messages append a `[diagnostic]` in brackets. `Ctrl+C` stops the
capture cleanly, prints a summary (valid/malformed, binding counts, datagrams
seen, duration), and finalizes the CSV export.

Filters apply to what is **displayed and exported**; the capture itself keeps
running unfiltered unless `--ports` narrows the BPF pre-filter. Type and
validity filters apply to structurally valid messages; select
`--validity malformed` to hunt for broken frames.

## parse-file

Offline analysis of hex-encoded STUN messages — **no Npcap or privileges
needed**, which also makes it the easiest way to share a reproducible
fixture:

```text
# comments are ignored
<hex-encoded STUN message>
<src-ip>:<src-port>-><dst-ip>:<dst-port> <hex-encoded message>
```

```powershell
python -m stunscope parse-file examples\fixtures.txt --verbose
python -m stunscope parse-file mine.txt --message-type binding-error --csv errs.csv --redact
```

Synthetic metadata defaults to `192.0.2.10:50000 -> 198.51.100.20:3478` per
RFC 5737 documentation ranges. Invalid lines are reported and skipped.

## gui and info

```powershell
python -m stunscope gui    # launch the desktop interface (needs PySide6)
python -m stunscope info   # versions, Scapy/PySide6 availability, paths
```

## Where results are stored

- CSV exports go wherever `--csv` points (parent directories are created).
- Diagnostic logs rotate at `%APPDATA%\STUNScope\logs\stunscope.log`
  (disable with `--no-log-file`; wipe from the GUI Settings page).
- No capture history is persisted anywhere by default.
