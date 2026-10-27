# Privacy and security

## Authorization boundary

**Use STUNScope only on networks you own or are explicitly authorized to
test.** Intercepting or analyzing traffic without authorization is illegal in
most jurisdictions, regardless of tooling. The GUI shows this notice
permanently in the sidebar and status bar, and the CLI prints it before every
capture.

STUNScope is a diagnostics tool. It is **not** designed or intended to:

- identify a remote call participant without their consent,
- extract another person's address from a third-party application's protected
  call session,
- defeat the security or privacy protections of calling applications.

## What the tool deliberately does not do

- **No ARP spoofing, traffic redirection, or man-in-the-middle mechanics.**
- **No stealth.** Capture requires explicitly selecting an interface and, on
  Windows, typically an elevated terminal.
- **No scanning** of unrelated devices, and no packet injection — the
  capture socket is receive-only.
- **No credential collection.** MESSAGE-INTEGRITY and FINGERPRINT are reported
  as present-but-not-verified; no key material is ever derived.
- **No covert peer identification.** Mapped addresses are labeled as
  server-observed NAT mappings, never as “the other person's IP”.
- **No telemetry or data exfiltration.** The application makes no network
  connections of its own; CSV exports are written to your chosen local path
  only.

## Address semantics (the honest version)

See [stun-protocol.md](stun-protocol.md) for the full primer. Summary:

- A **mapped address** is what the *server* saw for the *request sender* —
  usually your NAT binding, not anyone else's address.
- A **remote packet endpoint** is the far side of one datagram — typically a
  STUN/TURN server.
- A **TURN relay endpoint** is infrastructure, not a person.
- Third-party calling apps may use direct connections, relays, or other
  architectures, so **no tool can reliably “get the caller's IP” from a
  capture** — and STUNScope does not attempt to, nor claim it can.

## Data handling

| Data | Where it lives | How to remove it |
|---|---|---|
| Captured packets | memory only (bounded; nothing persisted) | Close the app, or Clear table / Ctrl+C stop |
| Settings | `%APPDATA%\STUNScope\settings.json` (UI prefs only) | Settings → Clear stored capture data |
| Diagnostic logs | `%APPDATA%\STUNScope\logs\stunscope.log` (rotating, 3×1 MB; interface names and errors, never payloads or addresses) | Settings → Clear stored capture data |
| CSV exports | wherever you choose, in plain UTF-8 | Delete the file |

## Export privacy mode

Enable with `--redact` (CLI) or the Export-page checkbox / Settings default
(GUI). IPv4 addresses are masked to their `/24` network and IPv6 addresses to
their `/64` network — enough for topology analysis, not enough to identify a
host. Ports, transaction IDs, and timestamps remain because they are not
personal addresses. If your threat model requires more, keep redaction on and
treat any unredacted export as sensitive.

## Fixture hygiene (for contributors)

All test fixtures and examples are synthetic and use only RFC 5737/3849
documentation ranges. Never paste real captures, credentials, tokens, or
personal addresses into issues, tests, or docs — this is enforced by the
issue templates and PR checklist.

## Security reports

Follow the process in [../SECURITY.md](../SECURITY.md); do not open public
issues for vulnerabilities. Note that reports about “the tool won't let me
capture someone's traffic” describe the intended boundary, not a defect.
