# Changelog

All notable changes to STUNScope are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-27

### Added

- Shared STUN (RFC 8489) protocol engine: header decode (message type, method
  and class, length, magic cookie, transaction ID), attribute parsing with
  correct 32-bit padding, and readable diagnostics for malformed messages.
- Attribute decoders: MAPPED-ADDRESS, XOR-MAPPED-ADDRESS (IPv4 and IPv6),
  USERNAME, MESSAGE-INTEGRITY, ERROR-CODE, REALM, NONCE, SOFTWARE, FINGERPRINT,
  plus an ICE/TURN attribute registry with raw retention of unknown types.
- Live capture layer built on Scapy with Npcap support: interface listing,
  responsive start/stop via `AsyncSniffer`, structural STUN detection (magic
  cookie + framing, never port-only), and optional convenience port filters.
- CLI (`python -m stunscope`): `list-interfaces`, `capture`, `parse-file`,
  `gui`, `info`; filters by message type/class, source/destination IP (exact,
  CIDR, prefix), transaction ID, validity, and free-text search; CSV export
  with optional privacy redaction; graceful `Ctrl+C` handling.
- PySide6 desktop GUI: dark theme with sidebar navigation; Dashboard, Live
  Capture, Packet Inspector, Filters, Export, and Settings pages; capture on a
  worker thread with batched signals; bounded memory; pause/resume display;
  shared selection between capture and inspector views.
- Shared CSV exporter: one row per attribute, `n/a` for not-applicable fields,
  UTF-8, atomic writes, IPv4 `/24` and IPv6 `/64` redaction in privacy mode.
- Test suite: parser, IPv4/IPv6 XOR decoding against hand-computed RFC vectors,
  malformed-packet robustness (including fuzz-lite), filters, exporter, CLI,
  and GUI import smoke tests — all on synthetic fixtures.
- Documentation set: architecture, Windows install, CLI/GUI usage, STUN
  protocol primer, troubleshooting, and privacy/security notices.
- GitHub Actions: multi-OS pytest matrix, ruff lint, PyInstaller Windows build.
- Windows helper scripts: setup, run-cli, run-gui, build.

### Notes

- Live capture requires Npcap on Windows and usually an elevated terminal.
- MESSAGE-INTEGRITY and FINGERPRINT are reported but never verified.
- The project is intended for analyzing networks you own or are authorized to
  test; see `docs/privacy-and-security.md`.

[1.0.0]: https://github.com/YOUR-USERNAME/stunscope/releases/tag/v1.0.0
