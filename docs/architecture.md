# Architecture

STUNScope is organized so that **one protocol engine serves two interfaces**.
This page explains the module layout, the data flow, and the threading model.

## Module map

```
src/stunscope/
├── models.py         dataclasses shared by everything
│                     (StunMessage, StunAttribute, PacketRecord)
├── parser.py         RFC 8489 decode; never raises on malformed input
├── capture.py        Scapy/Npcap capture engine (no Qt, no CLI)
├── filters.py        PacketFilter predicate (shared by CLI, GUI, exporter)
├── exporter.py       atomic UTF-8 CSV writer (shared by CLI and GUI)
├── config.py         JSON settings in %APPDATA%\STUNScope
├── logging_config.py  rotating diagnostic log
├── cli.py            argparse front end (`python -m stunscope`)
└── gui/
    ├── main.py             QApplication bootstrap
    ├── main_window.py      shared state + navigation + capture control
    ├── workers.py          CaptureWorker (QObject on a QThread)
    ├── models.py           Qt table model + filter proxy
    ├── theme.py            dark palette + stylesheet
    ├── logging_bridge.py   routes ERROR logs to a dialog
    ├── pages/              Dashboard, Live Capture, Inspector, Filters,
    │                       Export, Settings
    └── widgets/            cards, status badge, empty state
```

## Data flow

```
                 ┌──────────────────────────────────────────┐
                 │                capture.py                │
                 │  Scapy AsyncSniffer → maybe_stun() →     │
                 │  build_record() → PacketRecord            │
                 └───────────────┬──────────────────────────┘
                                 │ PacketRecord (pure dataclass)
             ┌───────────────────┴────────────────────┐
             │                                        │
      CLI (cli.py)                           GUI (workers.py →
      prints/exports                          batch_ready signal →
                                                PacketTableModel)
             │                                        │
             └──────────────┬─────────────────────────┘
                            ▼
                 filters.py (PacketFilter.matches)
                            ▼
                 exporter.py (export_csv)
```

Key invariant: a `PacketRecord` is produced exactly once, by the parser, and
everything downstream — table rows, inspector panes, dashboard counters, CSV
rows — renders the same object. Neither interface re-implements decoding.

## Why records are created in the capture layer

`build_record()` in `capture.py` is deliberately a **pure function**:
it takes addressing fields plus a payload and returns a `PacketRecord` or
`None`. That makes it directly unit-testable without Scapy, Npcap, or
Administrator privileges (see `tests/test_filters.py`). Only the thin Scapy
adapter `build_record_from_scapy()` touches packet objects.

## Threading model (GUI)

- `CaptureEngine` (capture.py) runs Scapy's `AsyncSniffer` on its own thread
  and polls a stop event at 10 Hz, so **stop is prompt even on idle
  interfaces**.
- In the GUI, `CaptureWorker` is a `QObject` moved onto a `QThread`.
  Parsed packets are batched (64 records or 150 ms, whichever first) and
  delivered with a queued signal — the capture thread never blocks on UI
  work.
- The GUI thread ingests batches into `PacketTableModel`. **Two bounds
  prevent unbounded memory growth**: the model keeps at most
  `max_display_rows` records (configurable in Settings), and the worker drops
  the oldest buffered records beyond a fixed cap when the UI cannot keep up.
  Both bounds are counted, so the Dashboard can report dropped packets
  honestly.
- **Pause display** freezes only the view/model ingestion path: packets
  accumulate in a bounded pending buffer and flush on resume. The capture
  itself never pauses.
- Opening the capture device happens behind a synchronous pre-flight check,
  so Npcap/permission failures surface as clear errors instead of dying
  inside the sniffer thread.

## Detection strategy

STUN is identified **structurally**: a UDP payload with zero framing bits and
the magic cookie `0x2112A442` is a candidate (`maybe_stun()`); the parser then
validates framing and lengths, and malformed-but-real STUN still appears with
a readable diagnostic. The strict `looks_like_stun()` variant additionally
requires a complete, well-framed message and is used for tests and
preflight decisions. Ports such as 3478/19302 are offered only as optional
convenience pre-filters.

## Extension points

- **New attribute type**: add the constant + display name in `parser.py`, add
  a decoder branch in `decode_attribute_value()`, and extend the fixtures and
  tests. Both interfaces pick it up automatically.
- **New export format**: implement beside `export_csv()` and reuse
  `record_rows()`; expose it in both the CLI and the Export page.
- **New filter criterion**: extend `PacketFilter` and wire a control into the
  Filters page and a CLI flag at the same time — the shared predicate then
  covers both.

## Deliberate non-goals

- No STUN-over-TCP framing analysis.
- No RFC 3489 (pre-cookie) decode.
- No MESSAGE-INTEGRITY/FINGERPRINT verification (no credentials by design).
- No transmission of any data; no capture side effects (no injection, no
  ARP spoofing, no scanning).
