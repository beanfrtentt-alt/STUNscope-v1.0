# GUI usage

Launch with `python -m stunscope gui`, `python -m stunscope.gui`, or
`.\scripts\run_gui.ps1`. The window uses a dark slate/purple theme with a
sidebar on the left and six pages.

A permanent notice in the status bar and sidebar is worth repeating here:
**live capture may require an Administrator terminal, and you must be
authorized to inspect the traffic you select.**

## Dashboard

The landing page shows live metric cards:

- packets captured, valid STUN messages, malformed messages,
- Binding Requests, Binding Success Responses, Binding Error Responses,
- capture duration (updating every second while capturing),
- current interface and capture status (idle / capturing / failed).

It also carries the standing reminder that a mapped address is the server's
observation of the request sender — not a remote participant address. A
“getting started” empty state is shown until the first packet arrives.

## Live Capture

- **Interface** dropdown (populated from Npcap; pre-selected from Settings).
- **Duration (s)** and **Packet limit**: automatic stop values; blank/zero
  means “until stopped”.
- **Ports**: optional convenience pre-filter (e.g. `3478,19302`). STUN is
  always detected structurally, never by port alone.
- **Start / Stop**, plus **Pause display** — pausing freezes the table but
  the capture keeps running; buffered rows flush on resume.
- **Clear table** removes in-memory packets (with confirmation).
- **Search** box and a quick **type filter** combo (binding request/success/
  error/indication, any binding, valid/malformed only).
- The table shows time, source and destination endpoints, decoded type,
  shortened transaction ID, attribute count, and a green/red validity badge.
  Right-click for a context menu: inspect packet, copy transaction ID,
  copy endpoints, clear table. Double-click a row to jump to the inspector.
- A footer shows “N shown · M captured” when filters hide some packets, and
  a count of how many packets were dropped to respect the memory cap.

## Packet Inspector

The left side lists packets (selection shared with Live Capture — clicking
either list keeps both in sync). The right side shows:

- **Packet metadata**: timestamp, interface, source → destination, protocol,
  parse status, and the diagnostic line.
- **STUN header**: message type (hex + meaning), class, method, message
  length, magic cookie, full transaction ID.
- **Observed addresses**: MAPPED-ADDRESS and XOR-MAPPED-ADDRESS values, with
  the standing attribution note (server-observed mapping, not a remote
  participant address).
- **Attributes table**: name, type, length, decoded value, status, and note.
  Malformed attributes are flagged; unknown attributes show their raw bytes.
- **Raw payload**: offset/hex/ASCII dump of the retained bytes.

Malformed messages raise an amber warning banner with the exact protocol
violation instead of hiding the packet.

## Filters

Full control over the shared filter (applied live to tables, dashboards, and
filtered exports):

- STUN message type (concrete types or class-level),
- source and destination IP (exact, CIDR, or `prefix*`),
- transaction ID (prefix allowed),
- validity (any / valid / malformed),
- **Reset all filters** restores everything, including the quick search box
  on the Live Capture page.

The “Active:” label always describes the current criteria in plain text.

## Export

- **Directory** + **File name** (defaults from Settings),
- **All captured packets** or **Filtered packets only** (respecting the
  Filters page),
- **Privacy mode**: IPv4 → `/24`, IPv6 → `/64` masks,
- overwrite confirmation, and a success/error result line with the exact
  path and row count.

One CSV row is written per attribute (packets without attributes produce one
message row); see [usage-cli.md](usage-cli.md#csv-export) for column
documentation. Exports are written atomically and never leave the machine.

## Settings

- Defaults: interface (pre-selected at startup), export directory,
  maximum packets kept in memory, auto-scroll,
- privacy redaction default for exports,
- **Clear stored capture data**: wipes the settings file and diagnostic logs,
- about panel with version and intended-use notice.

Changes save immediately to `%APPDATA%\STUNScope\settings.json`.

## Responsiveness guarantees

Capture runs on a worker thread; the UI receives batched updates via Qt
signals and stays interactive. The in-memory packet list is capped
(configurable), and the worker drops oldest-first under extreme packet
pressure — both are reported rather than hidden. Stopping the capture is
prompt even when the interface is idle.
