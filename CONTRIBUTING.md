# Contributing to STUNScope

Thanks for helping improve STUNScope — a STUN analysis tool intended
exclusively for authorized network diagnostics.

## Ground rules

1. **Authorized traffic only.** Never commit real captured traffic, personal
   addresses, credentials, tokens, or data from third-party calls. Fixtures
   must be synthetic and use RFC 5737 / RFC 3849 documentation ranges
   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).
2. **No covert-collection features.** Contributions that add ARP spoofing,
   traffic redirection, credential collection, stealth capture, or scanning of
   unrelated devices will be rejected.
3. **One shared engine.** The CLI and GUI must keep using the same parser
   (`src/stunscope/parser.py`), the same filter (`src/stunscope/filters.py`),
   and the same exporter (`src/stunscope/exporter.py`). Do not duplicate
   protocol logic in either interface.
4. **Malformed input never crashes.** Any new decode path must return a
   readable diagnostic rather than raising.

## Development setup (Windows)

```powershell
git clone https://github.com/YOUR-USERNAME/stunscope.git
cd stunscope
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

Install [Npcap](https://npcap.com/) (with the WinPcap API-compatible option)
if you want to work on live capture.

## Everyday commands

```powershell
python -m pytest                # run the full test suite
ruff check src tests conftest.py
python -m stunscope parse-file examples\fixtures.txt --verbose
python -m stunscope gui
```

## Code layout

```
src/stunscope/        shared engine (parser, models, capture, filters, exporter)
src/stunscope/gui/    PySide6 desktop app (workers, pages, widgets, theme)
tests/                pytest suite + synthetic fixtures (tests/fixtures)
docs/                 user and protocol documentation
scripts/              Windows helper scripts
.github/workflows/    tests, lint, and Windows build pipelines
```

## Making a change

1. Open or comment on an issue first for anything non-trivial.
2. Create a branch: `git switch -c my-feature`.
3. Add or update **tests** for the behavior you are changing. Protocol changes
   need fixtures built in `tests/fixtures/stun_messages.py` — and when you add
   XOR-encoded values, derive expected bytes by hand (see the existing
   hand-computed vectors) so tests validate against the RFC, not against the
   implementation.
4. Make sure the suite passes: `python -m pytest` and
   `ruff check src tests conftest.py`.
5. Update `docs/` and `CHANGELOG.md` when user-facing behavior changes.
6. Send a pull request; the PR template includes the intended-use check.

## Style

- Python 3.11+; type hints in new engine code; `from __future__ import
  annotations` is already in place everywhere.
- Line length ≤ 110 (ruff-enforced); otherwise follow the surrounding style.
- GUI code stays in `src/stunscope/gui/` and never imports Scapy directly —
  capture always flows through `stunscope.capture` and `CaptureWorker`.
- Docstrings explain *why*, especially for protocol edge cases.

## Reporting bugs

Use the GitHub issue templates. Include the output of
`python -m stunscope info`, and attach only synthetic/sanitized packet data.

## Security reports

Do not open public issues for security problems — follow the process in
[SECURITY.md](SECURITY.md).
