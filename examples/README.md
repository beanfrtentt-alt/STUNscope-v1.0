# Examples

Everything in this folder is **synthetic** and safe to publish:

- All IPv4 addresses come from the RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- All IPv6 addresses come from the RFC 3849 documentation prefix
  (`2001:db8::/32`).
- Transaction IDs, nonces, and integrity values are invented.
- No bytes were captured from a real network, a real call, or a real
  service.

## Files

- `fixtures.txt` — hex-encoded STUN messages for the offline
  `parse-file` command, including one deliberately malformed frame:

  ```powershell
  python -m stunscope parse-file examples\fixtures.txt --verbose
  python -m stunscope parse-file examples\fixtures.txt --csv out.csv --redact
  ```

  XOR-MAPPED-ADDRESS values in this file were computed by hand from
  RFC 8489 §14.2 and match the reference vectors in
  `tests/fixtures/stun_messages.py` and `tests/test_ipv6.py`.

- `sample_capture.csv` — an example of the exporter output format,
  consistent with the messages in `fixtures.txt` (regenerate your own with
  the `parse-file ... --csv` command above). One row is written per decoded
  attribute; packet metadata repeats on every row. Fields that do not
  apply to a row contain `n/a`; genuinely empty values remain empty.
