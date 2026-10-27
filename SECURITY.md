# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x (main) | yes |

## Reporting a vulnerability

Please report security issues privately to the repository owner via
GitHub's **"Report a vulnerability"** button on the *Security* tab. If that is
unavailable in your copy, open a GitHub issue asking the maintainers for a
private contact channel — without disclosing the details.

Include: a description, reproduction steps, affected platforms, and any
relevant logs (redacted — never paste captured traffic or personal data).

You should receive an acknowledgment within 7 days. Fixes are released as
patch versions and credited in `CHANGELOG.md` unless you prefer to remain
anonymous.

## Scope and expectations

STUNScope runs with the privileges of its user and reads raw packets from the
interfaces the user selects. Please apply the usual caution with any capture
tool:

- Run it from an elevated terminal only when you are actually capturing, and
  prefer unprivileged use of `parse-file` for offline analysis.
- Exports and logs stay on your machine. STUNScope performs **no telemetry
  and no network calls of its own** (the only traffic is the capture socket
  plus any STUN traffic the analyzed applications themselves generate).
- The rotating diagnostic log contains interface names and error text, not
  packet payloads or decoded addresses. It can be wiped from
  Settings → Clear stored capture data.

## Intended-use boundary (also security relevant)

Vulnerability reports about *unauthorized surveillance use cases* — e.g. "it
cannot capture a specific person's call" — are out of scope. That is a design
boundary, not a defect. Features that would weaken the security or privacy of
other applications will not be added.
