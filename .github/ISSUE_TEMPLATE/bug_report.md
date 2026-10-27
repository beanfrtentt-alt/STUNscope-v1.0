name: Bug report
about: Report a crash, wrong decode, or capture problem
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to report a problem. Please remember that
        STUNScope is for analyzing networks you own or are authorized to test,
        and include only synthetic/sanitized packet data.
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: Describe the problem. A short description of what you expected instead helps a lot.
      placeholder: The GUI froze while capturing on Wi-Fi…
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to reproduce
      placeholder: |
        1. Start a capture on interface …
        2. Send a STUN Binding request …
      value: |
        1.
        2.
        3.
    validations:
      required: true
  - type: textarea
    id: environment
    attributes:
      label: Environment
      description: Output of `python -m stunscope info` is ideal.
      placeholder: |
        OS: Windows 11 22H2
        Python: 3.12.4
        STUNScope: 1.0.0
        Npcap: 1.79
    validations:
      required: true
  - type: textarea
    id: synthetic-packet
    attributes:
      label: Synthetic packet bytes (optional)
      description: >
        If this is a decode problem, attach a hex dump of the STUN payload.
        Please use synthetic or sanitized data only — no real captured
        traffic, credentials, or personal addresses.
      placeholder: "0101002c2112a44200112233445566778899aabb…"
  - type: checkboxes
    id: authorization
    attributes:
      label: Usage notice
      options:
        - label: I am analyzing my own network or traffic I am authorized to test.
          required: true
  - type: checkboxes
    id: checks
    attributes:
      label: Quick checks
      options:
        - label: I checked docs/troubleshooting.md first.
          required: true
