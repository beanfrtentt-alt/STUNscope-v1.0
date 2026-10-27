# The STUN protocol, as far as STUNScope explains it

A practical primer focused on what this tool decodes. The normative reference
is **RFC 8489** (obsoleting RFC 5389); TURN is RFC 8656, ICE is RFC 8445.

## Why STUN exists

STUN (Session Traversal Utilities for NAT) lets an endpoint discover the
public address and port that a NAT maps for it, and it underpins ICE, the
connectivity-establishment framework used by calling and conferencing
applications. The core flow STUNScope observes:

1. A client sends a **Binding Request** (`0x0001`) to a STUN server.
2. The server replies with a **Binding Success Response** (`0x0101`)
   containing the mapped address it observed, or a **Binding Error
   Response** (`0x0111`) with an ERROR-CODE.

## Message layout (RFC 8489 §5)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     Type                  |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Transaction ID (96 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Attributes                        |
```

- **Type** is 16 bits with the two top bits zero; 12 method bits interleave
  two class bits (C1 at bit 8, C0 at bit 4). Classes: 0 Request,
  1 Indication, 2 Success Response, 3 Error Response. STUNScope decodes
  method and class and labels e.g. `0x0111` as *Binding Error Response*.
- **Length** counts the body only and must be a multiple of four.
- **Magic cookie** is always `0x2112A442` — the structural fingerprint
  STUNScope uses to recognize traffic regardless of port.
- **Transaction ID** is 96 bits of randomness identifying the
  request/response pair. STUNScope shows the full ID (and a short form in
  tables) and lets you filter on it.
- **Attributes** are `type (16) | length (16) | value` TLVs, each padded to a
  32-bit boundary; padding bytes are ignored by receivers.

## Attributes STUNScope decodes

| Type | Name | Decode |
|---|---|---|
| `0x0001` | MAPPED-ADDRESS | family byte, port, plain address (IPv4/IPv6) |
| `0x0006` | USERNAME | UTF-8 text |
| `0x0008` | MESSAGE-INTEGRITY | presence noted; **never verified** (no credentials) |
| `0x0009` | ERROR-CODE | numeric code (300–699) + reason phrase |
| `0x0014` | REALM | UTF-8 text |
| `0x0015` | NONCE | opaque text |
| `0x0020` | XOR-MAPPED-ADDRESS | XOR-decoded mapped address (below) |
| `0x8022` | SOFTWARE | UTF-8 description of the sending agent |
| `0x8028` | FINGERPRINT | presence noted; **never verified** |

Types `0x0000–0x7FFF` are *comprehension-required*; unknown ones make
STUNScope emit a warning (a conforming agent would reject the message).
Types `0x8000–0xFFFF` are optional; unknown ones are kept as raw bytes with
no warning. A registry of common ICE/TURN attribute names is included for
readability.

## XOR-MAPPED-ADDRESS decoding (RFC 8489 §14.2)

The value stores the port XORed with the top 16 bits of the magic cookie
(`0x2112`), and the address XORed with:

- **IPv4**: the 32-bit magic cookie `0x2112A442`;
- **IPv6**: the 128-bit mask formed by the magic cookie followed by the
  96-bit transaction ID.

Worked example (test vector in `tests/test_xor_mapped_address.py`):
address `192.0.2.34`, port `0x1234`, any transaction ID →

```
port'  = 0x1234 ^ 0x2112            = 0x3326
addr'  = 0xC0000222 ^ 0x2112A442    = 0xE112A660
value  = 00 01 | 33 26 | E1 12 A6 60
```

For IPv6, the test in `tests/test_ipv6.py` uses the same hand-computed
method against the mask `2112:a442 || 00112233445566778899aabb`.

## Address-attribution: the four addresses people confuse

STUNScope displays several kinds of addresses, and honest labeling matters:

1. **Server-observed mapped address** (XOR-MAPPED-ADDRESS /
   MAPPED-ADDRESS in a Binding Success Response). This is the address the
   *STUN server* saw for the *request sender* — in home/office networks,
   the NAT binding of the **local** network. It is **not automatically the
   address of the other person in a call**.
2. **Local interface address.** An address configured on the machine doing
   the analysis (what interface pickers show).
3. **Remote packet endpoint.** The far end of a single datagram. For STUN
   traffic this is nearly always a **server you or your app chose**, not a
   call participant.
4. **TURN relay endpoint.** An allocation on a TURN server that forwards
   media for a session. It identifies relay infrastructure, not the peer.

Consequently: STUNScope **does not and cannot always identify a remote
caller's public IP address**. Modern calling apps may use direct connections,
TURN relays, media servers, or mixed architectures; a single capture sees
only the paths its own traffic took. Any attribution beyond "this is the
server-observed mapping" requires independent, authorized knowledge of the
test setup.

## Error codes worth knowing

| Code | Reason | Typical meaning |
|---|---|---|
| 300 | Try Alternate | server redirect |
| 400 | Bad Request | malformed request |
| 401 | Unauthorized | long-term credentials required |
| 420 | Unknown Attribute | lists the unknown attributes |
| 438 | Stale Nonce | re-authenticate with the fresh nonce |
| 500 | Server Error | transient server-side failure |

STUNScope decodes the code and reason, tolerates out-of-range codes with a
warning, and reports truncated values as malformed attributes.
