---
name: reversing-network-protocols
description: Reverse engineer undocumented binary network protocols from packet captures and the client that speaks them — recovering framing and field structure, identifying length prefixes, opcodes, checksums and encryption, and building a Wireshark/Kaitai/scapy parser to replay or fuzz. Use when analyzing a proprietary TCP/UDP protocol, a game or IoT or C2 protocol with no spec, or traffic that Wireshark shows only as raw bytes.
verified: 2026-08-07
---

# Reversing Network Protocols

An undocumented binary protocol is reverse-engineered from two sides at once:
the wire, which shows you the bytes that actually flow, and the client, which
shows you the code that produced them. Neither alone is enough — the capture
tells you *what* varies, the client tells you *why* — and the deliverable is a
parser precise enough to decode, replay, and eventually fuzz the protocol.

## When to Use

- A proprietary or custom TCP/UDP protocol with no public specification
- Traffic Wireshark displays as raw `Data` bytes because no dissector matches
- Game, IoT, industrial, or C2 protocols you must decode from captures plus the
  client binary
- Building a Wireshark dissector, a Kaitai Struct spec, or a scapy layer to
  parse and replay a protocol

## When NOT to Use

- **A known/structured protocol** — Protobuf or gRPC specifically is
  `attacking-grpc-protobuf`; standard protocols have dissectors already.
- **Defensive PCAP investigation** — hunting, IOC extraction, incident triage —
  is `analyzing-network-traffic`.
- **Reversing the client binary itself** (disassembly, decompilation) is
  `analyzing-binaries`; do that in service of the protocol, then structure it
  here.
- **Identifying or breaking the crypto** once you find the protocol is encrypted
  — `reviewing-cryptography`.

## Work Both Sides

**From the capture**, establish structure by comparing many messages:

- **Framing** — how a message knows where it ends: a length prefix (a field that
  tracks payload size across messages), a delimiter, or fixed-size records.
  Finding the length field is usually the first breakthrough.
- **Constants and magic** — bytes identical across every message mark headers,
  version fields, or type tags.
- **Opcode / message type** — a small field that correlates with different
  message shapes; group captures by it.
- **Counters and sequence numbers** — fields that increment monotonically.
- **Checksums** — a trailing field that changes unpredictably with the payload;
  test CRC variants against the message body.
- **TLV** — many custom protocols are type-length-value triplets once you see
  the pattern.
- **Endianness** — confirm from a known length: does a 260-byte message carry
  `04 01` or `01 04`?

**From the client**, resolve what the capture cannot:

- Find the serialization/parsing code by reversing the binary (`analyzing-
  binaries`), and read how it builds and consumes a message.
- **Hook `send`/`recv`** (or the app's socket wrapper) with Frida to capture the
  buffer *before* encryption and *after* decryption — this is how you read an
  encrypted protocol without breaking the crypto.
- If the protocol is encrypted, hook the plaintext side; identify the cipher and
  key handling with `reviewing-cryptography` only if you must operate off-client.

## Build a Parser

Turn the recovered structure into something executable, because a parser is both
the proof you understood the protocol and the tool for everything after:

- **Wireshark dissector** (Lua) to decode live captures field by field — the
  fastest way to validate a hypothesis against more traffic.
- **Kaitai Struct** to describe the binary format declaratively and generate
  parsers in several languages.
- **scapy** custom layers to both parse and *craft* messages for replay and
  fuzzing.

Iterate: decode a batch, find the message that does not parse, refine the spec.
The malformed message is where your model is wrong, not noise.

## Then What

A working parser enables the security work: **replay** to test whether the
server validates sequence, session, and authentication; **fuzz** individual
fields (lengths, type tags, counts) to find parser bugs; and reason about
**protocol-level auth** — whether nonces, session tokens, or MACs actually
prevent replay and tampering, or are decorative.

## Rationalizations to Reject

- **"Wireshark shows it as raw data, so there's nothing to see."** No dissector
  matched — that is the starting point, not a dead end. Diff messages to find
  framing and fields, or write a dissector.
- **"It's encrypted, so I can't reverse it."** Hook the client's send/recv to
  read plaintext before encryption. You rarely need to break the cipher to
  understand the protocol.
- **"I'll just eyeball the hex."** Structure emerges from *comparison* across
  many messages — the field that tracks length, the byte that selects type. One
  message in isolation hides all of it.
- **"The parser mostly works, one message fails — close enough."** The failing
  message is the counterexample that corrects your model. Chase it; it is where
  the real structure is.
- **"Replaying it is harmless."** Replay against a live service acts on that
  service. Treat it as testing that needs authorization, and reason about what a
  replayed message does before sending it.

## References

- `analyzing-binaries` — reversing the client to read its serialization code
- `attacking-grpc-protobuf` — when the protocol is Protobuf/gRPC, not custom
- `analyzing-network-traffic` — defensive PCAP investigation, not protocol RE
- `reviewing-cryptography` — identifying and assessing the protocol's crypto
