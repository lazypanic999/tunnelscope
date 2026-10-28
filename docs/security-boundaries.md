# Security boundaries

TunnelScope is an alpha measurement tool for networks whose endpoints and
traffic are under your control. It is not a public UDP service.

## What the protocol does and does not protect

- The receiver checks a 24-byte probe header and payload length, then sends a
  small acknowledgement to the packet's claimed source address. Neither side
  authenticates the peer. The random probe ID helps match an acknowledgement
  to a sent probe; it is not a secret or proof of identity.
- UDP probes, acknowledgements and JSON reports are not encrypted or signed.
  An attacker who can observe or inject traffic can affect results. Do not
  interpret a receiver report or a matching acknowledgement as trusted proof
  of who sent a packet.
- The receiver defaults to `127.0.0.1`. From v0.4.1, it refuses wildcard
  binds (`0.0.0.0` and `::`). An explicit non-loopback bind is still reachable
  wherever network routing and firewall policy allow it.
- Probe sizes, attempts, receiver observations and idle time are bounded by
  CLI limits. These limits reduce accidental workload; they are not a denial
  of service defense against traffic from untrusted hosts.
- JSON and generated HTML can contain IP addresses, timestamps and other
  report fields. The HTML embeds the full JSON. Sanitize either file before
  sharing it.

## Safe operating pattern

1. Use loopback, isolated VMs or a private lab network with endpoints you
   control. Bind the receiver to one lab interface address.
2. Restrict the receiver's UDP port (9471 by default) to the intended sender
   using the lab network or firewall. Stop the receiver when the test ends.
3. Keep reports local until their addresses and other fields are reviewed.
   Treat unexpected packets, timeouts and receiver observations as evidence
   to investigate, not as an authenticated diagnosis.

Before supporting untrusted or internet-facing use, the project would need an
explicit peer-authentication design, integrity protection, anti-replay rules,
resource controls and a review of response behavior. Encryption would be
needed where confidentiality matters. Those features are outside the current
protocol and v0.5 scope.

These boundaries reflect [RFC 8085's UDP security guidance](https://www.rfc-editor.org/rfc/rfc8085.html),
including its warning that source IP addresses are not authenticators.
