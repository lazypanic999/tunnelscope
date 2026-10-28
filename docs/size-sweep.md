# Bounded payload-size sweep

From v0.3.0, `probe --sweep START:STOP:STEP` expands
an ascending grid of UDP payload sizes, always including `STOP` even if `STEP`
does not land exactly on it. The bounds are 32 to 8192 bytes and at most 16
sizes. `--sweep` and `--sizes` cannot be used together. `--count` repeats each
size; existing per-size status counts and individual results remain in JSON.

On a controlled Linux IPv4 link, start the receiver first and run:

```sh
tunnelscope receive --bind RECEIVER_IP --output receiver.json
tunnelscope probe RECEIVER_IP --sweep 1200:1400:25 --count 2 --dont-fragment --output sweep.json
tunnelscope show sweep.json
```

Run the receiver and sender commands on separate terminals or hosts. The
receiver's small acknowledgement does not test a same-sized return packet.
Repeat with the endpoint roles reversed to test the other direction.

A sweep samples only the listed sizes. A successful size is an observed working
UDP payload size under these conditions, not the exact path MTU. A
`packet_too_large` result reflects the sender kernel's DF rejection and
current route knowledge. A timeout is inconclusive even if nearby smaller
sizes succeeded. Compare receiver observations with `correlate` to learn
whether a timed-out probe reached the cooperating receiver.

The [direct-link MTU lab](../labs/mtu_boundary.py) checks this option against a
known 1280-byte virtual link in both directions.
