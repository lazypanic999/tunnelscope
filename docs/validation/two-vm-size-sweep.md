# Two-VM payload-size sweep validation

Recorded on 2026-10-28 using separate Ubuntu 24.04 and Debian 12 VirtualBox
guests connected through a temporary 1500-byte host-only link. Ubuntu ran
Python 3.12.3 and Debian ran Python 3.11.2. Both guests ran the same
`tunnelscope.py` file (SHA-256
`43b0cb76dfa6b58452b9ecc844a5db27c2d057cb7cad4c3735233f75d454a857`).
The temporary host-only addresses and raw JSON reports are kept locally in
ignored `output/field-test-2026-10-28/`; they are not committed.

## Procedure

The destination ran `receive --max-packets 5 --idle-timeout 20 --output receiver.json`.
The source then ran the development CLI in Linux IPv4 DF mode:

```sh
python3 tunnelscope.py probe PEER_IP --sweep 1468:1476:1 --count 1 --timeout 2 --dont-fragment --output probe.json
```

The two files were correlated after each direction. The same procedure was
repeated with guest roles reversed. The direct-link expected UDP payload
boundary is 1472 bytes: 1500-byte link MTU minus 20-byte IPv4 and 8-byte UDP
headers.

## Results

| Direction | 1468–1472 bytes | 1473–1476 bytes | Receiver observed | Run ID |
| --- | --- | --- | ---: | --- |
| Ubuntu to Debian | 5/5 acknowledged | 4/4 `packet_too_large` | 5/5 | matched |
| Debian to Ubuntu | 5/5 acknowledged | 4/4 `packet_too_large` | 5/5 | matched |

Each sender identified its host-only interface with MTU 1500. All eight
oversized attempts reported kernel MTU 1500. Both receiver reports exited at
`max_packets`; the correlations had zero unmatched observations and no
receiver-observed timeouts. The source file was checked by SHA-256 on both
guests before testing.

## Limits

This confirms the size grid and known boundary on one directly connected
virtual link. It does not discover an unknown multi-hop path MTU. The
`packet_too_large` statuses are local kernel rejections, and the successful
ACKs only confirm forward payload delivery plus a small reply. The same
experiment on an unknown path can produce timeouts for several reasons.
