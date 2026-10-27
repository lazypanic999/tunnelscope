# Two-VM receiver correlation validation

Recorded on 2026-10-27 with separate Ubuntu 24.04 and Debian 12 VirtualBox
guests on a temporary host-only link. Both guests ran the same TunnelScope
source file, verified by SHA-256. Each guest used a 1500-byte link MTU.
The host-only addresses and raw JSON reports remain local and are not included
in this repository.

## Procedure

For each direction, the destination ran `receive` with `--output`,
`--max-packets 12` and a 30-second idle timeout. The source then ran:

```sh
python3 tunnelscope.py probe PEER_IP --sizes 64,512,1200,1400 --count 3 --timeout 2 --dont-fragment --output probe.json
```

The receiver exited after all 12 valid packets, writing its observation report.
The reports were copied to one machine and processed with:

```sh
python3 tunnelscope.py correlate probe.json receiver.json --output correlation.json
```

An initial Ubuntu-to-Debian attempt used a 15-second receiver idle timeout and
the receiver exited before probing began. Its empty observation report was
marked `unverified_no_receiver_observations`; that attempt was discarded and
repeated with the 30-second timeout.

## Results

| Direction | Sender acknowledgements | Receiver observations | Run ID | Endpoint checks |
| --- | ---: | ---: | --- | --- |
| Ubuntu to Debian | 12/12 | 12/12 | matched | port and IPv4 matched |
| Debian to Ubuntu | 12/12 | 12/12 | matched | port and IPv4 matched |

Both receiver reports ended with `exit_reason: max_packets`. Each correlation
had zero unmatched receiver observations and zero timed-out probes observed at
the receiver. When the Ubuntu-to-Debian sender report was deliberately paired
with the Debian-to-Ubuntu receiver report, `correlate` rejected it with
`receiver report has observations from a different run`.

## Limits

This validates successful cross-VM receiver observation and wrong-run rejection
on a direct virtual link. It does not validate the correlation of a real timeout
where the receiver saw a packet but the acknowledgement did not return. A
receiver report with no observations cannot prove that the receiver covered the
sender's run. These reports are unauthenticated and are intended for controlled
environments.
