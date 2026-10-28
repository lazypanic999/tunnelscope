# Correlate receiver observations

In v0.2, a cooperating receiver can save the probe IDs and payload sizes it
observed. The sender also includes each 128-bit random probe ID in its JSON
results. From v0.2.1, the sender puts one random run ID in every payload, and
both reports record it. Correlation answers whether a particular probe reached
the receiver and whether the receiver attempted to send an acknowledgement.

Start the receiver on endpoint B and give it an output path:

```sh
tunnelscope receive --bind B_IP --output receiver.json
```

After the receiver exits, `tunnelscope show receiver.json` groups its
observations by run ID and payload size. It shows how many probes arrived and
how many acknowledgement sends succeeded or failed locally. An empty capture
still displays its exit reason and a zero count. A successful send call does not
confirm that the acknowledgement reached the sender.

Run the sender on endpoint A:

```sh
tunnelscope probe B_IP --sizes 64,1252,1253,1400 --count 3 --dont-fragment --output a-to-b.json
```

After the sender finishes, stop the receiver with Ctrl-C or wait for its idle
timeout. The receiver writes `receiver.json` when it exits. Copy it to the
machine holding `a-to-b.json`, then run:

```sh
tunnelscope correlate a-to-b.json receiver.json --output correlation.json
```

`correlation.json` has one row per sender attempt. `receiver_observed: true`
confirms that the matching payload arrived at this receiver. A timeout with
`receiver_observed: true` narrows the investigation toward acknowledgement
transmission or return delivery, but does not identify which failed. A successful
acknowledgement send call only confirms that the local socket accepted it.

`receiver_observed: false` is inconclusive unless the receiver was running for
the full probe period and its report is complete. A packet may have been lost,
filtered, sent to another endpoint or missed because capture started late.
`unmatched_receiver_observations` counts valid probes seen by the receiver that
were not present in the sender file. It can reveal a mixed or incorrect pairing.

`pairing.run_id_check` is `matched` when the receiver observed only this sender
run, or `matched_with_other_runs` when the receiver file also contains probes
from another run. The terminal view shows unmatched receiver observations to
make mixed captures easier to spot. The command rejects a receiver file
containing only observations from another run. An empty receiver file cannot
establish which run it covered and is marked
`unverified_no_receiver_observations`. `pairing.endpoint_checks` compares the
target port and, unless the receiver bound to `0.0.0.0`, the target IPv4 address.
Mismatches need review; address translation can legitimately change them.
The two UTC capture windows and the receiver's `exit_reason` help review
coverage, but the command does not compare clocks across hosts because they
may be unsynchronized.

The reports are unauthenticated. Use them only in a controlled environment and
pair the files from the same run. Reports created before v0.2 do not contain
probe IDs and cannot be correlated. v0.2 reports can still be correlated by
probe ID, but their run ID check is unavailable. Receiver observation is complementary to
running probes in the reverse direction; it does not replace that test.
