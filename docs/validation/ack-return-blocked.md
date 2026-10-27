# Blocked acknowledgement return validation

Run the controlled lab as root on Linux with iproute2 and iptables:

```sh
sudo python3 labs/ack_return_blocked.py > ack-return-blocked.json
python3 tunnelscope.py show ack-return-blocked.json
```

The lab creates two temporary network namespaces on a 1500-byte direct link.
The receiver observes two UDP probes and sends small acknowledgements. A rule
in the sender namespace drops only incoming UDP packets from the receiver's
port. The lab changes no host firewall rule, route or interface and removes
the namespaces when it exits normally.

In the validated run, both 64- and 1400-byte probes timed out at the sender.
The receiver recorded both probes and both local acknowledgement sends. The
correlation reported `timed_out_but_receiver_observed: 2`, a matched run ID,
and zero unmatched receiver observations. The isolated firewall counted two
blocked acknowledgements.

This establishes the cause only inside the known lab topology. On an unknown
network, the same sender/receiver pattern narrows the investigation to the
acknowledgement path but does not identify a failing hop or rule. Forced
termination such as SIGKILL can prevent namespace cleanup.
