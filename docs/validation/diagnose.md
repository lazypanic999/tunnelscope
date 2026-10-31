# Diagnose workflow validation

Validated on 31 October 2026 against the isolated Linux network namespace lab
in `labs/mtu_boundary.py`. The lab creates a direct IPv4 veth link with MTU
1280 in both directions, starts a cooperating receiver, and runs `diagnose`
with payload bounds 1252..1253, one attempt per size and two search sizes.

For each direction the JSON report contained the DF comparison run, the
fragmentation-permitted run and the adaptive search run. The reported search
assessment was `adjacent_observed_bounds` with interval `[1252, 1253]` UDP
payload bytes. The lab verified that both JSON and offline HTML files were
written and that the target check matched. The report deliberately labels its
scope as one sender direction; the lab invokes it separately in each
direction. This direct-link result is a controlled functional check, not a
real VPN or Kubernetes field validation.

Verification commands:

```sh
python -m unittest discover -s tests -q
TUNNELSCOPE_RUN_NETNS_TESTS=1 python3 -m unittest discover -s tests -q
```

The privileged command requires Linux root and `iproute2`. The automated
checks include an existing-output refusal before network activity, an
unsupported-platform rejection, budget validation, JSON/report rendering and
HTML escaping.
