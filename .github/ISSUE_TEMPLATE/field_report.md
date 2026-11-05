---
name: Field report
about: Share sanitized TunnelScope evidence from a real VPN, overlay or routed path
title: "field: "
labels: field-report
---

Thank you for testing a real path. Read docs/field-reports.md first. Test only
paths you are allowed to test, and attach only reports produced by
`tunnelscope sanitize`.

**TunnelScope version and OS on each endpoint**

**Path type**
<!-- For example: WireGuard site-to-site, IPsec, OpenVPN, Kubernetes with Cilium VXLAN, routed IPv6 -->

**What you know about the path**
<!-- Configured tunnel or interface MTUs, number of hops if known, whether ICMP is filtered. "Unknown" is fine. -->

**Commands you ran**
<!-- Paste the exact commands with addresses replaced by A_IP and B_IP. -->

**Sanitized reports**
<!-- Attach the files from `tunnelscope sanitize ... --output-dir shared`: diagnosis.json, receiver.json and correlation.json (HTML optional). -->

**What you observed independently**
<!-- Optional: ping/tracepath results, application symptoms, or what fixed the problem. Say what was measured and what is a guess. -->

- [ ] I am allowed to test this path.
- [ ] I ran `tunnelscope sanitize` and read the copies before attaching them.
