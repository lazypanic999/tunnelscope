# Security policy

TunnelScope is an alpha tool for controlled networks. Its UDP probe protocol
has no authentication or encryption. Do not expose its receiver to untrusted
networks or use reports containing private addresses without sanitizing them.
The receiver binds to loopback by default and, from v0.4.1, refuses wildcard
binds such as `0.0.0.0` and `::`. For two-host tests, bind to the
specific lab interface address and restrict UDP port 9471 to the intended
sender with network controls. An IP address or the probe's random ID does not
authenticate a peer. See [security boundaries](docs/security-boundaries.md)
for the complete operational limits.

Security fixes are considered for the latest published version. Older alpha
versions are not guaranteed to receive fixes.

If you find a vulnerability, use GitHub's private vulnerability reporting on
the repository Security tab if it is available. If it is not available, open a
public issue asking for a private contact channel **without describing the
vulnerability or including exploit details**. The maintainer can then arrange
a private report. Please allow time for a response before public disclosure.
