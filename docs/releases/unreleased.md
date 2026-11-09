# Unreleased

Changes on `main` since [v0.9.6](v0.9.6.md). They are not on PyPI yet. When
the next version is prepared, rename this file to that version and start a new
empty one.

There is no wire-protocol or JSON schema change so far.

## Windows receiver no longer stops on unrelated receive errors

Windows reports an ICMP port unreachable for an earlier reply as
`WSAECONNRESET` (10054) on the receiver's next `recvfrom`. A late ACK to a
probe socket that had already timed out was enough to stop the receiver with
`exit_reason: socket_error`. Every later probe then had no receiver entry, which
looks like loss on the path. The receiver now skips that notice on Windows and
does not count it toward `--max-packets` (#76).

Windows also fails `recvfrom` with `WSAEMSGSIZE` (10040) when a datagram is
larger than the 8193-byte buffer, where Linux truncates it. One stray large
datagram stopped a Windows receiver. It is now counted and skipped, as on
Linux (#77). Other receive errors still stop the receiver.

## Port unreachable is named

A probe to a port with nothing listening came back as a bare `socket_error`
with the OS message. For connection-refused errno values (111 and 61 on Linux
and macOS, 10054 and 10061 on Windows), `show` now adds a line saying no
receiver was likely listening, and that a firewall can send the same answer.
`probe` prints a short note on stderr so stdout stays JSON (#78).

## Clearer errors

A host name that does not resolve now says which name and address family
failed, instead of `[Errno 11001] getaddrinfo failed`. An address literal used
with the other `--family`, such as `::1 --family ipv4`, also gets the fix in the
message.

Hand-edited or truncated reports with a non-string probe ID in a lab case, or a
non-integer status count, now fail with `Error: ...` instead of a Python
traceback. These were found by mutating every field of the example reports.

## Docs

The [two-endpoint guide](../bidirectional.md) now covers opening UDP 9471 to
the sender only (ufw, firewalld, Windows) and reading a run where nothing comes
back (#79).
