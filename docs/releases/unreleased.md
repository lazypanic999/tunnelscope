# Unreleased

Changes on `main` since [v0.9.6](v0.9.6.md). They are not on PyPI yet. When
the next version is prepared, rename this file to that version and start a new
empty one. Also search the docs for "after v0.9.6" and drop those qualifiers,
and update the version in the README install line.

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

Ctrl+C did not interrupt a waiting Windows receiver: Windows does not wake a
blocking socket wait for it, so the capture was saved only when the idle
timeout ran out (up to 120 seconds with the field-report settings). On Windows
the receiver now waits in 0.25-second slices against its own idle deadline, so
Ctrl+C saves the capture within a fraction of a second.
A second Ctrl+C while the capture is being written no longer loses it: the
receiver finishes the write and then exits as interrupted.

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

`correlate` and `combine` now say what each input file actually is when the
kinds are wrong, and `correlate` recognises the receiver and sender reports
given in the wrong order.

## Receiver shows probes as they arrive

`tunnelscope receive` prints one line per accepted probe with its size, source,
run and probe ID prefixes, and whether the reply send succeeded. This makes a
firewall or address mistake obvious during the run instead of after it.
With `--output`, it also says where the capture will be saved and that one
Ctrl+C stops early, and prints `Saved receiver.json: N probes; exit: ...` once
the file is written, so it is clear when the file is safe to copy.
`--quiet` turns it off. Calling `receive()` from Python stays quiet by default.

The sender commands (`probe`, `search`, `compare-fragmentation`, `diagnose`)
print one line per attempt on stderr with the size, attempt number, mode and
outcome. Stdout stays JSON. `--quiet` turns these off too.

## Testing

CI now runs on Python 3.14 as well (#81). A mutation test breaks every field
of the example reports one at a time and requires a clean error (#85).

## Docs

The [two-endpoint guide](../bidirectional.md) now covers opening UDP 9471 to
the sender only (ufw, firewalld, Windows) and reading a run where nothing comes
back (#79).
