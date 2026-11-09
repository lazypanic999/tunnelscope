# Windows PowerShell loopback quick start

Use Python 3.10 or newer and PowerShell to try ordinary UDP delivery on one
Windows machine. This example does not measure path MTU or validate Linux
fragmentation behavior. `--dont-fragment` and the network-namespace labs require
Linux or WSL2; do not add those options to this Windows example.

## Install

In an empty working directory, create a virtual environment with the Windows
Python launcher and install the published package:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install tunnelscope
.\.venv\Scripts\tunnelscope.exe --help
```

Check that `py -3 --version` reports Python 3.10 or newer. All commands use
the environment executables directly; activation and PowerShell execution-policy
changes are unnecessary.

## Send and receive

Open two PowerShell terminals in that same working directory. In terminal 1:

```powershell
.\.venv\Scripts\tunnelscope.exe receive --max-packets 2 --output receiver.json
```

Wait for `Listening on 127.0.0.1:9471`, then run in terminal 2:

```powershell
.\.venv\Scripts\tunnelscope.exe probe 127.0.0.1 --sizes 64,1200 --count 1 --output probe.json
```

Each terminal prints a line per probe as it goes (from releases after v0.9.6).
The receiver exits after two probes and writes `receiver.json`. If it does not
exit, stop it with Ctrl+C before inspecting its saved report. A timeout means
that no matching acknowledgement arrived; it does not establish an MTU problem.

## Inspect the reports

After the receiver exits, run in either terminal:

```powershell
.\.venv\Scripts\tunnelscope.exe show probe.json
.\.venv\Scripts\tunnelscope.exe html probe.json --output probe.html
.\.venv\Scripts\tunnelscope.exe correlate probe.json receiver.json --output correlation.json
.\.venv\Scripts\tunnelscope.exe show correlation.json
```

Open `probe.html` in your browser for the offline view. With successful local
delivery, both payload sizes are `acknowledged` and the correlation shows `2/2`
observed at the receiver with a matched run ID. The JSON files are also readable
in a text editor.

A receiver observation confirms forward arrival. A sender acknowledgement means
a small reply also returned; it does not prove delivery of an equally large
reverse payload. Loopback success does not validate a remote path, PMTU, or
Linux-specific options. See [receiver correlation](receiver-observations.md) for
the evidence limits and [the two-endpoint guide](bidirectional.md) for remote
experiments.
