# Contributing to TunnelScope

Thanks for helping improve TunnelScope. The project is an early Python CLI for
controlled Linux network experiments. Open an issue before making a large
change so the scope and expected evidence are clear.

## Report a problem

Include the TunnelScope version, Python version, OS, command line, expected
behavior and actual behavior. Attach a small, sanitized JSON report when useful.
Do not post credentials, real packet captures or private network details.
For a security issue, follow [SECURITY.md](SECURITY.md) instead.

## Make a change

1. Fork the repository and create a branch.
2. Keep measurements separate from conclusions. A timeout alone must not be
   described as proof of an MTU problem.
3. Update documentation when CLI behavior or report fields change.
4. Run `python -m unittest discover -s tests -v` before opening a pull request.
   The network namespace tests require Linux, root, `iproute2`, and an explicit
   `TUNNELSCOPE_RUN_NETNS_TESTS=1` setting.
5. Explain what changed and include a reproducible test or validation record
   for new measurement behavior.

Use a controlled lab for the unauthenticated UDP protocol. The repository uses
the MIT license; by submitting a contribution you agree that it can be
distributed under that license.
