# Contributing to TunnelScope

Thanks for helping improve TunnelScope. The project is an early Python CLI for
controlled Linux network experiments. Open an issue before making a large
change so the scope and expected evidence are clear.

## Choose a task

Start with the [open good first issues](https://github.com/lazypanic999/tunnelscope/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22).
Each issue states its expected behavior and validation; local report or CI
tasks can be completed without a VPN lab. Comment on the issue before
starting so work is coordinated, and ask questions there if setup is unclear.
For a larger change, discuss the scope before implementing it.

Operators with two permitted endpoints can instead contribute a
[field report](docs/field-reports.md). A healthy path is useful too; remote
access, credentials and private captures are not required. These reports
remain separate from the project's controlled lab results.

## Report a problem

Include the TunnelScope version, Python version, OS, command line, expected
behavior and actual behavior. Attach a small, sanitized JSON report when useful; see
[docs/sanitize.md](docs/sanitize.md).
Do not post credentials, real packet captures or private network details.
To share evidence from a real VPN, overlay or routed path, follow the
[field report guide](docs/field-reports.md).
For a security issue, follow [SECURITY.md](SECURITY.md) instead.

## Make a change

The installed CLI and compatibility imports live in `tunnelscope.py`.
Implementation code is in `tunnelscope_core`: `network.py` handles probes and
the receiver, `reports.py` handles evidence and terminal output, `search.py`
selects bounded sizes, and `view.py` renders the offline HTML report. Keep
schema-version-1 reports readable when adding fields.
`tables.py` supplies observation tables to HTML and Markdown, while
`markdown.py` renders the bounded issue summary. `sanitize.py` handles batch
identifier replacement, and `timestamps.py` parses aware timestamps across
supported Python versions.
`_version.py` holds the runtime version; keep it equal to `[project].version`
in `pyproject.toml` when preparing a release. Report producer claims and
legacy compatibility are described in [docs/report-versions.md](docs/report-versions.md).

1. Fork the repository and create a branch.
2. Keep measurements separate from conclusions. A timeout alone must not be
   described as proof of an MTU problem.
3. Update documentation when CLI behavior or report fields change.
4. Run `python -m unittest discover -s tests -v` before opening a pull request.
   The network namespace tests require Linux, root, `iproute2`, and an explicit
   `TUNNELSCOPE_RUN_NETNS_TESTS=1` setting.
5. Explain what changed and include a reproducible test or validation record
   for new measurement behavior.

After changing package layout, assets or report rendering, install the package
and verify the installed distribution with isolated imports:

```sh
python -m pip install .
python -I scripts/check_installed.py
```

The CI matrix runs this offline workflow on both operating systems. It checks
version metadata, correlation, sanitization, text, Markdown and the packaged
HTML logo without relying on source files being importable from the checkout.
Retained CI lab reports also include a [provenance and hash manifest](docs/validation/ci-artifacts.md).

Changes to `main` go through pull requests and the required `Delivery checks`
result. That check depends on all delivery-test matrix jobs, so every supported
platform must pass. The branch must be up to date before merging. The rule
also applies to administrators, blocks force pushes and prevents deletion of
`main`. No second person's approving review is required for this solo-maintainer
workflow.

The active rule is stored in GitHub; [its configuration](.github/main-branch-protection.json)
records the settings for restoration. Keep the `Delivery checks` job name
stable when extending the test matrix. Once its conditions pass, maintainers
can merge their own pull requests.

Use a controlled lab for the unauthenticated UDP protocol. The repository uses
the MIT license; by submitting a contribution you agree that it can be
distributed under that license.
