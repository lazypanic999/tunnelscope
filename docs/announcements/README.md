# Outreach record

## v0.9.5 publication — 2026-11-08

Published [A small ACK can hide a failed return path: collecting both endpoint logs](https://dev.to/lazypanic999/a-small-ack-can-hide-a-failed-return-path-collecting-both-endpoint-logs-9d7)
on DEV after the v0.9.5 PyPI publication succeeded and a fresh install from
PyPI passed the installed-package workflow checks. The existing unpublished
v0.7 draft was updated in place before publishing; it was not published as a
separate stale-version post. The DEV page is marked **Fully Autonomous** and
uses `networking`, `linux`, `python` and `opensource` tags.

`dev-v0.9.5-draft.md` records the pre-publication team draft. The final editor
body was revised to distinguish missing receiver evidence from proven
non-arrival, socket send acceptance from delivery, and local workflow checks
from independent VPN evidence. It also explicitly identifies the Linux/WSL2
shell example and links the native Windows guide. The public page is the
canonical final copy.

A single [maintainer update in r/Python's weekly project thread](https://www.reddit.com/r/Python/comments/1xqknnl/comment/19sc5zlflu0zm/)
was posted from `u/Lazy_Panic_7016`, with AI-assistance and maintainer
affiliation disclosed. The community's no-showcase rule directs project
sharing to its monthly showcase or daily threads; the Sunday thread explicitly
invites project links and feedback. No standalone showcase post or repeated
cross-post was made.

Both publications request feedback on the field-report workflow and reviewed,
sanitized evidence from permitted two-host VPN paths. They do not claim
independent production validation or guaranteed anonymization. Issue #2 stays
open until actual operator evidence is collected and reviewed.

## Historical v0.7 draft

`dev-v0.7-draft.md` was the original draft for the DEV post
"Small ACKs hide one-way MTU problems: same-sized replies in TunnelScope v0.7".
It was saved on DEV as an **unpublished draft** on 2026-11-06 with the tags
`networking`, `linux`, `python` and `opensource`. The DEV editor takes the
title and tags in separate fields, so the front matter in the file was not
pasted; the body was pasted unchanged and the saved preview was checked for
the results table, four code blocks and the repository links. No cover image
is attached yet.

Every command in the post was run from a clean `pip install tunnelscope==0.7.0`
on Linux (WSL2) before saving the draft. This source is retained as a historical
draft; the updated v0.9.5 publication is recorded above.

## v0.6 update

`dev-v0.6-update.md` is the replacement body published on 2026-11-04 for the DEV post
[I built TunnelScope to inspect MTU and packet-size failures with evidence](https://dev.to/lazypanic999/i-built-tunnelscope-to-inspect-mtu-and-packet-size-failures-with-evidence-b4p),
article ID 4958640. The existing title, URL and comment thread were retained.
The public article was checked after saving, including the v0.6 update and
the loaded demo GIF. Paragraph wrapping was normalized for DEV's renderer.

Prepared on 2026-11-04 from the v0.6.0 release and the linked validation records.
The demo GIF is available from this repository and is embedded in the article.
The text distinguishes the two-VM, routed namespace and local Kubernetes cases.
