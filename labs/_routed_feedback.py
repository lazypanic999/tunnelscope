"""Shared bounded receiver/probe capture for isolated routed-feedback labs."""

import json
from pathlib import Path
import selectors
import subprocess
import sys

from tunnelscope_core.reports import correlate_reports


def run_case(sender, destination, script, directory, label, *, target, sizes, family,
             search_maximum=1400, sized_reply=False, search=None):
    reply_options = ["--sized-reply"] if sized_reply else []
    receiver_path = Path(directory) / f"receiver-{label}.json"
    receiver = subprocess.Popen(
        ["ip", "netns", "exec", destination, sys.executable, "-u", script,
         "receive", "--bind", target, "--max-packets", "200", "--idle-timeout", "8",
         "--output", str(receiver_path), *reply_options],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(receiver.stdout, selectors.EVENT_READ)
            if not ready.select(timeout=5):
                raise RuntimeError("Receiver startup timed out")
        if not receiver.stdout.readline().startswith("Listening on"):
            raise RuntimeError("Receiver did not start")
        command = ["ip", "netns", "exec", sender, sys.executable, script]
        sent = subprocess.run(
            [*command, "probe", target, "--family", family, "--sizes", sizes,
             "--count", "1", "--timeout", "2", "--dont-fragment", "--observe-icmp", *reply_options],
            check=True, capture_output=True, text=True, timeout=15,
        )
        result = {"probe": json.loads(sent.stdout)}
        if search is True or (search is None and label == "blocked"):
            searched = subprocess.run(
                [*command, "search", target, "--family", family, "--min", "1200",
                 "--max", str(search_maximum), "--count", "1", "--timeout", "2", "--observe-icmp", *reply_options],
                check=True, capture_output=True, text=True, timeout=15,
            )
            result["search"] = json.loads(searched.stdout)
        if receiver.wait(timeout=12) != 0:
            raise RuntimeError(f"Receiver failed: {receiver.stderr.read()}")
        result["receiver"] = json.loads(receiver_path.read_text(encoding="utf-8"))
        result["correlation"] = correlate_reports(result["probe"], result["receiver"])
        if "search" in result:
            result["search_correlation"] = correlate_reports(result["search"], result["receiver"])
        return result
    finally:
        if receiver.poll() is None:
            receiver.terminate()
            try:
                receiver.wait(timeout=3)
            except subprocess.TimeoutExpired:
                receiver.kill()
                receiver.wait(timeout=3)
        receiver.stdout.close()
        receiver.stderr.close()
