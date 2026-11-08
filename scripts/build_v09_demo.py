"""Build a paced, selected-evidence replay of the recorded OpenVPN return lab.

Requires Pillow and Consolas or DejaVu Sans Mono. No browser, server or fresh
network measurements are used. The report-processing commands are rerun.
"""

import hashlib
from html import unescape
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap

from PIL import Image, ImageDraw, ImageFont, ImageOps

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "examples/openvpn-asymmetric-return-v09.json"
OUT = ROOT / "docs/images/v09-evidence-demo.gif"
PREVIEW = ROOT / "output/promo-v09"
SIZE = (1280, 760)
BG, PANEL, WHITE, MUTED = "#090f22", "#101b35", "#eef4ff", "#aec2dd"
BLUE, GREEN, AMBER = "#78b0ff", "#63e2af", "#ffd083"


def font(size, bold=False):
    for path in (Path("C:/Windows/Fonts/" + ("consolab.ttf" if bold else "consola.ttf")),
                 Path("/usr/share/fonts/truetype/dejavu/" +
                      ("DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"))):
        if path.exists():
            return ImageFont.truetype(str(path), size)
    raise RuntimeError("Install Consolas or DejaVu Sans Mono")


def cli(directory, *args):
    return subprocess.run([sys.executable, str(ROOT / "tunnelscope.py"), *args], cwd=directory,
                          env={**os.environ, "PYTHONIOENCODING": "utf-8"}, check=True,
                          capture_output=True, encoding="utf-8", timeout=15).stdout


def frame(title, chapter, command, lines, note):
    image = Image.new("RGB", SIZE, BG)
    draw = ImageDraw.Draw(image)
    draw.text((36, 24), "TunnelScope v0.9", fill=BLUE, font=font(32, True))
    badge = f"{chapter}/6 | selected recorded evidence"
    draw.text((SIZE[0] - 36 - draw.textlength(badge, font=font(17)), 36), badge,
              fill=MUTED, font=font(17))
    draw.text((36, 76), title, fill=WHITE, font=font(26, True))
    draw.rounded_rectangle((32, 133, 1248, 694), radius=14, fill=PANEL, outline="#395681", width=2)
    y = 158
    for line in textwrap.wrap(command, width=94, subsequent_indent="  ", break_long_words=False):
        draw.text((54, y), line, fill=GREEN, font=font(20))
        y += 28
    y += 18
    for line in lines:
        if draw.textlength(line, font=font(21)) > 1168 or y + 27 > 627:
            raise RuntimeError(f"Replay text does not fit: {line}")
        color = AMBER if any(word in line for word in ("timeout", "inconclusive", "missing", "failed")) else WHITE
        draw.text((54, y), line, fill=color, font=font(21))
        y += 31
    for index, line in enumerate(textwrap.wrap(note, width=110)):
        if index >= 2:
            raise RuntimeError("Replay note is too long")
        draw.text((54, 645 + index * 21), line, fill=MUTED, font=font(16))
    draw.text((36, 721), "Paced replay of a controlled OpenVPN/TUN lab on one kernel; not a live network capture",
              fill=MUTED, font=font(16))
    return image


def main():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    small, sized = (report["cases"][name] for name in ("small_ack", "sized_reply"))
    with tempfile.TemporaryDirectory(prefix="ts-v09-replay-") as directory:
        work = Path(directory)
        for name in ("probe", "receiver"):
            (work / f"{name}.json").write_text(json.dumps(sized[name], indent=2), encoding="utf-8")
        cli(work, "correlate", "probe.json", "receiver.json", "--output", "joined.json")
        joined = json.loads((work / "joined.json").read_text(encoding="utf-8"))
        (work / "shared").mkdir()
        cli(work, "sanitize", "probe.json", "receiver.json", "joined.json", "--output-dir", "shared")
        markdown = cli(work, "show", "shared/joined.json", "--format", "markdown")
        assert len(markdown) <= 24000 and "## Observations (4 of 4 rows)" in markdown
        assert "receiver_observed_sized_reply_missing" in unescape(markdown)
        assert "receiver_reply_send_failed" in unescape(markdown)
        assert [r["status"] for r in small["probe"]["results"]] == ["acknowledged"] * 4
        assert all(row["receiver_observed"] for row in small["correlation"]["results"])
        assert [r["return_status"] for r in sized["probe"]["results"]] == ["sized_reply_received"] * 2 + ["no_reply"] * 2
        assert all(row["receiver_observed"] for row in joined["results"])
        assert [(row["payload_bytes"], row["return_evidence"]) for row in joined["results"][2:]] == [
            (1253, "receiver_observed_sized_reply_missing"), (1300, "receiver_reply_send_failed")]
        search = sized["search"]["summary"]["search"]
        assert search["assessment"] == "inconclusive" and search["observed_interval_payload_bytes"] is None
        assert [(row["payload_bytes"], row["status"]) for row in sized["search"]["results"]] == [
            (1200, "acknowledged"), (1300, "timeout")]
        assert sized["search_correlation"]["summary"]["receiver_observed"] == 2

        baseline = ["UDP bytes   Sender status       Receiver saw", ""]
        baseline.extend(f"{row['payload_bytes']:<12}{row['status']:<20}yes" for row in small["probe"]["results"])
        returns = ["UDP bytes   Sender status       Same-sized return", ""]
        returns.extend(f"{row['payload_bytes']:<12}{row['status']:<20}{row['return_status']}"
                       for row in sized["probe"]["results"])
        joined_lines = ["Selected fields from the rerun correlation:", ""]
        for row in joined["results"][2:]:
            joined_lines.extend((f"{row['payload_bytes']} bytes: {row['return_evidence']}",
                                 f"  receiver saw: yes; local reply send: {row['ack_send_status']}"))
        frames = [
            frame("Small ACKs can hide a return-size problem", 1, "Recorded OpenVPN small-ACK baseline", baseline,
                  "Client TUN 1400; receiver LAN 1500; server return TUN egress deliberately reduced to 1280."),
            frame("Request replies of the probe's own size", 2, "Recorded probe --sized-reply results", returns,
                  "All four forward probes arrived. A sender timeout alone cannot locate a missing reply."),
            frame("Join both endpoints by probe ID", 3,
                  "$ tunnelscope correlate probe.json receiver.json --output joined.json", joined_lines,
                  "1253: local send accepted, reply absent. 1300: receiver send rejected after learned PMTU state."),
            frame("Keep an ambiguous search inconclusive", 4, "Recorded sized-reply size-search evidence", [
                "1200 bytes: acknowledged; receiver observed",
                "1300 bytes: timeout; receiver observed", "",
                f"Assessment: {search['assessment']}",
                "Observed interval: none", "No explicit sender size error establishes an upper bound."],
                "Known configured return egress is lab context, not automatic discovery of an unknown path MTU."),
            frame("Sanitize together, then share a bounded summary", 5,
                  "$ tunnelscope show shared/joined.json --format markdown > evidence.md", [
                "Generated Markdown: Observations (4 of 4 rows)",
                f"Report producer: {joined['tunnelscope_version']}",
                f"Sender input: {joined['input_versions']['probe']}",
                f"Receiver input: {joined['input_versions']['receiver']}", "",
                "Limits: 50 rows; 24,000 ASCII characters; escaped values.",
                "Review copies and attach full sanitized JSON."],
                "The exporter does not sanitize its input. Legacy versions remain unknown; metadata is not authentication."),
            frame("Try the release or choose a small starter task", 6,
                  "$ python -m pip install tunnelscope==0.9.0", [
                "github.com/lazypanic999/tunnelscope", "",
                "Replay this checked-in evidence without a live receiver.",
                "Fresh measurements need a cooperating, controlled endpoint.",
                "Missing ACKs and receiver entries remain inconclusive.",
                "Independent VPN and Windows cross-host reports are welcome."],
                "The recorded peers used temporary verified TLS; TunnelScope's own UDP protocol is unauthenticated."),
        ]
    PREVIEW.mkdir(parents=True, exist_ok=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    palette_frames = [image.quantize(colors=128) for image in frames]
    palette_frames[0].save(OUT, save_all=True, append_images=palette_frames[1:], duration=5000,
                           loop=0, optimize=True, disposal=2)
    sheet = Image.new("RGB", (1280, 1140), BG)
    for index, image in enumerate(frames):
        sheet.paste(ImageOps.contain(image, (640, 380)), ((index % 2) * 640, (index // 2) * 380))
        image.save(PREVIEW / f"frame-{index + 1}.png")
    sheet.save(PREVIEW / "contact-sheet.png")
    (PREVIEW / "evidence.md").write_text(markdown, encoding="ascii")
    manifest = {"input": str(REPORT.relative_to(ROOT)), "input_sha256": hashlib.sha256(REPORT.read_bytes()).hexdigest(),
                "renderer_version": joined["tunnelscope_version"],
                "gif_sha256": hashlib.sha256(OUT.read_bytes()).hexdigest(), "duration_seconds": 30,
                "interpretation": "Selected recorded evidence; local report commands rerun; no fresh network capture."}
    (PREVIEW / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUT.relative_to(ROOT)} and {PREVIEW.relative_to(ROOT)} (six frames, 30 seconds)")


if __name__ == "__main__":
    main()
