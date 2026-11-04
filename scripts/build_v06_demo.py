"""Build a 40-second replay from sanitized v0.6 lab evidence and HTML captures.

Requires Pillow. This is an editorial replay of recorded reports, not a live
terminal/network capture. The correlate command is rerun during each build.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap

from PIL import Image, ImageDraw, ImageFont, ImageOps


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/images/v06-workflow-demo.gif"
PREVIEW = ROOT / "output/promo-v06"
SIZE = (1280, 760)
BG, PANEL, WHITE, MUTED = "#090f22", "#101b35", "#eef4ff", "#aec2dd"
BLUE, GREEN, AMBER = "#78b0ff", "#63e2af", "#ffd083"


def font(size, bold=False):
    files = [Path("C:/Windows/Fonts/" + ("consolab.ttf" if bold else "consola.ttf")),
             Path("/usr/share/fonts/truetype/dejavu/" +
                  ("DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"))]
    for path in files:
        if path.exists():
            return ImageFont.truetype(str(path), size)
    raise RuntimeError("Install Consolas or DejaVu Sans Mono to render readable frames")


def base(title, chapter):
    image = Image.new("RGB", SIZE, BG)
    draw = ImageDraw.Draw(image)
    draw.text((36, 24), "TunnelScope v0.6", fill=BLUE, font=font(32, True))
    draw.text((36, 76), title, fill=WHITE, font=font(26, True))
    badge = f"{chapter}/6  |  recorded lab replay"
    draw.text((SIZE[0] - 36 - draw.textlength(badge, font=font(17)), 36), badge,
              fill=MUTED, font=font(17))
    draw.rounded_rectangle((32, 133, 1248, 694), radius=14, fill=PANEL, outline="#395681", width=2)
    draw.text((36, 718), "Sanitized captured evidence | playback paced for reading | not a live capture",
              fill=MUTED, font=font(17))
    return image


def terminal(title, chapter, command, lines, note=None):
    image = base(title, chapter)
    draw = ImageDraw.Draw(image)
    y = 158
    for line in textwrap.wrap(command, width=94, subsequent_indent="  ", break_long_words=False):
        draw.text((54, y), line, fill=GREEN, font=font(20))
        y += 28
    y += 18
    for line in lines:
        if draw.textlength(line, font=font(22)) > 1168:
            raise RuntimeError(f"Demo line too wide: {line}")
        if y + 27 > 638:
            raise RuntimeError("Demo output exceeds frame height")
        color = AMBER if any(word in line for word in ("packet_too_large", "inconclusive", "local error")) else WHITE
        draw.text((54, y), line, fill=color, font=font(22))
        y += 31
    if note:
        for index, line in enumerate(textwrap.wrap(note, width=108)):
            draw.text((54, 648 + index * 21), line, fill=MUTED, font=font(17))
    return image


def browser_frame(path, title):
    image = base(title, 5)
    screenshot = Image.open(path).convert("RGB")
    screenshot = ImageOps.contain(screenshot, (1208, 545))
    image.paste(screenshot, ((SIZE[0] - screenshot.width) // 2, 141))
    return image


def main():
    diagnosis_path = ROOT / "examples/diagnosis-v06.json"
    receiver_path = ROOT / "examples/receiver-v06.json"
    diagnosis = json.loads(diagnosis_path.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="ts-v06-replay-") as directory:
        joined_path = Path(directory) / "joined.json"
        subprocess.run([sys.executable, str(ROOT / "tunnelscope.py"), "correlate",
                        str(diagnosis_path), str(receiver_path), "--output", str(joined_path),
                        "--html", str(Path(directory) / "joined.html")],
                       check=True, capture_output=True, text=True)
        joined = json.loads(joined_path.read_text(encoding="utf-8"))
    assert diagnosis["summary"]["search"]["observed_interval_payload_bytes"] == [1252, 1253]
    assert joined["receiver_evidence"]["summary"]["receiver_observed"] == 4
    events = [event for row in diagnosis["runs"]["fragmentation_comparison"]["runs"]["df"]["results"]
              for event in row.get("icmp_observation", {}).get("events", [])
              if event.get("origin") == "icmpv4" and event.get("quoted_probe_match") is True]
    assert events and events[0]["reported_mtu_bytes"] == 1280
    intro = terminal("Diagnose, join the receiver log, inspect HTML", 1, "Captured controlled WireGuard case", [
        "Sender link 1500 -> WireGuard 1420 -> receiver LAN 1280",
        "",
        "1. Retain DF, fragmentation-permitted and search runs",
        "2. Match both endpoint logs by run ID and probe ID",
        "3. Browse the generated offline HTML report",
        "",
        "The observed interval belongs to this controlled path.",
    ])
    command = "$ tunnelscope diagnose 198.51.100.2 --min 1252 --max 1253 --count 1 --max-sizes 2 --output diagnosis.json"
    sender_lines = ["Selected evidence from the captured diagnosis:", "",
        "Run                         1252 bytes       1253 bytes",
        "DF                          acknowledged     packet_too_large",
        "fragmentation_permitted     acknowledged     acknowledged",
        "size_search                 acknowledged     packet_too_large", "",
        "Observed interval: 1252..1253 UDP payload bytes",
        "Scope: one sender direction; six attempts retained"]
    feedback = terminal("Keep routed feedback separate from local errors", 3, "Evidence retained in diagnosis.json", [
        "ICMPv4 fragmentation-needed: type 3 / code 4",
        "Reported MTU: 1280 bytes",
        "Quoted probe token: matched",
        "Initial sender interface MTU: 1500 bytes", "",
        "Later search size error: local (after PMTU cache update)",
        "No ACK or absent ICMP on an unknown path stays inconclusive.",
    ])
    join_command = "$ tunnelscope correlate diagnosis.json receiver.json --output joined.json --html joined.html"
    correlations = joined["receiver_evidence"]["correlations"]
    join_lines = ["Selected fields from the generated joined.json:", "",
                  "Run                          Receiver saw     Run ID"]
    for name in ("df", "fragmentation_permitted", "size_search"):
        item = correlations[name]
        seen, total = item["summary"]["receiver_observed"], item["summary"]["sent_probes"]
        join_lines.append(f"{name:<28} {seen}/{total:<14} {item['pairing']['run_id_check']}")
    join_lines += ["", "Total: four matching arrivals, two explicit size errors",
                   "Unmatched or other-run receiver observations: zero"]
    ending = terminal("Try the workflow with a controlled receiver", 6,
                      "$ python -m pip install tunnelscope==0.6.0", [
        "Guides: docs/diagnose.md and docs/demo-v06.md", "",
        "Validated: routed WireGuard and cross-node Calico pods",
        "Recorded environments and limitations are documented.", "",
        "Missing ACKs remain inconclusive.",
    ])
    frames, durations = [intro], [4000]
    for fraction, duration in ((0.35, 600), (0.7, 600), (1, 800)):
        frames.append(terminal("1. Replay the captured sender workflow", 2, command[:int(len(command) * fraction)], []))
        durations.append(duration)
    frames.append(terminal("1. Replay the captured sender workflow", 2, command, sender_lines))
    durations.append(7000)
    frames.append(feedback)
    durations.append(6000)
    for fraction, duration in ((0.4, 500), (0.75, 500), (1, 1000)):
        frames.append(terminal("2. Join the receiver capture", 4, join_command[:int(len(join_command) * fraction)], []))
        durations.append(duration)
    frames.append(terminal("2. Join the receiver capture", 4, join_command, join_lines))
    durations.append(6000)
    frames.append(browser_frame(ROOT / "docs/images/v06-report.jpg", "3. Inspect the actual generated HTML report"))
    durations.append(4000)
    frames.append(browser_frame(ROOT / "docs/images/v06-report-filtered.jpg", "3. Filter the report to 1253-byte attempts"))
    durations.append(5000)
    frames.append(ending)
    durations.append(4000)
    assert sum(durations) == 40000
    palette_frames = [image.convert("P", palette=Image.Palette.ADAPTIVE, colors=192) for image in frames]
    palette_frames[0].save(OUT, save_all=True, append_images=palette_frames[1:],
                           duration=durations, loop=0, optimize=True, disposal=2)
    PREVIEW.mkdir(parents=True, exist_ok=True)
    selected = [intro, frames[4], feedback, frames[9], frames[11], ending]
    contact = Image.new("RGB", (1280, 1140), BG)
    for index, image in enumerate(selected):
        contact.paste(image.resize((640, 380)), ((index % 2) * 640, (index // 2) * 380))
    contact.save(PREVIEW / "contact-sheet.png")
    with Image.open(OUT) as gif:
        actual_ms = 0
        for index in range(gif.n_frames):
            gif.seek(index)
            actual_ms += gif.info["duration"]
        assert actual_ms == 40000
    print(f"{OUT}: 40 seconds, {OUT.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
