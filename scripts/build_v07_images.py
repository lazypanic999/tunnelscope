"""Build the v0.7 README images from the recorded asymmetric return-path lab.

Inputs: examples/asymmetric-return-v07.json, the unedited JSON printed by
`sudo python3 labs/asymmetric_return.py`. Outputs:

- docs/images/v07-terminal.png: the real `tunnelscope show` output for that
  report, rendered as a terminal panel (text is not edited or reordered);
- docs/images/v07-report.png: a headless-browser screenshot of the real HTML
  produced by `tunnelscope html` for the lab's sized-reply probe run (the
  `probe` member of the same report, written out unchanged). The joined
  correlation table is too wide for one screenshot, so the terminal image
  shows it instead.

Requires Pillow and Microsoft Edge or Google Chrome. Set TUNNELSCOPE_BROWSER
to a browser executable to override the search.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from PIL import Image, ImageChops, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "examples/asymmetric-return-v07.json"
TERMINAL_OUT = ROOT / "docs/images/v07-terminal.png"
REPORT_OUT = ROOT / "docs/images/v07-report.png"
BG, PANEL, WHITE, MUTED, GREEN, BLUE = "#090f22", "#101b35", "#eef4ff", "#aec2dd", "#63e2af", "#78b0ff"
BROWSERS = (
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "/usr/bin/microsoft-edge", "/usr/bin/google-chrome", "/usr/bin/chromium",
)


def font(size, bold=False):
    for path in (Path("C:/Windows/Fonts/" + ("consolab.ttf" if bold else "consola.ttf")),
                 Path("/usr/share/fonts/truetype/dejavu/" +
                      ("DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"))):
        if path.exists():
            return ImageFont.truetype(str(path), size)
    raise RuntimeError("Install Consolas or DejaVu Sans Mono to render readable text")


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "tunnelscope.py"), *args], cwd=ROOT,
                          check=True, capture_output=True, text=True).stdout


def terminal_image(command, output):
    lines = output.rstrip("\n").splitlines()
    body, small = font(17), font(15)
    width = max(ImageDraw.Draw(Image.new("RGB", (1, 1))).textlength(line, font=body) for line in [command, *lines])
    size = (int(width) + 96, 24 * len(lines) + 150)
    image = Image.new("RGB", size, BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((16, 16, size[0] - 16, size[1] - 46), radius=12, fill=PANEL, outline="#395681", width=2)
    for index, colour in enumerate(("#ff6b6b", "#ffd083", GREEN)):
        draw.ellipse((36 + index * 22, 32, 48 + index * 22, 44), fill=colour)
    draw.text((48, 62), "$ " + command, fill=GREEN, font=body)
    for index, line in enumerate(lines):
        draw.text((48, 98 + 24 * index), line, fill=WHITE, font=body)
    draw.text((24, size[1] - 34), "Unedited output from the recorded asymmetric return-path lab "
              "(examples/asymmetric-return-v07.json)", fill=MUTED, font=small)
    return image


def browser():
    candidates = [os.environ.get("TUNNELSCOPE_BROWSER"), *BROWSERS,
                  shutil.which("msedge"), shutil.which("google-chrome"), shutil.which("chromium")]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise RuntimeError("Install Edge or Chrome, or set TUNNELSCOPE_BROWSER")


def report_image(html_path, work):
    shot = work / "report-full.png"
    subprocess.run([browser(), "--headless=new", "--disable-gpu", "--hide-scrollbars",
                    f"--user-data-dir={work / 'profile'}", "--window-size=1400,1400",
                    f"--screenshot={shot}", html_path.resolve().as_uri()],
                   check=True, capture_output=True, timeout=60)
    # msedge.exe can hand the work to another process and exit before the file exists.
    deadline = time.monotonic() + 60
    while not (shot.exists() and shot.stat().st_size > 0):
        if time.monotonic() > deadline:
            raise RuntimeError("the browser did not write a screenshot")
        time.sleep(0.5)
    time.sleep(1)
    image = Image.open(shot).convert("RGB")
    # Crop the empty page background below and beside the report.
    box = ImageChops.difference(image, Image.new("RGB", image.size, image.getpixel((2, 2)))).getbbox()
    if box:
        image = image.crop((max(box[0] - 24, 0), max(box[1] - 24, 0),
                            min(box[2] + 24, image.width), min(box[3] + 24, image.height)))
    framed = Image.new("RGB", (image.width + 32, image.height + 66), BG)
    framed.paste(image, (16, 16))
    ImageDraw.Draw(framed).text((24, image.height + 28),
                                "Screenshot of `tunnelscope html` for the lab's sized-reply probe run "
                                "(the `probe` member of examples/asymmetric-return-v07.json)",
                                fill=MUTED, font=font(15))
    return framed


def main():
    if not REPORT.exists():
        raise SystemExit(f"Missing {REPORT}; record it with labs/asymmetric_return.py first")
    command = "tunnelscope show examples/asymmetric-return-v07.json"
    terminal_image(command, cli("show", str(REPORT.relative_to(ROOT)))).save(TERMINAL_OUT, optimize=True)
    # The browser may keep its profile files open briefly after the screenshot.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
        work = Path(directory)
        probe_path, html_path = work / "probe.json", work / "report.html"
        probe = json.loads(REPORT.read_text(encoding="utf-8"))["probe"]
        probe_path.write_text(json.dumps(probe, indent=2), encoding="utf-8")
        cli("html", str(probe_path), "--output", str(html_path))
        report_image(html_path, work).save(REPORT_OUT, optimize=True)
    print(f"Wrote {TERMINAL_OUT.relative_to(ROOT)} and {REPORT_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
