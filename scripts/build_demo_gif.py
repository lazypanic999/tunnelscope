"""Render a short illustration from the checked-in controlled-lab reports.

Install Pillow separately: python -m pip install Pillow
"""

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "images" / "mtu-evidence-demo.gif"
SIZE = (1000, 550)
BG = "#090f22"
CARD = "#101b35"
WHITE = "#e8f0ff"
MUTED = "#a6b8d4"
BLUE = "#6da8ff"
GREEN = "#5de1ac"
ORANGE = "#ffc46b"


def font(size, bold=False):
    candidates = (
        [Path("C:/Windows/Fonts/consolab.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf")]
        if bold else
        [Path("C:/Windows/Fonts/consola.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")]
    )
    for path in candidates:
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


F_TITLE = font(29, bold=True)
F_SUB = font(17)
F_CARD = font(19, bold=True)
F_ROW = font(18)
F_NOTE = font(16)


def read_rows():
    direct = json.loads((ROOT / "examples" / "mtu-boundary.json").read_text(encoding="utf-8"))
    blocked = json.loads((ROOT / "examples" / "pmtu-blackhole.json").read_text(encoding="utf-8"))
    return (
        [(row["payload_bytes"], row["status"]) for row in direct["directions"][0]["results"]],
        [(row["payload_bytes"], row["status"]) for row in blocked["probe"]["results"]],
    )


def draw_card(draw, x, title, subtitle, rows, count):
    draw.rounded_rectangle((x, 140, x + 445, 407), radius=16, fill=CARD, outline="#2d436d", width=2)
    draw.text((x + 22, 158), title, font=F_CARD, fill=WHITE)
    draw.text((x + 22, 189), subtitle, font=F_SUB, fill=MUTED)
    draw.line((x + 22, 224, x + 423, 224), fill="#344c75", width=2)
    for i, (payload, status) in enumerate(rows[:count]):
        y = 241 + i * 40
        draw.text((x + 22, y), f"{payload:>4} B", font=F_ROW, fill=WHITE)
        color = GREEN if status == "acknowledged" else ORANGE
        draw.text((x + 143, y), status, font=F_ROW, fill=color)


def frame(direct, blocked, count):
    image = Image.new("RGB", SIZE, BG)
    draw = ImageDraw.Draw(image)
    draw.text((40, 28), "TunnelScope", font=F_TITLE, fill=BLUE)
    draw.text((40, 78), "Same sizes, different evidence", font=F_TITLE, fill=WHITE)
    draw_card(draw, 40, "Direct 1280-byte link", "Local size error with DF", direct, count)
    draw_card(draw, 515, "Routed 1280-byte link", "ICMP feedback blocked in lab", blocked, count)
    if count == len(direct):
        draw.text((40, 434), "Explicit size error != timeout", font=F_CARD, fill=WHITE)
        draw.text((40, 466), "Timeouts on an unknown path remain inconclusive.", font=F_NOTE, fill=MUTED)
    else:
        draw.text((40, 447), "UDP payload bytes; receiver sends a small ACK", font=F_NOTE, fill=MUTED)
    draw.text((40, 517), "Illustration from checked-in lab reports | not a live capture", font=F_NOTE, fill=MUTED)
    return image


def main():
    direct, blocked = read_rows()
    if [size for size, _ in direct] != [size for size, _ in blocked]:
        raise ValueError("Lab reports have different payload-size grids")
    frames = [frame(direct, blocked, count) for count in range(1, len(direct) + 1)]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        OUT,
        save_all=True,
        append_images=frames[1:],
        duration=[850, 850, 850, 3200],
        loop=0,
        optimize=True,
    )
    print(OUT)


if __name__ == "__main__":
    main()
