#!/usr/bin/env python3
"""Generate assets/social-preview.png (1280x640, GitHub social preview).

Run from the repo root:

    pip install Pillow
    python3 scripts/gen-social-preview.py

Upload the result manually: Settings -> General -> Social preview.
Requires the DejaVu fonts (Debian/Ubuntu: apt-get install fonts-dejavu);
adjust FONT_DIR below for other platforms.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640

# Catppuccin Mocha palette, matching assets/demo.tape
BASE = "#1e1e2e"
MANTLE = "#11111b"
TEXT = "#cdd6f4"
SUBTEXT = "#a6adc8"
GREEN = "#a6e3a1"
RED = "#f38ba8"
BLUE = "#89b4fa"
OVERLAY = "#313244"

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_DIR / name), size)


def main() -> None:
    img = Image.new("RGB", (W, H), BASE)
    d = ImageDraw.Draw(img)

    # Title and tagline
    d.text((64, 48), "ptuf", font=font("DejaVuSans-Bold.ttf", 110), fill=TEXT)
    d.text(
        (64, 196),
        "Deterministic guardrails for coding agents",
        font=font("DejaVuSans.ttf", 42),
        fill=SUBTEXT,
    )
    d.text(
        (64, 256),
        "Claude Code · Codex · Copilot · Kiro · Cline · Cursor",
        font=font("DejaVuSans.ttf", 28),
        fill=SUBTEXT,
    )

    # Terminal card
    card = (64, 320, W - 64, H - 24)
    d.rounded_rectangle(card, radius=18, fill=MANTLE, outline=OVERLAY, width=2)
    for i, dot in enumerate(("#f38ba8", "#f9e2af", "#a6e3a1")):
        cx = card[0] + 34 + i * 34
        d.ellipse((cx - 9, card[1] + 25, cx + 9, card[1] + 43), fill=dot)

    mono = font("DejaVuSansMono.ttf", 27)
    mono_b = font("DejaVuSansMono-Bold.ttf", 27)
    x, y = card[0] + 34, card[1] + 66
    lh = 42

    def line(parts: list[tuple[str, str, ImageFont.FreeTypeFont]]) -> None:
        nonlocal y
        cx = x
        for text, color, f in parts:
            d.text((cx, y), text, font=f, fill=color)
            cx += d.textlength(text, font=f)
        y += lh

    line([("$ ", GREEN, mono_b), ("ptuf check --tool Bash 'rm -rf /'", TEXT, mono)])
    line([("Decision: ", TEXT, mono), ("deny", RED, mono_b)])
    line([("Rule: ", TEXT, mono), ("core.filesystem.destructive-rm", BLUE, mono)])
    y += 10
    line([("$ ", GREEN, mono_b), ("ptuf check --tool Bash 'ls'", TEXT, mono)])
    line([("Decision: ", TEXT, mono), ("allow", GREEN, mono_b)])

    out = Path("assets/social-preview.png")
    img.save(out)
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
