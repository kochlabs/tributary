#!/usr/bin/env python3
"""Generate web-ready brand assets from the originals in this directory.

    python3 -I assets/brand/build.py        (or: make brand)

Writes to web/public/brand/ (served at /brand/...) and web/public/favicon.png.
"""
from pathlib import Path

from PIL import Image, ImageDraw

SRC = Path(__file__).resolve().parent
OUT = SRC.parent.parent / "web" / "public"
BRAND = OUT / "brand"


def light_variant(im: Image.Image) -> Image.Image:
    """Turn the dark navy parts white for use on dark backgrounds, keeping
    the blue and teal streams and the alpha channel."""
    im = im.convert("RGBA")
    px = []
    for r, g, b, a in im.getdata():
        # Navy (#012753, brightest channel ~83) is the only colour this dark.
        # It turns fully white; edges towards the blue stream (~170) ramp.
        dark = max(r, g, b)
        if dark < 150:
            t = 1.0 if dark <= 100 else (150 - dark) / 50
            r, g, b = (round(c + (255 - c) * t) for c in (r, g, b))
        px.append((r, g, b, a))
    out = Image.new("RGBA", im.size)
    out.putdata(px)
    return out


def fit_height(im: Image.Image, h: int) -> Image.Image:
    return im.resize((round(im.width * h / im.height), h), Image.LANCZOS)


def fit_width(im: Image.Image, w: int) -> Image.Image:
    return im.resize((w, round(im.height * w / im.width)), Image.LANCZOS)


def icon(mark: Image.Image, size: int, pad: float, radius: float) -> Image.Image:
    """The mark centred on a white rounded square (readable on any tab colour)."""
    tile = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(tile).rounded_rectangle((0, 0, size - 1, size - 1), radius=round(size * radius), fill=(255, 255, 255, 255))
    inner = round(size * (1 - 2 * pad))
    m = mark.copy()
    m.thumbnail((inner, inner), Image.LANCZOS)
    tile.alpha_composite(m, ((size - m.width) // 2, (size - m.height) // 2))
    return tile


def main() -> None:
    BRAND.mkdir(parents=True, exist_ok=True)
    mark = Image.open(SRC / "tributary-mark.png").convert("RGBA")
    word = Image.open(SRC / "tributary-word.png").convert("RGBA")
    bg = Image.open(SRC / "tributary-login-right-background.png").convert("RGB")

    # Displayed at up to 64 px tall: 2x for high-DPI screens.
    fit_height(mark, 128).save(BRAND / "mark.png", optimize=True)
    fit_height(light_variant(mark), 128).save(BRAND / "mark-light.png", optimize=True)
    # Wordmark displayed up to ~240 px wide.
    fit_width(word, 480).save(BRAND / "wordmark.png", optimize=True)
    fit_width(light_variant(word), 480).save(BRAND / "wordmark-light.png", optimize=True)
    # Login background: full panel height on large screens.
    bg.save(BRAND / "login-background.webp", quality=82, method=6)

    icon(mark, 64, 0.08, 0.2).save(OUT / "favicon.png", optimize=True)
    icon(mark, 180, 0.1, 0.0).save(BRAND / "apple-touch-icon.png", optimize=True)

    for f in sorted(BRAND.iterdir()) + [OUT / "favicon.png"]:
        print(f"{f.relative_to(OUT.parent.parent)}  {f.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
