"""Generate packaging/devils_eye.ico with zero dependencies.

Draws a dark disc with a glowing red eye — simple, recognisable at 16px.
ICO format: 32bpp BGRA entries (alpha-aware on Windows XP+).
"""

from __future__ import annotations

import math
import struct
from pathlib import Path

SIZES = (16, 24, 32, 48, 64)


def render(size: int) -> bytes:
    """Return bottom-up BGRA pixel rows for one size."""
    c = (size - 1) / 2.0
    r_outer = size / 2.0 - 0.5
    px = bytearray()
    for y in range(size):
        row = bytearray()
        for x in range(size):
            dx, dy = x - c, y - c
            dist = math.hypot(dx, dy)
            r, g, b, a = 0, 0, 0, 0
            if dist <= r_outer:
                # dark disc with subtle rim
                base = 24 if dist < r_outer - 1 else 52
                r, g, b, a = base, base + 4, base + 8, 255
                # eye lens (almond approximated by ellipse)
                ex = dx / (0.44 * r_outer)
                ey = dy / (0.24 * r_outer)
                if ex * ex + ey * ey <= 1.0:
                    r, g, b = 240, 238, 232                      # sclera
                    ir = math.hypot(dx, dy) / (0.17 * r_outer)
                    if ir <= 1.0:
                        r, g, b = 231, 76, 60                    # red iris
                        if math.hypot(dx, dy) / (0.075 * r_outer) <= 1.0:
                            r, g, b = 12, 12, 14                 # pupil
                # faint red glow at the rim
                glow = max(0.0, 1.0 - abs(dist - r_outer * 0.86) / (r_outer * 0.12))
                if glow > 0 and dist > r_outer * 0.7:
                    r = min(255, int(r + 120 * glow))
            row += bytes((b, g, r, a))
        px += bytes(row)
    return bytes(px)


def bmp_entry(size: int) -> bytes:
    pixels = render(size)
    header = struct.pack(
        "<IiiHHIIiiII",
        40,            # BITMAPINFOHEADER size
        size,          # width
        size * 2,      # height (XOR + AND mask)
        1,             # planes
        32,            # bpp
        0,             # no compression
        len(pixels),   # image size
        0, 0, 0, 0,
    )
    mask_len = ((size + 31) // 32) * 4 * size
    return header + pixels + b"\x00" * mask_len


def main() -> None:
    images = {s: bmp_entry(s) for s in SIZES}
    out = Path(__file__).resolve().parents[1] / "packaging" / "devils_eye.ico"
    out.parent.mkdir(parents=True, exist_ok=True)
    header = struct.pack("<HHH", 0, 1, len(images))
    directory = b""
    payload = b""
    offset = 6 + 16 * len(images)
    for size, data in images.items():
        directory += struct.pack(
            "<BBBBHHII",
            size % 256, size % 256, 0, 0, 1, 32, len(data), offset,
        )
        payload += data
        offset += len(data)
    out.write_bytes(header + directory + payload)
    print(f"wrote {out} ({out.stat().st_size} bytes, sizes {SIZES})")


if __name__ == "__main__":
    main()
