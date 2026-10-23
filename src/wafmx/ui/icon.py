"""Generate the tray/window icon in code so no binary assets live in the repo."""

from __future__ import annotations

from PIL import Image, ImageDraw


def make_icon(size: int = 64, state: str = "idle") -> Image.Image:
    colors = {"idle": "#2563eb", "busy": "#d97706", "off": "#64748b"}
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size
    d.rounded_rectangle((s * 0.06, s * 0.06, s * 0.94, s * 0.94), radius=s * 0.2, fill=colors.get(state, colors["idle"]))
    # a simple shield outline with a crosshair-like "detect" mark
    w = max(2, s // 14)
    d.polygon([(s * 0.5, s * 0.18), (s * 0.78, s * 0.3), (s * 0.74, s * 0.58), (s * 0.5, s * 0.82), (s * 0.26, s * 0.58), (s * 0.22, s * 0.3)], outline="white", width=w)
    d.line((s * 0.5, s * 0.34, s * 0.5, s * 0.64), fill="white", width=w)
    d.line((s * 0.36, s * 0.49, s * 0.64, s * 0.49), fill="white", width=w)
    return img


def save_ico(path: str) -> None:
    base = make_icon(256)
    base.save(path, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
