#!/usr/bin/env python3
"""Generate PWA icon derivatives from the source ``logo-icon.png``.

PWA install heuristic (Chrome/Edge desktop, Android Chrome, Brave)
requires 192/512 PNGs declared in the web app manifest. iOS Safari
also wants a 180x180 ``apple-touch-icon`` for Add-to-Home-Screen.

This script reads ``src/email_triage/web/static/logo-icon.png`` and
writes four derivatives next to it:

  * ``icon-192.png``           — 192x192 transparent (standard purpose)
  * ``icon-512.png``           — 512x512 transparent (standard purpose)
  * ``icon-512-maskable.png``  — 512x512, source composited at 80%
                                  on the brand background colour to
                                  satisfy Android's adaptive-icon
                                  safe-zone requirement (otherwise
                                  Android crops the round/squircle
                                  mask through the logo edges).
  * ``apple-touch-icon.png``   — 180x180 for iOS Add-to-Home-Screen.

The script is idempotent: running it twice produces byte-identical
output. Operator runs it once in dev when ``logo-icon.png`` changes
and commits the derivatives alongside the source.

Pillow is NOT a runtime dep — only this script needs it. Install
transiently with ``pip install Pillow`` (or ``dnf install
python3-pillow`` on Fedora-family hosts) before running. The
generated PNGs are checked into the repo so end users / CI never
need Pillow installed.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image

# Brand background — same as ``theme_color`` in manifest.webmanifest
# and the ``--bg`` token in style.css. Hex literal kept inline so this
# script has no runtime dependency on the rest of the codebase.
BRAND_BG = (0x13, 0x17, 0x1F, 0xFF)

# Maskable safe zone: Android crops to a 80%-of-canvas circle/squircle.
# Composite the source at 80% size centred on the brand background so
# the visible logo always lands inside the safe zone regardless of the
# launcher's mask shape.
MASKABLE_SCALE = 0.80


def _resize(src: Image.Image, size: int) -> Image.Image:
    return src.resize((size, size), Image.LANCZOS)


def _maskable(src: Image.Image, size: int = 512) -> Image.Image:
    """Source composited at 80% size on the brand background."""
    canvas = Image.new("RGBA", (size, size), BRAND_BG)
    inner = int(size * MASKABLE_SCALE)
    scaled = src.resize((inner, inner), Image.LANCZOS)
    offset = (size - inner) // 2
    # Use the scaled image's alpha as the paste mask so the source's
    # transparency carries through onto the brand background.
    canvas.paste(scaled, (offset, offset), scaled)
    return canvas


def main() -> None:
    here = Path(__file__).resolve().parent.parent
    static = here / "src" / "email_triage" / "web" / "static"
    source = static / "logo-icon.png"
    if not source.is_file():
        raise SystemExit(f"source missing: {source}")

    src = Image.open(source).convert("RGBA")

    derivatives = {
        "icon-192.png": _resize(src, 192),
        "icon-512.png": _resize(src, 512),
        "icon-512-maskable.png": _maskable(src, 512),
        "apple-touch-icon.png": _resize(src, 180),
    }

    for name, img in derivatives.items():
        out = static / name
        # ``optimize=True`` keeps the PNGs reproducible — same input,
        # same output bytes — so the commit diff stays empty when
        # nothing changed.
        img.save(out, "PNG", optimize=True)
        print(f"wrote {out.relative_to(here)} ({img.size[0]}x{img.size[1]})")


if __name__ == "__main__":
    main()
