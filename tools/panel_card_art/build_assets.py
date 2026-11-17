"""Turn the Blender renders into the WebP sprites the panel card loads.

    python3 build_assets.py <renders dir> <output dir> [geometry.json]

Needs Pillow and the `cwebp` encoder. See README.md in this folder.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

from PIL import Image

TILE_PPI = 200
NINE_PPI = 150
FEATHER = 8  # px over which a tile fades into the dead front around it
SHADOW = 0.8  # strength of the shadow a breaker casts on the space below


def load(path):
    return Image.open(path).convert("RGBA")


def clean_alpha(im, floor=6):
    """Drop the faint alpha noise a shadow catcher leaves behind."""
    r, g, b, a = im.split()
    a = a.point(lambda v: 0 if v < floor else v)
    return Image.merge("RGBA", (r, g, b, a))


def scale_alpha(im, box, ramp):
    """Multiply alpha inside `box` by `ramp(x, y)` (0..1)."""
    px = im.load()
    x0, y0, x1, y1 = box
    for y in range(y0, y1):
        for x in range(x0, x1):
            f = ramp(x, y)
            if f >= 1:
                continue
            r, g, b, a = px[x, y]
            px[x, y] = (r, g, b, int(a * max(0.0, f)))


def feather(im, left=False, right=False, top=False, bottom=False, y1=None):
    """Fade the named edges to transparent so the piece blends into its surroundings."""
    w, h = im.size
    y1 = h if y1 is None else y1
    if left:
        scale_alpha(im, (0, 0, FEATHER, y1), lambda x, y: (x + 0.5) / FEATHER)
    if right:
        scale_alpha(im, (w - FEATHER, 0, w, y1), lambda x, y: (w - x - 0.5) / FEATHER)
    if top:
        scale_alpha(im, (0, 0, w, FEATHER), lambda x, y: (y + 0.5) / FEATHER)
    if bottom:
        scale_alpha(im, (0, y1 - FEATHER, w, y1), lambda x, y: (y1 - y - 0.5) / FEATHER)
    return im


def tile(im, geo):
    """A breaker or filler: opaque over its own space, shadow-only in the strip below."""
    im = clean_alpha(im)
    w, h = im.size
    over = round(geo["overflow"] * TILE_PPI)
    rows_px = h - over
    margin = round((geo["tile_m"] + geo["slot_pad"] + 0.012) * TILE_PPI)
    px = im.load()
    for y in range(rows_px, h):  # below the space: only the shadow that falls on the next breaker
        for x in range(w):
            r, g, b, a = px[x, y]
            if x < margin or x >= w - margin or max(r, g, b) > 96:
                a = 0  # dead front, or light bounced onto the catcher rather than shadow
            # The shadow was caught on a flat surface; whatever sits below is
            # partly raised into the light, so it lands a little lighter.
            px[x, y] = (0, 0, 0, round(a * SHADOW))
    return feather(im, left=True, right=True, y1=rows_px)


def nine_slice(im, slice_px):
    """Make the stretched bands of a nine-slice perfectly even along their length."""
    im = im.copy()
    w, h = im.size
    px = im.load()
    a, b = slice_px, w - slice_px
    c, d = slice_px, h - slice_px

    def mean(points):
        n = len(points)
        return tuple(round(sum(p[i] for p in points) / n) for i in range(4))

    for y in list(range(0, c)) + list(range(d, h)):  # top and bottom bands
        m = mean([px[x, y] for x in range(a, b)])
        for x in range(a, b):
            px[x, y] = m
    for x in list(range(0, a)) + list(range(b, w)):  # left and right bands
        m = mean([px[x, y] for y in range(c, d)])
        for y in range(c, d):
            px[x, y] = m
    m = mean([px[x, y] for x in range(a, b) for y in range(c, d)])
    for x in range(a, b):
        for y in range(c, d):
            px[x, y] = m
    return im, m


def save_webp(im, path, lossless=False, quality=88):
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        im.save(tmp.name)
    args = ["cwebp", "-quiet", "-mt"]
    args += ["-lossless", "-z", "9", "-exact"] if lossless else ["-q", str(quality), "-alpha_q", "100", "-m", "6", "-sharp_yuv"]
    subprocess.run(args + [tmp.name, "-o", path], check=True)
    os.unlink(tmp.name)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    geo = json.load(open(sys.argv[3] if len(sys.argv) > 3 else os.path.join(src, "geometry.json")))
    os.makedirs(dst, exist_ok=True)
    report = {}
    names = sorted(n[:-4] for n in os.listdir(src) if n.endswith(".png"))
    for name in names:
        im = load(os.path.join(src, name + ".png"))
        lossless = False
        if name.startswith(("bk-", "fill-")):
            im = tile(im, geo)
        elif name.startswith("cap-"):
            im = feather(im, left=True, right=True, top=name.endswith("top"), bottom=name.endswith("bot"))
        elif name.startswith("main-"):
            im = feather(im, left=True, right=True, top=True, bottom=True)
        elif name == "frame":
            im, flat = nine_slice(im, round(geo["frame_slice"] * NINE_PPI))
            report["field"] = flat[:3]
            report["cover_at_frame"] = im.getpixel((2, im.height // 2))[:3]
            lossless = True
        elif name == "cover":
            im, flat = nine_slice(im, round(geo["cover_slice"] * NINE_PPI))
            report["cover"] = flat[:3]
            lossless = True
        else:  # screws, hero shots
            im = clean_alpha(im)
        out = os.path.join(dst, name + ".webp")
        save_webp(im, out, lossless=lossless)
        report.setdefault("sizes", {})[name] = [im.width, im.height, os.path.getsize(out)]
    digest = hashlib.sha256()
    for name in names:
        digest.update(open(os.path.join(dst, name + ".webp"), "rb").read())
    report["rev"] = digest.hexdigest()[:10]
    report["bytes"] = sum(v[2] for v in report["sizes"].values())
    json.dump(report, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
