"""Render the panel card's artwork and install it into the integration.

    python3 tools/panel_card_art/make_art.py            # render everything, then build
    python3 tools/panel_card_art/make_art.py --missing  # render only the pieces not rendered yet, then build
    python3 tools/panel_card_art/make_art.py --build    # rebuild the WebP files from existing renders

Needs Blender (4.2 or newer; set BLENDER to its executable if it isn't found),
Pillow, and the `cwebp` encoder. Renders go to tools/panel_card_art/renders
(ignored by git) unless LD_RENDERS names another folder; the finished images
go to custom_components/ldata/www/img and ART_REV in the card is updated to
match them.
"""

import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RENDERS = os.environ.get("LD_RENDERS") or os.path.join(HERE, "renders")
WWW = os.path.join(ROOT, "custom_components", "ldata", "www")
CARD = os.path.join(WWW, "ldata-panel-card.js")
STATES = ("on", "off", "trip")
# Smart breakers by protection: the letter used in file names, and the LEDs
# the face carries besides ON/OFF ("a" = AF, "g" = GF). Leviton makes AFCI and
# dual-function breakers as 1-pole units only.
SMART = (("s", ""), ("a", "a"), ("g", "g"), ("d", "ag"))
TWO_POLE = ("s", "g")


def faces():
    """Every breaker face that is drawn, as (poles, kind, code, protect)."""
    for poles in (1, 2):
        for code, protect in SMART:
            if poles == 1 or code in TWO_POLE:
                yield poles, "smart", code, protect
        yield poles, "std", "t", ""


def blender():
    for candidate in (
        os.environ.get("BLENDER"),
        shutil.which("blender"),
        "/Applications/Blender.app/Contents/MacOS/Blender",
    ):
        if candidate and os.path.exists(candidate):
            return candidate
    sys.exit("Blender not found. Set BLENDER to the path of its executable.")


def jobs():
    out = []
    for column, side in ((-1, "L"), (1, "R")):
        for poles, kind, code, protect in faces():
            for state in STATES:
                out.append({"job": "tile", "what": "breaker", "column": column, "poles": poles, "kind": kind, "protect": protect, "state": state, "name": f"bk-{side}{poles}{code}-{state}"})
        out.append({"job": "tile", "what": "filler", "column": column, "name": f"fill-{side}"})
        out.append({"job": "tile", "what": "cap_top", "column": column, "name": f"cap-{side}-top"})
        out.append({"job": "tile", "what": "cap_bottom", "column": column, "name": f"cap-{side}-bot"})
    out.append({"job": "frame", "ppi": 150, "samples": 256, "name": "frame"})
    out.append({"job": "cover", "ppi": 150, "samples": 256, "name": "cover"})
    out.append({"job": "screw", "angle": 25, "name": "screw-a"})
    out.append({"job": "screw", "angle": -62, "name": "screw-b"})
    for state in ("on", "off"):
        out.append({"job": "main", "state": state, "name": f"main-{state}"})
    for poles, kind, code, protect in faces():
        for state in STATES:
            out.append({"job": "hero", "poles": poles, "kind": kind, "protect": protect, "state": state, "ppi": 280, "samples": 160, "name": f"hero-{poles}{code}-{state}"})
    for job in out:
        job["out"] = os.path.join(RENDERS, job.pop("name") + ".png")
    return out


def render(missing_only=False):
    os.makedirs(RENDERS, exist_ok=True)
    job_file = os.path.join(RENDERS, "jobs.json")
    todo = [job for job in jobs() if not (missing_only and os.path.exists(job["out"]))]
    with open(job_file, "w") as fh:
        json.dump(todo, fh, indent=1)
    scene = os.path.join(HERE, "ld_scene.py")
    base = [blender(), "-b", "--factory-startup", "--python", scene, "--"]
    subprocess.run(base + ["--geometry", os.path.join(RENDERS, "geometry.json")], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(base + [job_file], check=True, stdout=subprocess.DEVNULL)


def build():
    report = subprocess.run(
        [sys.executable, os.path.join(HERE, "build_assets.py"), RENDERS, os.path.join(WWW, "img")],
        check=True,
        capture_output=True,
        text=True,
    )
    info = json.loads(report.stdout)
    with open(CARD) as fh:
        source = fh.read()
    updated, count = re.subn(r'const ART_REV = "[0-9a-f]*";', f'const ART_REV = "{info["rev"]}";', source)
    if count != 1:
        sys.exit("Could not find ART_REV in the card.")
    with open(CARD, "w") as fh:
        fh.write(updated)
    print(f'{len(info["sizes"])} images, {info["bytes"] / 1024:.0f} KB, ART_REV {info["rev"]}')
    print(f'flat colours: dead front {info["field"]}, cover {info["cover"]}')


if __name__ == "__main__":
    if "--build" not in sys.argv:
        render(missing_only="--missing" in sys.argv)
    build()
