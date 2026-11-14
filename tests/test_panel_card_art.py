"""The panel card and the artwork it loads have to stay in step."""

import hashlib
import re
from pathlib import Path

WWW = Path(__file__).parent.parent / "custom_components" / "ldata" / "www"
CARD = (WWW / "ldata-panel-card.js").read_text()
IMAGES = sorted((WWW / "img").glob("*.webp"))

# The faces a breaker can be drawn with, by number of poles: "s" a standard
# smart breaker, "a" AFCI, "g" GFCI, "d" dual function, "t" not smart.
# Leviton makes AFCI and dual function breakers as 1-pole units only.
FACES = {"1": "sagdt", "2": "sgt"}


def _expected() -> set[str]:
    """Every image name the card can ask for."""
    names = {"cover", "frame", "screw-a", "screw-b", "main-on", "main-off"}
    for side in "LR":
        names |= {f"fill-{side}", f"cap-{side}-top", f"cap-{side}-bot"}
        for poles, faces in FACES.items():
            for face in faces:
                for state in ("on", "off", "trip"):
                    names.add(f"bk-{side}{poles}{face}-{state}")
    for poles, faces in FACES.items():
        for face in faces:
            for state in ("on", "off", "trip"):
                names.add(f"hero-{poles}{face}-{state}")
    return names


def test_every_image_the_card_requests_is_shipped() -> None:
    shipped = {path.stem for path in IMAGES}

    assert _expected() - shipped == set()
    # Nothing left behind from an earlier set of artwork either.
    assert shipped - _expected() == set()


def test_card_builds_image_names_the_way_the_files_are_named() -> None:
    # The card assembles these names from a breaker's side, poles, kind and
    # handle position; the templates below are what the files above follow.
    source = re.sub(r"\s+", "", CARD)
    for template in (
        "`bk-${el.code}-${s.handle}`",
        "art(`fill-${col}`)",
        "`hero-${s.poles}${s.face}-${s.handle||\"on\"}`",
        "`bk-${p.column===1?\"L\":\"R\"}${s.poles}${s.face}`",
        "art(`main-${v}`)",
        '["cover","frame","screw-a","screw-b"]',
        '"cap-L-top"',
        '"cap-R-bot"',
        'data-code="${col}${s.poles}${s.face}"',
    ):
        assert template in source, template


def test_card_draws_only_the_faces_there_is_artwork_for() -> None:
    # A breaker's face comes from its catalog number; PROTECTION names the
    # artwork for each kind and FACES says which exist for 1 and 2 poles.
    table = re.search(r"const PROTECTION = \{(.*?)\n\};", CARD, re.DOTALL)
    faces = re.search(r'const FACES = \{ 1: "(\w+)", 2: "(\w+)" \};', CARD)

    assert table is not None and faces is not None
    drawn = set(re.findall(r'face: "(\w)"', table.group(1)))
    assert drawn == {"a", "g", "d"}
    # "s" is the fallback for a protected breaker without its own artwork.
    assert set(faces.group(1)) == set(FACES["1"]) - {"t"}
    assert set(faces.group(2)) == set(FACES["2"]) - {"t"}
    assert drawn <= set(faces.group(1))


def test_card_and_model_agree_on_where_the_leds_are() -> None:
    # The lit LEDs are drawn by the card over the artwork, so both have to
    # put them at the same distance down the breaker's face.
    scene = (WWW.parents[2] / "tools" / "panel_card_art" / "ld_scene.py").read_text()
    modelled = re.search(r'LED_D = \{"off": ([0-9.]+), "g": ([0-9.]+), "a": ([0-9.]+)\}', scene)

    assert modelled is not None
    off, gf, af = (float(value) for value in modelled.groups())
    for name, expected in (("led", off), ("ledGf", gf), ("ledAf", af)):
        placed = re.search(rf"\b{name}: \{{ d: ([0-9.]+), x: -0\.033 \}}", CARD)
        assert placed is not None, name
        assert float(placed.group(1)) == expected, name


def test_art_rev_matches_the_shipped_images() -> None:
    # ART_REV is part of every image URL. If the images change and it doesn't,
    # browsers keep showing cached artwork after an upgrade.
    digest = hashlib.sha256()
    for path in IMAGES:
        digest.update(path.read_bytes())
    match = re.search(r'const ART_REV = "([0-9a-f]+)";', CARD)

    assert match is not None
    assert match.group(1) == digest.hexdigest()[:10]


def test_images_stay_small_enough_to_load_over_a_remote_link() -> None:
    # A panel only fetches the faces its own breakers have, so what one
    # browser loads is well under the size of the whole folder.
    total = sum(path.stat().st_size for path in IMAGES)

    assert total < 1_000_000, f"{total} bytes of artwork"
    assert max(path.stat().st_size for path in IMAGES) < 120_000


def test_dark_appearance_keeps_the_cover_white() -> None:
    # The load center is white. With a dark theme the card takes the glare off
    # it; dimmed much further (it was 0.66) the white turns gray and the whole
    # panel looks faded.
    rule = re.search(r':host\(\[appearance="dark"\]\) \.cover \{([^}]*)\}', CARD)

    assert rule is not None
    brightness = re.search(r"brightness\(([0-9.]+)\)", rule.group(1))
    assert brightness is not None
    assert 0.85 <= float(brightness.group(1)) < 1
