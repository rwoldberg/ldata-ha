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
# A Gen 1 smart breaker has the same face without the "OFF" LED; its artwork
# is named with a "1" after the letter ("s1", "g1", ...).
GEN1_FACES = {poles: [f"{face}1" for face in faces if face != "t"] for poles, faces in FACES.items()}


def _expected() -> set[str]:
    """Every image name the card can ask for."""
    names = {"cover", "frame", "screw-a", "screw-b", "main-on", "main-off", "main-inv-on", "main-inv-off"}
    for side in "LR":
        names |= {f"fill-{side}", f"cap-{side}-top", f"cap-{side}-bot"}
        for poles, faces in FACES.items():
            for face in [*faces, *GEN1_FACES[poles]]:
                for state in ("on", "off", "trip"):
                    names.add(f"bk-{side}{poles}{face}-{state}")
    for poles, faces in FACES.items():
        for face in [*faces, *GEN1_FACES[poles]]:
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
        "art(`${this._mainArt}-${v}`)",
        'this._mainArt=low?"main-inv":"main";',
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
    across = re.search(r"LED_X = \((-?[0-9.]+), (-?[0-9.]+)\)", scene)
    assert across is not None
    centre = (float(across.group(1)) + float(across.group(2))) / 2
    for name, expected in (("led", off), ("ledGf", gf), ("ledAf", af)):
        placed = re.search(rf"\b{name}: \{{ d: ([0-9.]+), x: (-?[0-9.]+) \}}", CARD)
        assert placed is not None, name
        assert float(placed.group(1)) == expected, name
        assert abs(float(placed.group(2)) - centre) < 1e-9, name
    # A Gen 1 breaker's LEDs are at the same places, in a strip centred on the seam.
    assert "x = cx + side * STRIP_W" in scene
    assert re.search(r"\bgen1LedX: 0,", CARD)


def test_card_and_model_agree_on_the_main_breaker() -> None:
    # The main breaker image leaves its rating off and the card prints it, so
    # both have to agree on the image's size and where the rating goes.
    scene = (WWW.parents[2] / "tools" / "panel_card_art" / "ld_scene.py").read_text()

    def number(name: str) -> float:
        found = re.search(rf"^{name} = (-?[0-9.]+)", scene, re.MULTILINE)
        assert found is not None, name
        return float(found.group(1))

    plate = re.search(r"^LMT_W, LMT_H = ([0-9.]+), ([0-9.]+)", scene, re.MULTILINE)
    boss = re.search(r"^BOSS_W, BOSS_H = ([0-9.]+), ([0-9.]+)", scene, re.MULTILINE)
    rating = re.search(r"^LMT_RATING = \((-?[0-9.]+), (-?[0-9.]+), ([0-9.]+)\)", scene, re.MULTILINE)
    placed = re.search(r"\bmain: \{ w: ([0-9.]+), h: ([0-9.]+), rating: \[([0-9.]+), ([0-9.]+)\], size: ([0-9.]+) \}", CARD)
    assert plate is not None and boss is not None and rating is not None and placed is not None
    border = 2 * (number("LMT_GAP") + float(boss.group(1)) + number("MAIN_M"))
    width, height = float(plate.group(1)) + border, float(plate.group(2)) + border
    x, y, cap = (float(value) for value in rating.groups())
    card = [float(value) for value in placed.groups()]

    assert abs(card[0] - width) < 1e-3 and abs(card[1] - height) < 1e-3
    assert abs(card[2] - (width / 2 + x)) < 1e-3 and abs(card[3] - (height / 2 - y)) < 1e-3
    assert abs(card[4] - cap / 0.716) < 1e-3  # Arial's cap height is 0.716 of its size
    # The stylesheet draws the image at that size too.
    assert f"width: calc(var(--u) * {width:g}); height: calc(var(--u) * {height:g})" in CARD
    # Upside down at the bottom of the panel, the rating turns with the image.
    assert "const [rx, ry] = low ? [G.main.w - G.main.rating[0], G.main.h - G.main.rating[1]] : G.main.rating;" in CARD
    assert "rx, ry, low ? 90 : -90," in CARD


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
    # A panel only fetches the faces its own breakers have (and only Gen 1
    # or Gen 2 ones of each), so what one browser loads is well under the
    # size of the whole folder.
    total = sum(path.stat().st_size for path in IMAGES)

    assert total < 1_600_000, f"{total} bytes of artwork"
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


def test_header_load_and_amps_are_one_line_of_text() -> None:
    # As two grid columns of a button, Safari could leave the watts' column
    # narrower than the number after the card was resized, and the amps were
    # drawn over the "W" (PR #118). In one line of text they can't overlap.
    assert '<span class="m-read"><span class="m-big" data-h="total"></span><span class="m-amps" data-h="amps"></span></span>' in CARD
    main = re.search(r"\.m-main \{([^}]*)\}", CARD)
    assert main is not None
    assert "grid" not in main.group(1)


def test_standard_and_smart_breakers_are_printed_in_the_same_ink() -> None:
    # Leviton's photos of standard breakers show their printing lighter, but
    # in a panel with both kinds it is the same (PR #118).
    scene = (WWW.parents[2] / "tools" / "panel_card_art" / "ld_scene.py").read_text()
    assert re.search(r"^INK = \([0-9., ]+\)$", scene, re.MULTILINE)
    assert '"ink": material("ink", INK,' in scene
    # The rating the card prints on a breaker has one colour for every kind.
    assert len(re.findall(r"\.ink text[^{]*\{[^}]*\bfill:", CARD)) == 1


def test_every_card_follows_the_artwork_to_the_served_copy() -> None:
    """A card file copied by hand has no img/ beside it; every card on the page moves over.

    Not only the one that found its images missing: the others' cover, frame
    and screws are CSS backgrounds, which never report an error themselves.
    """
    source = re.sub(r"\s+", " ", CARD)
    # One check for the page, which then tells every card on it.
    assert "for (const card of artCards) card._artMoved();" in source
    assert "this._artProbe" not in source
    # A card is on the list while it is on the page, and catches up if the
    # artwork moved while it was away (a sidebar tab not on show).
    assert "connectedCallback() { artCards.add(this);" in source
    assert "if (this._artAt && this._artAt !== artBase) this._artMoved();" in source
    assert "disconnectedCallback() { artCards.delete(this);" in source
    moved = re.search(r"_artMoved\(\) \{(.*?)\}", source)
    assert moved is not None and "this._applyArt();" in moved.group(1) and "this._update(true);" in moved.group(1)
