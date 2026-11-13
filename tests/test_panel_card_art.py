"""The panel card and the artwork it loads have to stay in step."""

import hashlib
import re
from pathlib import Path

WWW = Path(__file__).parent.parent / "custom_components" / "ldata" / "www"
CARD = (WWW / "ldata-panel-card.js").read_text()
IMAGES = sorted((WWW / "img").glob("*.webp"))


def _expected() -> set[str]:
    """Every image name the card can ask for."""
    names = {"cover", "frame", "screw-a", "screw-b", "main-on", "main-off"}
    for side in "LR":
        names |= {f"fill-{side}", f"cap-{side}-top", f"cap-{side}-bot"}
        for poles in "12":
            for kind in "st":
                for state in ("on", "off", "trip"):
                    names.add(f"bk-{side}{poles}{kind}-{state}")
    for poles in "12":
        for kind in "st":
            for state in ("on", "off", "trip"):
                names.add(f"hero-{poles}{kind}-{state}")
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
        "`hero-${s.poles}${",
        "art(`main-${v}`)",
        '["cover","frame","screw-a","screw-b"]',
        '"cap-L-top"',
        '"cap-R-bot"',
        'data-code="${col}${s.poles}${',
    ):
        assert template in source, template


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
    total = sum(path.stat().st_size for path in IMAGES)

    assert total < 800_000, f"{total} bytes of artwork"
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
