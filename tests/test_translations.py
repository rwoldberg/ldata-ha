"""The translations are complete, well formed, and match what the code asks for.

Home Assistant loads translations/<language>.json for exactly the language a
user picked and falls back to English one string at a time. A string whose
placeholders differ from the English one is dropped with an error in the log,
so those mistakes are caught here instead.
"""

from __future__ import annotations

import json
import re
import string
from pathlib import Path
from typing import Any

import pytest
from homeassistant.generated.languages import LANGUAGES as HA_LANGUAGES

COMPONENT = Path(__file__).parent.parent / "custom_components" / "ldata"
TRANSLATIONS = COMPONENT / "translations"
CARD = COMPONENT / "www" / "ldata-panel-card.js"

# English plus the languages of the countries with the most Home Assistant
# installations (see README, "Languages"). Codes are Home Assistant's own.
LANGUAGES = [
    "cs",
    "da",
    "de",
    "es",
    "es-419",
    "fi",
    "fr",
    "hu",
    "it",
    "nb",
    "nl",
    "pl",
    "pt",
    "pt-BR",
    "ro",
    "ru",
    "sv",
    "uk",
    "zh-Hans",
    "zh-Hant",
]

# Rules hassfest applies to strings.json and translations/en.json.
RE_HTML = re.compile(r"<[a-z].*?>", re.IGNORECASE)
RE_QUOTED_PLACEHOLDER = re.compile(r"'{\w+}'")
RE_URL = re.compile(
    r"(((ftp|ftps|scp|http|https|mqtt|mqtts|socket|socks5):\/\/|www\.)"
    r"[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?)",
    re.IGNORECASE,
)
RE_REFERENCE = re.compile(r"^\[%key:.+%\]$")
RE_TRANSLATION_KEY = re.compile(r"^(?!.+[_-]{2})(?![_-])[a-z0-9-_]+(?<![_-])$")
TOP_LEVEL = {"config", "options", "selector", "services", "config_panel"}

# Proper names and international words that may read the same in any language.
SAME_AS_ENGLISH_LIMIT = 0.2


def _load(name: str) -> dict[str, Any]:
    return json.loads((TRANSLATIONS / f"{name}.json").read_text(encoding="utf-8"))


def _flatten(node: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in node.items():
        if isinstance(value, dict):
            flat.update(_flatten(value, f"{prefix}{key}."))
        else:
            flat[f"{prefix}{key}"] = value
    return flat


def _placeholders(text: str) -> set[str]:
    return {field for _, field, _, _ in string.Formatter().parse(text) if field is not None}


def _value_problem(text: Any, *, allow_reference: bool = False) -> str | None:
    """Return why hassfest (or Home Assistant at runtime) would reject a string."""
    if not isinstance(text, str):
        return "not a string"
    if not text:
        return "empty"
    if allow_reference and RE_REFERENCE.match(text):
        return None
    if text != text.strip():
        return "leading or trailing whitespace"
    if RE_HTML.search(text):
        return "contains HTML"
    if RE_QUOTED_PLACEHOLDER.search(text):
        return "placeholder inside single quotes"
    if RE_URL.search(text):
        return "contains a URL"
    if "[%" in text or "%]" in text:
        return "contains a translation reference"
    try:
        fields = _placeholders(text)
    except ValueError as err:
        return f"unbalanced braces ({err})"
    if any(not field.isidentifier() for field in fields):
        return "placeholder is not an identifier"
    return None


ENGLISH = _load("en")
ENGLISH_FLAT = _flatten(ENGLISH)


def test_shipped_languages_are_the_expected_ones() -> None:
    shipped = {path.stem for path in TRANSLATIONS.glob("*.json")}
    assert shipped == {"en", *LANGUAGES}
    # A file named for a code Home Assistant doesn't have is never loaded
    # (Portuguese is "pt", not "pt-PT").
    assert shipped <= HA_LANGUAGES


@pytest.mark.parametrize("language", ["en", *LANGUAGES])
def test_values_are_well_formed(language: str) -> None:
    problems = {
        key: problem
        for key, value in _flatten(_load(language)).items()
        if (problem := _value_problem(value)) is not None
    }
    assert not problems


@pytest.mark.parametrize("language", LANGUAGES)
def test_language_has_exactly_the_english_keys(language: str) -> None:
    flat = _flatten(_load(language))
    assert sorted(set(ENGLISH_FLAT) - set(flat)) == [], "missing"
    assert sorted(set(flat) - set(ENGLISH_FLAT)) == [], "not in en.json"
    # Same order too, so two files can be read side by side.
    assert list(flat) == list(ENGLISH_FLAT)


@pytest.mark.parametrize("language", LANGUAGES)
def test_language_keeps_the_placeholders(language: str) -> None:
    flat = _flatten(_load(language))
    wrong = {
        key: (sorted(_placeholders(flat[key])), sorted(_placeholders(english)))
        for key, english in ENGLISH_FLAT.items()
        if key in flat and _placeholders(flat[key]) != _placeholders(english)
    }
    assert not wrong


@pytest.mark.parametrize("language", LANGUAGES)
def test_language_is_actually_translated(language: str) -> None:
    flat = _flatten(_load(language))
    same = [key for key, english in ENGLISH_FLAT.items() if flat.get(key) == english]
    assert len(same) <= SAME_AS_ENGLISH_LIMIT * len(ENGLISH_FLAT), same


def test_english_follows_the_hassfest_layout() -> None:
    """The parts of hassfest's schema that the files here use."""
    strings = json.loads((COMPONENT / "strings.json").read_text(encoding="utf-8"))
    for name, doc in (("strings.json", strings), ("en.json", ENGLISH)):
        assert set(doc) <= TOP_LEVEL, name
        for flow in ("config", "options"):
            assert set(doc[flow]) <= {"step", "error", "abort"}, (name, flow)
            for step_id, step in doc[flow]["step"].items():
                assert set(step) <= {"title", "description", "data", "data_description", "sections"}, (name, step_id)
                # hassfest: "data_description key … is not in data"
                assert set(step.get("data_description", {})) <= set(step.get("data", {})), (name, step_id)
                for key, section in step.get("sections", {}).items():
                    assert RE_TRANSLATION_KEY.match(key), (name, step_id, key)
                    assert set(section) <= {"name", "description", "data", "data_description"}, (name, step_id, key)
        for key, selector in doc["selector"].items():
            assert RE_TRANSLATION_KEY.match(key) and set(selector) == {"options"}, (name, key)
            assert all(RE_TRANSLATION_KEY.match(option) for option in selector["options"]), (name, key)
        for service, description in doc["services"].items():
            assert {"name", "description"} <= set(description) <= {"name", "description", "fields"}, (name, service)
            for field, info in description.get("fields", {}).items():
                assert set(info) == {"name", "description"}, (name, service, field)
        for key in _flatten(doc["config_panel"]):
            assert all(RE_TRANSLATION_KEY.match(part) for part in key.split(".")), (name, key)
        problems = {
            key: problem
            for key, value in _flatten(doc).items()
            if (problem := _value_problem(value, allow_reference=name == "strings.json")) is not None
        }
        assert not problems, name

    # strings.json is en.json with Home Assistant's shared strings left as references.
    flat_strings = _flatten(strings)
    assert list(flat_strings) != [] and set(flat_strings) == set(ENGLISH_FLAT)
    differing = {key for key, value in flat_strings.items() if value != ENGLISH_FLAT[key]}
    assert all(RE_REFERENCE.match(flat_strings[key]) for key in differing), differing


def test_translations_cover_the_integration() -> None:
    """Every option, service and service field has a string."""
    import yaml

    from custom_components.ldata.const import GAP_HANDLING, GAP_HANDLING_LABELS, SHOW_SIDEBAR_PANEL

    assert SHOW_SIDEBAR_PANEL in ENGLISH["config"]["step"]["user"]["data"]
    assert SHOW_SIDEBAR_PANEL in ENGLISH["options"]["step"]["init"]["data"]
    assert set(ENGLISH["selector"][GAP_HANDLING]["options"]) == set(GAP_HANDLING_LABELS)
    # The options form's section, its "none" choice and the error it can raise.
    from custom_components.ldata.sub_panels import NOT_FED, SUB_PANELS

    assert {"name", "description"} == set(ENGLISH["options"]["step"]["init"]["sections"][SUB_PANELS])
    assert set(ENGLISH["selector"]["sub_panel_feed"]["options"]) == {NOT_FED}
    assert "sub_panel_loop" in ENGLISH["options"]["error"]

    services = yaml.safe_load((COMPONENT / "services.yaml").read_text(encoding="utf-8"))
    assert set(ENGLISH["services"]) == set(services)
    for service, description in services.items():
        assert set(ENGLISH["services"][service]["fields"]) == set(description["fields"]), service


def _card_source() -> str:
    return CARD.read_text(encoding="utf-8")


def test_card_carries_the_same_english() -> None:
    """The card's built-in English is en.json's config_panel, string for string."""
    match = re.search(r"/\* i18n:begin \*/\s*const EN = (\{.*?\});\s*/\* i18n:end \*/", _card_source(), re.DOTALL)
    assert match, "English block not found in the card"
    assert json.loads(match.group(1)) == ENGLISH["config_panel"]


def test_card_and_translations_use_the_same_keys() -> None:
    """No key the card asks for is missing, and none is translated for nothing."""
    source = _card_source()
    source = source[source.index("/* i18n:end */") :]
    known = set(_flatten(ENGLISH["config_panel"]))

    used = set(re.findall(r'"((?:card|editor|sidebar)\.[a-z0-9_]+(?:\.[a-z0-9_]+)*)"', source))
    # d("today") in the detail sheet is card.detail.today
    used |= {f"card.detail.{key}" for key in re.findall(r'\bd\(\s*"([a-z0-9_]+)"', source)}
    # d(v === true ? "remote_reset_yes" : "remote_reset_no")
    for group in re.findall(r"\bd\(([^()]*\?[^()]*)\)", source):
        used |= {f"card.detail.{key}" for key in re.findall(r'"([a-z0-9_]+)"', group)}
    # keys built at run time
    used |= {key for key in known if key.startswith("card.raw.")}  # Leviton's state names
    # card.trip.<cause> and card.protection.<kind>, from the card's own tables
    causes = re.search(r"const TRIP_CAUSES = \[(.*?)\n\];", _card_source(), re.DOTALL)
    kinds = re.search(r"const PROTECTION = \{(.*?)\n\};", _card_source(), re.DOTALL)
    assert causes and kinds, "fault-protection tables not found in the card"
    used |= {f"card.trip.{key}" for key in re.findall(r'\[/[^\n]*?/i, "([a-z_]+)"', causes.group(1))}
    used |= {f"card.protection.{key}" for key in re.findall(r'key: "([a-z_]+)"', kinds.group(1))}
    used |= {f"card.label.{action}" for action in ("show_details", "open_sub_panel", "open_sub_panel_dashboard")}

    assert sorted(used - known) == [], "the card asks for strings that en.json doesn't have"
    assert sorted(known - used) == [], "en.json has strings the card never shows"
