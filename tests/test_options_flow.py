"""Tests that saving the options form keeps the options it does not manage."""

from types import MappingProxyType, SimpleNamespace
from unittest.mock import MagicMock

import pytest
import voluptuous as vol
from homeassistant.config_entries import SOURCE_USER, ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from custom_components.ldata.config_flow import STEP_USER_DATA_SCHEMA, OptionsFlow
from custom_components.ldata.const import (
    DOMAIN,
    GAP_HANDLING,
    GAP_HANDLING_AVERAGE,
    GAP_HANDLING_LABELS,
    GAP_THRESHOLD,
    HA_INFORM_RATE,
    SHOW_SIDEBAR_PANEL,
    THREE_PHASE,
)

pytestmark = pytest.mark.asyncio

CONFIRMED_SOLAR = ["breaker-1_daily_import", "breaker-1_lifetime_import"]
SUPPRESSED = ["breaker-2_daily_import", "breaker-2_lifetime_import"]


def _entry(options: dict) -> ConfigEntry:
    return ConfigEntry(
        data={
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "secret",
            "refresh_token": "token",
            "userid": "user-1",
        },
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        minor_version=1,
        options=options,
        source=SOURCE_USER,
        subentries_data=None,
        title="Leviton LDATA (Home)",
        unique_id="user@example.com",
        version=1,
    )


def _flow(entry: ConfigEntry, coordinator=None) -> OptionsFlow:
    hass = MagicMock()
    hass.data = {DOMAIN: {entry.entry_id: coordinator}} if coordinator else {}
    hass.config_entries.async_get_known_entry.side_effect = (
        lambda entry_id: entry if entry_id == entry.entry_id else None
    )
    flow = OptionsFlow(entry)
    flow.hass = hass
    flow.handler = entry.entry_id
    return flow


def _suggested_value(form, key: str):
    marker = next(m for m in form["data_schema"].schema if str(m) == key)
    return (marker.description or {}).get("suggested_value")


def _stored_options() -> dict:
    return {
        HA_INFORM_RATE: 60.0,
        THREE_PHASE: False,
        "log_fields": "voltage",
        "confirmed_solar_import_uids": list(CONFIRMED_SOLAR),
        "suppressed_import_uids": list(SUPPRESSED),
    }


async def test_options_save_keeps_import_classifications() -> None:
    """The sensor platform's import-sensor classifications survive a save."""
    entry = _entry(_stored_options())

    result = await _flow(entry).async_step_init(
        {HA_INFORM_RATE: 5.0, THREE_PHASE: True, "log_fields": "   "}
    )

    assert result["type"] == "create_entry"
    assert result["data"]["confirmed_solar_import_uids"] == CONFIRMED_SOLAR
    assert result["data"]["suppressed_import_uids"] == SUPPRESSED
    # The form values still replace the stored ones.
    assert result["data"][HA_INFORM_RATE] == 5.0
    assert result["data"][THREE_PHASE] is True
    assert result["data"]["log_fields"] == ""


async def test_options_save_round_trip_through_form_schema() -> None:
    """Submitting the shown form, validated as HA does, keeps both lists."""
    entry = _entry(_stored_options())
    flow = _flow(entry)

    form = await flow.async_step_init()
    schema_keys = {str(key) for key in form["data_schema"].schema}
    assert "confirmed_solar_import_uids" not in schema_keys
    assert "suppressed_import_uids" not in schema_keys

    # The frontend pre-fills log_fields with its suggested value and submits
    # it unchanged. HA's flow manager validates the submission against the
    # form schema, which fills in the defaults for the other fields.
    user_input = form["data_schema"](
        {HA_INFORM_RATE: 30, "log_fields": _suggested_value(form, "log_fields")}
    )
    result = await flow.async_step_init(user_input)

    assert result["type"] == "create_entry"
    assert result["data"]["confirmed_solar_import_uids"] == CONFIRMED_SOLAR
    assert result["data"]["suppressed_import_uids"] == SUPPRESSED
    assert result["data"][HA_INFORM_RATE] == 30.0
    assert result["data"]["log_fields"] == "voltage"


async def test_options_save_clears_omitted_log_fields() -> None:
    """An emptied log_fields, which the frontend leaves out, is stored as ""."""
    entry = _entry(_stored_options())
    flow = _flow(entry)

    form = await flow.async_step_init()
    assert _suggested_value(form, "log_fields") == "voltage"

    result = await flow.async_step_init(form["data_schema"]({}))

    assert result["type"] == "create_entry"
    assert result["data"]["log_fields"] == ""
    assert result["data"]["suppressed_import_uids"] == SUPPRESSED


async def test_options_save_keeps_hidden_gap_options() -> None:
    """Gap options hidden because every panel has hw counters keep their value."""
    options = {
        **_stored_options(),
        GAP_HANDLING: GAP_HANDLING_AVERAGE,
        GAP_THRESHOLD: 12.0,
    }
    entry = _entry(options)
    service = SimpleNamespace(_panel_has_hw_counters={"panel-1": True})
    flow = _flow(entry, coordinator=SimpleNamespace(_service=service))

    form = await flow.async_step_init()
    schema_keys = {str(key) for key in form["data_schema"].schema}
    assert GAP_HANDLING not in schema_keys
    assert GAP_THRESHOLD not in schema_keys

    result = await flow.async_step_init(form["data_schema"]({THREE_PHASE: True}))

    assert result["data"][GAP_HANDLING] == GAP_HANDLING_AVERAGE
    assert result["data"][GAP_THRESHOLD] == 12.0
    assert result["data"][THREE_PHASE] is True
    assert result["data"]["suppressed_import_uids"] == SUPPRESSED


def _marker(form, key: str):
    return next(m for m in form["data_schema"].schema if str(m) == key)


async def test_sidebar_panel_is_offered_and_off_by_default() -> None:
    """The sidebar page is opt-in: an untouched form saves it as off."""
    entry = _entry(_stored_options())
    flow = _flow(entry)

    form = await flow.async_step_init()
    assert _marker(form, SHOW_SIDEBAR_PANEL).default() is False

    result = await flow.async_step_init(form["data_schema"]({}))
    assert result["data"][SHOW_SIDEBAR_PANEL] is False


async def test_sidebar_panel_option_shows_what_is_stored() -> None:
    """The form starts from the stored option, else from the choice made at setup."""
    stored = _entry({**_stored_options(), SHOW_SIDEBAR_PANEL: True})
    assert _marker(await _flow(stored).async_step_init(), SHOW_SIDEBAR_PANEL).default() is True

    at_setup = _entry(_stored_options())
    object.__setattr__(at_setup, "data", MappingProxyType({**at_setup.data, SHOW_SIDEBAR_PANEL: True}))
    assert _marker(await _flow(at_setup).async_step_init(), SHOW_SIDEBAR_PANEL).default() is True

    turned_off = _entry({**_stored_options(), SHOW_SIDEBAR_PANEL: False})
    object.__setattr__(turned_off, "data", MappingProxyType({**turned_off.data, SHOW_SIDEBAR_PANEL: True}))
    assert _marker(await _flow(turned_off).async_step_init(), SHOW_SIDEBAR_PANEL).default() is False


async def test_sidebar_panel_can_be_turned_on() -> None:
    entry = _entry(_stored_options())
    flow = _flow(entry)

    form = await flow.async_step_init()
    result = await flow.async_step_init(form["data_schema"]({SHOW_SIDEBAR_PANEL: True}))

    assert result["data"][SHOW_SIDEBAR_PANEL] is True
    # ... without losing what the form does not show.
    assert result["data"]["suppressed_import_uids"] == SUPPRESSED


async def test_setup_form_offers_the_sidebar_panel_off_by_default() -> None:
    filled = STEP_USER_DATA_SCHEMA(
        {
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "secret",
            THREE_PHASE: False,
            "allow_breaker_control": False,
        }
    )
    assert filled[SHOW_SIDEBAR_PANEL] is False


async def test_gap_handling_choices_can_be_translated() -> None:
    """The dropdown names its translation key and keeps English as the fallback."""
    form = await _flow(_entry(_stored_options())).async_step_init()
    config = form["data_schema"].schema[_marker(form, GAP_HANDLING)].config

    assert config["translation_key"] == GAP_HANDLING
    assert {option["value"]: option["label"] for option in config["options"]} == GAP_HANDLING_LABELS


# ── Sub-panels: which breaker feeds each load center ──────────────────────


def _two_load_centers(**extra) -> SimpleNamespace:
    """A loaded entry's coordinator: a main panel and a casita."""
    return SimpleNamespace(
        data={
            "panels": [
                {
                    "id": "main",
                    "name": "Main Panel",
                    "dumb_breakers": [{"id": "d1", "name": "Casita Feed", "position": 38, "poles": 2}],
                },
                {"id": "casita", "name": "Casita", "dumb_breakers": []},
            ],
            "breakers": {
                "b1": {"panel_id": "main", "position": 1, "poles": 1, "name": "Kitchen", "rating": 20},
                "b25": {"panel_id": "main", "position": 25, "poles": 2, "name": "Solar", "rating": 40},
                "c1": {"panel_id": "casita", "position": 1, "poles": 1, "name": "Casita Kitchen", "rating": 20},
            },
            **extra,
        }
    )


def _section(form):
    marker = next((m for m in form["data_schema"].schema if str(m) == "sub_panels"), None)
    return form["data_schema"].schema[marker] if marker is not None else None


def _feed_field(form, name: str):
    schema = _section(form).schema.schema
    marker = next(m for m in schema if str(m) == name)
    return marker, schema[marker]


async def test_sub_panels_are_not_asked_about_with_one_load_center() -> None:
    one = SimpleNamespace(data={"panels": [{"id": "main", "name": "Main Panel"}], "breakers": {}})

    assert _section(await _flow(_entry({}), one).async_step_init()) is None
    # ... nor while the entry is not loaded and its breakers are unknown.
    assert _section(await _flow(_entry({})).async_step_init()) is None


async def test_each_load_center_can_be_given_the_breaker_that_feeds_it() -> None:
    form = await _flow(_entry({}), _two_load_centers()).async_step_init()

    section = _section(form)
    assert isinstance(next(m for m in form["data_schema"].schema if str(m) == "sub_panels"), vol.Optional)
    # Closed until there is something in it.
    assert section.options == {"collapsed": True}
    # One field for each load center, named after it: Home Assistant shows a
    # field it has no translation for under its own name.
    assert sorted(str(m) for m in section.schema.schema) == ["Casita", "Main Panel"]

    marker, selector_ = _feed_field(form, "Casita")
    assert marker.default() == "none"
    assert selector_.config["translation_key"] == "sub_panel_feed"
    # "Not a sub-panel", then every breaker of the other load center by
    # position, smart or not.
    assert selector_.config["options"] == [
        {"value": "none", "label": "Not a sub-panel"},
        {"value": "main|1", "label": "Main Panel · 1 · Kitchen · 20 A"},
        {"value": "main|25", "label": "Main Panel · 25/27 · Solar · 40 A"},
        {"value": "main|38", "label": "Main Panel · 38/40 · Casita Feed"},
    ]
    _, main = _feed_field(form, "Main Panel")
    assert [option["value"] for option in main.config["options"]] == ["none", "casita|1"]


async def test_chosen_feed_is_stored() -> None:
    entry = _entry(_stored_options())

    result = await _flow(entry, _two_load_centers()).async_step_init(
        {HA_INFORM_RATE: 60.0, "sub_panels": {"Casita": "main|38", "Main Panel": "none"}}
    )

    assert result["type"] == "create_entry"
    assert result["data"]["sub_panels"] == {"casita": {"panel": "main", "position": 38}}
    # Nothing else the form does not manage is lost with it.
    assert result["data"]["confirmed_solar_import_uids"] == CONFIRMED_SOLAR


async def test_stored_feed_is_shown_with_the_section_open() -> None:
    entry = _entry({"sub_panels": {"casita": {"panel": "main", "position": 38}}})

    form = await _flow(entry, _two_load_centers()).async_step_init()

    assert _section(form).options == {"collapsed": False}
    assert _feed_field(form, "Casita")[0].default() == "main|38"
    assert _feed_field(form, "Main Panel")[0].default() == "none"


async def test_feed_can_be_removed() -> None:
    entry = _entry({"sub_panels": {"casita": {"panel": "main", "position": 38}}})

    result = await _flow(entry, _two_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "none", "Main Panel": "none"}}
    )

    assert result["data"]["sub_panels"] == {}


async def test_two_load_centers_cannot_feed_each_other() -> None:
    entry = _entry(_stored_options())

    result = await _flow(entry, _two_load_centers()).async_step_init(
        {THREE_PHASE: True, "sub_panels": {"Casita": "main|38", "Main Panel": "casita|1"}}
    )

    assert result["type"] == "form"
    assert result["errors"] == {"base": "sub_panel_loop"}
    # The form comes back as it was filled in.
    assert _feed_field(result, "Casita")[0].default() == "main|38"
    assert _feed_field(result, "Main Panel")[0].default() == "casita|1"
    assert _marker(result, THREE_PHASE).default() is True


async def test_feeds_survive_a_save_that_cannot_show_them() -> None:
    stored = {"sub_panels": {"casita": {"panel": "main", "position": 38}}}

    # The entry is not loaded: no section, and the links are left alone.
    result = await _flow(_entry(dict(stored))).async_step_init({HA_INFORM_RATE: 5.0})
    assert result["data"]["sub_panels"] == stored["sub_panels"]

    # A submission that leaves the section out (not Home Assistant's own form,
    # which always sends it) changes nothing either.
    result = await _flow(_entry(dict(stored)), _two_load_centers()).async_step_init({HA_INFORM_RATE: 5.0})
    assert result["data"]["sub_panels"] == stored["sub_panels"]

    # Leviton reports a third load center's feed only some of the time.
    stored["sub_panels"]["shed"] = {"panel": "casita", "position": 5}
    result = await _flow(_entry(dict(stored)), _two_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "main|38", "Main Panel": "none"}}
    )
    assert result["data"]["sub_panels"] == stored["sub_panels"]


async def test_feed_from_a_breaker_leviton_no_longer_lists_stays_on_offer() -> None:
    entry = _entry({"sub_panels": {"casita": {"panel": "main", "position": 12}}})

    form = await _flow(entry, _two_load_centers()).async_step_init()

    marker, selector_ = _feed_field(form, "Casita")
    assert marker.default() == "main|12"
    assert selector_.config["options"][-1] == {"value": "main|12", "label": "Main Panel · 12"}
    result = await _flow(entry, _two_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "main|12", "Main Panel": "none"}}
    )
    assert result["data"]["sub_panels"] == {"casita": {"panel": "main", "position": 12}}


async def test_load_centers_with_the_same_name_get_their_own_fields() -> None:
    twins = SimpleNamespace(
        data={
            "panels": [{"id": "a", "name": "Panel"}, {"id": "b", "name": "Panel"}],
            "breakers": {"b1": {"panel_id": "a", "position": 3, "poles": 1, "name": "Feed", "rating": 60}},
        }
    )

    form = await _flow(_entry({}), twins).async_step_init()

    assert sorted(str(m) for m in _section(form).schema.schema) == ["Panel", "Panel (b)"]
    result = await _flow(_entry({}), twins).async_step_init(
        {"sub_panels": {"Panel": "none", "Panel (b)": "a|3"}}
    )
    assert result["data"]["sub_panels"] == {"b": {"panel": "a", "position": 3}}
