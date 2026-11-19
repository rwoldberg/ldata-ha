"""Tests that saving the options form keeps the options it does not manage."""

from types import MappingProxyType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import voluptuous as vol
from homeassistant.config_entries import SOURCE_USER, ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from custom_components.ldata.config_flow import (
    STEP_USER_DATA_SCHEMA,
    CannotConnect,
    ConfigFlow,
    OptionsFlow,
)
from custom_components.ldata.sub_panels import MAIN_BREAKERS
from custom_components.ldata.const import (
    DOMAIN,
    ENERGY_TRACKING_MODE,
    GAP_HANDLING,
    GAP_HANDLING_AVERAGE,
    GAP_HANDLING_LABELS,
    GAP_THRESHOLD,
    HA_INFORM_RATE,
    PANEL_SUBENTRY_TYPE,
    SHOW_SIDEBAR_PANEL,
    THREE_PHASE,
)

pytestmark = pytest.mark.asyncio

CONFIRMED_SOLAR = ["breaker-1_daily_import", "breaker-1_lifetime_import"]
SUPPRESSED = ["breaker-2_daily_import", "breaker-2_lifetime_import"]


def _entry(options: dict, subentries: list[dict] | None = None) -> ConfigEntry:
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
        subentries_data=subentries,
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


async def test_energy_tracking_mode_is_offered_for_ldata_panels() -> None:
    """The option is shown when the entry has an LDATA panel, defaulting to auto."""
    entry = _entry(_stored_options())
    service = SimpleNamespace(_panel_has_hw_counters={"LDATA-1": False}, _ldata_panel_ids={"LDATA-1"})
    flow = _flow(entry, coordinator=SimpleNamespace(_service=service))

    form = await flow.async_step_init()
    assert ENERGY_TRACKING_MODE in {str(key) for key in form["data_schema"].schema}
    assert form["data_schema"]({})[ENERGY_TRACKING_MODE] == "auto"

    result = await flow.async_step_init(form["data_schema"]({ENERGY_TRACKING_MODE: "counter"}))
    assert result["data"][ENERGY_TRACKING_MODE] == "counter"
    assert result["data"]["suppressed_import_uids"] == SUPPRESSED


async def test_energy_tracking_mode_is_hidden_without_ldata_panels() -> None:
    entry = _entry(_stored_options())
    service = SimpleNamespace(_panel_has_hw_counters={"1000_ABCD": True}, _ldata_panel_ids=set())
    flow = _flow(entry, coordinator=SimpleNamespace(_service=service))

    form = await flow.async_step_init()
    assert ENERGY_TRACKING_MODE not in {str(key) for key in form["data_schema"].schema}


async def test_energy_tracking_mode_stays_offered_once_set() -> None:
    """A set mode stays visible (and changeable) while the integration is not loaded."""
    entry = _entry({**_stored_options(), ENERGY_TRACKING_MODE: "hourly"})

    form = await _flow(entry).async_step_init()
    assert form["data_schema"]({})[ENERGY_TRACKING_MODE] == "hourly"


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
    # Two fields for each load center, named after it: Home Assistant shows a
    # field it has no translation for under its own name. The second is the
    # size of the feeding breaker, which Leviton doesn't know for one that
    # isn't smart.
    assert [str(m) for m in section.schema.schema] == ["Casita", "Casita (Amps)", "Main Panel", "Main Panel (Amps)"]
    size = next(m for m in section.schema.schema if str(m) == "Casita (Amps)")
    assert isinstance(size, vol.Optional)
    assert (size.description or {}).get("suggested_value") is None
    assert section.schema.schema[size].config["unit_of_measurement"] == "A"

    marker, selector_ = _feed_field(form, "Casita")
    assert marker.default() == "none"
    assert selector_.config["translation_key"] == "sub_panel_feed"
    # "Not fed from another load center", then every breaker of the other load center by
    # position, smart or not.
    assert selector_.config["options"] == [
        {"value": "none", "label": "Not fed from another load center"},
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


async def test_feed_from_a_load_center_leviton_no_longer_lists_stays_on_offer() -> None:
    entry = _entry({"sub_panels": {"casita": {"panel": "garage", "position": 5}}})

    form = await _flow(entry, _two_load_centers()).async_step_init()

    # Named by its id: the form only knows the names of what Leviton lists.
    marker, selector_ = _feed_field(form, "Casita")
    assert marker.default() == "garage|5"
    assert selector_.config["options"][-1] == {"value": "garage|5", "label": "garage · 5"}
    result = await _flow(entry, _two_load_centers()).async_step_init(
        {HA_INFORM_RATE: 5.0, "sub_panels": {"Casita": "garage|5", "Main Panel": "none"}}
    )
    assert result["data"]["sub_panels"] == {"casita": {"panel": "garage", "position": 5}}


def _three_load_centers() -> SimpleNamespace:
    coordinator = _two_load_centers()
    coordinator.data["panels"].append({"id": "shed", "name": "Shed", "dumb_breakers": []})
    return coordinator


async def test_two_load_centers_cannot_be_fed_from_the_same_breaker() -> None:
    entry = _entry(_stored_options())

    result = await _flow(entry, _three_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "main|38", "Main Panel": "none", "Shed": "main|38"}}
    )

    assert result["type"] == "form"
    assert result["errors"] == {"base": "sub_panel_same_breaker"}
    assert _feed_field(result, "Casita")[0].default() == "main|38"
    assert _feed_field(result, "Shed")[0].default() == "main|38"

    # Each from a breaker of its own is fine.
    result = await _flow(entry, _three_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "main|38", "Main Panel": "none", "Shed": "main|25"}}
    )
    assert result["data"]["sub_panels"] == {
        "casita": {"panel": "main", "position": 38},
        "shed": {"panel": "main", "position": 25},
    }


async def test_breaker_feeding_a_load_center_the_form_cannot_show_is_taken() -> None:
    # Leviton doesn't list the shed right now; an answer that leaves its field
    # out keeps its feed, which counts.
    entry = _entry({"sub_panels": {"shed": {"panel": "main", "position": 38}}})

    result = await _flow(entry, _two_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "main|38", "Main Panel": "none"}}
    )

    assert result["errors"] == {"base": "sub_panel_same_breaker"}


async def test_load_centers_with_the_same_name_get_their_own_fields() -> None:
    twins = SimpleNamespace(
        data={
            "panels": [{"id": "a", "name": "Panel"}, {"id": "b", "name": "Panel"}],
            "breakers": {"b1": {"panel_id": "a", "position": 3, "poles": 1, "name": "Feed", "rating": 60}},
        }
    )

    form = await _flow(_entry({}), twins).async_step_init()

    assert [str(m) for m in _section(form).schema.schema] == ["Panel", "Panel (Amps)", "Panel (b)", "Panel (b) (Amps)"]
    result = await _flow(_entry({}), twins).async_step_init(
        {"sub_panels": {"Panel": "none", "Panel (b)": "a|3"}}
    )
    assert result["data"]["sub_panels"] == {"b": {"panel": "a", "position": 3}}


async def test_size_of_the_feeding_breaker_is_stored_with_its_feed() -> None:
    entry = _entry(_stored_options())

    result = await _flow(entry, _two_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "main|38", "Casita (Amps)": 100, "Main Panel": "none", "Main Panel (Amps)": 60}}
    )

    # A size for a load center that isn't fed from anywhere is dropped.
    assert result["data"]["sub_panels"] == {"casita": {"panel": "main", "position": 38, "rating": 100.0}}


async def test_stored_size_is_suggested_and_can_be_emptied() -> None:
    entry = _entry({"sub_panels": {"casita": {"panel": "main", "position": 38, "rating": 100}}})

    form = await _flow(entry, _two_load_centers()).async_step_init()
    size = next(m for m in _section(form).schema.schema if str(m) == "Casita (Amps)")
    assert size.description == {"suggested_value": 100.0}

    # Home Assistant leaves an emptied number field out of the submission.
    result = await _flow(entry, _two_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "main|38", "Main Panel": "none"}}
    )
    assert result["data"]["sub_panels"] == {"casita": {"panel": "main", "position": 38}}


async def test_refused_form_comes_back_with_the_size_that_was_typed() -> None:
    entry = _entry({})

    result = await _flow(entry, _two_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "main|38", "Casita (Amps)": 70, "Main Panel": "casita|1"}}
    )

    assert result["errors"] == {"base": "sub_panel_loop"}
    size = next(m for m in _section(result).schema.schema if str(m) == "Casita (Amps)")
    assert size.description == {"suggested_value": 70}


async def test_feed_of_a_load_center_leviton_no_longer_reports_can_be_taken_off() -> None:
    """A hub that was replaced keeps a field, so its feed doesn't hold a breaker for good."""
    entry = _entry(
        {"sub_panels": {"shed": {"panel": "main", "position": 38, "rating": 60}}},
        subentries=[{"data": {}, "subentry_type": PANEL_SUBENTRY_TYPE, "title": "Shed", "unique_id": "shed"}],
    )
    flow = _flow(entry, _two_load_centers())

    form = await flow.async_step_init()

    # Named after the load center's subentry, after the ones Leviton reports;
    # without a size field, and offering only its feed and "Not fed from another load center".
    assert [str(m) for m in _section(form).schema.schema] == [
        "Casita", "Casita (Amps)", "Main Panel", "Main Panel (Amps)", "Shed"
    ]
    assert _section(form).options == {"collapsed": False}
    marker, selector_ = _feed_field(form, "Shed")
    assert marker.default() == "main|38"
    assert selector_.config["options"] == [
        {"value": "none", "label": "Not fed from another load center"},
        {"value": "main|38", "label": "Main Panel · 38/40 · Casita Feed"},
    ]

    # Kept, it keeps its size too.
    result = await _flow(entry, _two_load_centers()).async_step_init(
        {"sub_panels": {"Casita": "none", "Main Panel": "none", "Shed": "main|38"}}
    )
    assert result["data"]["sub_panels"] == {"shed": {"panel": "main", "position": 38, "rating": 60.0}}

    # Taken off, its breaker can feed the casita.
    result = await flow.async_step_init(
        {"sub_panels": {"Casita": "main|38", "Main Panel": "none", "Shed": "none"}}
    )
    assert result["type"] == "create_entry"
    assert result["data"]["sub_panels"] == {"casita": {"panel": "main", "position": 38}}


async def test_feed_of_a_load_center_leviton_no_longer_reports_has_a_field_with_one_left() -> None:
    """With one load center left, the section is there for the old feed alone."""
    entry = _entry({"sub_panels": {"shed": {"panel": "main", "position": 38}}})
    one = SimpleNamespace(data={"panels": [{"id": "main", "name": "Main Panel"}], "breakers": {}})

    form = await _flow(entry, one).async_step_init()

    # Without a subentry, it goes by its id.
    assert [str(m) for m in _section(form).schema.schema] == ["shed"]
    result = await _flow(entry, one).async_step_init({"sub_panels": {"shed": "none"}})
    assert result["data"]["sub_panels"] == {}


async def test_load_center_named_like_a_size_field_gets_its_own_field() -> None:
    panels = SimpleNamespace(
        data={
            "panels": [{"id": "g", "name": "Garage"}, {"id": "g2", "name": "Garage (Amps)"}],
            "breakers": {"b1": {"panel_id": "g", "position": 3, "poles": 1, "name": "Feed", "rating": 60}},
        }
    )

    form = await _flow(_entry({}), panels).async_step_init()

    # "Garage (Amps)" is the size field of "Garage", so the other load center
    # called that gets its id added.
    assert [str(m) for m in _section(form).schema.schema] == [
        "Garage", "Garage (Amps)", "Garage (Amps) (g2)", "Garage (Amps) (g2) (Amps)"
    ]
    result = await _flow(_entry({}), panels).async_step_init(
        {"sub_panels": {"Garage": "none", "Garage (Amps) (g2)": "g|3", "Garage (Amps) (g2) (Amps)": 100}}
    )
    assert result["data"]["sub_panels"] == {"g2": {"panel": "g", "position": 3, "rating": 100.0}}


async def test_load_center_renamed_while_the_form_is_open_keeps_its_feed() -> None:
    """The answer is read against the form that was shown."""
    entry = _entry({"sub_panels": {"casita": {"panel": "main", "position": 38, "rating": 100}}})
    coordinator = _two_load_centers()
    flow = _flow(entry, coordinator)
    await flow.async_step_init()

    coordinator.data["panels"][1]["name"] = "Guest House"
    result = await flow.async_step_init(
        {"sub_panels": {"Casita": "main|38", "Casita (Amps)": 100, "Main Panel": "none"}}
    )

    assert result["data"]["sub_panels"] == {"casita": {"panel": "main", "position": 38, "rating": 100.0}}


def _mains(form):
    marker = next((m for m in form["data_schema"].schema if str(m) == MAIN_BREAKERS), None)
    return form["data_schema"].schema[marker] if marker is not None else None


def _suggested_mains(form) -> dict:
    """The rating fields' suggested values and the position fields' defaults."""
    shown = {}
    for marker in _mains(form).schema.schema:
        name = str(marker)
        shown[name] = (marker.description or {}).get("suggested_value") if name.endswith("(Amps)") else marker.default()
    return shown


async def test_main_breakers_are_asked_about_from_one_load_center() -> None:
    one = SimpleNamespace(data={"panels": [{"id": "main", "name": "Main Panel"}], "breakers": {}})

    section = _mains(await _flow(_entry({}), one).async_step_init())

    # Closed until there is something in it. Two fields for each load
    # center, as under Sub-panels: one named after it, for its type, and one
    # ending in (Amps) for its capacity.
    assert section.options == {"collapsed": True}
    assert [str(m) for m in section.schema.schema] == ["Main Panel", "Main Panel (Amps)"]
    kind, rating = list(section.schema.schema)
    # A main panel with its main breaker drawn or hidden, or a sub-panel,
    # which a load center is until said otherwise. Which way up it is drawn
    # is Leviton's to say, not a choice here.
    assert kind.default() == "sub"
    assert section.schema.schema[kind].config["translation_key"] == "panel_type"
    assert [o["value"] for o in section.schema.schema[kind].config["options"]] == ["main", "main_hidden", "sub"]
    assert isinstance(rating, vol.Optional)
    assert section.schema.schema[rating].config["unit_of_measurement"] == "A"
    # Not while the entry is not loaded and its load centers are unknown.
    assert _mains(await _flow(_entry({})).async_step_init()) is None


async def test_a_load_center_is_a_sub_panel_whichever_way_up_leviton_reports_it() -> None:
    coordinator = _two_load_centers()
    coordinator.data["panels"][0]["orientation"] = 180

    form = await _flow(_entry({}), coordinator).async_step_init()

    assert _suggested_mains(form) == {"Casita": "sub", "Casita (Amps)": None, "Main Panel": "sub", "Main Panel (Amps)": None}


async def test_panel_types_and_capacities_are_stored_by_load_center() -> None:
    entry = _entry(_stored_options())

    result = await _flow(entry, _two_load_centers()).async_step_init(
        {MAIN_BREAKERS: {"Casita": "sub", "Casita (Amps)": 100, "Main Panel": "main", "Main Panel (Amps)": 200}}
    )

    # Next to a capacity even a sub-panel is stored: a capacity without a
    # type is a main panel's, as the first test builds stored it.
    assert result["data"][MAIN_BREAKERS] == {
        "casita": {"rating": 100.0, "type": "sub"},
        "main": {"rating": 200.0, "type": "main"},
    }
    # Nothing else the form does not manage is lost with them.
    assert result["data"]["confirmed_solar_import_uids"] == CONFIRMED_SOLAR


async def test_a_main_panel_is_kept_without_a_capacity_and_a_sub_panel_is_not() -> None:
    result = await _flow(_entry({}), _two_load_centers()).async_step_init(
        {MAIN_BREAKERS: {"Casita": "sub", "Main Panel": "main_hidden"}}
    )

    assert result["data"][MAIN_BREAKERS] == {"main": {"type": "main_hidden"}}


async def test_a_main_panel_can_hide_its_main_breaker_and_keep_its_capacity() -> None:
    result = await _flow(_entry({}), _two_load_centers()).async_step_init(
        {MAIN_BREAKERS: {"Casita": "sub", "Main Panel": "main_hidden", "Main Panel (Amps)": 200}}
    )

    assert result["data"][MAIN_BREAKERS] == {"main": {"rating": 200.0, "type": "main_hidden"}}


async def test_the_first_test_builds_settings_keep_their_meaning() -> None:
    """A capacity alone, or a main breaker placed at the top or the bottom, was a main panel; "none", flipped or not, a sub-panel."""
    stored = {
        "main": {"rating": 200, "position": "bottom"},
        "casita": 100,  # a bare number, as the very first form stored it
    }
    form = await _flow(_entry({MAIN_BREAKERS: stored}), _two_load_centers()).async_step_init()
    assert _suggested_mains(form) == {"Casita": "main", "Casita (Amps)": 100, "Main Panel": "main", "Main Panel (Amps)": 200}

    expected = {"top": "main", "bottom": "main", "none": "sub", "none_flipped": "sub", None: "main"}
    for old, kind in expected.items():
        entry = {"rating": 200} if old is None else {"rating": 200, "position": old}
        form = await _flow(_entry({MAIN_BREAKERS: {"main": entry}}), _two_load_centers()).async_step_init()
        assert _suggested_mains(form)["Main Panel"] == kind, old


async def test_stored_capacity_is_suggested_and_can_be_emptied() -> None:
    entry = _entry({MAIN_BREAKERS: {"main": {"rating": 200, "type": "main"}, "casita": {"rating": 100, "type": "sub"}}})
    flow = _flow(entry, _two_load_centers())

    form = await flow.async_step_init()

    assert _mains(form).options == {"collapsed": False}
    assert _suggested_mains(form) == {"Casita": "sub", "Casita (Amps)": 100, "Main Panel": "main", "Main Panel (Amps)": 200}
    # The frontend leaves an emptied field out of the submission.
    result = await flow.async_step_init(
        form["data_schema"]({MAIN_BREAKERS: {"Casita": "sub", "Main Panel": "main", "Main Panel (Amps)": 225}})
    )
    assert result["data"][MAIN_BREAKERS] == {"main": {"rating": 225.0, "type": "main"}}


async def test_settings_of_a_load_center_leviton_no_longer_reports_are_kept() -> None:
    entry = _entry({MAIN_BREAKERS: {"gone": {"rating": 150, "position": "top"}, "main": 200}})

    result = await _flow(entry, _two_load_centers()).async_step_init(
        {MAIN_BREAKERS: {"Casita": "sub", "Main Panel": "sub", "Main Panel (Amps)": 200}}
    )

    # Kept as the type its old setting meant.
    assert result["data"][MAIN_BREAKERS] == {
        "gone": {"rating": 150.0, "type": "main"},
        "main": {"rating": 200.0, "type": "sub"},
    }


async def test_main_breakers_are_left_alone_without_their_section() -> None:
    """Not loaded, the form has no section; a submission without it changes nothing."""
    stored = {"main": {"rating": 200, "type": "main"}}
    entry = _entry({MAIN_BREAKERS: stored})

    for coordinator in (None, _two_load_centers()):
        result = await _flow(entry, coordinator).async_step_init({HA_INFORM_RATE: 30.0})
        assert result["data"][MAIN_BREAKERS] == stored


async def test_load_centers_with_the_same_name_get_their_own_main_breaker_fields() -> None:
    twins = SimpleNamespace(data={"panels": [{"id": "a", "name": "Panel"}, {"id": "b", "name": "Panel"}], "breakers": {}})

    form = await _flow(_entry({}), twins).async_step_init()

    assert [str(m) for m in _mains(form).schema.schema] == ["Panel", "Panel (Amps)", "Panel (b)", "Panel (b) (Amps)"]
    result = await _flow(_entry({}), twins).async_step_init(
        {MAIN_BREAKERS: {"Panel": "sub", "Panel (b)": "main", "Panel (b) (Amps)": 100}}
    )
    assert result["data"][MAIN_BREAKERS] == {"b": {"rating": 100.0, "type": "main"}}


async def test_refused_form_keeps_the_main_breakers_entered() -> None:
    flow = _flow(_entry({}), _two_load_centers())
    await flow.async_step_init()

    form = await flow.async_step_init(
        {
            "sub_panels": {"Casita": "main|38", "Main Panel": "casita|1"},
            MAIN_BREAKERS: {"Casita": "sub", "Main Panel": "main_hidden", "Main Panel (Amps)": 200},
        }
    )

    assert form["errors"] == {"base": "sub_panel_loop"}
    assert _suggested_mains(form) == {
        "Casita": "sub", "Casita (Amps)": None, "Main Panel": "main_hidden", "Main Panel (Amps)": 200
    }


def _config_flow(entry: ConfigEntry) -> ConfigFlow:
    flow = ConfigFlow()
    flow.hass = MagicMock()
    flow.hass.config_entries.async_get_entry.return_value = entry
    flow.handler = DOMAIN
    flow.flow_id = "flow-1"
    flow.context = {"source": "reauth", "entry_id": entry.entry_id}
    return flow


async def test_reauth_asks_for_the_login_only() -> None:
    """A re-authentication stores the new login and nothing else, so it shows nothing else."""
    entry = _entry({SHOW_SIDEBAR_PANEL: True})

    form = await _config_flow(entry).async_step_reauth(dict(entry.data))

    assert [str(m) for m in form["data_schema"].schema] == [CONF_USERNAME, CONF_PASSWORD]
    assert _marker(form, CONF_USERNAME).default() == "user@example.com"


async def _reauth_signed_in_as(entry: ConfigEntry, userid: str | None):
    """Finish a re-authentication whose sign-in returned this Leviton user id."""
    flow = _config_flow(entry)
    flow.hass.config_entries.async_reload = AsyncMock()
    await flow.async_step_reauth(dict(entry.data))
    flow.user_data.update({CONF_USERNAME: "user@example.com", CONF_PASSWORD: "new-secret"})
    flow.service = SimpleNamespace(userid=userid, refresh_token="new-token")
    return flow, await flow._finalize_entry("Leviton LDATA (user@example.com)")


async def test_reauth_into_another_account_is_refused() -> None:
    """Another account would make every device and entity a new one, so nothing is stored."""
    flow, result = await _reauth_signed_in_as(_entry({}), "user-2")

    assert result["type"] == "abort"
    assert result["reason"] == "wrong_account"
    flow.hass.config_entries.async_update_entry.assert_not_called()
    flow.hass.config_entries.async_reload.assert_not_called()


async def test_reauth_into_the_same_account_stores_the_new_login() -> None:
    flow, result = await _reauth_signed_in_as(_entry({}), "user-1")

    assert result["reason"] == "reauth_successful"
    data = flow.hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert data[CONF_PASSWORD] == "new-secret"
    assert data["refresh_token"] == "new-token"
    flow.hass.config_entries.async_reload.assert_awaited_once()


@pytest.mark.parametrize("stored, returned", [(None, "user-2"), ("user-1", None)])
async def test_reauth_without_both_user_ids_is_not_checked(stored, returned) -> None:
    """An entry from 1.x stores no user id, so there is nothing to compare."""
    entry = _entry({})
    object.__setattr__(entry, "data", MappingProxyType({**entry.data, "userid": stored}))

    _, result = await _reauth_signed_in_as(entry, returned)

    assert result["reason"] == "reauth_successful"


async def test_refused_first_setup_comes_back_as_it_was_filled_in() -> None:
    flow = _config_flow(_entry({}))
    flow.context = {"source": SOURCE_USER}
    flow._validate_input = MagicMock(side_effect=CannotConnect)
    answer = STEP_USER_DATA_SCHEMA(
        {
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "secret",
            THREE_PHASE: False,
            "allow_breaker_control": True,
            SHOW_SIDEBAR_PANEL: True,
        }
    )

    form = await flow.async_step_user(answer)

    assert form["errors"] == {"base": "cannot_connect"}
    assert _marker(form, SHOW_SIDEBAR_PANEL).default() is True
    assert _marker(form, THREE_PHASE).default() is False
