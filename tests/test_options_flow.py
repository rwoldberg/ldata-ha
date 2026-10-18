"""Tests that saving the options form keeps the options it does not manage."""

from types import MappingProxyType, SimpleNamespace
from unittest.mock import MagicMock

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from custom_components.ldata.config_flow import OptionsFlow
from custom_components.ldata.const import (
    DOMAIN,
    GAP_HANDLING,
    GAP_HANDLING_AVERAGE,
    GAP_THRESHOLD,
    HA_INFORM_RATE,
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
