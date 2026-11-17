"""Null or missing names, pole counts and other fields can't stop the platforms loading.

Entity names are built from the breaker, panel, CT or Decora device name and
each breaker entity's leg from its pole count. One record with a null in
either (a breaker not yet set up in the Leviton app, for example) raised in
the entity constructor, and the whole platform failed to load.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from custom_components.ldata import (
    binary_sensor,
    button,
    fan,
    light,
    select,
    sensor,
    switch,
    update,
)
from custom_components.ldata.const import ALLOW_BREAKER_CONTROL, ALLOW_LED_BLINK, ENABLE_DECORA
from custom_components.ldata.ldata_service import LDATAService

PLATFORMS = [binary_sensor, button, fan, light, select, sensor, switch, update]


def _data() -> dict:
    service = LDATAService("", "", None)
    data = service.parse_panels([{
        "id": "1000_ABCD", "name": None, "model": "LWHEM", "ModuleType": "WHEMS", "connected": True,
        "rmsVoltage": 120.0, "rmsVoltage2": 120.0, "version": "2.0.0",
        "residentialBreakers": [
            # Only the id and model: every other key missing.
            {"id": "B1", "model": "LB120"},
            {"id": "B2", "model": "LB250", "name": None, "poles": None, "position": 3,
             "currentRating": None, "currentState": None, "serialNumber": None,
             "hwVersion": None, "firmwareVersionMeter": None, "canRemoteOn": None, "remoteState": None},
            # No id: nothing could key it, so it is left out.
            {"model": "LB120", "name": "Orphan"},
        ],
        "CTs": [{"id": 7, "usageType": None, "channel": 2}, {"usageType": "GRID"}],
    }])
    data["decora_devices"] = service.parse_decora_devices([
        {"id": 5, "model": "D26HD", "name": None, "mac": "AA:BB:CC:DD:EE:FF", "canSetLevel": True},
    ])
    data["rooms"] = {}
    return data


@pytest.mark.asyncio
async def test_every_platform_loads() -> None:
    data = _data()
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = data
    coordinator._service.panel_has_hw_counters.return_value = False
    config_entry = SimpleNamespace(
        entry_id="entry-1",
        data={},
        options={ALLOW_BREAKER_CONTROL: True, ALLOW_LED_BLINK: True, ENABLE_DECORA: True},
        subentries={},
    )
    hass = SimpleNamespace(data={"ldata": {config_entry.entry_id: coordinator}})
    entities: list = []

    with patch("custom_components.ldata.sensor.er.async_get", return_value=MagicMock(
        async_get_entity_id=MagicMock(return_value=None)
    )):
        for platform in PLATFORMS:
            await platform.async_setup_entry(hass, config_entry, entities.extend)

    names = {entity.name for entity in entities}
    assert "Breaker Watts" in names  # no name and no position
    assert "Breaker 3 Watts" in names  # no name, slot 3
    assert any(name.startswith("CT 2 ") for name in names)
    assert any(name.startswith("Unknown Panel ") for name in names)
    assert "Decora 5" in names
    assert set(data["breakers"]) == {"B1", "B2"}
    assert set(data["cts"]) == {"7"}


def test_defaults() -> None:
    data = _data()
    b1, b2 = data["breakers"]["B1"], data["breakers"]["B2"]
    assert b1["poles"] == 1 and b2["poles"] == 1
    assert b1["leg"] == 2  # unknown position: as before, not leg 1
    assert b2["canRemoteOn"] is False and b2["remoteState"] == "RemoteON"
    assert data["panels"][0]["name"] == "Unknown Panel"
    assert data["cts"]["7"]["name"] == "CT 2"
