"""Regression tests for LDATA breaker alarm entities."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from homeassistant.components.binary_sensor import BinarySensorDeviceClass

from custom_components.ldata.binary_sensor import (
    LDATABreakerOverVoltageSensor,
    async_setup_entry,
)


def _breaker() -> dict:
    return {
        "id": "breaker-1",
        "stable_id": "breaker-1",
        "name": "Kitchen",
        "panel_id": "panel-1",
        "model": "LB120-ST",
        "rating": 20,
        "position": 1,
        "poles": 1,
        "serialNumber": "test-serial",
        "hardware": "test-hardware",
        "firmware": "test-firmware",
        "state": "ManualON",
        "remoteState": "RemoteON",
        "overCurrent": False,
        "overVoltage": True,
        "underVoltage": False,
    }


def _coordinator(breaker: dict) -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"breakers": {breaker["id"]: breaker}}
    coordinator.async_add_listener.return_value = MagicMock()
    return coordinator


@pytest.mark.asyncio
async def test_setup_adds_over_voltage_sensor() -> None:
    breaker = _breaker()
    coordinator = _coordinator(breaker)
    config_entry = SimpleNamespace(
        entry_id="entry-1", data={}, options={}, subentries={}
    )
    hass = SimpleNamespace(data={"ldata": {config_entry.entry_id: coordinator}})
    entities = []

    await async_setup_entry(hass, config_entry, entities.extend)

    matching = [
        entity
        for entity in entities
        if isinstance(entity, LDATABreakerOverVoltageSensor)
    ]
    assert len(matching) == 1
    assert matching[0].is_on is True
    assert matching[0].device_class is BinarySensorDeviceClass.PROBLEM


def test_over_voltage_sensor_tracks_coordinator_updates() -> None:
    breaker = _breaker()
    coordinator = _coordinator(breaker)
    sensor = LDATABreakerOverVoltageSensor(coordinator, breaker)
    sensor.async_write_ha_state = MagicMock()

    coordinator.data["breakers"][breaker["id"]]["overVoltage"] = False
    sensor._state_update()

    assert sensor.is_on is False
    sensor.async_write_ha_state.assert_called_once_with()
