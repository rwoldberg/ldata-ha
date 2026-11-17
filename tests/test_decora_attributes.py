"""Decora entities carry only their room as an attribute.

Signal strength (it has its own sensor) and the LAN address were attributes
of every entity of a device, so each signal change recorded a new state row
for all of them, and the LAN address went into the recorder's history.
"""

from unittest.mock import MagicMock

import pytest

from custom_components.ldata.decora_entity import DecoraEntity
from custom_components.ldata.fan import DecoraFan
from custom_components.ldata.light import DecoraLight
from custom_components.ldata.switch import DecoraSwitch

DEVICE = {
    "id": 5, "name": "Hall", "model": "D26HD", "mac": "AA:BB:CC:DD:EE:FF", "connected": True,
    "rssi": -61, "localIP": "192.168.1.23", "roomName": "Hallway", "power": "ON", "brightness": 40,
    "canSetLevel": True,
}


def _coordinator(device: dict) -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "u"
    coordinator.data = {"decora_devices": {5: device}}
    return coordinator


@pytest.mark.parametrize("entity_class", [DecoraEntity, DecoraLight, DecoraFan, DecoraSwitch])
def test_only_the_room(entity_class) -> None:
    entity = entity_class(coordinator=_coordinator(dict(DEVICE)), data=dict(DEVICE))
    assert entity.extra_state_attributes == {"room": "Hallway"}


def test_no_room_no_attributes() -> None:
    device = {**DEVICE, "roomName": None}
    entity = DecoraEntity(coordinator=_coordinator(device), data=device)
    assert entity.extra_state_attributes == {}


def test_signal_changes_leave_the_attributes_alone() -> None:
    device = dict(DEVICE)
    coordinator = _coordinator(device)
    entity = DecoraLight(coordinator, dict(DEVICE))
    before = entity.extra_state_attributes

    device["rssi"] = -75
    assert entity.extra_state_attributes == before
