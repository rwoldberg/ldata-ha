"""Tests for the reset_panel_energy service's panel and device lookup."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from custom_components import ldata
from custom_components.ldata.const import DOMAIN

PANEL_ID = "LDATA-PANEL-1"
OTHER_PANEL_ID = "LDATA-PANEL-2"


class _Coordinator:
    def __init__(self, data):
        self.data = data


def _breaker(stable_id, serial, panel_id=PANEL_ID, raw_id=None):
    return {
        "id": raw_id or stable_id,
        "stable_id": stable_id,
        "serialNumber": serial,
        "panel_id": panel_id,
    }


DATA = {
    "panels": [
        {"id": PANEL_ID, "serialNumber": PANEL_ID},
        {"id": OTHER_PANEL_ID, "serialNumber": OTHER_PANEL_ID},
    ],
    "breakers": {
        "BRK000000001": _breaker("BRK000000001", "SER001"),
        "BRK000000002_0001": _breaker(
            "BRK000000002", "SER002", raw_id="BRK000000002_0001"
        ),
        "BRK000000003": _breaker("BRK000000003", "SER003", panel_id=OTHER_PANEL_ID),
    },
    "cts": {"1": {"panel_id": PANEL_ID}},
}


def _device(device_id, *identifiers):
    return SimpleNamespace(
        id=device_id,
        name=device_id,
        identifiers={(DOMAIN, *identifier) for identifier in identifiers},
    )


def _entity(entity_id, device_id):
    return SimpleNamespace(entity_id=entity_id, domain="sensor", device_id=device_id)


async def _reset(target_device_id):
    """Run the service against a registry with current breaker devices."""
    devices = {
        device.id: device
        for device in (
            _device("panel", (PANEL_ID,)),
            _device("garage_outlets", ("BRK000000001",)),
            _device("dryer", ("BRK000000002",)),
            _device("other-panel-breaker", ("BRK000000003",)),
            _device("ct", (PANEL_ID, "1")),
        )
    }
    entities = [
        _entity("sensor.panel_daily", "panel"),
        _entity("sensor.garage_outlets_daily", "garage_outlets"),
        _entity("sensor.dryer_daily", "dryer"),
        _entity("sensor.other_daily", "other-panel-breaker"),
        _entity("sensor.ct_daily", "ct"),
    ]
    dev_reg = MagicMock()
    dev_reg.async_get.side_effect = devices.get
    hass = MagicMock()
    hass.data = {DOMAIN: {"entry-1": _Coordinator(DATA), "_frontend_registered": True}}
    reset = MagicMock(side_effect=lambda _entity, entity_id: entity_id)

    with (
        patch.object(ldata, "LDATAUpdateCoordinator", _Coordinator),
        patch.object(ldata.dr, "async_get", return_value=dev_reg),
        patch.object(ldata.er, "async_get", return_value=MagicMock()),
        patch.object(ldata.er, "async_entries_for_config_entry", return_value=entities),
        patch.object(
            ldata,
            "_get_sensor_entity",
            return_value=SimpleNamespace(_accept_next_value=False),
        ),
        patch.object(ldata, "_reset_energy_entity", reset),
    ):
        await ldata._async_reset_panel_energy(hass, target_device_id)
    return sorted(call.args[1] for call in reset.call_args_list)


PANEL_1_SENSORS = [
    "sensor.ct_daily",
    "sensor.dryer_daily",
    "sensor.garage_outlets_daily",
    "sensor.panel_daily",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["panel", "garage_outlets", "dryer", "ct"])
async def test_reset_covers_the_panel_and_its_breakers(target) -> None:
    assert await _reset(target) == PANEL_1_SENSORS


@pytest.mark.asyncio
async def test_reset_from_a_breaker_resolves_its_own_panel() -> None:
    assert await _reset("other-panel-breaker") == ["sensor.other_daily"]


@pytest.mark.parametrize(
    ("identifier", "panel_id"),
    [
        ("BRK000000001", PANEL_ID),  # stable_id
        ("BRK000000002_0001", PANEL_ID),  # raw id, before stable_id
        ("SER001", PANEL_ID),  # serialNumber, before 2.0.9
        ("SER003", OTHER_PANEL_ID),
        (PANEL_ID, PANEL_ID),
        ("UNKNOWN", None),
    ],
)
def test_resolve_panel_id(identifier, panel_id) -> None:
    coordinators = [_Coordinator(DATA)]
    assert (
        ldata._resolve_reset_panel_id({(DOMAIN, identifier)}, coordinators)
        == panel_id
    )


def test_id_match_wins_over_a_serial_match() -> None:
    # Serial numbers are not unique: a serial equal to another breaker's
    # stable_id must not decide the panel.
    data = {
        "panels": [],
        "breakers": {
            "A": _breaker("A", "B", panel_id=PANEL_ID),
            "B": _breaker("B", "X", panel_id=OTHER_PANEL_ID),
        },
    }
    assert (
        ldata._resolve_reset_panel_id({(DOMAIN, "B")}, [_Coordinator(data)])
        == OTHER_PANEL_ID
    )


def test_panel_device_identifiers_include_every_breaker_key() -> None:
    identifiers = ldata._panel_device_identifiers(PANEL_ID, [_Coordinator(DATA)])

    assert identifiers == {
        (DOMAIN, PANEL_ID),
        (DOMAIN, "BRK000000001"),
        (DOMAIN, "SER001"),
        (DOMAIN, "BRK000000002"),
        (DOMAIN, "BRK000000002_0001"),
        (DOMAIN, "SER002"),
        (DOMAIN, PANEL_ID, "1"),
    }
