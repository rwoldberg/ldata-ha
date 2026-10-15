"""Tests for the panel Wi-Fi RSSI diagnostic sensor."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from custom_components.ldata.sensor import (
    LDATAPanelWifiRSSISensor,
    async_setup_entry,
)

RSSI_UID = "test-user-ldata_LDATA-panel-1_wifi_rssi"


def _panel(rssi, panel_type="LDATA") -> dict:
    return {
        "id": "LDATA-panel-1",
        "name": "Panel",
        "serialNumber": "LDATA-panel-1",
        "model": "LDATA",
        "firmware": "1.0",
        "panel_type": panel_type,
        "rssi": rssi,
        "voltage": 240.0,
        "voltage1": 120.0,
        "voltage2": 120.0,
        "frequency": 60.0,
        "frequency1": 60.0,
        "frequency2": 60.0,
    }


def _sensor(panel: dict) -> tuple[LDATAPanelWifiRSSISensor, MagicMock]:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.last_update_success = True
    coordinator.data = {"panels": [panel]}
    coordinator.async_add_listener.return_value = MagicMock()
    entity_data = {
        "id": panel["serialNumber"],
        "name": panel["name"],
        "serialNumber": panel["serialNumber"],
        "model": panel["model"],
        "hardware": "LDATA",
        "firmware": panel["firmware"],
        "poles": 2,
        "data": panel,
    }
    sensor = LDATAPanelWifiRSSISensor(coordinator, entity_data)
    sensor.async_write_ha_state = MagicMock()
    return sensor, coordinator


def _registry(existing: dict[str, str]) -> MagicMock:
    registry = MagicMock()
    registry.async_get_entity_id.side_effect = (
        lambda domain, platform, uid: existing.get(uid)
    )
    return registry


async def _setup(panel: dict, registry: MagicMock) -> list:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"panels": [panel]}
    coordinator.async_add_listener.return_value = MagicMock()
    config_entry = SimpleNamespace(
        entry_id="entry-1", data={}, options={}, subentries={}
    )
    hass = SimpleNamespace(data={"ldata": {config_entry.entry_id: coordinator}})
    entities: list = []
    with patch(
        "custom_components.ldata.sensor.er.async_get", return_value=registry
    ):
        await async_setup_entry(hass, config_entry, entities.extend)
    return [e for e in entities if isinstance(e, LDATAPanelWifiRSSISensor)]


@pytest.mark.asyncio
async def test_setup_skips_rssi_sensor_for_wired_ldata_panel() -> None:
    registry = _registry({})

    assert await _setup(_panel(None), registry) == []
    registry.async_remove.assert_not_called()


@pytest.mark.asyncio
async def test_setup_removes_stale_rssi_entity_for_wired_ldata_panel() -> None:
    registry = _registry({RSSI_UID: "sensor.panel_wifi_signal"})

    assert await _setup(_panel(None), registry) == []
    registry.async_remove.assert_called_once_with("sensor.panel_wifi_signal")


@pytest.mark.asyncio
async def test_setup_creates_rssi_sensor_for_wifi_ldata_panel() -> None:
    registry = _registry({RSSI_UID: "sensor.panel_wifi_signal"})

    sensors = await _setup(_panel(-61.4), registry)

    assert len(sensors) == 1
    assert sensors[0].unique_id == RSSI_UID
    assert sensors[0].native_value == -61
    registry.async_remove.assert_not_called()


@pytest.mark.asyncio
async def test_setup_creates_rssi_sensor_for_whems_panel_without_rssi() -> None:
    registry = _registry({RSSI_UID: "sensor.panel_wifi_signal"})

    sensors = await _setup(_panel(None, panel_type="WHEMS"), registry)

    assert len(sensors) == 1
    registry.async_remove.assert_not_called()


def test_whems_panel_rssi_tracks_coordinator_updates() -> None:
    panel = _panel(-70.0, panel_type="WHEMS")
    sensor, coordinator = _sensor(panel)

    coordinator.data["panels"][0] = {**panel, "rssi": -55.0}
    sensor._state_update()

    assert sensor.native_value == -55


def test_rssi_sensor_reports_rssi_when_it_arrives() -> None:
    panel = _panel(None, panel_type="WHEMS")
    sensor, coordinator = _sensor(panel)
    assert sensor.native_value is None

    coordinator.data["panels"][0] = {**panel, "rssi": -48.0}
    sensor._state_update()

    assert sensor.available is True
    assert sensor.native_value == -48


def test_rssi_sensor_unavailable_when_coordinator_update_fails() -> None:
    sensor, coordinator = _sensor(_panel(-60.0))
    coordinator.last_update_success = False

    assert sensor.available is False


def test_rssi_sensor_clears_value_when_rssi_cleared() -> None:
    panel = _panel(-58.0)
    sensor, coordinator = _sensor(panel)

    coordinator.data["panels"][0] = {**panel, "rssi": None}
    sensor._state_update()

    assert sensor.available is True
    assert sensor.native_value is None


def test_rssi_sensor_keeps_state_when_panel_missing() -> None:
    sensor, coordinator = _sensor(_panel(-58.0))

    coordinator.data["panels"] = []
    sensor._state_update()

    assert sensor.available is True
    assert sensor.native_value == -58
