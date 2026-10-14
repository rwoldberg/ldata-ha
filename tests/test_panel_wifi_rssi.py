"""Tests for the panel Wi-Fi RSSI diagnostic sensor."""

from unittest.mock import MagicMock

from custom_components.ldata.sensor import LDATAPanelWifiRSSISensor


def _panel(rssi, panel_type="LDATA") -> dict:
    return {
        "id": "LDATA-panel-1",
        "name": "Panel",
        "serialNumber": "LDATA-panel-1",
        "model": "LDATA",
        "firmware": "1.0",
        "panel_type": panel_type,
        "rssi": rssi,
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


def test_wired_panel_without_rssi_is_unavailable() -> None:
    sensor, _ = _sensor(_panel(None))

    assert sensor.available is False
    assert sensor.native_value is None


def test_wifi_panel_with_rssi_is_available() -> None:
    sensor, _ = _sensor(_panel(-61.4))

    assert sensor.available is True
    assert sensor.native_value == -61


def test_whems_panel_rssi_tracks_coordinator_updates() -> None:
    panel = _panel(-70.0, panel_type="WHEMS")
    sensor, coordinator = _sensor(panel)

    coordinator.data["panels"][0] = {**panel, "rssi": -55.0}
    sensor._state_update()

    assert sensor.available is True
    assert sensor.native_value == -55


def test_rssi_sensor_becomes_available_when_rssi_arrives() -> None:
    panel = _panel(None)
    sensor, coordinator = _sensor(panel)
    assert sensor.available is False

    coordinator.data["panels"][0] = {**panel, "rssi": -48.0}
    sensor._state_update()

    assert sensor.available is True
    assert sensor.native_value == -48


def test_rssi_sensor_unavailable_when_coordinator_update_fails() -> None:
    sensor, coordinator = _sensor(_panel(-60.0))
    coordinator.last_update_success = False

    assert sensor.available is False
