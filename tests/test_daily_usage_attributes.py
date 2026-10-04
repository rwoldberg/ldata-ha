"""The daily energy sensors must not publish a timestamp that changes every update."""

from unittest.mock import MagicMock

from custom_components.ldata.sensor import (
    LDATACTDailyUsageSensor,
    LDATADailyUsageSensor,
)


def _coordinator() -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {}
    coordinator.async_add_listener.return_value = MagicMock()
    return coordinator


def test_breaker_daily_sensor_has_no_update_timestamp() -> None:
    data = {"id": "breaker-1", "name": "Kitchen", "poles": 1, "position": 1}
    sensor = LDATADailyUsageSensor(_coordinator(), data, False, "panel-1")
    # What used to leak into the attributes on every update.
    sensor._last_update_time = 1759140000.0

    attributes = sensor.extra_state_attributes

    assert "last_update_time" not in attributes
    # The attributes restore relies on are still published.
    assert "midnight_baseline" in attributes
    assert "last_date" in attributes


def test_ct_daily_sensor_has_no_update_timestamp() -> None:
    data = {"id": "ct-1", "panel_id": "panel-1", "name": "Grid", "channel": 1}
    sensor = LDATACTDailyUsageSensor(_coordinator(), data)
    sensor._last_update_time = 1759140000.0

    attributes = sensor.extra_state_attributes

    assert "last_update_time" not in attributes
    assert attributes["energy_key"] == "consumption"
    assert "midnight_baseline" in attributes
    assert "last_date" in attributes
