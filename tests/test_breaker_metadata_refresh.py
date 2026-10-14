"""Tests that breaker metadata follows coordinator data after setup."""

from unittest.mock import MagicMock

from custom_components.ldata.binary_sensor import LDATABinarySensor
from custom_components.ldata.ldata_service import LDATAService


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
        "serialNumber": "serial-1",
        "hardware": "hw-1",
        "firmware": "1.0.0",
        "canRemoteOn": False,
        "state": "ManualON",
        "remoteState": "RemoteON",
    }


def _coordinator(breaker: dict) -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"breakers": {breaker["id"]: breaker}}
    coordinator.async_add_listener.return_value = MagicMock()
    return coordinator


def test_status_attributes_follow_replaced_coordinator_breaker() -> None:
    breaker = _breaker()
    coordinator = _coordinator(breaker)
    sensor = LDATABinarySensor(coordinator, breaker)

    # Refresh paths replace the breaker dict (copy-on-write), so the
    # constructor's dict no longer sees the new values.
    coordinator.data["breakers"]["breaker-1"] = {
        **breaker,
        "firmware": "2.0.0",
        "hardware": "hw-2",
        "rating": 15,
        "model": "LB115-DST",
        "serialNumber": "serial-2",
        "canRemoteOn": True,
    }

    attrs = sensor.extra_state_attributes
    assert attrs["firmware"] == "2.0.0"
    assert attrs["hardware"] == "hw-2"
    assert attrs["rating"] == 15
    assert attrs["model"] == "LB115-DST"
    assert attrs["serialNumber"] == "serial-2"
    assert attrs["canRemoteOn"] is True


def test_status_attributes_fall_back_when_breaker_missing() -> None:
    breaker = _breaker()
    coordinator = _coordinator(breaker)
    sensor = LDATABinarySensor(coordinator, breaker)

    coordinator.data = {"breakers": {}}

    attrs = sensor.extra_state_attributes
    assert attrs["firmware"] == "1.0.0"
    assert attrs["hardware"] == "hw-1"
    assert attrs["rating"] == 20
    assert attrs["canRemoteOn"] is False


def test_breaker_update_refreshes_metadata() -> None:
    service = LDATAService("", "", None)
    existing = _breaker()

    service._apply_breaker_update(
        "breaker-1",
        existing,
        {
            "firmwareVersionMeter": "2.0.0",
            "hwVersion": "hw-2",
            "currentRating": 15,
            "canRemoteOn": True,
        },
        source="REST",
    )

    assert existing["firmware"] == "2.0.0"
    assert existing["hardware"] == "hw-2"
    assert existing["rating"] == 15
    assert existing["canRemoteOn"] is True


def test_partial_breaker_update_keeps_metadata() -> None:
    service = LDATAService("", "", None)
    existing = _breaker()

    service._apply_breaker_update(
        "breaker-1",
        existing,
        {"power": 100.0, "firmwareVersionMeter": None},
        source="WS",
    )

    assert existing["firmware"] == "1.0.0"
    assert existing["hardware"] == "hw-1"
    assert existing["rating"] == 20
    assert existing["model"] == "LB120-ST"
