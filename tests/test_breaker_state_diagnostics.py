"""Focused tests for raw breaker-state diagnostics."""

from unittest.mock import MagicMock

from custom_components.ldata import sensor
from custom_components.ldata.ldata_service import LDATAService


class FakeCoordinator:
    """Minimal coordinator used by the diagnostic entity tests."""

    def __init__(self, breaker: dict) -> None:
        self.data = {"breakers": {breaker["id"]: breaker}}
        self.last_update_success = True
        self.user = "test-user"

    def async_add_listener(self, update_callback, context=None):
        return lambda: None


def _service() -> LDATAService:
    return LDATAService("", "", None)


def _breaker_payload() -> dict:
    return {
        "id": "breaker-test",
        "name": "Test Circuit",
        "model": "LB120-DST",
        "currentRating": 20,
        "position": 1,
        "poles": 2,
        "serialNumber": "not-exposed",
        "hwVersion": "1",
        "firmwareVersionMeter": "2",
        "canRemoteOn": True,
        "currentState": "Tripped",
        "currentState2": "ManualON",
        "currentStatePrev": "ManualON",
        "currentStatePrev2": "ManualON",
        "chgReason": "OverCurrent",
        "remoteState": "RemoteON",
        "meterChipOk": True,
        "locked": False,
        "branchType": "Outlets",
        "critical": True,
        "critical2": False,
    }


def test_rest_parse_preserves_breaker_state_diagnostics() -> None:
    panel = {
        "id": "panel-test",
        "name": "Test Panel",
        "updateVersion": "2.1.0",
        "residentialBreakers": [_breaker_payload()],
    }

    breaker = _service().parse_panels([panel])["breakers"]["breaker-test"]

    assert breaker["state"] == "Tripped"
    assert breaker["state2"] == "ManualON"
    assert breaker["previous_state"] == "ManualON"
    assert breaker["previous_state2"] == "ManualON"
    assert breaker["change_reason"] == "OverCurrent"
    assert breaker["remoteState"] == "RemoteON"
    assert breaker["meter_chip_ok"] is True
    assert breaker["locked"] is False
    assert breaker["branch_type"] == "Outlets"
    assert breaker["critical"] is True
    assert breaker["critical2"] is False


def test_partial_update_preserves_breaker_state_diagnostics() -> None:
    service = _service()
    breaker = {
        "leg": 1,
        "poles": 2,
        "state": "ManualON",
        "state2": "ManualON",
        "previous_state": "ManualOFF",
        "previous_state2": "ManualOFF",
        "change_reason": None,
        "remoteState": "RemoteON",
        "meter_chip_ok": True,
        "locked": False,
        "branch_type": "Outlets",
        "critical": False,
        "critical2": False,
    }

    service._apply_breaker_update(
        "breaker-test",
        breaker,
        {
            "currentState": "Tripped",
            "currentState2": "Tripped",
            "currentStatePrev": "ManualON",
            "currentStatePrev2": "ManualON",
            "chgReason": "GroundFault",
            "remoteState": "RemoteOFF",
            "meterChipOk": False,
            "locked": True,
            "branchType": "Kitchen",
            "critical": True,
            "critical2": True,
        },
        source="WS",
    )

    assert breaker == {
        "leg": 1,
        "poles": 2,
        "state": "Tripped",
        "state2": "Tripped",
        "previous_state": "ManualON",
        "previous_state2": "ManualON",
        "change_reason": "GroundFault",
        "remoteState": "RemoteOFF",
        "meter_chip_ok": False,
        "locked": True,
        "branch_type": "Kitchen",
        "critical": True,
        "critical2": True,
    }


def test_state_sensor_exposes_only_safe_trip_diagnostics() -> None:
    breaker = {
        "id": "breaker-private-id",
        "stable_id": "breaker-private-stable-id",
        "serialNumber": "breaker-private-serial",
        "name": "Test Circuit",
        "model": "LB240-0ST",
        "firmware": "2",
        "position": 1,
        "poles": 2,
        "connected": False,
        "state": "Tripped",
        "state2": "Tripped",
        "previous_state": "ManualON",
        "previous_state2": "ManualON",
        "change_reason": "GroundFault",
        "remoteState": "RemoteOFF",
        "meter_chip_ok": False,
        "locked": True,
        "branch_type": "Kitchen",
        "critical": True,
        "critical2": True,
        "account_id": "private-account",
    }
    coordinator = FakeCoordinator(breaker)

    entity = sensor.LDATABreakerStateSensor(coordinator, breaker)

    assert entity.native_value == "Tripped"
    assert entity.available is True
    assert entity.name_suffix == "Breaker State"
    assert entity.unique_id_suffix == "breaker_state"
    assert entity.extra_state_attributes == {
        "second_pole_state": "Tripped",
        "previous_state": "ManualON",
        "previous_second_pole_state": "ManualON",
        "change_reason": "GroundFault",
        "remote_state": "RemoteOFF",
        "meter_chip_ok": False,
        "locked": True,
        "branch_type": "Kitchen",
        "critical": True,
        "critical_second_pole": True,
    }


def test_state_sensor_uses_coordinator_lifecycle_and_clears_missing_breaker() -> None:
    breaker = {
        "id": "breaker-test",
        "stable_id": "breaker-test",
        "name": "Test Circuit",
        "model": "LB120-ST",
        "firmware": "2",
        "position": 1,
        "poles": 1,
        "state": "ManualON",
    }
    coordinator = FakeCoordinator(breaker)
    entity = sensor.LDATABreakerStateSensor(coordinator, breaker)
    entity.async_write_ha_state = MagicMock()

    coordinator.data["breakers"][breaker["id"]] = {
        **breaker,
        "state": "SoftwareTrip",
    }
    entity._handle_coordinator_update()
    assert entity.native_value == "SoftwareTrip"

    coordinator.data["breakers"] = {}
    entity._handle_coordinator_update()
    assert entity.native_value is None
    assert all(value is None for value in entity.extra_state_attributes.values())
