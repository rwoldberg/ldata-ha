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


def test_trip_cause_and_protection_reach_the_panel_card() -> None:
    """The card draws a breaker's AF/GF LEDs from two things it is given.

    The catalog number says which protection the breaker has (LB120-GST is a
    GFCI), and Leviton's own state name says what tripped it. Both have to
    arrive unchanged, and a trip must never read as "on".
    """
    from custom_components.ldata.binary_sensor import LDATABinarySensor
    from custom_components.ldata.ldata_base_entity import is_breaker_on

    payload = {
        **_breaker_payload(),
        "model": "LB120-GST",
        "poles": 1,
        "currentState": "GFCIFault",
        "currentState2": "",
    }
    panel = {
        "id": "panel-test",
        "name": "Test Panel",
        "updateVersion": "2.1.0",
        "residentialBreakers": [payload],
    }

    breaker = _service().parse_panels([panel])["breakers"]["breaker-test"]

    assert breaker["model"] == "LB120-GST"
    assert breaker["state"] == "GFCIFault"
    assert is_breaker_on(breaker) is False

    state = sensor.LDATABreakerStateSensor(FakeCoordinator(breaker), breaker)
    assert state.native_value == "GFCIFault"

    status = LDATABinarySensor(FakeCoordinator(breaker), breaker)
    assert status.extra_state_attributes["model"] == "LB120-GST"


def test_second_pole_operational_state_reaches_the_sensor() -> None:
    """A 2-pole breaker reports each pole's health; the second pole's is kept.

    Leviton's app shows operationalState2 as the breaker's status when only
    the second pole has failed.
    """
    payload = {
        **_breaker_payload(),
        "operationalState": "Normal",
        "operationalState2": "GFCIErrorPhase2Failed",
    }
    panel = {
        "id": "panel-test",
        "name": "Test Panel",
        "updateVersion": "2.1.0",
        "residentialBreakers": [payload],
    }
    service = _service()
    breaker = service.parse_panels([panel])["breakers"]["breaker-test"]

    assert breaker["operationalState"] == "Normal"
    assert breaker["operationalState2"] == "GFCIErrorPhase2Failed"

    coordinator = FakeCoordinator(breaker)
    entity = sensor.LDATABreakerOperationalStateSensor(coordinator, breaker)
    # The breaker's state is the failed pole's, so an automation watching it
    # sees the fault.
    assert entity.native_value == "GFCIErrorPhase2Failed"
    # Next to the leg every breaker entity reports.
    assert entity.extra_state_attributes == {"leg": "both", "second_pole_state": "GFCIErrorPhase2Failed"}
    assert entity.icon == "mdi:alert-circle"

    # A live update can clear it again.
    entity.async_write_ha_state = MagicMock()
    service._apply_breaker_update("breaker-test", breaker, {"operationalState2": "Normal"}, source="WS")
    entity._state_update()
    assert entity.native_value == "Normal"
    assert entity.extra_state_attributes == {"leg": "both", "second_pole_state": "Normal"}
    assert entity.icon == "mdi:check-circle-outline"


def test_first_pole_fault_is_the_breakers_state() -> None:
    """A fault on the first pole stays the state, whatever the second says."""
    payload = {
        **_breaker_payload(),
        "operationalState": "AFCIGFCISelfTestFailure",
        "operationalState2": "GFCIErrorPhase2Failed",
    }
    breaker = _service().parse_panels(
        [{"id": "panel-test", "name": "Test Panel", "updateVersion": "2.1.0", "residentialBreakers": [payload]}]
    )["breakers"]["breaker-test"]

    entity = sensor.LDATABreakerOperationalStateSensor(FakeCoordinator(breaker), breaker)

    assert entity.native_value == "AFCIGFCISelfTestFailure"
    assert entity.icon == "mdi:alert-circle"
    # A second pole with nothing to say is no fault.
    entity._state, entity._second = "Normal", "UNDEFINED"
    assert entity.native_value == "Normal"
    assert entity.icon == "mdi:check-circle-outline"


def test_one_pole_breaker_has_no_second_pole_operational_state() -> None:
    payload = {**_breaker_payload(), "poles": 1, "operationalState": "Normal", "operationalState2": ""}
    panel = {
        "id": "panel-test",
        "name": "Test Panel",
        "updateVersion": "2.1.0",
        "residentialBreakers": [payload],
    }
    breaker = _service().parse_panels([panel])["breakers"]["breaker-test"]

    entity = sensor.LDATABreakerOperationalStateSensor(FakeCoordinator(breaker), breaker)
    assert entity.extra_state_attributes == {"leg": "1", "second_pole_state": None}
    assert entity.icon == "mdi:check-circle-outline"
