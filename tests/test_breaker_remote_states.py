"""A breaker is on or off by Leviton's remoteState, read the way the My Leviton app reads it."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from custom_components.ldata.binary_sensor import LDATABinarySensor
from custom_components.ldata.ldata_base_entity import is_breaker_on
from custom_components.ldata.switch import LDATASwitch

# Every breakerRemoteState in the app, and whether it shows the power as on.
REMOTE_STATES = {
    "RemoteON": True,
    "RemoteOFF": False,
    "RemoteERROR": True,
    "RemoteOVERVOLTAGE": True,
    "RemoteOVERVOLTAGEON": False,
    "RemoteOVERVOLTAGEOFF": True,
    "RemotePENDINGON": True,
    "RemotePENDINGOFF": False,
    "RemoteFAILEDON": False,
    "RemoteFAILEDOFF": True,
    "UNKNOWN": True,
}


@pytest.mark.parametrize(("remote_state", "on"), REMOTE_STATES.items())
def test_remote_state_decides_power_like_the_app(remote_state: str, on: bool) -> None:
    assert is_breaker_on({"state": "ManualON", "remoteState": remote_state}) is on


@pytest.mark.parametrize("remote_state", REMOTE_STATES)
def test_a_breaker_not_manually_on_is_off(remote_state: str) -> None:
    for state in ("ManualOFF", "GFCIFault", "OverloadTrip", "NotCommunicating", None):
        assert is_breaker_on({"state": state, "remoteState": remote_state}) is False


def test_missing_remote_state_is_off() -> None:
    assert is_breaker_on({"state": "ManualON"}) is False


def _breaker(remote_state: str) -> dict:
    return {
        "id": "breaker-1",
        "stable_id": "breaker-1",
        "name": "Dryer",
        "panel_id": "panel-1",
        "model": "LB230-ST",
        "position": 3,
        "poles": 2,
        "serialNumber": "test-serial",
        "hardware": "test-hardware",
        "firmware": "test-firmware",
        "state": "ManualON",
        "remoteState": remote_state,
    }


def _coordinator(breaker: dict) -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"breakers": {breaker["id"]: breaker}}
    coordinator.async_add_listener.return_value = MagicMock()
    return coordinator


def test_switch_and_status_follow_a_failed_switch_off() -> None:
    # Leviton could not switch the breaker off: the power is still on.
    breaker = _breaker("RemoteFAILEDOFF")
    coordinator = _coordinator(breaker)

    assert LDATASwitch(coordinator, breaker).is_on is True
    assert LDATABinarySensor(coordinator, breaker).is_on is True


def test_switch_follows_over_voltage_switch_off() -> None:
    breaker = _breaker("RemoteON")
    coordinator = _coordinator(breaker)
    switch = LDATASwitch(coordinator, breaker)
    switch.async_write_ha_state = MagicMock()

    coordinator.data["breakers"]["breaker-1"] = {**breaker, "remoteState": "RemoteOVERVOLTAGEON"}
    switch._state_update()

    assert switch.is_on is False
