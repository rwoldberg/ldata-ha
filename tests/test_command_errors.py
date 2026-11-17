"""Failed commands raise HomeAssistantError instead of returning as if they worked.

Breaker on/off, blink LED and every Decora command logged a failure (or
nothing) and returned normally, so the UI showed no error and an automation
that tripped a breaker believed it had.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.exceptions import HomeAssistantError

from custom_components.ldata.button import DecoraIdentifyButton, DecoraSilenceBuzzerButton
from custom_components.ldata.fan import DecoraFan
from custom_components.ldata.ldata_service import LDATAAuthError
from custom_components.ldata.light import DecoraLight
from custom_components.ldata.select import AUTO_SHUTOFF_MAP, DecoraSelectEntity
from custom_components.ldata.switch import (
    DecoraBuzzerSwitch,
    DecoraSwitch,
    LDATABlinkLEDSwitch,
    LDATASwitch,
)

pytestmark = pytest.mark.asyncio

BREAKER = {
    "id": "b1", "stable_id": "b1", "name": "Dryer", "panel_id": "p1", "poles": 2, "position": 1,
    "model": "LB250", "firmware": "2", "state": "ManualON", "remoteState": "RemoteON", "blinkLED": False,
}
DEVICE = {
    "id": 5, "name": "Hall", "model": "D26HD", "mac": "AA", "connected": True, "power": "OFF",
    "brightness": 0, "canSetLevel": True, "residenceId": 9, "autoOffTime": 0, "enableBuzzer": False,
}


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("custom_components.ldata.fan.asyncio.sleep", AsyncMock())


def _coordinator() -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "u"
    coordinator.data = {"breakers": {"b1": dict(BREAKER)}, "decora_devices": {5: dict(DEVICE)}}
    coordinator.hass.async_add_executor_job = AsyncMock(side_effect=lambda func, *args: func(*args))
    coordinator.async_request_refresh = AsyncMock()
    return coordinator


def _ready(entity):
    entity.async_write_ha_state = MagicMock()
    return entity


# ── Breakers ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("method", "service_call"), [("async_turn_off", "remote_off"), ("async_turn_on", "remote_on")]
)
@pytest.mark.parametrize("failure", [None, LDATAAuthError("401")], ids=["not accepted", "auth"])
async def test_failed_breaker_command_raises(method, service_call, failure) -> None:
    coordinator = _coordinator()
    mock = getattr(coordinator.service, service_call)
    if isinstance(failure, Exception):
        mock.side_effect = failure
    else:
        mock.return_value = failure
    entity = _ready(LDATASwitch(coordinator, dict(BREAKER)))
    state = entity.is_on

    with pytest.raises(HomeAssistantError, match="Dryer Breaker"):
        await getattr(entity, method)()

    assert entity.is_on == state
    entity.async_write_ha_state.assert_called()  # the toggle snaps back


async def test_breaker_command_that_works_does_not_raise() -> None:
    coordinator = _coordinator()
    coordinator.service.remote_off.return_value = object()
    entity = _ready(LDATASwitch(coordinator, dict(BREAKER)))

    await entity.async_turn_off()

    assert entity.is_on is False


@pytest.mark.parametrize("method", ["async_turn_on", "async_turn_off"])
async def test_failed_blink_led_command_raises(method) -> None:
    coordinator = _coordinator()
    coordinator.service.set_blink_led.return_value = None
    entity = _ready(LDATABlinkLEDSwitch(coordinator, dict(BREAKER)))

    with pytest.raises(HomeAssistantError, match="Blink LED"):
        await getattr(entity, method)()


# ── Decora ───────────────────────────────────────────────────────────

DECORA_COMMANDS = {
    "light on": (DecoraLight, lambda e: e.async_turn_on()),
    "light off": (DecoraLight, lambda e: e.async_turn_off()),
    "fan on": (DecoraFan, lambda e: e.async_turn_on(percentage=50)),
    "fan off": (DecoraFan, lambda e: e.async_turn_off()),
    "fan speed": (DecoraFan, lambda e: e.async_set_percentage(25)),
    "switch on": (DecoraSwitch, lambda e: e.async_turn_on()),
    "switch off": (DecoraSwitch, lambda e: e.async_turn_off()),
    "buzzer on": (DecoraBuzzerSwitch, lambda e: e.async_turn_on()),
    "identify": (DecoraIdentifyButton, lambda e: e.async_press()),
    "silence": (DecoraSilenceBuzzerButton, lambda e: e.async_press()),
    "select": (
        lambda c, d: DecoraSelectEntity(
            c, d, api_field="autoOffTime", suffix="Auto Shutoff", icon_str="mdi:timer", option_map=AUTO_SHUTOFF_MAP
        ),
        lambda e: e.async_select_option("5 Minutes"),
    ),
}


@pytest.mark.parametrize(("make", "command"), DECORA_COMMANDS.values(), ids=DECORA_COMMANDS.keys())
@pytest.mark.parametrize("failure", [False, LDATAAuthError("401")], ids=["not accepted", "auth"])
async def test_failed_decora_command_raises(make, command, failure) -> None:
    coordinator = _coordinator()
    if isinstance(failure, Exception):
        coordinator.service.set_iot_switch.side_effect = failure
    else:
        coordinator.service.set_iot_switch.return_value = failure
    entity = _ready(make(coordinator, dict(DEVICE)))

    with pytest.raises(HomeAssistantError, match="Hall"):
        await command(entity)

    coordinator.async_request_refresh.assert_not_awaited()


@pytest.mark.parametrize(("make", "command"), DECORA_COMMANDS.values(), ids=DECORA_COMMANDS.keys())
async def test_decora_command_that_works_does_not_raise(make, command) -> None:
    coordinator = _coordinator()
    coordinator.service.set_iot_switch.return_value = True
    entity = _ready(make(coordinator, dict(DEVICE)))

    await command(entity)

    coordinator.service.set_iot_switch.assert_called_once()
    assert coordinator.service.set_iot_switch.call_args.args[:2] == (9, 5)


async def test_decora_command_for_a_missing_device_raises() -> None:
    coordinator = _coordinator()
    coordinator.data["decora_devices"] = {}
    entity = _ready(DecoraLight(coordinator, dict(DEVICE)))

    with pytest.raises(HomeAssistantError, match="not available"):
        await entity.async_turn_on()
    coordinator.service.set_iot_switch.assert_not_called()
