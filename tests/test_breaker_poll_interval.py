"""The breaker REST poll has its own interval, not the HA inform rate."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.ldata import coordinator as coordinator_module
from custom_components.ldata.const import BREAKER_POLL_INTERVAL, HA_INFORM_RATE
from custom_components.ldata.coordinator import LDATAUpdateCoordinator


def _coordinator(options: dict) -> LDATAUpdateCoordinator:
    def _no_task(_hass, coro, _name):
        coro.close()

    entry = MagicMock()
    entry.options = options
    entry.async_create_background_task.side_effect = _no_task
    return LDATAUpdateCoordinator(MagicMock(), "user@example.com", "secret", entry)


@pytest.mark.parametrize(
    ("inform_rate", "expected"),
    [
        (2.0, BREAKER_POLL_INTERVAL),  # the minimum inform rate no longer drives the poll
        (None, BREAKER_POLL_INTERVAL),  # default inform rate: as often as before
        (600.0, 600.0),  # results only reach HA at the next push
    ],
)
def test_breaker_poll_interval(inform_rate, expected) -> None:
    options = {} if inform_rate is None else {HA_INFORM_RATE: inform_rate}
    assert _coordinator(options)._breaker_poll_interval() == expected


def test_interval_is_a_minute() -> None:
    assert BREAKER_POLL_INTERVAL == 60.0


@pytest.mark.asyncio
async def test_rest_poll_loop_uses_its_own_interval(monkeypatch) -> None:
    coordinator = _coordinator({HA_INFORM_RATE: 2.0})
    coordinator._service.status_data = {"panels": []}
    coordinator._fallback_poll_loop = AsyncMock()
    monkeypatch.setattr(coordinator_module.asyncio, "sleep", AsyncMock())

    await coordinator._rest_poll_loop()

    get_interval = coordinator._fallback_poll_loop.await_args.kwargs["get_interval"]
    assert get_interval() == BREAKER_POLL_INTERVAL
