"""Tests that coordinator shutdown also stops DataUpdateCoordinator's own work."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.ldata.coordinator import LDATAUpdateCoordinator

pytestmark = pytest.mark.asyncio


def _coordinator() -> LDATAUpdateCoordinator:
    """Build a coordinator whose background tasks are never started."""

    def _no_task(_hass, coro, _name):
        coro.close()

    hass = MagicMock()
    entry = MagicMock()
    entry.entry_id = "entry-1"
    entry.options = {}
    entry.async_create_background_task.side_effect = _no_task
    coordinator = LDATAUpdateCoordinator(hass, "user@example.com", "secret", entry)
    coordinator._debounced_refresh = MagicMock()
    return coordinator


async def test_shutdown_cancels_request_refresh_debouncer() -> None:
    coordinator = _coordinator()

    await coordinator.async_shutdown()

    coordinator._debounced_refresh.async_shutdown.assert_called_once_with()
    assert coordinator._shutdown_requested is True
    assert coordinator._service._shutdown_requested is True


async def test_refresh_after_shutdown_does_not_fetch() -> None:
    coordinator = _coordinator()
    coordinator._async_update_data = AsyncMock()
    await coordinator.async_shutdown()

    await coordinator._async_refresh()

    coordinator._async_update_data.assert_not_awaited()
