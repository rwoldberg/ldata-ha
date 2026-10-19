"""Tests that one unload shuts the coordinator down once."""

import asyncio
import logging
from types import MappingProxyType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.exceptions import ConfigEntryNotReady

from custom_components import ldata
from custom_components.ldata.const import DOMAIN, LOGGER_NAME
from custom_components.ldata.coordinator import LDATAUpdateCoordinator
from custom_components.ldata.ldata_energy import LDATAEnergyLedger

SHUTDOWN_LOG = "Shutting down LDATA coordinator"


def _entry() -> ConfigEntry:
    return ConfigEntry(
        data={
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "secret",
            "refresh_token": "token",
            "userid": "user-1",
        },
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        minor_version=1,
        options={},
        source=SOURCE_USER,
        subentries_data=None,
        title="Leviton LDATA (Home)",
        unique_id="user@example.com",
        version=1,
    )


def _hass() -> MagicMock:
    hass = MagicMock()
    hass.data = {DOMAIN: {}}
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    # ConfigEntry.async_create_task (used for the on-unload callbacks) runs
    # its coroutine on the loop, as Home Assistant does.
    hass.async_create_task_internal.side_effect = (
        lambda target, _name=None, _eager_start=True: asyncio.get_running_loop().create_task(target)
    )
    return hass


def _coordinator(hass: MagicMock, entry: ConfigEntry) -> LDATAUpdateCoordinator:
    """A real coordinator on a real entry, without its background tasks."""

    def _no_task(_entry, _hass, coro, _name, *_args, **_kwargs):
        coro.close()

    with patch.object(ConfigEntry, "async_create_background_task", _no_task):
        coordinator = LDATAUpdateCoordinator(hass, "user@example.com", "secret", entry)
    hass.data[DOMAIN][entry.entry_id] = coordinator
    return coordinator


def _shutdown_logs(caplog: pytest.LogCaptureFixture) -> int:
    return sum(record.getMessage() == SHUTDOWN_LOG for record in caplog.records)


def test_unload_shuts_the_coordinator_down_once(caplog) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER_NAME)
    hass, entry = _hass(), _entry()

    async def run():
        coordinator = _coordinator(hass, entry)
        body = AsyncMock(wraps=coordinator._async_shutdown)
        coordinator._async_shutdown = body
        assert coordinator.async_shutdown in entry._on_unload

        # What ConfigEntry.async_unload does after the platforms unloaded:
        # async_unload_entry, then the on-unload callbacks, which include the
        # one DataUpdateCoordinator registered for async_shutdown.
        assert await ldata.async_unload_entry(hass, entry)
        await entry._async_process_on_unload(hass)

        body.assert_awaited_once()
        assert coordinator._service._shutdown_requested is True

    asyncio.run(run())

    assert _shutdown_logs(caplog) == 1


def test_failed_shutdown_runs_again_on_the_next_call() -> None:
    hass, entry = _hass(), _entry()

    async def run():
        coordinator = _coordinator(hass, entry)
        body = AsyncMock(side_effect=[OSError("disk full"), None])
        coordinator._async_shutdown = body

        with pytest.raises(OSError):
            await coordinator.async_shutdown()
        await coordinator.async_shutdown()
        await coordinator.async_shutdown()

        assert body.await_count == 2

    asyncio.run(run())


def test_unload_after_a_failed_shutdown_retries_the_ledger_write(caplog) -> None:
    hass, entry = _hass(), _entry()
    attempts, written = [], []

    async def save(data):
        attempts.append(data)
        if len(attempts) == 1:
            raise OSError("disk full")
        written.append(data)

    async def run():
        coordinator = _coordinator(hass, entry)
        ledger = LDATAEnergyLedger()
        # A burst received at 14:00:29 UTC, booked but not written yet.
        ledger.apply("tech", 15, {"1": 0.5}, 1792332029.0, "WS")
        assert ledger.dirty
        coordinator._service.energy_ledger = ledger
        coordinator._energy_loaded = True
        coordinator._energy_store = MagicMock()
        coordinator._energy_store.async_save = AsyncMock(side_effect=save)
        body = AsyncMock(wraps=coordinator._async_shutdown)
        coordinator._async_shutdown = body

        # The final write fails in async_unload_entry's call; the unload
        # still succeeds, so Home Assistant runs the on-unload callbacks.
        assert await ldata.async_unload_entry(hass, entry)
        assert written == []
        assert ledger.dirty
        await entry._async_process_on_unload(hass)

        assert body.await_count == 2
        assert len(attempts) == 2
        assert len(written) == 1
        assert "tech" in written[0]["breakers"]
        assert not ledger.dirty

    asyncio.run(run())

    assert "Shutting down the LDATA coordinator failed" in caplog.text


def test_failed_first_refresh_keeps_config_entry_not_ready(caplog) -> None:
    hass, entry = _hass(), _entry()
    hass.data = {}
    created = []

    def _failing_coordinator(hass, user, password, entry):
        coordinator = _coordinator(hass, entry)
        coordinator.async_config_entry_first_refresh = AsyncMock(
            side_effect=ConfigEntryNotReady("panel offline")
        )
        coordinator._async_shutdown = AsyncMock(side_effect=[OSError("disk full"), None])
        created.append(coordinator)
        return coordinator

    async def run():
        with (
            patch.object(ldata, "LDATAUpdateCoordinator", _failing_coordinator),
            pytest.raises(ConfigEntryNotReady),
        ):
            await ldata.async_setup_entry(hass, entry)
        # Home Assistant then runs the on-unload callbacks of the failed setup.
        await entry._async_process_on_unload(hass)

        (coordinator,) = created
        assert coordinator._async_shutdown.await_count == 2

    asyncio.run(run())

    assert "after the failed first refresh failed" in caplog.text
