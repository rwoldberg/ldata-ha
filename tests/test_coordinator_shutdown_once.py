"""Tests that one unload shuts the coordinator down once."""

import asyncio
import json
import logging
from types import MappingProxyType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_USERNAME,
    EVENT_HOMEASSISTANT_FINAL_WRITE,
)
from homeassistant.core import Event
from homeassistant.exceptions import ConfigEntryNotReady

from custom_components import ldata
from custom_components.ldata.const import DOMAIN, LOGGER_NAME
from custom_components.ldata.coordinator import LDATAUpdateCoordinator, energy_store_key
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


def _booked_ledger() -> LDATAEnergyLedger:
    ledger = LDATAEnergyLedger()
    # A burst received at 14:00:29 UTC, booked but not written yet.
    ledger.apply("tech", 15, {"1": 0.5}, 1792332029.0, "WS")
    assert ledger.dirty
    return ledger


def test_final_write_stage_writes_the_ledger() -> None:
    """Home Assistant stopping does not unload the entry: the final-write stage writes."""
    hass, entry = _hass(), _entry()
    written = []

    async def save(data):
        written.append(data)

    async def run():
        coordinator = _coordinator(hass, entry)
        (event_type, listener), _ = hass.bus.async_listen_once.call_args
        assert event_type == EVENT_HOMEASSISTANT_FINAL_WRITE
        ledger = _booked_ledger()
        expected = ledger.as_dict()
        coordinator._service.energy_ledger = ledger
        coordinator._energy_loaded = True
        coordinator._energy_store = MagicMock()
        coordinator._energy_store.async_save = AsyncMock(side_effect=save)

        await listener(Event(EVENT_HOMEASSISTANT_FINAL_WRITE))

        assert written == [expected]
        assert not ledger.dirty
        # No save starts after the final write: the executor shuts down next.
        ledger.apply("tech", 15, {"1": 0.2}, 1792335629.0, "WS")
        coordinator._save_energy_ledger()
        assert coordinator._energy_save_task is None
        assert len(written) == 1
        # The listener is used up: the on-unload callback leaves it alone.
        unsub = hass.bus.async_listen_once.return_value
        await entry._async_process_on_unload(hass)
        unsub.assert_not_called()

    asyncio.run(run())


def test_unload_removes_the_final_write_listener() -> None:
    hass, entry = _hass(), _entry()

    async def run():
        _coordinator(hass, entry)
        unsub = hass.bus.async_listen_once.return_value
        assert await ldata.async_unload_entry(hass, entry)
        await entry._async_process_on_unload(hass)
        unsub.assert_called_once_with()

    asyncio.run(run())


def test_home_assistant_stop_stores_a_booking_not_yet_pushed(tmp_path) -> None:
    """A booking made after the last push is in the stored ledger after a real stop."""
    from homeassistant.core import CoreState, HomeAssistant
    from homeassistant.helpers import storage

    async def run():
        hass = HomeAssistant(str(tmp_path))
        hass.data[DOMAIN] = {}
        entry = _entry()
        coordinator = _coordinator(hass, entry)
        await coordinator._async_load_energy_ledger()
        ledger = coordinator._service.energy_ledger
        ledger.apply("tech", 15, {"1": 0.5}, 1792332029.0, "WS")
        expected = ledger.as_dict()

        hass.set_state(CoreState.running)
        await hass.async_stop(force=True)
        return entry.entry_id, expected

    entry_id, expected = asyncio.run(run())

    path = tmp_path / storage.STORAGE_DIR / energy_store_key(entry_id)
    stored = json.loads(path.read_text())
    assert stored["data"] == json.loads(json.dumps(expected))
