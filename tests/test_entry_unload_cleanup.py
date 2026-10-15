"""Tests that entry setup leaves nothing behind after unload or reload."""

from types import MappingProxyType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from custom_components import ldata
from custom_components.ldata.const import DOMAIN
from custom_components.ldata.coordinator import LDATAUpdateCoordinator

pytestmark = pytest.mark.asyncio


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
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    # Services are already registered; registration is not under test.
    hass.services.has_service.return_value = True
    return hass


class _FakeCoordinator(LDATAUpdateCoordinator):
    """A coordinator that starts nothing; isinstance checks still match."""

    def __init__(self, *_args) -> None:
        self.data = {}
        self.async_config_entry_first_refresh = AsyncMock()
        self.async_shutdown = AsyncMock()
        self.async_add_listener = MagicMock(return_value=lambda: None)


@pytest.fixture
def patched_setup():
    with (
        patch.object(ldata, "LDATAUpdateCoordinator", _FakeCoordinator),
        patch.object(ldata, "_async_reconcile_subentries", AsyncMock()),
        patch.object(ldata, "_async_ensure_panel_devices"),
        patch.object(ldata, "_async_purge_orphaned_devices", AsyncMock()),
        patch.object(ldata, "_async_purge_stale_breaker_duplicates", AsyncMock()),
    ):
        yield


async def _unload(hass: MagicMock, entry: ConfigEntry) -> None:
    """Run the parts of HA's reload that tear an entry down."""
    assert await ldata.async_unload_entry(hass, entry)
    await entry._async_process_on_unload(hass)


async def _fire_entry_update(
    hass: MagicMock, entry: ConfigEntry, *, data=None, options=None
) -> None:
    """Change the entry and call every update listener, as async_update_entry does."""
    # ConfigEntry blocks normal assignment to these; HA uses object.__setattr__.
    if data is not None:
        object.__setattr__(entry, "data", MappingProxyType(data))
    if options is not None:
        object.__setattr__(entry, "options", MappingProxyType(options))
    for listener in list(entry.update_listeners):
        await listener(hass, entry)


async def _fire_options_update(hass: MagicMock, entry: ConfigEntry) -> None:
    await _fire_entry_update(
        hass, entry, options={**entry.options, "log_parsed_data": True}
    )


async def test_setup_registers_one_update_listener(patched_setup) -> None:
    hass, entry = _hass(), _entry()

    assert await ldata.async_setup_entry(hass, entry)

    assert len(entry.update_listeners) == 1


async def test_unload_removes_update_listener(patched_setup) -> None:
    hass, entry = _hass(), _entry()
    assert await ldata.async_setup_entry(hass, entry)

    await _unload(hass, entry)

    assert entry.update_listeners == []


async def test_options_update_after_reloads_reloads_once(patched_setup) -> None:
    hass, entry = _hass(), _entry()
    assert await ldata.async_setup_entry(hass, entry)
    for _ in range(2):
        await _unload(hass, entry)
        assert await ldata.async_setup_entry(hass, entry)

    await _fire_options_update(hass, entry)

    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)


async def test_data_only_update_does_not_reload(patched_setup) -> None:
    # A persisted token refresh or a reauth changes entry.data only.
    hass, entry = _hass(), _entry()
    assert await ldata.async_setup_entry(hass, entry)

    await _fire_entry_update(
        hass, entry, data={**entry.data, "refresh_token": "new-token"}
    )

    hass.config_entries.async_reload.assert_not_awaited()


async def test_options_change_reloads_once(patched_setup) -> None:
    hass, entry = _hass(), _entry()
    assert await ldata.async_setup_entry(hass, entry)

    await _fire_options_update(hass, entry)

    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)


def _removed_services(hass: MagicMock) -> set[str]:
    return {
        call.args[1]
        for call in hass.services.async_remove.call_args_list
        if call.args[0] == DOMAIN
    }


async def test_services_removed_when_last_entry_unloads(patched_setup) -> None:
    hass = _hass()
    first, second = _entry(), _entry()
    assert await ldata.async_setup_entry(hass, first)
    assert await ldata.async_setup_entry(hass, second)

    await _unload(hass, first)
    # The other entry still uses them.
    assert _removed_services(hass) == set()

    await _unload(hass, second)
    assert _removed_services(hass) == {
        ldata.SERVICE_RESET_ENERGY,
        ldata.SERVICE_RESET_PANEL,
    }


async def test_failed_unload_keeps_services(patched_setup) -> None:
    hass, entry = _hass(), _entry()
    assert await ldata.async_setup_entry(hass, entry)
    hass.config_entries.async_unload_platforms.return_value = False

    assert not await ldata.async_unload_entry(hass, entry)

    hass.services.async_remove.assert_not_called()
