"""The reset services are admin services.

reset_energy_baseline and reset_panel_energy rewrite energy totals the
Energy dashboard records; any user could call them.
"""

from functools import partial
from types import MappingProxyType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import Context
from homeassistant.exceptions import Unauthorized

from custom_components import ldata
from custom_components.ldata.const import DOMAIN
from custom_components.ldata.coordinator import LDATAUpdateCoordinator

pytestmark = pytest.mark.asyncio


class _FakeCoordinator(LDATAUpdateCoordinator):
    def __init__(self, *_args) -> None:
        self.data = {}
        self.async_config_entry_first_refresh = AsyncMock()
        self.async_shutdown = AsyncMock()
        self.async_add_listener = MagicMock(return_value=lambda: None)


def _entry() -> ConfigEntry:
    return ConfigEntry(
        data={CONF_USERNAME: "user@example.com", CONF_PASSWORD: "secret", "refresh_token": "t", "userid": "u1"},
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


async def _registered_handlers() -> tuple[MagicMock, dict]:
    hass = MagicMock()
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    hass.services.has_service.return_value = False
    with (
        patch.object(ldata, "LDATAUpdateCoordinator", _FakeCoordinator),
        patch.object(ldata, "_async_reconcile_subentries", AsyncMock()),
        patch.object(ldata, "_async_ensure_panel_devices"),
        patch.object(ldata, "_async_purge_orphaned_devices", AsyncMock()),
        patch.object(ldata, "_async_purge_stale_breaker_duplicates", AsyncMock()),
    ):
        assert await ldata.async_setup_entry(hass, _entry())
    handlers = {
        call.args[1]: call.args[2]
        for call in hass.services.async_register.call_args_list
        if call.args[0] == DOMAIN
    }
    return hass, handlers


async def test_both_reset_services_are_admin_services() -> None:
    _hass, handlers = await _registered_handlers()

    assert set(handlers) == {ldata.SERVICE_RESET_ENERGY, ldata.SERVICE_RESET_PANEL}
    for handler in handlers.values():
        assert isinstance(handler, partial)
        assert handler.func.__name__ == "_async_admin_handler"


@pytest.mark.parametrize("service", [ldata.SERVICE_RESET_ENERGY, ldata.SERVICE_RESET_PANEL])
async def test_non_admin_users_are_refused(service) -> None:
    hass, handlers = await _registered_handlers()
    hass.auth.async_get_user = AsyncMock(return_value=SimpleNamespace(is_admin=False))
    call = SimpleNamespace(context=Context(user_id="non-admin"), data={})

    with pytest.raises(Unauthorized):
        await handlers[service](call)
