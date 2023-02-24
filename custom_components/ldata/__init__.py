"""The Leviton LDATA integration."""
from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN, UPDATE_INTERVAL, UPDATE_INTERVAL_DEFAULT
from .ldata_uppdate_coordinator import LDATAUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the LDATA component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Leviton LDATA from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    user = entry.data[CONF_USERNAME]
    password = entry.data[CONF_PASSWORD]
    update_interval = entry.options.get(UPDATE_INTERVAL, UPDATE_INTERVAL_DEFAULT)
    _LOGGER.debug(update_interval)
    for item in entry.data:
        _LOGGER.debug(item)

    coordinator = LDATAUpdateCoordinator(hass, user, password, update_interval)

    await coordinator.async_refresh()  # Get initial data

    if not coordinator.last_update_success:
        raise ConfigEntryNotReady

    hass.data[DOMAIN][entry.entry_id] = coordinator

    for component in PLATFORMS:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setup(entry, component)
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = all(
        await asyncio.gather(
            *[
                hass.config_entries.async_forward_entry_unload(entry, component)
                for component in PLATFORMS
            ]
        )
    )
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok
