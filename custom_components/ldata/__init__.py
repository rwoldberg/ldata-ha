"""The Leviton LDATA integration."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.typing import ConfigType

from .const import (
    DOMAIN,
    LOGGER_NAME,
    READ_ONLY,
    READ_ONLY_DEFAULT,
    THREE_PHASE,
    THREE_PHASE_DEFAULT,
    UPDATE_INTERVAL,
    UPDATE_INTERVAL_DEFAULT,
    UPDATE_INTERVAL_MIN,
)
from .coordinator import LDATAUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH]

_LOGGER = logging.getLogger(LOGGER_NAME)


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
    three_phase = entry.options.get(
        THREE_PHASE, entry.data.get(THREE_PHASE, THREE_PHASE_DEFAULT)
    )
    read_only = entry.options.get(
        READ_ONLY, entry.data.get(READ_ONLY, READ_ONLY_DEFAULT)
    )

    # Don't update more that every 10 seconds.
    update_interval = max(update_interval, UPDATE_INTERVAL_MIN)

    _LOGGER.debug("LDATA update interval: %d", update_interval)
    _LOGGER.debug("LDATA three phase: %d", three_phase)
    _LOGGER.debug("LDATA read only: %d", read_only)

    coordinator = LDATAUpdateCoordinator(hass, user, password, update_interval, entry)

    await coordinator.async_refresh()  # Get initial data

    if not coordinator.last_update_success:
        raise ConfigEntryNotReady

    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

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
