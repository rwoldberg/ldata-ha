"""The LDATA integration."""
from __future__ import annotations
import logging

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN, LOGGER_NAME, UPDATE_INTERVAL, UPDATE_INTERVAL_DEFAULT
from .coordinator import LDATAUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH]
_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up LDATA from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    
    # Handle backward compatibility for username/email field
    username = entry.data.get("email", entry.data.get("username"))

    # Get the update interval from options and enforce a 30-second minimum.
    user_update_interval = entry.options.get(UPDATE_INTERVAL, UPDATE_INTERVAL_DEFAULT)
    update_interval = max(user_update_interval, 30)

    if user_update_interval < 30:
        _LOGGER.warning(
            "Update interval was set to %s seconds, which is too frequent. "
            "Forcing a minimum interval of 30 seconds to avoid API rate limiting.",
            user_update_interval,
        )

    coordinator = LDATAUpdateCoordinator(
        hass,
        username,
        entry.data["password"],
        update_interval, # Use the validated update_interval
        entry,
    )

    if entry.state == ConfigEntryState.SETUP_IN_PROGRESS:
        await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Set up a listener for options updates
    entry.add_update_listener(options_update_listener)

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Use the built-in unload method
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

async def options_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    # This is the recommended way to handle options updates.
    await hass.config_entries.async_reload(entry.entry_id)
