"""The LDATA integration."""
from __future__ import annotations
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import DOMAIN, LOGGER_NAME, UPDATE_INTERVAL, UPDATE_INTERVAL_DEFAULT
from .coordinator import LDATAUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH]
_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up LDATA from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    
    # Handle backward compatibility for username/email field
    username = entry.data.get("email", entry.data.get(CONF_USERNAME))

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
        entry.data[CONF_PASSWORD],
        update_interval, # Use the validated update_interval
        entry,
    )

    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = coordinator

    # This line will now only be reached if the first refresh was successful.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Set up a listener for options updates
    entry.add_update_listener(options_update_listener)

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Use the built-in unload method
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    # Also pop the coordinator from hass.data
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
        
    return unload_ok

async def options_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    # This is the recommended way to handle options updates.
    await hass.config_entries.async_reload(entry.entry_id)
