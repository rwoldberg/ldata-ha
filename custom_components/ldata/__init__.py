"""The LDATA integration."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import LDATAUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.SENSOR]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up LDATA from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    
    # Handle backward compatibility for username/email field
    username = entry.data.get("email", entry.data.get("username"))

    coordinator = LDATAUpdateCoordinator(
        hass,
        username,
        entry.data["password"],
        30, # Update interval in seconds
        entry,
    )

    # --- START OF CHANGE ---
    # Only perform the first refresh during initial setup.
    if entry.state == ConfigEntryState.SETUP_IN_PROGRESS:
        await coordinator.async_config_entry_first_refresh()
    # --- END OF CHANGE ---

    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    #entry.add_update_listener(async_reload_entry)

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok

async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
