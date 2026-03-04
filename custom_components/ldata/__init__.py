"""The LDATA integration."""
from __future__ import annotations
import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers import entity_registry as er
import homeassistant.helpers.config_validation as cv

from .const import DOMAIN, LOGGER_NAME
from .coordinator import LDATAUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH]
_LOGGER = logging.getLogger(LOGGER_NAME)

SERVICE_RESET_ENERGY = "reset_energy_baseline"
ATTR_ENTITY_ID = "entity_id"
ATTR_VALUE = "value"

SERVICE_RESET_ENERGY_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_ENTITY_ID): cv.entity_id,
        vol.Optional(ATTR_VALUE): vol.Coerce(float),
    }
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up LDATA from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    
    # Handle backward compatibility for username/email field
    username = entry.data.get("email", entry.data.get(CONF_USERNAME))

    coordinator = LDATAUpdateCoordinator(
        hass,
        username,
        entry.data[CONF_PASSWORD],
        entry,
    )

    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = coordinator

    # This line will now only be reached if the first refresh was successful.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Set up a listener for options updates
    entry.add_update_listener(options_update_listener)

    # Register services (only once, not per entry)
    if not hass.services.has_service(DOMAIN, SERVICE_RESET_ENERGY):
        async def handle_reset_energy(call: ServiceCall) -> None:
            """Handle the reset_energy_baseline service call."""
            entity_id = call.data[ATTR_ENTITY_ID]
            new_value = call.data.get(ATTR_VALUE)

            # Find the entity object through the entity platform
            target_entity = None
            for entry_id, coord in hass.data[DOMAIN].items():
                if not isinstance(coord, LDATAUpdateCoordinator):
                    continue
                ent_reg = er.async_get(hass)
                for ent_entry in er.async_entries_for_config_entry(ent_reg, entry_id):
                    if ent_entry.entity_id == entity_id:
                        comp = hass.data.get("entity_components", {}).get("sensor")
                        if comp:
                            target_entity = comp.get_entity(entity_id)
                        break
                if target_entity:
                    break

            if target_entity is None:
                _LOGGER.error(
                    "Could not find entity %s — ensure it is an LDATA energy sensor",
                    entity_id
                )
                return

            if not hasattr(target_entity, '_accept_next_value'):
                _LOGGER.error(
                    "Entity %s does not support reset_energy_baseline",
                    entity_id
                )
                return

            # Log current state for visibility
            current = target_entity._state
            _LOGGER.warning(
                "reset_energy_baseline called for %s — current value: %s kWh",
                entity_id, current
            )

            # Daily sensors need baselines cleared so they re-establish
            is_daily = hasattr(target_entity, '_midnight_baseline')

            if new_value is not None:
                target_entity._state = new_value
                target_entity._accept_next_value = False
                if hasattr(target_entity, '_consecutive_decrease'):
                    target_entity._consecutive_decrease = 0
                if hasattr(target_entity, '_monotonic_reject_since'):
                    target_entity._monotonic_reject_since = None
                target_entity.async_write_ha_state()
                _LOGGER.warning(
                    "Reset %s: %.2f -> %.2f kWh (forced value)",
                    entity_id, current or 0, new_value
                )
            else:
                target_entity._accept_next_value = True
                if hasattr(target_entity, '_consecutive_decrease'):
                    target_entity._consecutive_decrease = 0
                if hasattr(target_entity, '_monotonic_reject_since'):
                    target_entity._monotonic_reject_since = None
                if is_daily:
                    target_entity._midnight_baseline = None
                    if hasattr(target_entity, '_panel_baselines'):
                        target_entity._panel_baselines = {}
                    target_entity._state = 0.0
                    target_entity.async_write_ha_state()
                    _LOGGER.warning(
                        "Reset %s: cleared baselines and state — will "
                        "re-establish on next update (was %.2f kWh)",
                        entity_id, current or 0
                    )
                else:
                    _LOGGER.warning(
                        "Reset %s: will accept next API value "
                        "unconditionally (currently %.2f kWh)",
                        entity_id, current or 0
                    )

        hass.services.async_register(
            DOMAIN,
            SERVICE_RESET_ENERGY,
            handle_reset_energy,
            schema=SERVICE_RESET_ENERGY_SCHEMA,
        )

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Gracefully shutdown WebSocket before unloading
    coordinator = hass.data[DOMAIN].get(entry.entry_id)
    if coordinator:
        await coordinator.async_shutdown()
    
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