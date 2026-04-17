"""The LDATA integration."""
from __future__ import annotations
import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
import homeassistant.helpers.config_validation as cv

from .const import DOMAIN, LOGGER_NAME
from .coordinator import LDATAUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH]
_LOGGER = logging.getLogger(LOGGER_NAME)

SERVICE_RESET_ENERGY = "reset_energy_baseline"
SERVICE_RESET_PANEL = "reset_panel_energy"
ATTR_ENTITY_ID = "entity_id"
ATTR_DEVICE_ID = "device_id"
ATTR_VALUE = "value"
ATTR_BASELINE = "baseline"

SERVICE_RESET_ENERGY_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_ENTITY_ID): cv.entity_id,
        vol.Optional(ATTR_VALUE): vol.Coerce(float),
        vol.Optional(ATTR_BASELINE): vol.Coerce(float),
    }
)

SERVICE_RESET_PANEL_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_DEVICE_ID): cv.string,
    }
)


def _reset_energy_entity(entity, entity_id: str) -> str:
    """Apply a full auto-reset to one energy entity. Returns a summary log line.

    Clears all guard state so the entity re-establishes cleanly from the next
    API reading — the right behaviour after a factory reset where all hardware
    counters drop to zero simultaneously.
    """
    current = getattr(entity, "_state", None)
    is_daily = hasattr(entity, "_midnight_baseline")

    entity._accept_next_value = True
    if hasattr(entity, "_consecutive_decrease"):
        entity._consecutive_decrease = 0
    if hasattr(entity, "_consecutive_none"):
        entity._consecutive_none = 0
    if hasattr(entity, "_monotonic_reject_since"):
        entity._monotonic_reject_since = None
    if hasattr(entity, "_last_reported"):
        entity._last_reported = None

    if is_daily:
        entity._midnight_baseline = None
        if hasattr(entity, "_panel_baselines"):
            entity._panel_baselines = {}
        if hasattr(entity, "_last_breaker_deltas"):
            entity._last_breaker_deltas = {}
        entity._state = 0.0
        entity.async_write_ha_state()
        was = f"{current:.2f}" if current is not None else "?"
        return f"{entity_id}: daily cleared (was {was} kWh)"
    else:
        entity.async_write_ha_state()
        return f"{entity_id}: lifetime guard cleared (was {current} kWh)"


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
            new_baseline = call.data.get(ATTR_BASELINE)

            # Find the entity object through the entity platform
            target_entity = None
            comp = hass.data.get("entity_components", {}).get("sensor")
            ent_reg = er.async_get(hass)
            for entry_id, coord in hass.data[DOMAIN].items():
                if not isinstance(coord, LDATAUpdateCoordinator):
                    continue
                for ent_entry in er.async_entries_for_config_entry(ent_reg, entry_id):
                    if ent_entry.entity_id == entity_id:
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

            if not hasattr(target_entity, "_accept_next_value"):
                _LOGGER.error(
                    "Entity %s does not support reset_energy_baseline",
                    entity_id
                )
                return

            current = target_entity._state
            _LOGGER.warning(
                "reset_energy_baseline called for %s — current value: %s kWh",
                entity_id, current
            )

            is_daily = hasattr(target_entity, "_midnight_baseline")

            # 1. Forced baseline (daily sensors only)
            if new_baseline is not None:
                if is_daily:
                    target_entity._midnight_baseline = new_baseline
                    if hasattr(target_entity, "_monotonic_reject_since"):
                        target_entity._monotonic_reject_since = None
                    target_entity.async_write_ha_state()
                    _LOGGER.warning(
                        "Reset %s: forced midnight_baseline to %.3f kWh", entity_id, new_baseline
                    )
                else:
                    _LOGGER.warning("Cannot set baseline on %s — not a daily sensor", entity_id)

            # 2. Forced state value
            if new_value is not None:
                target_entity._state = new_value
                target_entity._accept_next_value = False
                if hasattr(target_entity, "_consecutive_decrease"):
                    target_entity._consecutive_decrease = 0
                if hasattr(target_entity, "_monotonic_reject_since"):
                    target_entity._monotonic_reject_since = None
                target_entity.async_write_ha_state()
                _LOGGER.warning(
                    "Reset %s: %.2f -> %.2f kWh (forced value)", entity_id, current or 0, new_value
                )

            # 3. Full auto-reset (no parameters)
            elif new_baseline is None and new_value is None:
                summary = _reset_energy_entity(target_entity, entity_id)
                _LOGGER.warning("reset_energy_baseline: %s", summary)

        hass.services.async_register(
            DOMAIN,
            SERVICE_RESET_ENERGY,
            handle_reset_energy,
            schema=SERVICE_RESET_ENERGY_SCHEMA,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_RESET_PANEL):
        async def handle_reset_panel_energy(call: ServiceCall) -> None:
            """Reset all energy sensors for a WHEM panel after a factory reset.

            Accepts any device belonging to the panel — the panel itself, a
            breaker, or a CT.  Resolves the panel serial number then resets
            every daily and lifetime energy sensor associated with that panel.
            """
            target_device_id = call.data[ATTR_DEVICE_ID]
            dev_reg = dr.async_get(hass)
            ent_reg = er.async_get(hass)
            comp = hass.data.get("entity_components", {}).get("sensor")

            device = dev_reg.async_get(target_device_id)
            if not device:
                _LOGGER.error("reset_panel_energy: device %s not found", target_device_id)
                return

            # Resolve the selected device to a panel serial number.
            # Identifier shapes:
            #   (DOMAIN, panel_serial)          — panel-level entity
            #   (DOMAIN, breaker_serial)         — breaker entity
            #   (DOMAIN, panel_serial, ct_id)    — CT entity (3-tuple)
            panel_serial = None
            for identifier in device.identifiers:
                if len(identifier) < 2 or identifier[0] != DOMAIN:
                    continue
                if len(identifier) == 3:
                    # CT device — second element is always panel_id
                    panel_serial = identifier[1]
                    break
                serial = identifier[1]
                # Check every coordinator: is this serial a panel or a breaker?
                for coord in hass.data[DOMAIN].values():
                    if not isinstance(coord, LDATAUpdateCoordinator) or not coord.data:
                        continue
                    for p in coord.data.get("panels", []):
                        if p["serialNumber"] == serial:
                            panel_serial = serial
                            break
                    if panel_serial:
                        break
                    for b_data in coord.data.get("breakers", {}).values():
                        if b_data.get("serialNumber") == serial:
                            panel_serial = b_data.get("panel_id")
                            break
                    if panel_serial:
                        break
                if panel_serial:
                    break

            if not panel_serial:
                _LOGGER.error(
                    "reset_panel_energy: could not resolve panel for device '%s' (%s). "
                    "Select the WHEM panel device, or any breaker/CT that belongs to it.",
                    device.name, target_device_id
                )
                return

            # Build the set of HA device identifiers that belong to this panel:
            #   • the panel device itself
            #   • every breaker device whose panel_id matches
            #   • every CT device whose panel_id matches (3-tuple)
            panel_device_identifiers: set[tuple] = {(DOMAIN, panel_serial)}
            for coord in hass.data[DOMAIN].values():
                if not isinstance(coord, LDATAUpdateCoordinator) or not coord.data:
                    continue
                for b_data in coord.data.get("breakers", {}).values():
                    if b_data.get("panel_id") == panel_serial:
                        panel_device_identifiers.add((DOMAIN, b_data["serialNumber"]))
                for ct_id, ct_data in coord.data.get("cts", {}).items():
                    if ct_data.get("panel_id") == panel_serial:
                        panel_device_identifiers.add((DOMAIN, panel_serial, ct_id))

            # Walk every sensor entity in every ldata config entry and reset
            # the ones whose device identifier is in the panel set.
            reset_lines: list[str] = []
            for entry_id, coord in hass.data[DOMAIN].items():
                if not isinstance(coord, LDATAUpdateCoordinator):
                    continue
                for ent_entry in er.async_entries_for_config_entry(ent_reg, entry_id):
                    if ent_entry.domain != "sensor" or not ent_entry.device_id:
                        continue
                    ent_device = dev_reg.async_get(ent_entry.device_id)
                    if not ent_device:
                        continue
                    if not ent_device.identifiers.intersection(panel_device_identifiers):
                        continue
                    if comp is None:
                        continue
                    entity = comp.get_entity(ent_entry.entity_id)
                    if entity is None or not hasattr(entity, "_accept_next_value"):
                        continue
                    reset_lines.append(_reset_energy_entity(entity, ent_entry.entity_id))

            if reset_lines:
                _LOGGER.warning(
                    "reset_panel_energy: reset %d energy sensors for panel %s (%s):\n  %s",
                    len(reset_lines), device.name, panel_serial,
                    "\n  ".join(reset_lines)
                )
            else:
                _LOGGER.warning(
                    "reset_panel_energy: no energy sensors found for panel %s (%s). "
                    "Ensure the integration is loaded and the panel has sensors.",
                    device.name, panel_serial
                )

        hass.services.async_register(
            DOMAIN,
            SERVICE_RESET_PANEL,
            handle_reset_panel_energy,
            schema=SERVICE_RESET_PANEL_SCHEMA,
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