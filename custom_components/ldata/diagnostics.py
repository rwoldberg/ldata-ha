"""Diagnostics support for the Leviton LDATA integration.

Downloadable from Settings > Devices & Services > Leviton LDATA > the "..."
menu > Download diagnostics. Deliberately keeps device/breaker ids, MACs, and
serial numbers visible (not redacted) — those aren't account-identifying, and
they're exactly the fields needed to diagnose the class of bug this was added
for: a device silently forking in two because Leviton changed an id's format,
or a device not landing in its expected panel/room subentry. Only genuine
credentials/tokens and account identifiers are redacted.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN
from .coordinator import LDATAUpdateCoordinator

TO_REDACT = {
    "username",
    "password",
    "auth_token",
    "refresh_token",
    "userid",
    "userId",
    "accountId",
    "Token",
    "token",
    "regKey",
    "resKey",
}


def _serialize_device(device: dr.DeviceEntry) -> dict[str, Any]:
    return {
        "id": device.id,
        "name": device.name,
        "name_by_user": device.name_by_user,
        "identifiers": sorted(str(i) for i in device.identifiers),
        "via_device_id": device.via_device_id,
        "config_subentry_id": device.config_subentry_id,
        "model": device.model,
        "manufacturer": device.manufacturer,
        "sw_version": device.sw_version,
        "hw_version": device.hw_version,
        "disabled_by": device.disabled_by,
    }


def _serialize_entity(entity: er.RegistryEntry) -> dict[str, Any]:
    return {
        "entity_id": entity.entity_id,
        "unique_id": entity.unique_id,
        "device_id": entity.device_id,
        "config_subentry_id": entity.config_subentry_id,
        "platform": entity.platform,
        "disabled_by": entity.disabled_by,
        "hidden_by": entity.hidden_by,
    }


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator: LDATAUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)
    devices = [
        _serialize_device(d)
        for d in dev_reg.devices.get_devices_for_config_entry_id(entry.entry_id)
    ]
    entities = [
        _serialize_entity(e)
        for e in er.async_entries_for_config_entry(ent_reg, entry.entry_id)
    ]
    subentries = [
        {
            "subentry_id": se.subentry_id,
            "subentry_type": se.subentry_type,
            "title": se.title,
            "unique_id": se.unique_id,
        }
        for se in entry.subentries.values()
    ]

    return {
        "entry": {
            "title": entry.title,
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": async_redact_data(dict(entry.options), TO_REDACT),
        },
        "subentries": subentries,
        "devices": devices,
        "entities": entities,
        "coordinator_data": async_redact_data(coordinator.data or {}, TO_REDACT),
    }


async def async_get_device_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry, device: dr.DeviceEntry
) -> dict[str, Any]:
    """Return diagnostics for a single device — the same duplicate-device
    investigation this was added for, scoped to one device instead of
    requiring the whole entry's dump.
    """
    ent_reg = er.async_get(hass)
    return {
        "device": _serialize_device(device),
        "entities": [
            _serialize_entity(e)
            for e in er.async_entries_for_device(
                ent_reg, device.id, include_disabled_entities=True
            )
        ],
    }
