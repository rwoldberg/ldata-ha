"""Diagnostics support for the Leviton LDATA integration.

Downloadable from Settings > Devices & Services > Leviton LDATA > the "..."
menu > Download diagnostics. Deliberately keeps device/breaker ids, MACs, and
serial numbers visible (not redacted) — those aren't account-identifying, and
they're exactly the fields needed to diagnose the class of bug this was added
for: a device silently forking in two because Leviton changed an id's format,
or a device not landing in its expected panel/room subentry.

What identifies the account or the home is taken out, because these files
get attached to public issues: credentials and tokens, the account's email
(which is also in the entry's title and in the unique id of every entity
made before ids were keyed on the user id), the user, account and residence
ids, the entry's title (the email, or the residence's name, which can be its
street address), and the local network addresses of Decora devices.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from homeassistant.components.diagnostics import REDACTED, async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import CONF_RESIDENCE_ID, DOMAIN
from .coordinator import LDATAUpdateCoordinator

TO_REDACT = {
    # Credentials and tokens.
    CONF_USERNAME,
    CONF_PASSWORD,
    "email",  # what entries made by 1.x keep the username under
    "auth_token",
    "refresh_token",
    "Token",
    "token",
    "regKey",
    "resKey",
    # The account and the home.
    "userid",
    "userId",
    "accountId",
    "residentialAccountId",
    CONF_RESIDENCE_ID,
    "residenceId",
    "_residenceId",
    # The home network.
    "localIP",
    "local_ip",
}

# A user id shorter than this is too likely to turn up inside unrelated
# strings to be searched for everywhere; its own keys are redacted anyway.
_MIN_SCRUBBED = 6


def _account_strings(entry: ConfigEntry) -> list[str]:
    """Return the account's own identifiers, to be taken out wherever they appear.

    The email is in the entry's title and in unique ids, not only under its
    own key, so it is searched for in every string, ignoring case: an entry
    re-authenticated with different capitals has ids with both spellings.
    """
    found = []
    for key in (CONF_USERNAME, "email", "userid"):
        value = entry.data.get(key)
        if isinstance(value, str) and len(value) >= _MIN_SCRUBBED and value not in found:
            found.append(value)
    return found


def _scrub(value: Any, secrets: Iterable[str]) -> Any:
    """Return value with every copy of the secrets replaced, in keys and values."""
    if isinstance(value, str):
        for secret in secrets:
            value = re.sub(re.escape(secret), REDACTED, value, flags=re.IGNORECASE)
        return value
    if isinstance(value, dict):
        return {_scrub(key, secrets): _scrub(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_scrub(item, secrets) for item in value]
    return value


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
        for d in dr.async_entries_for_config_entry(dev_reg, entry.entry_id)
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

    return _scrub(
        {
            "entry": {
                # The account's email, or the name of the residence.
                "title": REDACTED,
                "data": async_redact_data(dict(entry.data), TO_REDACT),
                "options": async_redact_data(dict(entry.options), TO_REDACT),
            },
            "subentries": subentries,
            "devices": devices,
            "entities": entities,
            "coordinator_data": async_redact_data(coordinator.data or {}, TO_REDACT),
        },
        _account_strings(entry),
    )


async def async_get_device_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry, device: dr.DeviceEntry
) -> dict[str, Any]:
    """Return diagnostics for a single device — the same duplicate-device
    investigation this was added for, scoped to one device instead of
    requiring the whole entry's dump.
    """
    ent_reg = er.async_get(hass)
    return _scrub(
        {
            "device": _serialize_device(device),
            "entities": [
                _serialize_entity(e)
                for e in er.async_entries_for_device(
                    ent_reg, device.id, include_disabled_entities=True
                )
            ],
        },
        _account_strings(entry),
    )
