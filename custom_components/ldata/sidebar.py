"""The optional sidebar panel: the load center card as a page of its own.

Off by default. Every config entry has a "show in the sidebar" option; while
at least one entry has it on, one item is registered in Home Assistant's
sidebar, and its page shows the load centers of every such entry.

The item follows the config entries, not whether they are loaded. It is
there as soon as the integration is set up and stays through a reload or a
cloud outage, because the frontend sends anyone looking at a panel that
disappears back to their default dashboard — a wall tablet left on this page
would not come back by itself.

The page is the <ldata-sidebar-panel> element defined in the card's own file,
loaded from the same URL as the Lovelace card (see card.py).
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any

from homeassistant.components import frontend, panel_custom
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import translation

from .card import async_serve_card
from .const import (
    DOMAIN,
    LOGGER_NAME,
    PANEL_SUBENTRY_TYPE,
    SHOW_SIDEBAR_PANEL,
    SHOW_SIDEBAR_PANEL_DEFAULT,
)

# The page's address (/ldata). Dashboards must have a hyphen in theirs, so a
# user-made dashboard cannot already be using this one.
SIDEBAR_URL_PATH = "ldata"
SIDEBAR_ELEMENT = "ldata-sidebar-panel"
SIDEBAR_ICON = "mdi:electric-switch"
# Used when the translations cannot be read; the real title is the
# config_panel.sidebar.title string of the server's language.
SIDEBAR_TITLE = "Load Center"
SIDEBAR_TITLE_KEY = f"component.{DOMAIN}.config_panel.sidebar.title"

_LOGGER = logging.getLogger(LOGGER_NAME)

_STATE_KEY = "_sidebar"  # what is registered right now, or absent
_LOCK_KEY = "_sidebar_lock"



def _safe_area_arguments() -> dict[str, bool]:
    """Tell newer frontends that the page keeps clear of the notch itself.

    They pad a custom page away from the phone's status bar and home
    indicator unless told otherwise. This page does that itself, so its
    header colour runs under the status bar like Home Assistant's own pages.
    Older cores have neither the padding nor the argument.
    """
    parameters = inspect.signature(panel_custom.async_register_panel).parameters
    return {"handle_safe_area": True} if "handle_safe_area" in parameters else {}


def sidebar_enabled(entry: ConfigEntry) -> bool:
    """Return whether this entry asks for the sidebar panel."""
    return bool(
        entry.options.get(
            SHOW_SIDEBAR_PANEL,
            entry.data.get(SHOW_SIDEBAR_PANEL, SHOW_SIDEBAR_PANEL_DEFAULT),
        )
    )


def _wanting_entries(hass: HomeAssistant, removed_entry_id: str | None) -> list[ConfigEntry]:
    return [
        entry
        for entry in hass.config_entries.async_entries(DOMAIN)
        if entry.entry_id != removed_entry_id
        and not entry.disabled_by
        and sidebar_enabled(entry)
    ]


def _panel_ids(hass: HomeAssistant, entry: ConfigEntry) -> list[Any]:
    """Return the ids of the entry's load centers.

    A loaded entry knows them from Leviton. One that is not loaded (still
    starting, reloading, cloud unreachable) has the panels an earlier run
    found recorded as config subentries, so the page keeps showing the same
    load centers instead of going empty.
    """
    coordinator = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    data = getattr(coordinator, "data", None)
    if data:
        return [panel["id"] for panel in data.get("panels", []) if panel.get("id")]
    return [
        subentry.unique_id
        for subentry in getattr(entry, "subentries", {}).values()
        if subentry.subentry_type == PANEL_SUBENTRY_TYPE and subentry.unique_id
    ]


def _panel_device(
    dev_reg: dr.DeviceRegistry, entry: ConfigEntry, panel_id: Any
) -> dr.DeviceEntry | None:
    """Return the device registry entry of one of the entry's load centers."""
    by_identifier = getattr(dev_reg, "async_get_device_by_identifier", None)
    if by_identifier is not None:
        return by_identifier((DOMAIN, panel_id), entry.entry_id)
    # Home Assistant cores that predate the per-entry lookup, where
    # async_get_device is not deprecated yet.
    return dev_reg.async_get_device(identifiers={(DOMAIN, panel_id)})


def _panel_devices(hass: HomeAssistant, entries: list[ConfigEntry]) -> list[dict[str, str]]:
    """Return the load centers to show, as device registry ids.

    Sorted by name so the page does not depend on the order entries happen
    to load in.
    """
    dev_reg = dr.async_get(hass)
    devices: dict[str, dr.DeviceEntry] = {}
    for entry in entries:
        for panel_id in _panel_ids(hass, entry):
            device = _panel_device(dev_reg, entry, panel_id)
            if device is not None:
                devices[device.id] = device
    ordered = sorted(
        devices.values(),
        key=lambda device: ((device.name_by_user or device.name or "").casefold(), device.id),
    )
    return [{"device_id": device.id} for device in ordered]


async def _async_title(hass: HomeAssistant) -> str:
    """Return the sidebar title in the server's language.

    The sidebar shows the title it is given as-is, so it cannot follow each
    user's own language the way the page does.
    """
    try:
        strings = await translation.async_get_translations(
            hass, hass.config.language, "config_panel", {DOMAIN}
        )
    except Exception:  # pylint: disable=broad-except
        _LOGGER.debug("Could not read the sidebar title translation", exc_info=True)
        return SIDEBAR_TITLE
    return strings.get(SIDEBAR_TITLE_KEY) or SIDEBAR_TITLE


async def async_update_sidebar_panel(
    hass: HomeAssistant, *, removed_entry_id: str | None = None
) -> None:
    """Add, refresh or remove the sidebar item so it matches the config entries.

    Called when the integration is set up and whenever an entry is set up,
    unloaded or removed. removed_entry_id names an entry that is being
    deleted, which Home Assistant still lists at that point. Never raises: a
    problem here must not stop a config entry from loading.
    """
    domain_data = hass.data.setdefault(DOMAIN, {})
    lock = domain_data.setdefault(_LOCK_KEY, asyncio.Lock())
    async with lock:
        try:
            await _async_update(hass, domain_data, removed_entry_id)
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Failed to update the LDATA sidebar panel")


async def _async_update(
    hass: HomeAssistant, domain_data: dict[str, Any], removed_entry_id: str | None
) -> None:
    registered = domain_data.get(_STATE_KEY)
    entries = _wanting_entries(hass, removed_entry_id)

    if not entries:
        if registered is not None:
            frontend.async_remove_panel(hass, SIDEBAR_URL_PATH)
            domain_data.pop(_STATE_KEY, None)
            _LOGGER.debug("Removed the LDATA sidebar panel")
        return

    module_url = await async_serve_card(hass)
    if module_url is None:
        return

    wanted = {
        "title": await _async_title(hass),
        "module_url": module_url,
        "config": {"panels": _panel_devices(hass, entries)},
    }
    if wanted == registered:
        return

    # The frontend rebuilds the page when anything about it changes, so this
    # runs only on a real difference. Both calls happen without yielding, so
    # a browser asking for the panels in between never sees the item missing.
    if registered is not None:
        frontend.async_remove_panel(hass, SIDEBAR_URL_PATH)
        domain_data.pop(_STATE_KEY, None)
    try:
        await panel_custom.async_register_panel(
            hass,
            frontend_url_path=SIDEBAR_URL_PATH,
            webcomponent_name=SIDEBAR_ELEMENT,
            sidebar_title=wanted["title"],
            sidebar_icon=SIDEBAR_ICON,
            module_url=module_url,
            embed_iframe=False,
            require_admin=False,
            config=wanted["config"],
            **_safe_area_arguments(),
        )
    except ValueError:
        _LOGGER.warning(
            "Could not add the LDATA sidebar panel: another panel already uses /%s",
            SIDEBAR_URL_PATH,
        )
        return
    domain_data[_STATE_KEY] = wanted
    _LOGGER.debug(
        "LDATA sidebar panel registered with %d load center(s)",
        len(wanted["config"]["panels"]),
    )
