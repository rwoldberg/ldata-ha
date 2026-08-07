"""The LDATA integration."""
from __future__ import annotations
import logging
from pathlib import Path

import voluptuous as vol

from homeassistant.components.http import StaticPathConfig
from homeassistant.components.lovelace.const import LOVELACE_DATA, MODE_STORAGE
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_ENTITY_ID, EVENT_HOMEASSISTANT_STARTED, Platform, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import CoreState, HomeAssistant, ServiceCall
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import entity_platform
import homeassistant.helpers.config_validation as cv

from .const import DECORA_ROOM_SUBENTRY_TYPE, DOMAIN, LOGGER_NAME, PANEL_SUBENTRY_TYPE
from .coordinator import LDATAUpdateCoordinator
from .ldata_service import VERSION

# URL path the panel card is served under — served directly from this
# integration's own www/ folder (see _async_register_frontend below), so
# users never need to copy the file into config/www or manually add it as
# a Lovelace resource.
_FRONTEND_URL_PATH = "/ldata_static"
_PANEL_CARD_FILENAME = "ldata-panel-card.js"

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.FAN,
    Platform.LIGHT,
    Platform.SELECT,
    Platform.SENSOR,
    Platform.SWITCH,
]
_LOGGER = logging.getLogger(LOGGER_NAME)

SERVICE_RESET_ENERGY = "reset_energy_baseline"
SERVICE_RESET_PANEL = "reset_panel_energy"
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


def _get_sensor_entity(hass: HomeAssistant, entity_id: str):
    """Look up a live LDATA sensor entity object via the entity platform registry.

    Avoids reaching into the private hass.data["entity_components"] dict, which
    is an internal HA implementation detail not guaranteed across core versions.
    """
    for platform in entity_platform.async_get_platforms(hass, DOMAIN):
        if platform.domain != "sensor":
            continue
        entity = platform.entities.get(entity_id)
        if entity:
            return entity
    return None


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


async def _async_register_frontend(hass: HomeAssistant) -> None:
    """Serve the panel card from this integration's own www/ folder and
    register it as a genuine Lovelace resource, so users never need to copy
    the file into config/www or manually add it via Settings > Dashboards.

    Deliberately does NOT use frontend.add_extra_js_url() — that injects a
    raw `import()` into the index page, which races the rest of the
    frontend bundle: if Lovelace evaluates a card's config before that
    import resolves, it permanently marks the card as an unknown custom
    element and never rechecks, even after the module finishes loading a
    moment later. Registering as a proper Lovelace resource instead uses
    the same loading path Lovelace itself waits on before resolving card
    types, avoiding the race entirely.

    Guarded to run only once regardless of how many config entries this
    integration ends up with (e.g. one per residence) — async_setup runs
    once per HA process, but belt-and-suspenders since this is also called
    from the deferred STARTED-event listener.
    """
    if hass.data.get(DOMAIN, {}).get("_frontend_registered"):
        return
    hass.data.setdefault(DOMAIN, {})["_frontend_registered"] = True

    www_dir = Path(__file__).parent / "www"
    if not await hass.async_add_executor_job(www_dir.is_dir):
        _LOGGER.warning("LDATA www directory not found at %s — panel card won't load", www_dir)
        return

    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig(_FRONTEND_URL_PATH, str(www_dir), True)
        ])
    except RuntimeError:
        _LOGGER.debug("LDATA static path already registered at %s", _FRONTEND_URL_PATH)

    lovelace = hass.data.get(LOVELACE_DATA)
    if lovelace is None or lovelace.resource_mode != MODE_STORAGE:
        # No Lovelace data yet, or the dashboard is in legacy YAML mode —
        # the storage-backed resources collection used below doesn't apply
        # either way. Falls back to needing the manual install steps.
        _LOGGER.debug(
            "Lovelace storage mode not available — panel card is served at "
            "%s/%s but won't be auto-registered as a resource; add it "
            "manually via Settings > Dashboards > Resources if needed.",
            _FRONTEND_URL_PATH, _PANEL_CARD_FILENAME,
        )
        return

    card_url = f"{_FRONTEND_URL_PATH}/{_PANEL_CARD_FILENAME}"
    try:
        already_registered = any(
            resource["url"].split("?", 1)[0] == card_url
            for resource in lovelace.resources.async_items()
        )
        if not already_registered:
            await lovelace.resources.async_create_item({
                "res_type": "module",
                "url": f"{card_url}?v={VERSION}",
            })
            _LOGGER.info("Registered LDATA panel card as a Lovelace resource: %s", card_url)
    except Exception:
        _LOGGER.exception("Failed to auto-register the LDATA panel card as a Lovelace resource")


def _resolve_panel_id_for_device(device, existing_panel_ids: set[str], dev_reg) -> str | None:
    """Resolve which panel a device belongs to, using the device registry alone.

    Doesn't touch coordinator.data at all — via_device_id and identifiers are
    already persisted from prior runs, so this works even for a panel that's
    currently offline or has since been removed from the account.
    """
    for identifier in device.identifiers:
        if identifier[0] != DOMAIN:
            continue
        if len(identifier) == 3:
            # CT device: (DOMAIN, panel_id, ct_id) — panel_id is right there.
            return identifier[1]
        if len(identifier) == 2 and identifier[1] in existing_panel_ids:
            # The panel device itself — its own identifier IS the panel id.
            return identifier[1]

    if device.via_device_id:
        # Breaker — resolve via the panel device it's linked to.
        parent = dev_reg.async_get(device.via_device_id)
        if parent:
            for identifier in parent.identifiers:
                if identifier[0] == DOMAIN and identifier[1] in existing_panel_ids:
                    return identifier[1]

    return None


def _resolve_decora_room_id_for_device(device, mac_to_room: dict[str, str]) -> str | None:
    """Resolve which Decora room a device belongs to.

    Unlike _resolve_panel_id_for_device above, this can't work from the
    device registry alone — a Decora device's identifier is just (DOMAIN,
    mac) with no via_device_id, and room membership (residentialRoomId) is a
    Leviton-side device attribute, not something HA's registry encodes the
    way panel/breaker/CT relationships are via identifiers/via_device_id. So
    this needs mac_to_room, built fresh from the current coordinator data —
    a device that's dropped out of it (e.g. a transient API hiccup) simply
    isn't resolved this run; reconciliation runs on every setup, so it
    converges again on the next successful fetch.
    """
    for identifier in device.identifiers:
        if identifier[0] == DOMAIN and len(identifier) == 2 and identifier[1] in mac_to_room:
            return mac_to_room[identifier[1]]
    return None


async def _async_purge_orphaned_devices(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove this entry's devices that no longer have any entities.

    A device's `identifiers` changing (e.g. breaker devices moving from
    serialNumber-based to id-based identifiers, since Leviton's serialNumber
    field turned out not to be reliably unique) makes HA register a brand
    new device for the same physical hardware — every entity follows (same
    unique_id, so same entity_id), but the old device record isn't deleted
    automatically; it just lingers with zero entities. Run this AFTER
    platform setup so entities have already been re-linked to their new
    device before we decide what's actually orphaned.
    """
    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)

    devices = list(dev_reg.devices.get_devices_for_config_entry_id(entry.entry_id))
    removed = 0
    for device in devices:
        if er.async_entries_for_device(ent_reg, device.id, include_disabled_entities=True):
            continue
        dev_reg.async_remove_device(device.id)
        removed += 1

    if removed:
        _LOGGER.info(
            "Removed %d orphaned device(s) with no remaining entities "
            "(likely left behind by a device-identity change)",
            removed,
        )


async def _async_reconcile_subentries(
    hass: HomeAssistant, entry: ConfigEntry, coordinator: LDATAUpdateCoordinator
) -> None:
    """Ensure every discovered panel and Decora room has a matching config
    subentry, and move any pre-subentry devices/entities into theirs.

    Panels and Decora devices are unrelated product lines sharing one config
    entry, each grouped by its own natural key — panel id for panels/CTs/
    breakers, Leviton's own residentialRoomId for Decora devices (there's no
    panel to group those under). Safe to call on every setup —
    devices/entities that already have a config_subentry_id are left alone,
    so this converges naturally without needing a separate "have I migrated"
    flag. No-ops entirely on an HA core old enough not to support subentries
    at all.
    """
    try:
        from homeassistant.config_entries import ConfigSubentry
    except ImportError:
        return  # HA core predates config subentries — nothing to do.

    if not coordinator.data:
        return

    existing_panel = {
        se.unique_id: se.subentry_id
        for se in entry.subentries.values()
        if se.subentry_type == PANEL_SUBENTRY_TYPE and se.unique_id
    }
    existing_room = {
        se.unique_id: se.subentry_id
        for se in entry.subentries.values()
        if se.subentry_type == DECORA_ROOM_SUBENTRY_TYPE and se.unique_id
    }

    for panel in coordinator.data.get("panels", []):
        panel_id = panel.get("id")
        if not panel_id or panel_id in existing_panel:
            continue
        subentry = ConfigSubentry(
            data={},
            subentry_type=PANEL_SUBENTRY_TYPE,
            title=panel.get("name") or panel_id,
            unique_id=panel_id,
        )
        hass.config_entries.async_add_subentry(entry, subentry)
        existing_panel[panel_id] = subentry.subentry_id
        _LOGGER.info(
            "Created config subentry for panel '%s' (%s)", subentry.title, panel_id
        )

    # Only rooms that currently have at least one Decora device — rooms is
    # every room Leviton knows about for the residence (kitchen, bedroom,
    # etc., most of which have no smart devices in them), not just the ones
    # relevant here; a subentry per room regardless would clutter Devices &
    # Services with empty groups nobody asked for. Room ids are coerced to
    # str throughout — Leviton's API has previously returned other ids
    # (residence, panel) as raw JSON numbers rather than strings, and
    # ConfigSubentry.unique_id needs to compare equal run over run.
    room_names = {str(k): v for k, v in coordinator.data.get("rooms", {}).items()}
    device_room_ids: set[str] = set()
    mac_to_room: dict[str, str] = {}
    for dev_id, dev in coordinator.data.get("decora_devices", {}).items():
        room_id = dev.get("residentialRoomId")
        if not room_id:
            continue
        room_id = str(room_id)
        device_room_ids.add(room_id)
        mac_to_room[str(dev.get("mac") or dev_id)] = room_id

    for room_id in device_room_ids:
        if room_id in existing_room:
            continue
        title = room_names.get(room_id) or f"Room {room_id}"
        subentry = ConfigSubentry(
            data={},
            subentry_type=DECORA_ROOM_SUBENTRY_TYPE,
            title=title,
            unique_id=room_id,
        )
        hass.config_entries.async_add_subentry(entry, subentry)
        existing_room[room_id] = subentry.subentry_id
        _LOGGER.info(
            "Created config subentry for Decora room '%s' (%s)", title, room_id
        )

    if not existing_panel and not existing_room:
        return

    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)
    existing_panel_ids = set(existing_panel)

    # Config-entry-level subentries (ConfigSubentry, async_add_subentry — the
    # create step above) and device/entity-registry-level subentry support
    # (DeviceEntry.config_subentry_id, RegistryEntry.config_subentry_id)
    # apparently didn't land in the same HA release — the subentries just
    # created above are real either way and will scope newly-created
    # devices/entities going forward, but backfilling pre-existing ones only
    # works once the running core's registries actually carry the field.
    # device_subentry ends up covering every device that resolves to a panel,
    # not just ones actually moved in this call — a device already carrying
    # the right config_subentry_id from a prior run still needs to be in
    # here, so the entity loop below can catch up any of its entities that
    # didn't get migrated alongside it (e.g. if entity-registry subentry
    # support landed on this HA core after device-registry support did, or a
    # previous run's entity pass was interrupted). Otherwise entity
    # migration would only ever get one shot, on the same run its device
    # was first moved, with no way to retry on a later load.
    devices = dev_reg.devices.get_devices_for_config_entry_id(entry.entry_id)
    unresolved = 0
    no_subentry_support = 0
    device_subentry: dict[str, str] = {}
    for device in devices:
        panel_id = _resolve_panel_id_for_device(device, existing_panel_ids, dev_reg)
        subentry_id = existing_panel.get(panel_id) if panel_id else None
        if not subentry_id:
            # Not a panel-family device (or its panel isn't known this run)
            # — try Decora room resolution before giving up on it.
            room_id = _resolve_decora_room_id_for_device(device, mac_to_room)
            subentry_id = existing_room.get(room_id) if room_id else None
        # Catch per-device, not around the whole loop — device_subentry_id
        # support can be missing on some HA cores (see the warning below),
        # and a broad try/except around the entire loop would silently stop
        # processing every device that comes after the first failure in
        # iteration order (and skip the entity-migration pass entirely,
        # since that runs after this loop) instead of just skipping the
        # one device that doesn't support it.
        try:
            if not subentry_id:
                if device.config_subentry_id is None:
                    unresolved += 1
                    _LOGGER.warning(
                        "Could not resolve a panel or Decora room for device '%s' "
                        "(%s) — leaving it out of any subentry. identifiers=%s "
                        "via_device_id=%s",
                        device.name, device.id, device.identifiers, device.via_device_id,
                    )
                continue
            device_subentry[device.id] = subentry_id
            if device.config_subentry_id != subentry_id:
                dev_reg.async_update_device(device.id, new_config_subentry_id=subentry_id)
        except AttributeError:
            # debug, not warning — this is a known, permanent-until-HA-updates
            # condition on some HA core versions (subentries work at the
            # integration/creation-time level, but this core's device
            # registry doesn't yet support updating config_subentry_id on an
            # already-existing device). Re-attempted every setup since there's
            # no persistent "already told you" flag, so warning-level here
            # would repeat the same noise on every single restart forever.
            no_subentry_support += 1
            _LOGGER.debug(
                "This Home Assistant core doesn't support config_subentry_id "
                "on device '%s' (%s) yet — leaving it out of its subentry "
                "until HA is updated further.",
                device.name, device.id,
            )

    if no_subentry_support:
        _LOGGER.debug(
            "%d device(s) could not be moved into their subentry — "
            "this Home Assistant core supports config subentries at the "
            "integration level, but its device registry doesn't yet carry "
            "config_subentry_id on individual devices. Newly-created "
            "devices are unaffected.",
            no_subentry_support,
        )

    if not device_subentry:
        if not unresolved:
            _LOGGER.debug("No devices found for this entry — nothing to reconcile.")
        return

    moved = 0
    no_subentry_support = 0
    for ent_entry in er.async_entries_for_config_entry(ent_reg, entry.entry_id):
        if not ent_entry.device_id:
            continue
        # Re-check even entities that already carry a subentry, not just
        # unassigned ones — a breaker moved to a different panel (in the
        # Leviton account, not in HA) gets its device re-resolved to the
        # new panel's subentry above, but its entities would otherwise
        # keep pointing at the panel they were first migrated to,
        # forever, since a plain "only migrate if None" check has no way
        # to notice the device it belongs to has since moved.
        subentry_id = device_subentry.get(ent_entry.device_id)
        if not subentry_id:
            continue
        # Caught per-entity for the same reason as the device loop above —
        # one entity lacking config_subentry_id support shouldn't stop the
        # rest of the batch from being migrated. Wraps the *read* of
        # ent_entry.config_subentry_id too, not just the update call —
        # device- and entity-registry subentry support can land on different
        # HA releases (confirmed true for at least one real HA core: device
        # support missing, entity support unconfirmed), so the read itself
        # could just as easily be what's unsupported here.
        try:
            if ent_entry.config_subentry_id == subentry_id:
                continue
            ent_reg.async_update_entity(ent_entry.entity_id, config_subentry_id=subentry_id)
            moved += 1
        except AttributeError:
            no_subentry_support += 1

    if no_subentry_support:
        # debug, not warning — same reasoning as the device loop above: a
        # known, permanent-until-HA-updates condition that would otherwise
        # repeat identical noise on every single restart forever.
        _LOGGER.debug(
            "%d entit(y/ies) could not be moved into their subentry "
            "— this HA core's entity registry doesn't support "
            "config_subentry_id yet. They'll show under their device but "
            "won't be grouped by subentry themselves until HA is updated "
            "further.",
            no_subentry_support,
        )

    if moved:
        _LOGGER.info(
            "Migrated %d device(s) / %d entities into panel/room subentries",
            len(device_subentry), moved,
        )


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the LDATA integration (runs once per HA process, independent
    of any config entry).

    Registers the panel card's frontend resources here rather than in
    async_setup_entry — that runs once per config entry (e.g. once per
    residence, per the residence picker), but frontend registration should
    only ever happen once. Deferred until HA has fully started if it
    hasn't yet, since Lovelace's storage-backed resources collection isn't
    reliably available during early boot.
    """
    if hass.state == CoreState.running:
        await _async_register_frontend(hass)
    else:
        async def _on_started(_event) -> None:
            await _async_register_frontend(hass)

        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _on_started)
    return True


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

    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        # The coordinator's constructor already started websocket/REST/CT
        # background tasks; make sure they're torn down explicitly if first
        # refresh fails, instead of relying solely on HA's own config-entry
        # background-task bookkeeping for a coordinator that never made it
        # into hass.data.
        await coordinator.async_shutdown()
        raise

    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Ensure each panel has its own config subentry, and migrate any
    # pre-subentry devices/entities into theirs, before platforms set up —
    # so newly-discovered breakers get the right config_subentry_id from
    # the moment they're created instead of needing a second pass.
    await _async_reconcile_subentries(hass, entry, coordinator)

    # This line will now only be reached if the first refresh was successful.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Platforms have now registered every current entity against its device —
    # safe to remove any device that's left with none (see docstring).
    await _async_purge_orphaned_devices(hass, entry)

    # Set up a listener for options updates
    entry.add_update_listener(options_update_listener)

    # Register services (only once, not per entry)
    if not hass.services.has_service(DOMAIN, SERVICE_RESET_ENERGY):
        async def handle_reset_energy(call: ServiceCall) -> None:
            """Handle the reset_energy_baseline service call."""
            entity_id = call.data[ATTR_ENTITY_ID]
            new_value = call.data.get(ATTR_VALUE)
            new_baseline = call.data.get(ATTR_BASELINE)

            # Find the entity object through the entity platform, but only if
            # it belongs to one of our config entries.
            target_entity = None
            ent_reg = er.async_get(hass)
            ent_entry = ent_reg.async_get(entity_id)
            if ent_entry is not None and ent_entry.config_entry_id in hass.data[DOMAIN]:
                target_entity = _get_sensor_entity(hass, entity_id)

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
                    entity = _get_sensor_entity(hass, ent_entry.entity_id)
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
    # Unload platforms first. Only tear down the coordinator's websocket/REST
    # tasks (and drop it from hass.data) once we know the unload actually
    # succeeded — if it fails, entities remain loaded and need a live
    # coordinator to keep updating, not a shut-down one.
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
        if coordinator:
            await coordinator.async_shutdown()

    return unload_ok

async def options_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    # This is the recommended way to handle options updates.
    await hass.config_entries.async_reload(entry.entry_id)