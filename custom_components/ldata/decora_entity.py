"""Defines a base entity for Leviton Decora Smart Wi-Fi devices."""

import logging

from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DECORA_ROOM_SUBENTRY_TYPE, DOMAIN, LOGGER_NAME, MANUFACTURER
from .coordinator import LDATAUpdateCoordinator

_LOGGER = logging.getLogger(LOGGER_NAME)


def add_entities_grouped_by_decora_room(config_entry, async_add_entities, entities) -> None:
    """Call async_add_entities once per Decora room, scoped to that room's subentry.

    Mirrors ldata_base_entity.add_entities_grouped_by_panel — same shape,
    same safe degradation (config_subentry_id ends up None for anything
    unresolved, whether because the device has no room assigned — e.g. a
    Wi-Fi bridge, which parse_bridge_devices always sets residentialRoomId
    to None for — or the HA core doesn't support subentries yet), just
    keyed by residentialRoomId (str) instead of panel id.
    """
    if not entities:
        return
    subentry_by_room = {
        se.unique_id: se.subentry_id
        for se in getattr(config_entry, "subentries", {}).values()
        if se.subentry_type == DECORA_ROOM_SUBENTRY_TYPE and se.unique_id
    }
    groups: dict[str | None, list] = {}
    for entity in entities:
        room_id = entity.entity_data.get("residentialRoomId")
        groups.setdefault(str(room_id) if room_id else None, []).append(entity)
    for room_id, group in groups.items():
        try:
            async_add_entities(group, config_subentry_id=subentry_by_room.get(room_id))
        except TypeError:
            async_add_entities(group)


class DecoraEntity(CoordinatorEntity[LDATAUpdateCoordinator]):
    """Defines a base Decora Smart Wi-Fi entity.

    Deliberately separate from LDATABaseEntity (used by breakers/CTs/panels)
    rather than unified with it — Decora is a different Leviton product line
    with its own id/naming scheme (keyed by device id/MAC, not tied to a
    panel), so sharing a base class would add coupling without real benefit.
    """

    def __init__(self, data, coordinator: LDATAUpdateCoordinator) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self.coordinator = coordinator
        self.entity_data = data
        self._dev_id = data["id"]
        self._device_id = f"decora_{self._dev_id}"
        if suffix := self.name_suffix:
            self._name = data["name"] + " " + suffix
        else:
            self._name = data["name"]
        self.coordinator_context = object()

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    def _get_device_data(self) -> dict | None:
        """Get the latest data for this device from the coordinator."""
        if self.coordinator.data and "decora_devices" in self.coordinator.data:
            return self.coordinator.data["decora_devices"].get(self._dev_id)
        return None

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        device = self._get_device_data()
        if device is None:
            return False
        return device.get("connected", False) and super().available

    @property
    def device_id(self):
        """Returns the device id of the entity."""
        return self._device_id

    @property
    def name(self):
        """Return the name of the entity."""
        return self._name

    @property
    def unique_id(self):
        """Return the unique ID of the entity."""
        mac = self.entity_data.get("mac", self._dev_id)
        if suffix := self.unique_id_suffix:
            return f"{self.coordinator.user}-{mac}_{suffix}"
        return f"{self.coordinator.user}-{mac}"

    @property
    def name_suffix(self) -> str | None:
        """Return the name suffix of the entity."""
        return None

    @property
    def unique_id_suffix(self) -> str | None:
        """Return the unique id suffix of the entity."""
        return None

    @property
    def device_info(self):
        """Return device information about this device."""
        mac = self.entity_data.get("mac", str(self._dev_id))
        info = {
            "identifiers": {(DOMAIN, mac)},
            "name": self.entity_data["name"],
            "model": self.entity_data.get("model"),
            "sw_version": self.entity_data.get("version"),
            "manufacturer": self.entity_data.get("manufacturer", MANUFACTURER),
        }
        if self.entity_data.get("roomName"):
            info["suggested_area"] = self.entity_data["roomName"]
        return info

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return extra state attributes."""
        device = self._get_device_data()
        attrs = {}
        if device:
            if device.get("rssi") is not None:
                attrs["signal_strength"] = device["rssi"]
            if device.get("localIP"):
                attrs["local_ip"] = device["localIP"]
            if device.get("roomName"):
                attrs["room"] = device["roomName"]
        return attrs
