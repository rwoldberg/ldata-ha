"""Defines a base LDATA entity."""

import logging

from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import _LEG1_POSITIONS, DOMAIN, LOGGER_NAME, MANUFACTURER
from .coordinator import LDATAUpdateCoordinator

_LOGGER = logging.getLogger(LOGGER_NAME)


class LDATAEntity(CoordinatorEntity[LDATAUpdateCoordinator]):
    """Defines a base LDATA entity."""

    def __init__(self, data, coordinator: LDATAUpdateCoordinator) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self.coordinator = coordinator
        self.entity_data = data
        self._device_id = "ldata_" + self.entity_data["id"]
        if suffix := self.name_suffix:
            self._name = self.entity_data["name"] + " " + suffix
        else:
            self._name = self.entity_data["name"]
        if "poles" in self.entity_data and "position" in self.entity_data:
            if int(self.entity_data["poles"]) == 2:
                self.leg = "both"
            elif self.entity_data["position"] in _LEG1_POSITIONS:
                self.leg = "1"
            else:
                self.leg = "2"
        else:
            self.leg = "both"
        # Required for HA 2022.7
        self.coordinator_context = object()

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    @property
    def device_id(self):
        """Returns the device id of the entity."""
        return self.device_id

    @property
    def name(self):
        """Return the name of the entity."""
        return self._name

    @property
    def unique_id(self):
        """Return the unique ID of the entity."""
        if suffix := self.unique_id_suffix:
            return f"{self.coordinator.user}-{self._device_id}_{suffix}"
        return f"{self.coordinator.user}-{self._device_id}"

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
        if self._device_id is None:
            return None

        return {
            "identifiers": {(DOMAIN, self.entity_data["serialNumber"])},
            "name": self.entity_data["name"],
            "model": self.entity_data["model"],
            "hw_version": self.entity_data.get("hardware"),
            "sw_version": self.entity_data["firmware"],
            "manufacturer": MANUFACTURER,
        }

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the extra attributes for the breaker."""
        attributes = {}
        attributes["leg"] = self.leg

        return attributes
