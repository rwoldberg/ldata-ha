"""Defines a base LDATA entity."""

from .const import _LEG1_POSITIONS, DOMAIN, MANUFACTURER
from .coordinator import LDATAUpdateCoordinator
from .ldata_base_entity import LDATABaseEntity


class LDATAEntity(LDATABaseEntity):
    """Defines a base LDATA entity."""

    def __init__(self, data, coordinator: LDATAUpdateCoordinator) -> None:
        """Initialize the entity."""
        super().__init__(data, coordinator)
        if "poles" in self.entity_data and "position" in self.entity_data:
            if int(self.entity_data["poles"]) == 2:
                self.leg = "both"
            elif self.entity_data["position"] in _LEG1_POSITIONS:
                self.leg = "1"
            else:
                self.leg = "2"
        else:
            self.leg = "both"

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
        return {"leg": self.leg}
