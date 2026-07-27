"""Defines a base LDATA CT entity."""

from .const import DOMAIN, MANUFACTURER
from .ldata_base_entity import LDATABaseEntity


class LDATACTEntity(LDATABaseEntity):
    """Defines CT Sensor entity."""

    def _build_device_id(self) -> str:
        """CT device ids are scoped by panel_id since CT ids aren't globally unique."""
        return "ldata_" + self.entity_data["panel_id"] + self.entity_data["id"]

    @property
    def device_info(self):
        """Return device information about this device."""
        if self._device_id is None:
            return None

        return {
            "identifiers": {
                (DOMAIN, self.entity_data["panel_id"], self.entity_data["id"])
            },
            "name": self.entity_data["name"],
            "manufacturer": MANUFACTURER,
            "via_device": (DOMAIN, self.entity_data["panel_id"]),
        }

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the extra attributes for the breaker."""
        return {
            "channel": self.entity_data["channel"],
            "panel_id": self.entity_data["panel_id"],
        }
