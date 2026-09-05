"""Defines a base LDATA CT entity."""

from homeassistant.helpers import device_registry as dr

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

        info = {
            "identifiers": {
                (DOMAIN, self.entity_data["panel_id"], self.entity_data["id"])
            },
            "name": self.entity_data["name"],
            "manufacturer": MANUFACTURER,
        }
        # via_device_id (not the deprecated via_device identifiers-tuple
        # form) needs the panel's actual device id — __init__.py's
        # _async_ensure_panel_devices guarantees it already exists by the
        # time any CT entity gets this far (see ldata_entity.py for the
        # matching breaker-side comment).
        panel_id = self.entity_data["panel_id"]
        if self.hass and (
            panel_device := dr.async_get(self.hass).async_get_device(
                identifiers={(DOMAIN, panel_id)}
            )
        ):
            info["via_device_id"] = panel_device.id
        return info

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the extra attributes for the breaker."""
        return {
            "channel": self.entity_data["channel"],
            "panel_id": self.entity_data["panel_id"],
        }
