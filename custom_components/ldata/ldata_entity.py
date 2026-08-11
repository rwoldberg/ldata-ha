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

        info = {
            # Leviton's own "serialNumber" field is not reliably unique across
            # breakers — confirmed via a real user report where two distinct
            # breakers (different id, position, model, and even different
            # parent panels) shared the same serialNumber, causing HA to
            # merge them into a single device. "id" is what unique_id/the
            # in-memory breaker cache already key off of and is far more
            # trustworthy (MAC-address-shaped, effectively guaranteed
            # globally unique). For panels, serialNumber is set to the same
            # value as id anyway (see parse_panels()), so this is a no-op
            # there — only breakers are actually affected.
            #
            # stable_id (falling back to id where absent, e.g. panels/CTs)
            # strips a breaker id-format change Leviton introduced in
            # firmware 2.2.0 (a panel-serial suffix got appended to every
            # breaker id) — confirmed via a real user's device registry that
            # using raw "id" here forks every breaker into a second HA
            # device the moment Leviton changes this format again. "id"
            # itself is deliberately left alone elsewhere (WS subscriptions,
            # the breakers cache, every entity's own coordinator lookup) —
            # this stripped form exists only for device identity/unique_id.
            "identifiers": {(DOMAIN, self.entity_data.get("stable_id", self.entity_data["id"]))},
            "name": self.entity_data["name"],
            "model": self.entity_data["model"],
            "hw_version": self.entity_data.get("hardware"),
            "sw_version": self.entity_data["firmware"],
            "manufacturer": MANUFACTURER,
        }
        # Breakers carry panel_id (panels themselves don't) — link the breaker
        # device to its panel device in HA's device registry so frontend code
        # (e.g. a panel-layout card) can discover "all breakers on this panel"
        # without needing a separate data source.
        if panel_id := self.entity_data.get("panel_id"):
            info["via_device"] = (DOMAIN, panel_id)
        return info

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the extra attributes for the breaker."""
        return {"leg": self.leg}
