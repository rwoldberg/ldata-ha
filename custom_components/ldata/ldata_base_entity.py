"""Shared scaffolding for LDATA entities (breaker/panel and CT variants)."""

from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import PANEL_SUBENTRY_TYPE
from .coordinator import LDATAUpdateCoordinator


def add_entities_grouped_by_panel(config_entry, async_add_entities, entities) -> None:
    """Call async_add_entities once per panel, scoped to that panel's subentry.

    Every LDATA entity's __init__ stores its constructor data verbatim as
    entity_data (see LDATABaseEntity.__init__ below) — breaker/CT entities
    carry panel_id directly there; a panel-level entity's entity_data IS the
    panel's own dict, so its own "id" is used instead. This lets every
    platform's async_setup_entry keep its existing accumulation logic
    untouched and just swap the final flat async_add_entities(...) call for
    this one.

    config_subentry_id ends up None for anything that doesn't resolve to a
    known panel subentry (older HA cores without subentry support, or a
    panel that hasn't been reconciled into a subentry yet) — identical to
    today's behavior, so this degrades safely rather than failing setup.
    On an HA core old enough that async_add_entities doesn't accept the
    config_subentry_id keyword at all, the call itself falls back to the
    plain (pre-subentry) form rather than raising.
    """
    if not entities:
        return
    subentry_by_panel = {
        se.unique_id: se.subentry_id
        for se in getattr(config_entry, "subentries", {}).values()
        if se.subentry_type == PANEL_SUBENTRY_TYPE and se.unique_id
    }
    groups: dict[str | None, list] = {}
    for entity in entities:
        panel_id = entity.entity_data.get("panel_id") or entity.entity_data.get("id")
        groups.setdefault(panel_id, []).append(entity)
    for panel_id, group in groups.items():
        try:
            async_add_entities(group, config_subentry_id=subentry_by_panel.get(panel_id))
        except TypeError:
            async_add_entities(group)


def is_breaker_on(data: dict) -> bool:
    """Return whether a breaker's raw state fields indicate it's manually on.

    Shared by LDATABinarySensor (binary_sensor.py) and LDATASwitch
    (switch.py), which both derive their on/off state from the same
    state/remoteState field pair.
    """
    return data.get("state") == "ManualON" and data.get("remoteState") == "RemoteON"


def find_panel(coordinator: LDATAUpdateCoordinator, panel_id: str) -> dict | None:
    """Return the panel dict with the given id from coordinator.data, or None.

    Shared by every sensor/binary_sensor class that needs to look up its own
    panel's latest data on each coordinator update (panel counts are small,
    so a linear scan is fine — this just avoids five copies of the loop).
    """
    if not coordinator.data:
        return None
    for panel in coordinator.data.get("panels", []):
        if panel.get("id") == panel_id:
            return panel
    return None


class LDATABaseEntity(CoordinatorEntity[LDATAUpdateCoordinator]):
    """Common __init__/name/unique_id/device_id scaffolding.

    Subclasses (LDATAEntity, LDATACTEntity) differ only in how the device id
    is built and what device_info/extra_state_attributes they expose.
    """

    def __init__(self, data, coordinator: LDATAUpdateCoordinator) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self.entity_data = data
        self._device_id = self._build_device_id()
        if suffix := self.name_suffix:
            self._name = self.entity_data["name"] + " " + suffix
        else:
            self._name = self.entity_data["name"]
        self.coordinator_context = object()

    def _build_device_id(self) -> str:
        """Build this entity's device id. Default shape; CT entities override."""
        return "ldata_" + self.entity_data["id"]

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

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
