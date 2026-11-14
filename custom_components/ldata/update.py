"""Support for Leviton firmware-update entities (panels and Decora Smart Wi-Fi devices)."""

import logging

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType

from .const import DOMAIN, LOGGER_NAME, is_decora_bridge
from .coordinator import LDATAUpdateCoordinator
from .decora_entity import DecoraEntity, add_entities_grouped_by_decora_room
from .ldata_base_entity import add_entities_grouped_by_panel, find_panel
from .ldata_entity import LDATAEntity

_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up panel and Decora firmware-update entities."""
    coordinator: LDATAUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id]

    if not coordinator.data:
        return

    entities_to_add = []

    for panel in coordinator.data.get("panels", []):
        entity_data = {
            "id": panel["serialNumber"],
            "name": panel["name"],
            "model": panel["model"],
            "hardware": "LDATA",
            "firmware": panel["firmware"],
            "data": panel,
        }
        entities_to_add.append(LDATAPanelFirmwareUpdateEntity(coordinator, entity_data))

    for breaker in coordinator.data.get("breakers", {}).values():
        entities_to_add.append(LDATABreakerFirmwareUpdateEntity(coordinator, breaker))

    add_entities_grouped_by_panel(config_entry, async_add_entities, entities_to_add)

    decora_entities = []
    for dev_data in coordinator.data.get("decora_devices", {}).values():
        if is_decora_bridge(dev_data):
            continue
        decora_entities.append(LDATADecoraFirmwareUpdateEntity(coordinator, dev_data))

    add_entities_grouped_by_decora_room(config_entry, async_add_entities, decora_entities)


class LDATAPanelFirmwareUpdateEntity(LDATAEntity, UpdateEntity):
    """Report panel firmware availability without offering an install action.

    Applying firmware to electrical-panel hardware should remain an explicit
    operation in My Leviton — no UpdateEntityFeature.INSTALL is declared, so
    HA never shows an install button. This only surfaces metadata already
    returned by the cloud so an available update is not silently missed: the
    entity turns "on" when a newer version is available, which can drive a
    notification automation.

    Without INSTALL, the frontend's "Updates available" sidebar badge and
    Settings dashboard card do not count this entity, whatever its category:
    both only count updates that can be installed, and neither checks
    entity_category.

    entity_category is None rather than DIAGNOSTIC so the entity is listed
    with the device's main entities instead of under Diagnostic.
    """

    _attr_device_class = UpdateDeviceClass.FIRMWARE
    # Must be set explicitly: UpdateEntity.entity_category falls back to
    # DIAGNOSTIC for any entity without INSTALL support unless an
    # _attr_entity_category (even None) is present.
    _attr_entity_category = None

    def __init__(self, coordinator, data) -> None:
        """Initialize the panel firmware update entity."""
        super().__init__(data=data, coordinator=coordinator)
        self._panel_id = data["data"]["id"]
        self._installed = data["data"].get(
            "installed_firmware", data.get("firmware")
        )
        self._available = data["data"].get("available_firmware")
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Refresh firmware metadata from the latest panel snapshot."""
        try:
            panel = find_panel(self.coordinator, self._panel_id)
            if panel is not None:
                self._installed = panel.get(
                    "installed_firmware", panel.get("firmware", self._installed)
                )
                self._available = panel.get("available_firmware")
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def installed_version(self) -> StateType:
        """Return the currently installed firmware version."""
        return self._installed

    @property
    def latest_version(self) -> StateType:
        """Return the latest available firmware version.

        Equal to installed_version when no update is pending, which is what
        tells HA there is nothing to report.
        """
        return self._available or self._installed

    @property
    def name_suffix(self) -> str | None:
        return "Firmware Update"

    @property
    def unique_id_suffix(self) -> str | None:
        return "firmware_update"


class LDATABreakerFirmwareUpdateEntity(LDATAEntity, UpdateEntity):
    """Report a smart breaker's firmware availability, without installing it.

    Same no-install-button design as LDATAPanelFirmwareUpdateEntity. Whether
    an update is waiting is decided in ldata_service._breaker_firmware_versions
    with the My Leviton app's own rules, which differ between LDATA and LWHEM
    breakers, so the versions are not compared again here.

    Disabled by default: there is one per breaker, and Leviton updates every
    breaker of a model at once, so the firmware notification blueprint would
    otherwise send one notification per breaker to everyone who uses it.
    """

    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_entity_category = None  # explicit — see LDATAPanelFirmwareUpdateEntity
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator, data) -> None:
        """Init LDATABreakerFirmwareUpdateEntity."""
        super().__init__(data=data, coordinator=coordinator)
        self._breaker = data

    @callback
    def _handle_coordinator_update(self) -> None:
        """Take the breaker's latest firmware fields."""
        try:
            self._breaker = self.coordinator.data["breakers"][self.entity_data["id"]]
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def installed_version(self) -> StateType:
        """Return the firmware the breaker runs."""
        return self._breaker.get("installed_firmware") or self._breaker.get("firmware")

    @property
    def latest_version(self) -> StateType:
        """Return the firmware waiting for it, or the installed one if none."""
        return self._breaker.get("available_firmware") or self.installed_version

    @property
    def release_summary(self) -> str | None:
        """Name each firmware image the update changes (LWHEM breakers)."""
        return self._breaker.get("firmware_update_summary")

    def version_is_newer(self, latest_version: str, installed_version: str) -> bool:
        """Leviton's rule already decided there is an update; trust it."""
        return True

    @property
    def name_suffix(self) -> str | None:
        return "Firmware Update"

    @property
    def unique_id_suffix(self) -> str | None:
        return "firmware_update"


class LDATADecoraFirmwareUpdateEntity(DecoraEntity, UpdateEntity):
    """Report Decora Smart Wi-Fi device firmware availability.

    Same no-install-button design as LDATAPanelFirmwareUpdateEntity — this
    only detects an available update via HA's native Update entity so it can
    drive a notification automation; installing still happens in My Leviton.
    Like the panel entity, it is not counted in the "Updates available" badge
    or Settings card, and its entity_category is None rather than DIAGNOSTIC
    — see LDATAPanelFirmwareUpdateEntity's docstring.
    """

    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_entity_category = None  # explicit — see LDATAPanelFirmwareUpdateEntity

    def __init__(self, coordinator, data) -> None:
        """Init LDATADecoraFirmwareUpdateEntity."""
        super().__init__(data=data, coordinator=coordinator)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()

    @property
    def installed_version(self) -> StateType:
        """Return the currently installed firmware version."""
        device = self._get_device_data()
        return device.get("version") if device else None

    @property
    def latest_version(self) -> StateType:
        """Return the latest available firmware version."""
        device = self._get_device_data()
        if not device:
            return None
        return device.get("available_firmware") or device.get("version")

    @property
    def name_suffix(self) -> str | None:
        return "Firmware Update"

    @property
    def unique_id_suffix(self) -> str | None:
        return "firmware_update"
