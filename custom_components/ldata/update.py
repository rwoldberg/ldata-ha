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
    returned by the cloud so an available update is not silently missed, and
    lets HA's own Settings > Updates / notification system handle alerting.

    Deliberately NOT entity_category=DIAGNOSTIC: HA excludes diagnostic
    entities from the Settings-level "Updates available" aggregation (sidebar
    badge, Devices & Services banner) — they'd still work fine per-device,
    but the entire point of using UpdateEntity here is that global surfacing.
    """

    _attr_device_class = UpdateDeviceClass.FIRMWARE

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


class LDATADecoraFirmwareUpdateEntity(DecoraEntity, UpdateEntity):
    """Report Decora Smart Wi-Fi device firmware availability.

    Same no-install-button design as LDATAPanelFirmwareUpdateEntity — this
    only detects and surfaces an available update via HA's native Update
    entity so it shows up in Settings > Updates and can drive a notification
    automation; installing still happens in My Leviton.

    Deliberately NOT entity_category=DIAGNOSTIC — see
    LDATAPanelFirmwareUpdateEntity's docstring for why.
    """

    _attr_device_class = UpdateDeviceClass.FIRMWARE

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
