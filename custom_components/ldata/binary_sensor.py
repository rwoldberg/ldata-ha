"""Defines a binary sensor for an LDATA entity."""

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DECORA_MODELS_GFCI, DOMAIN, ENABLE_DECORA, ENABLE_DECORA_DEFAULT, LOGGER_NAME
from .decora_entity import DecoraEntity, add_entities_grouped_by_decora_room
from .ldata_base_entity import add_entities_grouped_by_panel, find_panel, is_breaker_on
from .ldata_entity import LDATAEntity

_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the binary sensor for the breakers and panels."""

    entry = hass.data[DOMAIN][config_entry.entry_id]
    sensors_to_add = []

    if "breakers" in entry.data:
        for breaker_id in entry.data["breakers"]:
            breaker_data = entry.data["breakers"][breaker_id]
            sensors_to_add.append(LDATABinarySensor(entry, breaker_data))
            sensors_to_add.append(LDATABreakerOverCurrentSensor(entry, breaker_data))
            sensors_to_add.append(LDATABreakerUnderVoltageSensor(entry, breaker_data))

    if "panels" in entry.data:
        for panel_data in entry.data["panels"]:
            sensors_to_add.append(LdataCloudConnectedSensor(entry, panel_data))
            sensors_to_add.append(LDATAPanelOverVoltageSensor(entry, panel_data))
            sensors_to_add.append(LDATAPanelUnderVoltageSensor(entry, panel_data))

    add_entities_grouped_by_panel(config_entry, async_add_entities, sensors_to_add)

    # Decora Smart Wi-Fi device connectivity sensors
    enable_decora = config_entry.options.get(
        ENABLE_DECORA,
        config_entry.data.get(ENABLE_DECORA, ENABLE_DECORA_DEFAULT),
    )
    if enable_decora:
        decora_entities = []
        for dev_id, dev_data in entry.data.get("decora_devices", {}).items():
            decora_entities.append(DecoraConnectedSensor(entry, dev_data))
            if dev_data.get("model") in DECORA_MODELS_GFCI:
                decora_entities.append(DecoraGFCIFaultSensor(entry, dev_data))

        add_entities_grouped_by_decora_room(config_entry, async_add_entities, decora_entities)


class LDATABinarySensor(LDATAEntity, BinarySensorEntity):
    """LDATA binary sensor class."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init LDATABinarySensor."""
        super().__init__(data=data, coordinator=coordinator)
        self._attr_unique_id = f"{data['id']}_status"
        self.breaker_data = data
        # `data` is the same breaker dict entry the coordinator already holds
        # at construction time (see async_setup_entry) — use it directly
        # instead of re-indexing coordinator.data["breakers"], which would
        # raise KeyError if this breaker ever briefly dropped out of the
        # coordinator's cache between setup and entity construction.
        self._state = is_breaker_on(data)
        # Subscribe to updates.
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data["breakers"]:
                if new_data := breakers[self.breaker_data["id"]]:
                    self._state = is_breaker_on(new_data)
        except (KeyError, TypeError, AttributeError):
            self._state = None
        self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the extra attributes for the breaker."""
        attributes = super().extra_state_attributes
        attributes["id"] = self.breaker_data["id"]
        attributes["rating"] = self.breaker_data["rating"]
        attributes["position"] = self.breaker_data["position"]
        attributes["model"] = self.breaker_data["model"]
        attributes["poles"] = self.breaker_data["poles"]
        attributes["serialNumber"] = self.breaker_data["serialNumber"]
        attributes["hardware"] = self.breaker_data["hardware"]
        attributes["firmware"] = self.breaker_data["firmware"]
        attributes["panel_id"] = self.breaker_data["panel_id"]
        # Gen2 breakers can be reset remotely; Gen1 breakers report False and
        # must be reset by hand at the panel (frontend code uses this to warn
        # before a remote "on" that won't actually do anything on Gen1).
        attributes["canRemoteOn"] = self.breaker_data.get("canRemoteOn", False)

        return attributes

    @property
    def is_on(self) -> bool | None:
        """Returns true if the breaker is on."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return "Status"

class LdataCloudConnectedSensor(LDATAEntity, BinarySensorEntity):
    """LDATA Cloud Connection binary sensor for a specific panel."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init LdataCloudConnectedSensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.panel_data = data
        self._state = None
        self._consecutive_update_failures = 0
        
        self._update_state() # Set initial state
        # Subscribe to updates.
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        self._update_state()
        self.async_write_ha_state()

    def _update_state(self):
        """Update the internal state of the sensor."""
        try:
            panel = find_panel(self.coordinator, self.panel_data["id"])
            if panel is not None:
                self._state = panel["connected"]
                self._consecutive_update_failures = 0  # Reset failure count
                return

            # Only set to None after multiple failures to prevent flickering
            self._consecutive_update_failures += 1
            if self._consecutive_update_failures > 5:
                self._state = None
            # Else: keep the last known self._state

        except (KeyError, TypeError, AttributeError):
            self._state = None

    @property
    def is_on(self) -> bool | None:
        """Returns true if the panel is connected to the cloud."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return "Cloud Connected"

    @property
    def icon(self) -> str:
        """Return the icon to use in the frontend."""
        return "mdi:cloud-check" if self.is_on else "mdi:cloud-off-outline"

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the panel's physical mounting orientation and slot count.

        These don't change at runtime, so they're read once from the panel
        data captured at entity construction rather than re-looked-up on
        every coordinator update.
        """
        attributes = super().extra_state_attributes
        attributes["orientation"] = self.panel_data.get("orientation", 0)
        attributes["panel_size"] = self.panel_data.get("panel_size")
        attributes["dumb_breakers"] = self.panel_data.get("dumb_breakers", [])
        return attributes


# ── Panel alarm sensors ──────────────────────────────────────────────


class _PanelAlarmSensor(LDATAEntity, BinarySensorEntity):
    """Base for panel-level alarm binary sensors (over/under voltage).

    Subclasses set _data_key/_threshold_key/_name_suffix/_unique_id_suffix.
    """

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _data_key: str
    _threshold_key: str
    _name_suffix: str
    _unique_id_suffix: str

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.panel_data = data
        self._state = data.get(self._data_key, False)
        self._threshold = data.get(self._threshold_key)
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            panel = find_panel(self.coordinator, self.panel_data["id"])
            if panel is not None:
                self._state = panel.get(self._data_key, False)
                self._threshold = panel.get(self._threshold_key)
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        """Return True if the alarm is active."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return self._name_suffix

    @property
    def unique_id_suffix(self) -> str | None:
        return self._unique_id_suffix

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        attributes = super().extra_state_attributes
        if self._threshold is not None:
            attributes["threshold_v"] = self._threshold
        return attributes

    @property
    def icon(self) -> str:
        return "mdi:flash-alert" if self.is_on else "mdi:flash-outline"


class LDATAPanelOverVoltageSensor(_PanelAlarmSensor):
    """Panel over-voltage alarm."""

    _data_key = "overVoltage"
    _threshold_key = "overVoltageThreshold"
    _name_suffix = "Over Voltage"
    _unique_id_suffix = "over_voltage"


class LDATAPanelUnderVoltageSensor(_PanelAlarmSensor):
    """Panel under-voltage alarm."""

    _data_key = "underVoltage"
    _threshold_key = "underVoltageThreshold"
    _name_suffix = "Under Voltage"
    _unique_id_suffix = "under_voltage"


# ── Breaker alarm sensors ────────────────────────────────────────────


class _BreakerAlarmSensor(LDATAEntity, BinarySensorEntity):
    """Base for breaker-level alarm binary sensors (over-current, under-voltage).

    Subclasses set _data_key/_name_suffix/_unique_id_suffix/_icon_off.
    """

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _data_key: str
    _name_suffix: str
    _unique_id_suffix: str
    _icon_off: str = "mdi:flash-outline"

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get(self._data_key, False)
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    self._state = new_data.get(self._data_key, False)
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        """Return True if the alarm is active."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return self._name_suffix

    @property
    def unique_id_suffix(self) -> str | None:
        return self._unique_id_suffix

    @property
    def icon(self) -> str:
        return "mdi:flash-alert" if self.is_on else self._icon_off


class LDATABreakerOverCurrentSensor(_BreakerAlarmSensor):
    """Breaker over-current alarm."""

    _data_key = "overCurrent"
    _name_suffix = "Over Current"
    _unique_id_suffix = "over_current"
    _icon_off = "mdi:current-ac"


class LDATABreakerUnderVoltageSensor(_BreakerAlarmSensor):
    """Breaker under-voltage alarm."""

    _data_key = "underVoltage"
    _name_suffix = "Under Voltage"
    _unique_id_suffix = "under_voltage"
    _icon_off = "mdi:flash-outline"


# ── Decora Smart Wi-Fi device sensors ──────────────────────────────────


class DecoraConnectedSensor(DecoraEntity, BinarySensorEntity):
    """Connectivity binary sensor for a Decora Smart Wi-Fi device."""

    def __init__(self, coordinator, data) -> None:
        """Init DecoraConnectedSensor."""
        super().__init__(data=data, coordinator=coordinator)
        self._state = data.get("connected", False)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        device = self._get_device_data()
        if device:
            self._state = device.get("connected", False)
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        """Returns true if the device is connected."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the device's name."""
        return "Connected"

    @property
    def unique_id_suffix(self) -> str | None:
        """Return the unique id suffix."""
        return "connected"

    @property
    def icon(self) -> str:
        """Return the icon to use in the frontend."""
        return "mdi:wifi" if self.is_on else "mdi:wifi-off"

    @property
    def available(self) -> bool:
        """Always available since this sensor reports connectivity itself."""
        return self.coordinator.last_update_success


GFCI_STATUS_PROTECTED = ""


class DecoraGFCIFaultSensor(DecoraEntity, BinarySensorEntity):
    """GFCI fault detection binary sensor for D2GF1/D2GF2."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, coordinator, data) -> None:
        """Init DecoraGFCIFaultSensor."""
        super().__init__(data=data, coordinator=coordinator)
        fault = data.get("fault", "")
        self._state = fault is not None and fault != GFCI_STATUS_PROTECTED

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        device = self._get_device_data()
        if device:
            fault = device.get("fault", "")
            self._state = fault is not None and fault != GFCI_STATUS_PROTECTED
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        """Returns true if a GFCI fault is detected."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "Fault Detected"

    @property
    def unique_id_suffix(self) -> str | None:
        return "fault"