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

from .const import DOMAIN, LOGGER_NAME
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

    async_add_entities(sensors_to_add)


class LDATABinarySensor(LDATAEntity, BinarySensorEntity):
    """LDATA binary sensor class."""

    def __init__(self, coordinator, data) -> None:
        """Init LDATABinarySensor."""
        super().__init__(data=data, coordinator=coordinator)
        self._attr_unique_id = f"{data['id']}_status"
        self.breaker_data = data
        self._state = None
        if current_data := self.coordinator.data["breakers"][self.breaker_data["id"]]:
            if (
                current_data["state"] == "ManualON"
                and current_data["remoteState"] == "RemoteON"
            ):
                self._state = True
            else:
                self._state = False
        # Subscribe to updates.
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data["breakers"]:
                if new_data := breakers[self.breaker_data["id"]]:
                    if (
                        new_data["state"] == "ManualON"
                        and new_data["remoteState"] == "RemoteON"
                    ):
                        self._state = True
                    else:
                        self._state = False
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
            # Find the specific panel's data in the latest update
            found = False
            for panel in self.coordinator.data["panels"]:
                if panel["id"] == self.panel_data["id"]:
                    self._state = panel["connected"]
                    self._consecutive_update_failures = 0 # Reset failure count
                    found = True
                    return # Exit after finding the panel
            
            # Only set to None after multiple failures to prevent flickering
            if not found:
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


# ── Panel alarm sensors ──────────────────────────────────────────────


class LDATAPanelOverVoltageSensor(LDATAEntity, BinarySensorEntity):
    """Panel over-voltage alarm."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.panel_data = data
        self._state = data.get("overVoltage", False)
        self._threshold = data.get("overVoltageThreshold")
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            for panel in self.coordinator.data.get("panels", []):
                if panel["id"] == self.panel_data["id"]:
                    self._state = panel.get("overVoltage", False)
                    self._threshold = panel.get("overVoltageThreshold")
                    break
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        """Return True if over-voltage alarm is active."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "Over Voltage"

    @property
    def unique_id_suffix(self) -> str | None:
        return "over_voltage"

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        attributes = super().extra_state_attributes
        if self._threshold is not None:
            attributes["threshold_v"] = self._threshold
        return attributes

    @property
    def icon(self) -> str:
        return "mdi:flash-alert" if self.is_on else "mdi:flash-outline"


class LDATAPanelUnderVoltageSensor(LDATAEntity, BinarySensorEntity):
    """Panel under-voltage alarm."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.panel_data = data
        self._state = data.get("underVoltage", False)
        self._threshold = data.get("underVoltageThreshold")
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            for panel in self.coordinator.data.get("panels", []):
                if panel["id"] == self.panel_data["id"]:
                    self._state = panel.get("underVoltage", False)
                    self._threshold = panel.get("underVoltageThreshold")
                    break
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        """Return True if under-voltage alarm is active."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "Under Voltage"

    @property
    def unique_id_suffix(self) -> str | None:
        return "under_voltage"

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        attributes = super().extra_state_attributes
        if self._threshold is not None:
            attributes["threshold_v"] = self._threshold
        return attributes

    @property
    def icon(self) -> str:
        return "mdi:flash-alert" if self.is_on else "mdi:flash-outline"


# ── Breaker alarm sensors ────────────────────────────────────────────


class LDATABreakerOverCurrentSensor(LDATAEntity, BinarySensorEntity):
    """Breaker over-current alarm."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get("overCurrent", False)
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    self._state = new_data.get("overCurrent", False)
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        """Return True if over-current alarm is active."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "Over Current"

    @property
    def unique_id_suffix(self) -> str | None:
        return "over_current"

    @property
    def icon(self) -> str:
        return "mdi:flash-alert" if self.is_on else "mdi:current-ac"


class LDATABreakerUnderVoltageSensor(LDATAEntity, BinarySensorEntity):
    """Breaker under-voltage alarm."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get("underVoltage", False)
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    self._state = new_data.get("underVoltage", False)
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool | None:
        """Return True if under-voltage alarm is active."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "Under Voltage"

    @property
    def unique_id_suffix(self) -> str | None:
        return "under_voltage"

    @property
    def icon(self) -> str:
        return "mdi:flash-alert" if self.is_on else "mdi:flash-outline"