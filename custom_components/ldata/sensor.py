"""Support for power sensors in LDATA devices."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import logging
import time
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfFrequency,
    UnitOfPower,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.typing import StateType
from homeassistant.util import dt as dt_util

from .const import DOMAIN, LOGGER_NAME
from .coordinator import LDATAUpdateCoordinator
from .ldata_ct_entity import LDATACTEntity
from .ldata_entity import LDATAEntity

_LOGGER = logging.getLogger(LOGGER_NAME)


@dataclass(frozen=True, kw_only=True)
class SensorDescription(SensorEntityDescription):
    """SensorEntityDescription for LDATA entities."""

    unique_id_suffix: str | None = None
    name: str | None = None


SENSOR_TYPES = (
    SensorDescription(  # index=0
        device_class=SensorDeviceClass.POWER,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfPower.WATT,
        name="Watts",
        key="power",
        unique_id_suffix="_watts",
    ),
    SensorDescription(  # index=1
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        name="Volts",
        key="voltage",
        unique_id_suffix="_volts",
    ),
    SensorDescription(  # index=2
        device_class=SensorDeviceClass.CURRENT,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        name="Amps",
        key="current",
        unique_id_suffix="_amps",
    ),
    SensorDescription(  # index=3
        device_class=SensorDeviceClass.FREQUENCY,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfFrequency.HERTZ,
        name="Frequency",
        key="frequency",
        unique_id_suffix="_hz",
    ),
    SensorDescription(  # index=4
        device_class=SensorDeviceClass.ENERGY,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        name="Import",
        key="import",
        unique_id_suffix="_Import_kWh",
    ),
    SensorDescription(  # index=5
        device_class=SensorDeviceClass.ENERGY,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        name="Consumption",
        key="consumption",
        unique_id_suffix="_Consumption_kWh",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the power and kilowatt sensors for the breakers."""

    # Get the coordinator from hass.data
    coordinator: LDATAUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id]

    # If the coordinator has no data (e.g., auth failed in __init__.py),
    # stop setup here to prevent a crash.
    if not coordinator.data:
        _LOGGER.warning(
            "Coordinator has no data, skipping sensor setup. "
            "This may be due to an authentication error or network issue."
        )
        return

    # Create a single list to add all entities at the end
    entities_to_add: list[SensorEntity] = []

    for ct_id, ct_data in coordinator.data.get("cts", {}).items():
        entities_to_add.append(
            LDATAEnergyUsageSensor(coordinator, ct_data, SENSOR_TYPES[4])
        )
        entities_to_add.append(
            LDATAEnergyUsageSensor(coordinator, ct_data, SENSOR_TYPES[5])
        )
        entities_to_add.append(
            LDATACTOutputSensor(coordinator, ct_data, SENSOR_TYPES[2])
        )
        entities_to_add.append(
            LDATACTOutputSensor(coordinator, ct_data, SENSOR_TYPES[0])
        )
        entities_to_add.append(
            LDATACTDailyUsageSensor(coordinator, ct_data, False, "")
        )

    for breaker_id, breaker_data in coordinator.data.get("breakers", {}).items():
        entities_to_add.append(LDATADailyUsageSensor(coordinator, breaker_data, False, ""))
        entities_to_add.append(
            LDATAOutputSensor(coordinator, breaker_data, SENSOR_TYPES[0])
        )
        entities_to_add.append(
            LDATAOutputSensor(coordinator, breaker_data, SENSOR_TYPES[2])
        )

    for panel in coordinator.data.get("panels", []):
        entity_data = {}
        entity_data["id"] = panel["serialNumber"]
        entity_data["name"] = panel["name"]
        entity_data["serialNumber"] = panel["serialNumber"]
        entity_data["model"] = panel["model"]
        entity_data["hardware"] = "LDATA"
        entity_data["firmware"] = panel["firmware"]
        entity_data["poles"] = 2
        entity_data["voltage"] = panel["voltage"]
        entity_data["voltage1"] = panel["voltage1"]
        entity_data["voltage2"] = panel["voltage2"]
        entity_data["frequency"] = panel["frequency"]
        entity_data["frequency1"] = panel["frequency1"]
        entity_data["frequency2"] = panel["frequency2"]
        entity_data["data"] = panel
        
        entities_to_add.append(
            LDATADailyUsageSensor(
                coordinator, entity_data, True, which_panel=panel["id"]
            )
        )
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data, SENSOR_TYPES[0], average=False, which_leg="both"
            )
        )
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data, SENSOR_TYPES[2], average=False, which_leg="both"
            )
        )
        entities_to_add.append(
            LDATAPanelOutputSensor(
                coordinator, entity_data, SENSOR_TYPES[3], which_leg="1"
            )
        )
        entities_to_add.append(
            LDATAPanelOutputSensor(
                coordinator, entity_data, SENSOR_TYPES[3], which_leg="2"
            )
        )
        entities_to_add.append(
            LDATAPanelOutputSensor(
                coordinator, entity_data, SENSOR_TYPES[1], which_leg="1"
            )
        )
        entities_to_add.append(
            LDATAPanelOutputSensor(
                coordinator, entity_data, SENSOR_TYPES[1], which_leg="2"
            )
        )
        
        entity_data_leg1 = copy.deepcopy(entity_data)
        entity_data_leg1["poles"] = 1
        entity_data_leg1["position"] = 1
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data_leg1, SENSOR_TYPES[0], average=False, which_leg="1"
            )
        )
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data_leg1, SENSOR_TYPES[2], average=False, which_leg="1"
            )
        )
        
        entity_data_leg2 = copy.deepcopy(entity_data)
        entity_data_leg2["poles"] = 1
        entity_data_leg2["position"] = 3
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data_leg2, SENSOR_TYPES[0], average=False, which_leg="2"
            )
        )
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data_leg2, SENSOR_TYPES[2], average=False, which_leg="2"
            )
        )

    # Add all entities in one go for efficiency
    if entities_to_add:
        async_add_entities(entities_to_add)


class LDATADailyUsageSensor(LDATAEntity, SensorEntity, RestoreEntity):
    """Sensor that tracks daily usage for an LDATA device."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR

    def __init__(
        self, coordinator: LDATAUpdateCoordinator, data, panelTotal, which_panel: str
    ) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state: float | None = None
        self.last_update_time = 0.0
        self.previous_value = 0.0
        self.last_update_date = dt_util.now()
        self.panel_total = panelTotal
        self.panel_id = which_panel

    async def async_added_to_hass(self) -> None:
        """Handle entity which is added to hass to restore state on startup."""
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass # Ignore if the stored state is invalid

    @callback
    def _schedule_immediate_update(self):
        self.async_schedule_update_ha_state(True)

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return "Total Daily Energy"

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        return "todaymw"

    @property
    def native_value(self) -> StateType:
        """Return the used kilowatts of the device."""
        if self._state is not None:
            return round(self._state, 2)
        return 0.0

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        # Add safety check for coordinator data
        if not self.coordinator.data:
            return

        try:
            have_values = False
            new_data = None
            if self.panel_total is True:
                current_value = 0
                if (self.panel_id + "totalPower") in self.coordinator.data:
                    current_value = self.coordinator.data[self.panel_id + "totalPower"]
                    have_values = True
            else:
                if "breakers" in self.coordinator.data and self.breaker_data["id"] in self.coordinator.data["breakers"]:
                    new_data = self.coordinator.data["breakers"][self.breaker_data["id"]]
            
            if ((self.panel_total is True) and (have_values is True)) or (
                new_data is not None
            ):
                if new_data is not None:
                    current_value = new_data["power"]
                try:
                    current_value = float(current_value)
                except ValueError:
                    current_value = 0
                try:
                    self.previous_value = float(self.previous_value)
                except ValueError:
                    self.previous_value = 0
                
                current_time = time.time()
                current_date = dt_util.now()
                
                if (
                    (self.last_update_date.day != current_date.day)
                    or (self.last_update_date.month != current_date.month)
                    or (self.last_update_date.year != current_date.year)
                ):
                    self._state = 0
                    # Reset the baseline immediately to prevent calculating a phantom spike from the "gap" time across midnight. We treat the new day as starting from "now".
                    self.last_update_time = current_time
                    self.previous_value = current_value
                    self.last_update_date = current_date
                    self.async_write_ha_state()
                    return

                if self.last_update_time > 0:
                    # Calculate power by averaging current and previous readings.
                    power = ((self.previous_value + current_value) / 2) / 1000
                    if power < 0:
                        power = -power
                    
                    # Calculate time elapsed since last update in hours.
                    time_span = (current_time - self.last_update_time) / 3600
                    
                    # Update total energy by adding energy used in the time span (Power * Time).
                    try:
                        if self._state is not None:
                            self._state = self._state + (power * time_span)
                        else:
                            self._state = power * time_span
                    except Exception:
                        if self.coordinator.config_entry.options.get("log_warnings", True):
                            _LOGGER.exception("Error in daily usage calculation for %s", self.entity_id)

                # Store current values for the next calculation.
                self.last_update_time = current_time
                self.previous_value = current_value
                self.last_update_date = current_date
        except Exception:
            # Catch all other errors to prevent crashes.
            if self.coordinator.config_entry.options.get("log_warnings", True):
                _LOGGER.exception("Error updating daily usage sensor for %s", self.entity_id)
        self.async_write_ha_state()


class LDATACTDailyUsageSensor(LDATACTEntity, SensorEntity, RestoreEntity):
    """Sensor that tracks daily usage from a CT clamp's lifetime total."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR

    def __init__(
        self, coordinator: LDATAUpdateCoordinator, data, panelTotal, which_panel: str
    ) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state: float | None = None
        self.last_update_date = dt_util.now()
        # Stores the last known lifetime consumption value from the API.
        self.previous_consumption = None
        # Flag to indicate the sensor has just reloaded and needs to establish a baseline.
        self._just_reloaded = True

    async def async_added_to_hass(self) -> None:
        """Handle entity which is added to hass to restore state on startup."""
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        
        # Restore the last known daily total from the database.
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass # Ignore if the stored state is invalid
            
            # Restore the last_update_date from attributes
            if last_state.attributes and last_state.attributes.get("last_update_date"):
                try:
                    self.last_update_date = dt_util.parse_datetime(last_state.attributes["last_update_date"])
                except (ValueError, TypeError, AttributeError):
                    _LOGGER.warning("Could not parse restored last_update_date for %s, defaulting to now", self.entity_id)
                    self.last_update_date = dt_util.now()
            else:
                # If the attribute doesn't exist, this is an older version
                # We must reset the date to "now" to avoid midnight reset bugs
                self.last_update_date = dt_util.now()
            
            # This is critical to correctly calculate usage after a restart.
            if last_state.attributes and "last_lifetime_consumption" in last_state.attributes:
                try:
                    self.previous_consumption = float(last_state.attributes["last_lifetime_consumption"])
                    _LOGGER.debug("Restored last_lifetime_consumption for %s: %s", self.entity_id, self.previous_consumption)
                except (ValueError, TypeError):
                    self.previous_consumption = None # Reset if stored value is invalid

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return "Total Daily Energy"

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        return "todaymw"

    @property
    def native_value(self) -> StateType:
        """Return the used kilowatts of the device."""
        if self._state is not None:
            return round(self._state, 2)
        return 0.0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the extra attributes for the sensor."""
        attributes = super().extra_state_attributes
        if self.previous_consumption is not None:
            # Store the last known lifetime value so it can be restored.
            attributes["last_lifetime_consumption"] = self.previous_consumption
        
        attributes["last_update_date"] = self.last_update_date.isoformat()
        return attributes

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        current_date = dt_util.now()

        # --- Midnight Reset Logic ---
        # Prioritize the midnight check. If the day has rolled over,
        # reset the state and update the date immediately.
        if self.last_update_date.day != current_date.day:
            if self.coordinator.config_entry.options.get("log_data_warnings", True):
                _LOGGER.info("New day detected for %s, resetting daily total.", self.entity_id)
            self._state = 0.0
            self.last_update_date = current_date
            # We don't reset previous_consumption to None here,
            # so the first update of the new day calculates correctly.

        # --- Data Processing and Validation ---
        try:
            # Add safety checks for coordinator.data
            if not self.coordinator.data or "cts" not in self.coordinator.data or self.breaker_data["id"] not in self.coordinator.data["cts"]:
                if self.coordinator.config_entry.options.get("log_warnings", True):
                    _LOGGER.debug("Could not update %s, data missing or invalid.", self.entity_id)
                return
                
            new_data = self.coordinator.data["cts"][self.breaker_data["id"]]
            current_consumption = float(new_data["consumption"])

            if self._state is None:
                self._state = 0.0
            
            # If previous_consumption is None (first run ever or after failed restore),
            # set the baseline and wait for the next update.
            if self.previous_consumption is None:
                self.previous_consumption = current_consumption
                self.last_update_date = current_date
                self._just_reloaded = False # Baseline is set
                self.async_write_ha_state()
                return

            # --- Normal operation within the same day ---
            # Calculate the energy used since the last update.
            value_diff = current_consumption - self.previous_consumption

            # Validation: Check for a decrease (device reset).
            if value_diff < -0.01:
                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                    _LOGGER.warning(
                        "Ignoring decreasing value for %s: new_total=%s, previous_total=%s",
                        self.entity_id,
                        current_consumption,
                        self.previous_consumption,
                    )
                # DO NOT update the baseline to the new low value ---
                # This prevents the "catch-up" spike from being calculated as the full lifetime value.
                # We just log the error and wait for the value to recover.
                self.last_update_date = current_date
                self._just_reloaded = False
                return

            # Validation: Check for an unrealistic jump (e.g., more than 50 kWh).
            if value_diff > 50:
                if self._just_reloaded:
                    # This is the first update after a reload.
                    # The large 'value_diff' is the energy used while HA was off.
                    _LOGGER.info("Accepting large value change for %s after reload: %s kWh", self.entity_id, value_diff)
                    # We accept the change and proceed.
                else:
                    # This is a real-time spike OR a device reset catch-up. Reject it.
                    if self.coordinator.config_entry.options.get("log_data_warnings", True):
                        _LOGGER.warning("Spike detected for %s: change of %s kWh is too large.", self.entity_id, value_diff)
                    return # Exit without updating state.

            # If valid (or an accepted reload catch-up), add the positive difference.
            if value_diff > 0:
                self._state += value_diff

            # Store the current values for the next comparison.
            self.previous_consumption = current_consumption
            self.last_update_date = current_date
            self._just_reloaded = False # No longer in a post-reload state

        except (KeyError, ValueError, TypeError):
            if self.coordinator.config_entry.options.get("log_warnings", True):
                _LOGGER.debug("Could not update %s, data missing or invalid.", self.entity_id)
            return

        self.async_write_ha_state()

class LDATATotalUsageSensor(LDATAEntity, SensorEntity):
    """Sensor that reads all outputs from all LDATA devices based on the passed in description."""

    entity_description: SensorDescription

    def __init__(
        self,
        coordinator: LDATAUpdateCoordinator,
        data,
        description: SensorDescription,
        average: bool,
        which_leg: str,
    ) -> None:
        """Init sensor."""
        self.entity_description = description
        self.leg_to_total = which_leg
        super().__init__(data=data, coordinator=coordinator)
        self.is_average = average
        self._state = self.total_values()
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    def total_values(self) -> float:
        """Total value for all breakers."""
        total = 0.0
        count = 0
        
        # Add safety check for coordinator.data
        if not self.coordinator.data or "breakers" not in self.coordinator.data:
            return 0.0

        for breaker in self.coordinator.data["breakers"].items():
            breaker_data = breaker[1]
            if breaker_data["panel_id"] == self.entity_data["serialNumber"]:
                current_value = 0.0
                if self.leg_to_total == "both":
                    try:
                        current_value = float(breaker_data[self.entity_description.key])
                    except (ValueError, KeyError):
                        current_value = 0.0
                else:
                    try:
                        current_value = float(
                            breaker_data[
                                self.entity_description.key + self.leg_to_total
                            ]
                        )
                    except (ValueError, KeyError):
                        current_value = 0.0
                current_value = max(current_value, 0.0)
                total += current_value
                count += 1
        if self.is_average is True:
            if count > 0:
                return total / count
            return 0
        return total

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        self._state = self.total_values()
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        if (self.entity_description.name is not None) and (self.leg_to_total != "both"):
            return str(self.entity_description.name) + " Leg " + self.leg_to_total
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        if (self.entity_description.name is not None) and (self.leg_to_total != "both"):
            return (
                "_leg_"
                + self.leg_to_total
                + str(self.entity_description.unique_id_suffix)
            )
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        """Return the power value."""
        if self._state is not None:
            return round(self._state, 2)
        return 0.0


class LDATAOutputSensor(LDATAEntity, SensorEntity):
    """Sensor that reads an output based on the passed in description from an LDATA device."""

    entity_description: SensorDescription

    def __init__(
        self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription
    ) -> None:
        """Init sensor."""
        self.entity_description = description
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        try:
            self._state = float(self.breaker_data[self.entity_description.key])
        except ValueError:
            self._state = 0.0
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            # Add safety check for coordinator.data
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    self._state = new_data[self.entity_description.key]
                else:
                    self._state = None # Breaker data not found
            else:
                self._state = None # No breaker data in coordinator
        except KeyError:
            self._state = None
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        """Return the power value."""
        if self._state is not None:
            return round(self._state, 2)
        return self._state

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the extra attributes for the breaker."""
        attributes = super().extra_state_attributes
        attributes["panel_id"] = self.breaker_data["panel_id"]
        return attributes


class LDATAPanelOutputSensor(LDATAEntity, SensorEntity):
    """Sensor that reads an output based on the passed in description from an LDATA device."""

    entity_description: SensorDescription

    def __init__(
        self,
        coordinator: LDATAUpdateCoordinator,
        data,
        description: SensorDescription,
        which_leg: str,
    ) -> None:
        """Init sensor."""
        self.entity_description = description
        self.leg_to_total = which_leg
        super().__init__(data=data, coordinator=coordinator)
        self.panel_data = data
        try:
            self._state = float(
                self.panel_data["data"][self.entity_description.key + self.leg_to_total]
            )
        except ValueError:
            self._state = 0.0
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            # Add safety check for coordinator.data
            if panels := self.coordinator.data.get("panels"):
                for panel in panels:
                    if panel["id"] == self.panel_data["id"]:
                        self._state = panel[
                            self.entity_description.key + self.leg_to_total
                        ]
                        break
            else:
                self._state = None # No panel data in coordinator
        except KeyError:
            self._state = None
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return str(self.entity_description.name) + " Leg " + self.leg_to_total

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        return (
            "_leg_" + self.leg_to_total + str(self.entity_description.unique_id_suffix)
        )

    @property
    def native_value(self) -> StateType:
        """Return the power value."""
        if self._state is not None:
            return round(self._state, 2)
        return self._state


class LDATACTOutputSensor(LDATACTEntity, SensorEntity):
    """Sensor that reads an output based on the passed in description from an LDATA device."""

    entity_description: SensorDescription

    def __init__(
        self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription
    ) -> None:
        """Init sensor."""
        self.entity_description = description
        super().__init__(data=data, coordinator=coordinator)
        self.ct_data = data
        self._pending_state = None
        try:
            self._state = float(self.ct_data[self.entity_description.key])
        except ValueError:
            self._state = 0.0
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            # Add safety check for coordinator.data
            if cts := self.coordinator.data.get("cts"):
                if new_data := cts.get(self.ct_data["id"]):
                    new_value = float(new_data[self.entity_description.key])
                    is_potential_spike = False

                    if self._state is None:
                        if abs(new_value) > 3000:
                            if self.coordinator.config_entry.options.get("log_data_warnings", True):
                                _LOGGER.warning("Potential spike on first update for %s: %s", self.entity_id, new_value)
                            is_potential_spike = True
                    else:
                        # Normal operation: check for spikes relative to the previous state.
                        previous_state = float(self._state)
                        # Case 1: A large jump from zero.
                        if previous_state == 0 and abs(new_value) > 3000:
                            is_potential_spike = True
                        # Case 2: A large relative AND absolute jump from a non-zero value.
                        elif previous_state != 0 and abs(new_value) > (abs(previous_state) * 10) and abs(new_value - previous_state) > 2000:
                            is_potential_spike = True
                    
                    # --- Consistency Check Logic ---
                    if is_potential_spike:
                        # A potential spike is detected. Check if it's consistent with a previous pending value.
                        if self._pending_state is not None:
                            # Check if the new value is within 15% of the pending spike value.
                            if self._pending_state != 0 and abs(new_value - self._pending_state) / abs(self._pending_state) < 0.15:
                                # The spike is consistent, so accept it as the new state.
                                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                                    _LOGGER.info("Accepting consistent high value for %s: %s", self.entity_id, new_value)
                                self._state = new_value
                                self._pending_state = None # Clear pending state since it's confirmed.
                            else:
                                # The spike is not consistent with the last one. Discard the old and start a new check.
                                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                                    _LOGGER.warning("Discarding inconsistent spike for %s: new=%s, pending=%s", self.entity_id, new_value, self._pending_state)
                                self._pending_state = new_value # Start a new pending check with this new value.
                        else:
                            # This is the first time we've seen this potential spike. Store it for verification.
                            if self.coordinator.config_entry.options.get("log_data_warnings", True):
                                _LOGGER.warning("High value detected for %s. Pending verification: %s", self.entity_id, new_value)
                            self._pending_state = new_value
                    else:
                        # No spike detected, this is a normal value.
                        self._pending_state = None # Clear any old pending state.
                        self._state = new_value
                else:
                    self._state = None # CT data not found
            else:
                self._state = None # No CT data in coordinator

        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            # If any error occurs during parsing, set state to unavailable.
            self._state = None
            self._pending_state = None
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        """Return the power value."""
        if self._state is not None:
            return round(self._state, 2)
        return self._state


class LDATAEnergyUsageSensor(LDATACTEntity, SensorEntity, RestoreEntity):
    """Sensor that reads an output based on the passed in description from an LDATA CT device."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR

    entity_description: SensorDescription

    def __init__(
        self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription
    ) -> None:
        """Init sensor."""
        self.entity_description = description
        super().__init__(data=data, coordinator=coordinator)
        self.ct_data = data
        self._state = None # Initialize state as None to be populated by restore or first update.
        self._pending_state = None
    
    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        # The entity is available if the coordinator has data OR if the sensor has a valid state (from restore).
        return self.coordinator.last_update_success or self._state is not None

    async def async_added_to_hass(self) -> None:
        """Handle entity which is added to hass to restore state on startup."""
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        # Restore the last known state from the database.
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass # Ignore if the stored state is invalid

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            # Add safety check for coordinator.data
            if cts := self.coordinator.data.get("cts"):
                if new_data := cts.get(self.ct_data["id"]):
                    new_value = float(new_data[self.entity_description.key])
                    is_potential_spike = False
                    ROUNDING_TOLERANCE = 0.01

                    # Initialize state on the very first update if not already set by restore.
                    if self._state is None:
                        self._state = new_value
                        self.async_write_ha_state()
                        return

                    # --- Data Validation ---
                    # Check for a significant decrease, ignoring minor rounding errors.
                    if (float(self._state) - new_value) > ROUNDING_TOLERANCE:
                        if self.coordinator.config_entry.options.get("log_data_warnings", True):
                            _LOGGER.warning(
                                "Ignoring decreasing value for %s: new=%s, old=%s",
                                self.entity_id, new_value, self._state
                            )
                        return # Exit without updating.

                    # Check for unrealistic upward jumps (spikes).
                    # Case 1: A large absolute jump from a very low value.
                    if float(self._state) <= 1 and new_value > 100:
                        is_potential_spike = True
                    # Case 2: A large relative jump during normal operation.
                    elif float(self._state) > 1 and new_value > (float(self._state) * 1.5):
                        is_potential_spike = True
                    
                    if is_potential_spike:
                        if self._pending_state is not None:
                            if self._pending_state != 0 and abs(new_value - self._pending_state) / abs(self._pending_state) < 0.15:
                                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                                    _LOGGER.info("Accepting consistent high value for %s: %s", self.entity_id, new_value)
                                self._state = new_value
                                self._pending_state = None
                            else:
                                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                                    _LOGGER.warning("Discarding inconsistent spike for %s: new=%s, pending=%s", self.entity_id, new_value, self._pending_state)
                                self._pending_state = new_value
                        else:
                            if self.coordinator.config_entry.options.get("log_data_warnings", True):
                                _LOGGER.warning("High value detected for %s. Pending verification: %s", self.entity_id, new_value)
                            self._pending_state = new_value
                    else:
                        self._pending_state = None
                        self._state = new_value
                else:
                    # CT data not found, do not change state
                    if self.coordinator.config_entry.options.get("log_warnings", True):
                        _LOGGER.debug("Data for CT %s not found in update.", self.ct_data["id"])
            else:
                # No CT data in coordinator, do not change state
                if self.coordinator.config_entry.options.get("log_warnings", True):
                    _LOGGER.debug("No 'cts' data found in coordinator update.")

        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            if self.coordinator.config_entry.options.get("log_warnings", True):
                _LOGGER.debug("Invalid value received for %s", self.entity_id)
            return

        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        """Return the power value."""
        if self._state is not None:
            return round(self._state, 2)
        return self._state