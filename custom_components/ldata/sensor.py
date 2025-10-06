"""Support for power sensors in LDATA devices."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import logging
import time

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

    entry = hass.data[DOMAIN][config_entry.entry_id]

    for ct_id in entry.data["cts"]:
        ct_data = entry.data["cts"][ct_id]
        power_sensor = LDATAEnergyUsageSensor(entry, ct_data, SENSOR_TYPES[4])
        async_add_entities([power_sensor])
        power_sensor = LDATAEnergyUsageSensor(entry, ct_data, SENSOR_TYPES[5])
        async_add_entities([power_sensor])
        ctpower_sensor = LDATACTOutputSensor(entry, ct_data, SENSOR_TYPES[2])
        async_add_entities([ctpower_sensor])
        ctpower_sensor = LDATACTOutputSensor(entry, ct_data, SENSOR_TYPES[0])
        async_add_entities([ctpower_sensor])
        ctusage_sensor = LDATACTDailyUsageSensor(entry, ct_data, False, "")
        async_add_entities([ctusage_sensor])
    for breaker_id in entry.data["breakers"]:
        breaker_data = entry.data["breakers"][breaker_id]
        usage_sensor = LDATADailyUsageSensor(entry, breaker_data, False, "")
        async_add_entities([usage_sensor])
        output_sensor = LDATAOutputSensor(entry, breaker_data, SENSOR_TYPES[0])
        async_add_entities([output_sensor])
        output_sensor = LDATAOutputSensor(entry, breaker_data, SENSOR_TYPES[2])
        async_add_entities([output_sensor])
    for panel in entry.data["panels"]:
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
        usage_sensor = LDATADailyUsageSensor(
            entry, entity_data, True, which_panel=panel["id"]
        )
        async_add_entities([usage_sensor])
        total_sensor = LDATATotalUsageSensor(
            entry, entity_data, SENSOR_TYPES[0], average=False, which_leg="both"
        )
        async_add_entities([total_sensor])
        total_sensor = LDATATotalUsageSensor(
            entry, entity_data, SENSOR_TYPES[2], average=False, which_leg="both"
        )
        async_add_entities([total_sensor])
        paneloutput_sensor = LDATAPanelOutputSensor(
            entry, entity_data, SENSOR_TYPES[3], which_leg="1"
        )
        async_add_entities([paneloutput_sensor])
        paneloutput_sensor = LDATAPanelOutputSensor(
            entry, entity_data, SENSOR_TYPES[3], which_leg="2"
        )
        async_add_entities([paneloutput_sensor])
        paneloutput_sensor = LDATAPanelOutputSensor(
            entry, entity_data, SENSOR_TYPES[1], which_leg="1"
        )
        async_add_entities([paneloutput_sensor])
        paneloutput_sensor = LDATAPanelOutputSensor(
            entry, entity_data, SENSOR_TYPES[1], which_leg="2"
        )
        async_add_entities([paneloutput_sensor])
        entity_data = copy.deepcopy(entity_data)
        entity_data["poles"] = 1
        entity_data["position"] = 1
        total_sensor = LDATATotalUsageSensor(
            entry, entity_data, SENSOR_TYPES[0], average=False, which_leg="1"
        )
        async_add_entities([total_sensor])
        total_sensor = LDATATotalUsageSensor(
            entry, entity_data, SENSOR_TYPES[2], average=False, which_leg="1"
        )
        async_add_entities([total_sensor])
        entity_data = copy.deepcopy(entity_data)
        entity_data["position"] = 3
        total_sensor = LDATATotalUsageSensor(
            entry, entity_data, SENSOR_TYPES[0], average=False, which_leg="2"
        )
        async_add_entities([total_sensor])
        total_sensor = LDATATotalUsageSensor(
            entry, entity_data, SENSOR_TYPES[2], average=False, which_leg="2"
        )
        async_add_entities([total_sensor])


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
        try:
            have_values = False
            new_data = None
            if self.panel_total is True:
                current_value = 0
                current_value = self.coordinator.data[self.panel_id + "totalPower"]
                have_values = True
            else:
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
                
                if self.last_update_time > 0:
                    # Reset daily total at midnight.
                    if (
                        (self.last_update_date.day != current_date.day)
                        or (self.last_update_date.month != current_date.month)
                        or (self.last_update_date.year != current_date.year)
                    ):
                        self._state = 0
                    
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
        try:
            new_data = self.coordinator.data["cts"][self.breaker_data["id"]]
            current_consumption = float(new_data["consumption"])
            current_date = dt_util.now()
            
            # Initialize the daily total on the very first run.
            if self._state is None:
                self._state = 0.0
            
            # Initialize the previous_consumption baseline on the first successful update.
            if self.previous_consumption is None:
                if current_consumption < self._state:
                    if self.coordinator.config_entry.options.get("log_data_warnings", True):
                        _LOGGER.warning(
                            "Ignoring initial value for %s: API value (%s) is lower than restored daily total (%s). Waiting for valid data.",
                            self.entity_id, current_consumption, self._state
                        )
                    return

                self.previous_consumption = current_consumption
                self.last_update_date = current_date
                self.async_write_ha_state()
                return

            # Check if the day has rolled over to midnight.
            if self.last_update_date.day != current_date.day:
                # Log the daily reset if warnings are enabled.
                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                    _LOGGER.info("New day detected for %s, resetting daily total.", self.entity_id)
                # Reset the daily counter to zero.
                self._state = 0.0
                # Set the baseline for the new day's calculation to prevent a false spike report.
                self.previous_consumption = current_consumption
                self.last_update_date = current_date
                self.async_write_ha_state()
                return

            # --- Normal operation within the same day ---
            # Calculate the energy used since the last update.
            value_diff = current_consumption - self.previous_consumption

            # Validation: Check for a significant decrease (device reset), ignoring minor rounding errors.
            if value_diff < -0.01:
                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                    _LOGGER.warning(
                        "Ignoring decreasing value for %s: new_total=%s, previous_total=%s",
                        self.entity_id,
                        current_consumption,
                        self.previous_consumption
                    )
                return # Exit without updating state.
            
            # Validation: Check for an unrealistic jump (e.g., more than 50 kWh between updates).
            if value_diff > 50: 
                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                    _LOGGER.warning("Spike detected for %s: change of %s kWh is too large.", self.entity_id, value_diff)
                return # Exit without updating state.

            # If valid, add the positive difference to the daily total.
            if value_diff > 0:
                self._state += value_diff

            # Store the current lifetime total for the next comparison.
            self.previous_consumption = current_consumption
            self.last_update_date = current_date

        except (KeyError, ValueError, TypeError):
            # Handle cases where data from the API is missing or invalid.
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
        for breaker in self.coordinator.data["breakers"].items():
            breaker_data = breaker[1]
            if breaker_data["panel_id"] == self.entity_data["serialNumber"]:
                current_value = 0.0
                if self.leg_to_total == "both":
                    try:
                        current_value = float(breaker_data[self.entity_description.key])
                    except ValueError:
                        current_value = 0.0
                else:
                    try:
                        current_value = float(
                            breaker_data[
                                self.entity_description.key + self.leg_to_total
                            ]
                        )
                    except ValueError:
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
            if breakers := self.coordinator.data["breakers"]:
                if new_data := breakers[self.breaker_data["id"]]:
                    self._state = new_data[self.entity_description.key]
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
            if panels := self.coordinator.data["panels"]:
                for panel in panels:
                    if panel["id"] == self.panel_data["id"]:
                        self._state = panel[
                            self.entity_description.key + self.leg_to_total
                        ]
                        break
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
            if cts := self.coordinator.data["cts"]:
                if new_data := cts[self.ct_data["id"]]:
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
            if cts := self.coordinator.data["cts"]:
                if new_data := cts[self.ct_data["id"]]:
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
