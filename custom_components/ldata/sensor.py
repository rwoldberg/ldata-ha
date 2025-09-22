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


class LDATADailyUsageSensor(LDATAEntity, SensorEntity):
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
        """Handle entity which will be added."""
        # Subscribe to updates.
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

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
                # Make sure values are floats
                try:
                    current_value = float(current_value)
                except ValueError:
                    current_value = 0
                try:
                    self.previous_value = float(self.previous_value)
                except ValueError:
                    self.previous_value = 0
                # Save the current date and time
                current_time = time.time()
                current_date = dt_util.now()
                # Only update if we have a previous update
                if self.last_update_time > 0:
                    # Clear the running total if the last update date and now are not the same day
                    if (
                        (self.last_update_date.day != current_date.day)
                        or (self.last_update_date.month != current_date.month)
                        or (self.last_update_date.year != current_date.year)
                    ):
                        self._state = 0
                    # Power usage is half the previous plus current power consumption in kilowatts
                    power = ((self.previous_value + current_value) / 2) / 1000
                    if power < 0:
                        power = -power
                    # How long has it been since the last update in hours
                    time_span = (current_time - self.last_update_time) / 3600
                    # Update our running total
                    try:
                        if self._state is not None:
                            self._state = self._state + (power * time_span)
                        else:
                            self._state = power * time_span
                    except Exception:  # pylint: disable=broad-except
                        _LOGGER.exception(
                            "Error updating sensor! (%f %f %f)",
                            self._state,
                            power,
                            time_span,
                        )
                # Save the current values
                self.last_update_time = current_time
                self.previous_value = current_value
                self.last_update_date = current_date
        except Exception:  # pylint: disable=broad-except
            # self._state = None
            _LOGGER.exception("Error updating sensor!")
        self.async_write_ha_state()


class LDATACTDailyUsageSensor(LDATACTEntity, SensorEntity):
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
        """Handle entity which will be added."""
        # Subscribe to updates.
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

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
                new_data = self.coordinator.data["cts"][self.breaker_data["id"]]
            if ((self.panel_total is True) and (have_values is True)) or (
                new_data is not None
            ):
                if new_data is not None:
                    current_value = new_data["consumption"]
                # Make sure values are floats
                try:
                    current_value = float(current_value)
                except ValueError:
                    current_value = 0
                try:
                    self.previous_value = float(self.previous_value)
                except ValueError:
                    self.previous_value = 0
                # Save the current date and time
                current_time = time.time()
                current_date = dt_util.now()
                # Only update if we have a previous update
                if self.last_update_time > 0:
                    # Clear the running total if the last update date and now are not the same day
                    if (
                        (self.last_update_date.day != current_date.day)
                        or (self.last_update_date.month != current_date.month)
                        or (self.last_update_date.year != current_date.year)
                    ):
                        self._state = 0
                    # Update our running total
                    try:
                        value_diff = max(current_value - self.previous_value, 0)
                        if self._state is not None:
                            self._state += value_diff
                        else:
                            self._state = value_diff
                    except Exception:  # pylint: disable=broad-except
                        _LOGGER.exception(
                            "Error updating sensor! (%f %f)",
                            self._state,
                            current_value,
                        )
                # Save the current values
                self.last_update_time = current_time
                self.previous_value = current_value
                self.last_update_date = current_date
        except Exception:  # pylint: disable=broad-except
            # self._state = None
            _LOGGER.exception("Error updating sensor!")
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
        # Subscribe to updates.
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
        # Subscribe to updates.
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
        # Subscribe to updates.
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
        try:
            self._state = float(self.ct_data[self.entity_description.key])
        except ValueError:
            self._state = 0.0
        # Subscribe to updates.
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if cts := self.coordinator.data["cts"]:
                if new_data := cts[self.ct_data["id"]]:
                    new_value = float(new_data[self.entity_description.key])

                    # Check for invalid values only if a previous state exists
                    if self._state is not None:
                        previous_state = float(self._state)

                        # Case 1: Previous state was 0. Check for an extreme jump from a standstill.
                        # You can adjust the 8000 threshold if needed.
                        if previous_state == 0 and abs(new_value) > 8000:
                            _LOGGER.warning(
                                "Spike from 0 detected for %s. Ignoring new value of %s",
                                self.entity_id,
                                new_value,
                            )
                            return

                        # Case 2: Previous state was not 0. Use dynamic checks for spikes.
                        elif previous_state != 0 and abs(new_value) > (abs(previous_state) * 10) and abs(new_value - previous_state) > 2000:
                            _LOGGER.warning(
                                "Spike detected for %s. Ignoring new value of %s (previous was %s)",
                                self.entity_id,
                                new_value,
                                previous_state,
                            )
                            return

                    # If value is valid, update the state
                    self._state = new_value
        except (KeyError, ValueError, TypeError):
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


class LDATAEnergyUsageSensor(LDATACTEntity, SensorEntity):
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
        try:
            self._state = float(self.ct_data[self.entity_description.key])
        except ValueError:
            self._state = 0.0
        # Subscribe to updates.
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if cts := self.coordinator.data["cts"]:
                if new_data := cts[self.ct_data["id"]]:
                    new_value = float(new_data[self.entity_description.key])

                    # Check for invalid values if a previous state exists
                    if self._state is not None:
                        # Ignore if the new value is less than the old one (device reset)
                        if new_value < float(self._state):
                            _LOGGER.warning(
                                "Ignoring decreasing value for %s: new=%s, old=%s",
                                self.entity_id,
                                new_value,
                                self._state,
                            )
                            return # Exit without updating

                        # Ignore unrealistic jumps (spike)
                        if new_value > (float(self._state) * 1.5) and float(self._state) > 1:
                             _LOGGER.warning(
                                "Spike detected for %s: new=%s, old=%s",
                                self.entity_id,
                                new_value,
                                self._state,
                            )
                             return # Exit without updating

                    # If value is valid, update the state
                    self._state = new_value
        except (KeyError, ValueError, TypeError):
            # Handle cases where the value isn't a valid number
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
