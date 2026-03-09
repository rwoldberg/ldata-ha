"""Support for power sensors in LDATA devices."""

from __future__ import annotations

import copy
import datetime
from dataclasses import dataclass
import logging
import time
from typing import Any

import voluptuous as vol

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
from homeassistant.helpers import entity_platform
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.typing import StateType
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    LOGGER_NAME,
    MAX_DAILY_ENERGY_KWH,
)
from .coordinator import LDATAUpdateCoordinator
from .ldata_ct_entity import LDATACTEntity
from .ldata_entity import LDATAEntity

_LOGGER = logging.getLogger(LOGGER_NAME)

ATTR_VALUE = "value"
ATTR_BASELINE = "baseline"

SERVICE_RESET_ENERGY_SCHEMA = {
    vol.Optional(ATTR_VALUE): vol.Coerce(float),
    vol.Optional(ATTR_BASELINE): vol.Coerce(float),
}


@dataclass(frozen=True, kw_only=True)
class SensorDescription(SensorEntityDescription):
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
    coordinator: LDATAUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id]

    if not coordinator.data:
        _LOGGER.warning("Coordinator has no data, skipping sensor setup.")
        return

    platform = entity_platform.async_get_current_platform()
    platform.async_register_entity_service(
        "reset_energy_baseline",
        SERVICE_RESET_ENERGY_SCHEMA,
        "async_reset_baseline",
    )

    entities_to_add: list[SensorEntity] = []

    for ct_id, ct_data in coordinator.data.get("cts", {}).items():
        entities_to_add.append(LDATAEnergyUsageSensor(coordinator, ct_data, SENSOR_TYPES[4]))
        entities_to_add.append(LDATAEnergyUsageSensor(coordinator, ct_data, SENSOR_TYPES[5]))
        entities_to_add.append(LDATACTOutputSensor(coordinator, ct_data, SENSOR_TYPES[2]))
        entities_to_add.append(LDATACTOutputSensor(coordinator, ct_data, SENSOR_TYPES[0]))
        entities_to_add.append(LDATACTDailyUsageSensor(coordinator, ct_data, False, ""))
        entities_to_add.append(LDATACTDailyUsageSensor(coordinator, ct_data, False, "", energy_key="import"))

    for breaker_id, breaker_data in coordinator.data.get("breakers", {}).items():
        entities_to_add.append(LDATADailyUsageSensor(coordinator, breaker_data, False, ""))
        entities_to_add.append(LDATAOutputSensor(coordinator, breaker_data, SENSOR_TYPES[0]))
        entities_to_add.append(LDATAOutputSensor(coordinator, breaker_data, SENSOR_TYPES[2]))
        entities_to_add.append(LDATABreakerEnergyUsageSensor(coordinator, breaker_data, SENSOR_TYPES[5]))
        
        breaker_import = float(breaker_data.get("import", 0) or 0)
        breaker_consumption = float(breaker_data.get("consumption", 0) or 0)
        has_import = breaker_import > 0 or breaker_consumption == 0
        if has_import:
            entities_to_add.append(LDATADailyUsageSensor(coordinator, breaker_data, False, "", breaker_energy_key="import"))
            entities_to_add.append(LDATABreakerEnergyUsageSensor(coordinator, breaker_data, SENSOR_TYPES[4]))
            
        entities_to_add.append(LDATABreakerOperationalStateSensor(coordinator, breaker_data))
        entities_to_add.append(LDATABreakerBleRSSISensor(coordinator, breaker_data))

    for panel in coordinator.data.get("panels", []):
        entity_data = {}
        entity_data["id"] = panel["serialNumber"]
        entity_data["name"] = panel["name"]
        entity_data["serialNumber"] = panel["serialNumber"]
        entity_data["model"] = panel["model"]
        entity_data["hardware"] = panel.get("panel_type", "LDATA")
        entity_data["firmware"] = panel["firmware"]
        entity_data["poles"] = 2
        entity_data["voltage"] = panel["voltage"]
        entity_data["voltage1"] = panel["voltage1"]
        entity_data["voltage2"] = panel["voltage2"]
        entity_data["frequency"] = panel["frequency"]
        entity_data["frequency1"] = panel["frequency1"]
        entity_data["frequency2"] = panel["frequency2"]
        entity_data["data"] = panel
        
        entities_to_add.append(LDATADailyUsageSensor(coordinator, entity_data, True, which_panel=panel["id"]))
        entities_to_add.append(LDATADailyUsageSensor(coordinator, entity_data, True, which_panel=panel["id"], panel_energy_key="import"))
        entities_to_add.append(LDATATotalUsageSensor(coordinator, entity_data, SENSOR_TYPES[0], average=False, which_leg="both"))
        entities_to_add.append(LDATATotalUsageSensor(coordinator, entity_data, SENSOR_TYPES[2], average=False, which_leg="both"))
        entities_to_add.append(LDATAPanelOutputSensor(coordinator, entity_data, SENSOR_TYPES[3], which_leg="1"))
        entities_to_add.append(LDATAPanelOutputSensor(coordinator, entity_data, SENSOR_TYPES[3], which_leg="2"))
        entities_to_add.append(LDATAPanelOutputSensor(coordinator, entity_data, SENSOR_TYPES[1], which_leg="1"))
        entities_to_add.append(LDATAPanelOutputSensor(coordinator, entity_data, SENSOR_TYPES[1], which_leg="2"))
        entities_to_add.append(LDATAPanelWifiRSSISensor(coordinator, entity_data))
        
        entity_data_leg1 = copy.deepcopy(entity_data)
        entity_data_leg1["poles"] = 1
        entity_data_leg1["position"] = 1
        entities_to_add.append(LDATATotalUsageSensor(coordinator, entity_data_leg1, SENSOR_TYPES[0], average=False, which_leg="1"))
        entities_to_add.append(LDATATotalUsageSensor(coordinator, entity_data_leg1, SENSOR_TYPES[2], average=False, which_leg="1"))
        
        entity_data_leg2 = copy.deepcopy(entity_data)
        entity_data_leg2["poles"] = 1
        entity_data_leg2["position"] = 3
        entities_to_add.append(LDATATotalUsageSensor(coordinator, entity_data_leg2, SENSOR_TYPES[0], average=False, which_leg="2"))
        entities_to_add.append(LDATATotalUsageSensor(coordinator, entity_data_leg2, SENSOR_TYPES[2], average=False, which_leg="2"))

    if entities_to_add:
        async_add_entities(entities_to_add)


class LDATADailyUsageSensor(LDATAEntity, SensorEntity, RestoreEntity):
    """Sensor that tracks daily energy usage using ldata_service.py's Riemann engine."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR

    def __init__(self, coordinator: LDATAUpdateCoordinator, data, panelTotal, which_panel: str, panel_energy_key: str = "consumption", breaker_energy_key: str | None = None) -> None:
        self.panel_total = panelTotal
        self._panel_energy_key: str = panel_energy_key
        self._breaker_energy_key: str | None = breaker_energy_key
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state: float | None = None
        self._last_reported: float | None = None
        self.panel_id = which_panel
        self._midnight_baseline: float | None = None
        self._last_date: datetime.date | None = None
        self._energy_key: str | None = None

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass
            attrs = last_state.attributes or {}
            try:
                self._midnight_baseline = float(attrs["midnight_baseline"])
            except (KeyError, ValueError, TypeError):
                self._midnight_baseline = None
            if date_str := attrs.get("last_date"):
                try:
                    parsed = dt_util.parse_datetime(date_str)
                    self._last_date = parsed.date() if parsed else None
                except (ValueError, TypeError):
                    self._last_date = None
            if "energy_key" in attrs:
                self._energy_key = attrs["energy_key"]

    async def async_reset_baseline(self, value: float | None = None, baseline: float | None = None) -> None:
        """Handle the reset_energy_baseline service call natively."""
        if baseline is not None:
            self._midnight_baseline = baseline
        if value is not None:
            self._state = value
        elif baseline is None and value is None:
            self._midnight_baseline = None
            self._state = 0.0
        self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attributes = super().extra_state_attributes
        attributes["midnight_baseline"] = self._midnight_baseline
        attributes["last_date"] = self._last_date.isoformat() if self._last_date else None
        attributes["energy_key"] = self._energy_key
        attributes["panel_energy_key"] = self._panel_energy_key
        return attributes

    @property
    def name_suffix(self) -> str | None:
        if self.panel_total and self._panel_energy_key == "import":
            return "Total Daily Import"
        if not self.panel_total and self._breaker_energy_key == "import":
            return "Daily Import"
        return "Total Daily Energy"

    @property
    def unique_id_suffix(self) -> str | None:
        if self.panel_total and self._panel_energy_key == "import":
            return "todaymw_import"
        if not self.panel_total and self._breaker_energy_key == "import":
            return "daily_import"
        return "todaymw"

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            val = round(self._state, 2)
            if self._last_reported is not None and val < self._last_reported:
                if self._last_reported > 0 and val / self._last_reported > 0.5:
                    return self._last_reported
            self._last_reported = val
            return val
        return 0.0

    def _detect_energy_key(self) -> str:
        if breakers := self.coordinator.data.get("breakers"):
            if breaker := breakers.get(self.breaker_data["id"]):
                imp = float(breaker.get("import", 0) or 0)
                cons = float(breaker.get("consumption", 0) or 0)
                if imp > cons and imp > 1.0:
                    return "import"
        return "consumption"

    def _get_breaker_consumption(self) -> float | None:
        if breakers := self.coordinator.data.get("breakers"):
            if breaker := breakers.get(self.breaker_data["id"]):
                key = self._energy_key or "consumption"
                val = breaker.get(key)
                if val is not None:
                    try:
                        return float(val)
                    except (ValueError, TypeError):
                        pass
        return None

    @callback
    def _state_update(self):
        if not self.coordinator.data:
            return
        try:
            if self._energy_key is None and not self.panel_total:
                if self._breaker_energy_key is not None:
                    self._energy_key = self._breaker_energy_key
                else:
                    self._energy_key = self._detect_energy_key()
            today = dt_util.now().date()
            is_new_day = self._last_date is not None and self._last_date != today
            
            if self.panel_total:
                self._update_panel_total(today, is_new_day)
            else:
                self._update_single_breaker(today, is_new_day)
                
            self._last_date = today
        except Exception:
            pass
        self.async_write_ha_state()

    def _update_single_breaker(self, today: datetime.date, is_new_day: bool):
        consumption = self._get_breaker_consumption()
        if consumption is None:
            return

        if is_new_day or self._midnight_baseline is None:
            self._midnight_baseline = consumption
            self._state = 0.0
            return

        daily = consumption - self._midnight_baseline
        if daily < 0:
            # AUTO-RECOVERY: If HA rebooted and the software drift was wiped, reset baseline
            if daily <= -0.1:
                self._midnight_baseline = consumption
                self._state = 0.0
            return
            
        if daily > MAX_DAILY_ENERGY_KWH:
            self._midnight_baseline = consumption
            daily = 0.0

        self._state = daily

    def _update_panel_total(self, today: datetime.date, is_new_day: bool):
        key = self._panel_energy_key
        cts = self.coordinator.data.get("cts", {})
        panel_cts = {b_id: b_data for b_id, b_data in cts.items() if b_data.get("panel_id") == self.panel_id}
        
        if panel_cts:
            data_to_sum = panel_cts
        else:
            breakers = self.coordinator.data.get("breakers", {})
            data_to_sum = {b_id: b_data for b_id, b_data in breakers.items() if b_data.get("panel_id") == self.panel_id}

        if not data_to_sum:
            return

        current_lifetime_sum = 0.0
        for b_id, b_data in data_to_sum.items():
            val = b_data.get(key)
            if val is not None:
                try:
                    current_lifetime_sum += float(val)
                except (ValueError, TypeError):
                    pass

        if is_new_day or self._midnight_baseline is None:
            self._midnight_baseline = current_lifetime_sum
            self._state = 0.0
            return

        daily = current_lifetime_sum - self._midnight_baseline
        if daily < 0:
            # AUTO-RECOVERY: If HA rebooted and the software drift was wiped, reset baseline
            if daily <= -0.1:
                self._midnight_baseline = current_lifetime_sum
                self._state = 0.0
            return
            
        if daily > MAX_DAILY_ENERGY_KWH:
            self._midnight_baseline = current_lifetime_sum
            daily = 0.0

        self._state = daily


class LDATACTDailyUsageSensor(LDATACTEntity, SensorEntity, RestoreEntity):
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR

    def __init__(self, coordinator: LDATAUpdateCoordinator, data, panelTotal, which_panel: str, energy_key: str = "consumption") -> None:
        self._energy_key: str = energy_key
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state: float | None = None
        self._last_reported: float | None = None
        self._midnight_baseline: float | None = None
        self._last_date: datetime.date | None = None

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass
            attrs = last_state.attributes or {}
            try:
                self._midnight_baseline = float(attrs["midnight_baseline"])
            except (KeyError, ValueError, TypeError):
                self._midnight_baseline = None
            if date_str := attrs.get("last_date"):
                try:
                    parsed = dt_util.parse_datetime(date_str)
                    self._last_date = parsed.date() if parsed else None
                except (ValueError, TypeError):
                    self._last_date = None

    async def async_reset_baseline(self, value: float | None = None, baseline: float | None = None) -> None:
        if baseline is not None:
            self._midnight_baseline = baseline
        if value is not None:
            self._state = value
        elif baseline is None and value is None:
            self._midnight_baseline = None
            self._state = 0.0
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        if self._energy_key == "import":
            return "Daily Import"
        return "Total Daily Energy"

    @property
    def unique_id_suffix(self) -> str | None:
        if self._energy_key == "import":
            return "daily_import"
        return "todaymw"

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            val = round(self._state, 2)
            if self._last_reported is not None and val < self._last_reported:
                if self._last_reported > 0 and val / self._last_reported > 0.5:
                    return self._last_reported
            self._last_reported = val
            return val
        return 0.0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attributes = super().extra_state_attributes
        attributes["midnight_baseline"] = self._midnight_baseline
        attributes["last_date"] = self._last_date.isoformat() if self._last_date else None
        return attributes

    def _get_ct_consumption(self) -> float | None:
        if not self.coordinator.data or "cts" not in self.coordinator.data:
            return None
        ct_data = self.coordinator.data["cts"].get(self.breaker_data["id"])
        if ct_data is None:
            return None
        val = ct_data.get(self._energy_key)
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                pass
        return None

    @callback
    def _state_update(self):
        if not self.coordinator.data:
            return
        try:
            today = dt_util.now().date()
            is_new_day = self._last_date is not None and self._last_date != today
            
            consumption = self._get_ct_consumption()
            if consumption is not None:
                if is_new_day or self._midnight_baseline is None:
                    self._midnight_baseline = consumption
                    self._state = 0.0
                else:
                    daily = consumption - self._midnight_baseline
                    if daily < 0:
                        # AUTO-RECOVERY: If HA rebooted and the software drift was wiped, reset baseline
                        if daily <= -0.1:
                            self._midnight_baseline = consumption
                            self._state = 0.0
                    else:
                        if daily > MAX_DAILY_ENERGY_KWH:
                            self._midnight_baseline = consumption
                            self._state = 0.0
                        else:
                            self._state = daily

            self._last_date = today
        except Exception:
            return
        self.async_write_ha_state()


class LDATATotalUsageSensor(LDATAEntity, SensorEntity):
    entity_description: SensorDescription

    def __init__(self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription, average: bool, which_leg: str) -> None:
        self.entity_description = description
        self.leg_to_total = which_leg
        super().__init__(data=data, coordinator=coordinator)
        self.is_average = average
        self._state = self.total_values()

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    def total_values(self) -> float:
        if not self.coordinator.data or "breakers" not in self.coordinator.data:
            return 0.0
        if self.entity_description.key == "power" and self.leg_to_total == "both" and not self.is_average:
            key = self.entity_data["serialNumber"] + "totalPower"
            try:
                return float(self.coordinator.data.get(key, 0))
            except (ValueError, TypeError):
                return 0.0
        total = 0.0
        count = 0
        for breaker in self.coordinator.data["breakers"].items():
            breaker_data = breaker[1]
            if breaker_data["panel_id"] == self.entity_data["serialNumber"]:
                current_value = 0.0
                if self.leg_to_total == "both":
                    try:
                        val = breaker_data[self.entity_description.key]
                        if val is not None:
                            current_value = float(val)
                    except (ValueError, KeyError, TypeError):
                        current_value = 0.0
                else:
                    try:
                        val = breaker_data[self.entity_description.key + self.leg_to_total]
                        if val is not None:
                            current_value = float(val)
                    except (ValueError, KeyError, TypeError):
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
        self._state = self.total_values()
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        if (self.entity_description.name is not None) and (self.leg_to_total != "both"):
            return str(self.entity_description.name) + " Leg " + self.leg_to_total
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        if (self.entity_description.name is not None) and (self.leg_to_total != "both"):
            return "_leg_" + self.leg_to_total + str(self.entity_description.unique_id_suffix)
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            return round(self._state, 2)
        return 0.0


class LDATAOutputSensor(LDATAEntity, SensorEntity):
    entity_description: SensorDescription

    def __init__(self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription) -> None:
        self.entity_description = description
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        try:
            val = self.breaker_data[self.entity_description.key]
            self._state = float(val) if val is not None else None
        except (ValueError, TypeError):
            self._state = None

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    @callback
    def _state_update(self):
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    self._state = new_data[self.entity_description.key]
                else:
                    self._state = None
            else:
                self._state = None
        except KeyError:
            self._state = None
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            return round(self._state, 2)
        return self._state

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        attributes = super().extra_state_attributes
        attributes["panel_id"] = self.breaker_data["panel_id"]
        return attributes


class LDATABreakerEnergyUsageSensor(LDATAEntity, SensorEntity, RestoreEntity):
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    entity_description: SensorDescription

    def __init__(self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription) -> None:
        self.entity_description = description
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = None

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success or self._state is not None

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass

    @callback
    def _state_update(self):
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    raw = new_data.get(self.entity_description.key)
                    if raw is not None:
                        self._state = float(raw)
        except (KeyError, ValueError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            return round(self._state, 2)
        return self._state


class LDATAPanelOutputSensor(LDATAEntity, SensorEntity):
    entity_description: SensorDescription

    def __init__(self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription, which_leg: str) -> None:
        self.entity_description = description
        self.leg_to_total = which_leg
        super().__init__(data=data, coordinator=coordinator)
        self.panel_data = data
        try:
            self._state = float(self.panel_data["data"][self.entity_description.key + self.leg_to_total])
        except ValueError:
            self._state = 0.0

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    @callback
    def _state_update(self):
        try:
            if panels := self.coordinator.data.get("panels"):
                for panel in panels:
                    if panel["id"] == self.panel_data["id"]:
                        self._state = panel[self.entity_description.key + self.leg_to_total]
                        break
        except KeyError:
            self._state = None
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        return str(self.entity_description.name) + " Leg " + self.leg_to_total

    @property
    def unique_id_suffix(self) -> str | None:
        return "_leg_" + self.leg_to_total + str(self.entity_description.unique_id_suffix)

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            return round(self._state, 2)
        return self._state


class LDATACTOutputSensor(LDATACTEntity, SensorEntity):
    entity_description: SensorDescription

    def __init__(self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription) -> None:
        self.entity_description = description
        super().__init__(data=data, coordinator=coordinator)
        self.ct_data = data
        try:
            self._state = float(self.ct_data[self.entity_description.key])
        except ValueError:
            self._state = 0.0

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    @callback
    def _state_update(self):
        try:
            if cts := self.coordinator.data.get("cts"):
                if new_data := cts.get(self.ct_data["id"]):
                    self._state = float(new_data[self.entity_description.key])
                else:
                    self._state = None
            else:
                self._state = None
        except (KeyError, ValueError, TypeError):
            self._state = None
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            return round(self._state, 2)
        return self._state


class LDATAEnergyUsageSensor(LDATACTEntity, SensorEntity, RestoreEntity):
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    entity_description: SensorDescription

    def __init__(self, coordinator: LDATAUpdateCoordinator, data, description: SensorDescription) -> None:
        self.entity_description = description
        super().__init__(data=data, coordinator=coordinator)
        self.ct_data = data
        self._state = None
    
    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success or self._state is not None

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass

    @callback
    def _state_update(self):
        try:
            if cts := self.coordinator.data.get("cts"):
                if new_data := cts.get(self.ct_data["id"]):
                    raw = new_data.get(self.entity_description.key)
                    if raw is not None:
                        self._state = float(raw)
        except (KeyError, ValueError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        return self.entity_description.name

    @property
    def unique_id_suffix(self) -> str | None:
        return self.entity_description.unique_id_suffix

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            return round(self._state, 2)
        return self._state


class LDATABreakerOperationalStateSensor(LDATAEntity, SensorEntity):
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get("operationalState", "Normal")

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    @callback
    def _state_update(self):
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    self._state = new_data.get("operationalState", "Normal")
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def native_value(self) -> StateType:
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "Operational State"

    @property
    def unique_id_suffix(self) -> str | None:
        return "operational_state"

    @property
    def icon(self) -> str:
        if self._state and self._state != "Normal":
            return "mdi:alert-circle"
        return "mdi:check-circle-outline"


class LDATABreakerBleRSSISensor(LDATAEntity, SensorEntity):
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_native_unit_of_measurement = "dBm"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH

    def __init__(self, coordinator, data) -> None:
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get("bleRSSI")

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    @callback
    def _state_update(self):
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    val = new_data.get("bleRSSI")
                    if val is not None and val < 0:
                        if self._state is None or abs(val - self._state) > 5:
                            self._state = val
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            return round(self._state, 0)
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "BLE Signal"

    @property
    def unique_id_suffix(self) -> str | None:
        return "ble_rssi"


class LDATAPanelWifiRSSISensor(LDATAEntity, SensorEntity):
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_native_unit_of_measurement = "dBm"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH

    def __init__(self, coordinator, data) -> None:
        super().__init__(data=data, coordinator=coordinator)
        self.panel_data = data
        self._panel_id = data["data"]["id"]
        self._state = data["data"].get("rssi")

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    @callback
    def _state_update(self):
        try:
            if panels := self.coordinator.data.get("panels"):
                for panel in panels:
                    if panel["id"] == self._panel_id:
                        val = panel.get("rssi")
                        if val is not None:
                            self._state = val
                        break
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def native_value(self) -> StateType:
        if self._state is not None:
            return round(self._state, 0)
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "WiFi Signal"

    @property
    def unique_id_suffix(self) -> str | None:
        return "wifi_rssi"

    @property
    def icon(self) -> str:
        if self._state is not None:
            if self._state >= -50:
                return "mdi:wifi-strength-4"
            elif self._state >= -60:
                return "mdi:wifi-strength-3"
            elif self._state >= -70:
                return "mdi:wifi-strength-2"
            elif self._state >= -80:
                return "mdi:wifi-strength-1"
            else:
                return "mdi:wifi-strength-alert-outline"
        return "mdi:wifi-strength-off-outline"