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
    GAP_HANDLING,
    GAP_HANDLING_DEFAULT,
    GAP_HANDLING_SKIP,
    GAP_HANDLING_EXTRAPOLATE,
    GAP_HANDLING_AVERAGE,
    GAP_THRESHOLD,
    GAP_THRESHOLD_DEFAULT,
    HW_COUNTER_NONE_TOLERANCE,
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

def _check_spike_and_update(
    state: float | None,
    pending_state: float | None,
    new_value: float,
    entity_id: str,
    log_enabled: bool,
    *,
    low_threshold: float = 1.0,
    high_absolute: float = 100.0,
    high_ratio: float = 1.5,
) -> tuple[float | None, float | None, bool]:
    is_potential_spike = False
    if state is None:
        return new_value, None, True

    current = float(state)
    if current <= low_threshold and new_value > high_absolute:
        is_potential_spike = True
    elif current > low_threshold and new_value > (current * high_ratio):
        is_potential_spike = True

    if not is_potential_spike:
        return new_value, None, True

    if pending_state is not None:
        if pending_state != 0 and abs(new_value - pending_state) / abs(pending_state) < 0.15:
            if log_enabled:
                _LOGGER.info("Accepting consistent high value for %s: %s", entity_id, new_value)
            return new_value, None, True
        else:
            if log_enabled:
                _LOGGER.warning("Discarding inconsistent spike for %s: new=%s, pending=%s", entity_id, new_value, pending_state)
            return state, new_value, False
    else:
        if log_enabled:
            _LOGGER.warning("High value detected for %s. Pending verification: %s", entity_id, new_value)
        return state, new_value, False


def _log_data_warnings_enabled(coordinator) -> bool:
    return coordinator.config_entry.options.get("log_data_warnings", True)


def _log_warnings_enabled(coordinator) -> bool:
    return coordinator.config_entry.options.get("log_warnings", True)


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
        # Solar breakers have import > consumption. Skip import sensors only
        # when we can definitively tell it's not solar: consumption is
        # accumulating but import is still zero. When both are zero (e.g.
        # panel just powered on, or nighttime startup), we create the sensors
        # — they'll sit harmlessly at 0 until the next reload confirms.
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
    """Sensor that tracks daily energy usage for an LDATA device.

    Dual-mode operation:
    1. Hardware counters (primary): Uses energyConsumption/energyImport lifetime
       kWh totals. Daily energy = current_consumption - midnight_baseline.
       Available on firmware 2.0+ panels.
    2. Power×time integration (fallback): For older firmware without hardware
       counters. Integrates power over time with configurable gap handling.

    Mode is auto-detected per panel based on whether energyConsumption data
    is available.
    """

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
        self._last_update_time: float | None = None
        self._last_power: float | None = None
        self._use_hw_counters: bool | None = None
        self._energy_key: str | None = None
        self._consecutive_none: int = 0
        self._accept_next_value: bool = False
        self._consecutive_decrease: int = 0

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
            try:
                self._last_update_time = float(attrs["last_update_time"])
            except (KeyError, ValueError, TypeError):
                self._last_update_time = None
            if "use_hw_counters" in attrs:
                self._use_hw_counters = attrs["use_hw_counters"]
            if "energy_key" in attrs:
                self._energy_key = attrs["energy_key"]

    async def async_reset_baseline(self, value: float | None = None, baseline: float | None = None) -> None:
        """Handle the reset_energy_baseline service call natively."""
        current = self._state
        _LOGGER.warning("reset_energy_baseline called for %s — current value: %s kWh", self.entity_id, current)

        if baseline is not None:
            self._midnight_baseline = baseline
            if hasattr(self, '_monotonic_reject_since'):
                self._monotonic_reject_since = None
            self.async_write_ha_state()
            _LOGGER.warning("Reset %s: manually forced midnight baseline to %.3f kWh", self.entity_id, baseline)

        if value is not None:
            self._state = value
            self._accept_next_value = False
            self._consecutive_decrease = 0
            if hasattr(self, '_monotonic_reject_since'):
                self._monotonic_reject_since = None
            self.async_write_ha_state()
            _LOGGER.warning("Reset %s: %.2f -> %.2f kWh (forced value)", self.entity_id, current or 0, value)
            
        elif baseline is None and value is None:
            self._accept_next_value = True
            self._consecutive_decrease = 0
            if hasattr(self, '_monotonic_reject_since'):
                self._monotonic_reject_since = None
            self._midnight_baseline = None
            if hasattr(self, '_panel_baselines'):
                self._panel_baselines = {}
            if hasattr(self, '_last_breaker_deltas'):
                self._last_breaker_deltas = {}
            self._state = 0.0
            self.async_write_ha_state()
            _LOGGER.warning("Reset %s: cleared baselines, cached deltas, and state", self.entity_id)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attributes = super().extra_state_attributes
        attributes["midnight_baseline"] = self._midnight_baseline
        attributes["last_date"] = self._last_date.isoformat() if self._last_date else None
        attributes["use_hw_counters"] = self._use_hw_counters
        attributes["energy_key"] = self._energy_key
        attributes["panel_energy_key"] = self._panel_energy_key
        if self._last_update_time is not None:
            attributes["last_update_time"] = self._last_update_time
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

    def _get_breaker_consumption(self, breaker_id: str) -> float | None:
        if breakers := self.coordinator.data.get("breakers"):
            if breaker := breakers.get(breaker_id):
                key = self._energy_key or "consumption"
                val = breaker.get(key)
                if val is not None:
                    try:
                        fval = float(val)
                        if fval == 0.0 and self._midnight_baseline and self._midnight_baseline > 1.0:
                            return None
                        return fval
                    except (ValueError, TypeError):
                        pass
        return None

    def _detect_mode(self) -> bool:
        if hasattr(self.coordinator, '_service') and self.coordinator._service:
            return self.coordinator._service.panel_has_hw_counters(self.panel_id)
        if not self.panel_total:
            consumption = self._get_breaker_consumption(self.breaker_data["id"])
            return consumption is not None and consumption > 0
        return False

    @callback
    def _state_update(self):
        if not self.coordinator.data:
            return
        try:
            if self._use_hw_counters is None:
                self._use_hw_counters = self._detect_mode()
            if self._energy_key is None and not self.panel_total:
                if self._breaker_energy_key is not None:
                    self._energy_key = self._breaker_energy_key
                else:
                    self._energy_key = self._detect_energy_key()
            today = dt_util.now().date()
            is_new_day = self._last_date is not None and self._last_date != today
            if self._use_hw_counters:
                if self.panel_total:
                    self._update_panel_total_hw(today, is_new_day)
                else:
                    self._update_single_breaker_hw(today, is_new_day)
            else:
                if self.panel_total:
                    self._update_panel_total_pxt(today, is_new_day)
                else:
                    self._update_single_breaker_pxt(today, is_new_day)
            self._last_date = today
        except Exception:
            if _log_warnings_enabled(self.coordinator):
                _LOGGER.exception("Error updating daily usage sensor for %s", self.entity_id)
        self.async_write_ha_state()

    def _update_single_breaker_hw(self, today: datetime.date, is_new_day: bool):
        consumption = self._get_breaker_consumption(self.breaker_data["id"])
        if consumption is None:
            self._consecutive_none += 1
            if self._consecutive_none >= HW_COUNTER_NONE_TOLERANCE:
                # If this is an explicit import sensor and the lifetime import is zero,
                # the breaker has no export/import activity — stay at zero, don't fall
                # back to power×time which would incorrectly mirror consumption.
                if self._breaker_energy_key == "import":
                    if breakers := self.coordinator.data.get("breakers"):
                        if breaker := breakers.get(self.breaker_data["id"]):
                            lifetime_import = float(breaker.get("import", 0) or 0)
                            if lifetime_import == 0.0:
                                self._consecutive_none = 0
                                self._state = 0.0
                                return
                self._use_hw_counters = False
                self._consecutive_none = 0
            return
        self._consecutive_none = 0

        if is_new_day:
            if self._midnight_baseline is not None and self._midnight_baseline > 10.0 and consumption < 1.0:
                self._state = 0.0
                return
            self._midnight_baseline = consumption
            self._state = 0.0
            return

        if self._midnight_baseline is None:
            self._midnight_baseline = consumption
            self._state = 0.0
            return

        daily = consumption - self._midnight_baseline
        if daily < 0:
            return

        if daily > MAX_DAILY_ENERGY_KWH:
            self._midnight_baseline = consumption
            daily = 0.0

        if self._state is not None and self._state > 0.5 and daily < self._state - 0.05:
            if getattr(self, '_monotonic_reject_since', None) is None:
                self._monotonic_reject_since = time.time()
            elapsed = time.time() - self._monotonic_reject_since
            if elapsed < 300:
                return
            else:
                self._monotonic_reject_since = None

        if getattr(self, '_monotonic_reject_since', None) is not None:
            self._monotonic_reject_since = None

        self._state = daily

    def _update_panel_total_hw(self, today: datetime.date, is_new_day: bool):
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
                    fval = float(val)
                    current_lifetime_sum += fval
                except (ValueError, TypeError):
                    pass

        if is_new_day:
            if self._midnight_baseline is not None and self._midnight_baseline > 10.0 and current_lifetime_sum < 1.0:
                self._state = 0.0
                return
            self._midnight_baseline = current_lifetime_sum
            self._state = 0.0
            return

        if self._midnight_baseline is None:
            self._midnight_baseline = current_lifetime_sum
            self._state = 0.0
            return

        daily = current_lifetime_sum - self._midnight_baseline
        if daily < 0:
            return

        if daily > MAX_DAILY_ENERGY_KWH:
            self._midnight_baseline = current_lifetime_sum
            daily = 0.0

        if self._state is not None and self._state > 0.5 and daily < self._state - 0.05:
            if getattr(self, '_monotonic_reject_since', None) is None:
                self._monotonic_reject_since = time.time()
            elapsed = time.time() - self._monotonic_reject_since
            if elapsed < 300:
                return
            else:
                self._monotonic_reject_since = None

        if getattr(self, '_monotonic_reject_since', None) is not None:
            self._monotonic_reject_since = None

        self._state = daily

    def _update_single_breaker_pxt(self, today: datetime.date, is_new_day: bool):
        new_data = self.coordinator.data.get("breakers", {}).get(self.breaker_data["id"])
        if not new_data:
            return
        try:
            current_power = abs(float(new_data.get("power", 0)))
        except (ValueError, TypeError):
            return

        now = time.time()
        options = self.coordinator.config_entry.options

        if is_new_day:
            self._state = 0.0
            self._last_update_time = now
            self._last_power = current_power
            return

        if self._last_update_time is None or self._state is None:
            self._last_update_time = now
            self._last_power = current_power
            if self._state is None:
                self._state = 0.0
            return

        time_span = now - self._last_update_time
        if time_span <= 0:
            return

        gap_threshold_secs = options.get(GAP_THRESHOLD, GAP_THRESHOLD_DEFAULT) * 60
        gap_mode = options.get(GAP_HANDLING, GAP_HANDLING_DEFAULT)

        if time_span > gap_threshold_secs:
            if gap_mode == GAP_HANDLING_SKIP:
                pass
            elif gap_mode == GAP_HANDLING_EXTRAPOLATE:
                last_p = self._last_power or 0
                self._state += (last_p * time_span) / 3_600_000
            elif gap_mode == GAP_HANDLING_AVERAGE:
                last_p = self._last_power or 0
                avg_power = (last_p + current_power) / 2
                self._state += (avg_power * time_span) / 3_600_000
        else:
            avg_power = ((self._last_power or 0) + current_power) / 2
            self._state += (avg_power * time_span) / 3_600_000

        self._last_update_time = now
        self._last_power = current_power

    def _update_panel_total_pxt(self, today: datetime.date, is_new_day: bool):
        try:
            current_power = abs(float(self.coordinator.data.get(self.panel_id + "totalPower", 0)))
        except (ValueError, TypeError):
            return

        now = time.time()
        options = self.coordinator.config_entry.options

        if is_new_day:
            self._state = 0.0
            self._last_update_time = now
            self._last_power = current_power
            return

        if self._last_update_time is None or self._state is None:
            self._last_update_time = now
            self._last_power = current_power
            if self._state is None:
                self._state = 0.0
            return

        time_span = now - self._last_update_time
        if time_span <= 0:
            return

        gap_threshold_secs = options.get(GAP_THRESHOLD, GAP_THRESHOLD_DEFAULT) * 60
        gap_mode = options.get(GAP_HANDLING, GAP_HANDLING_DEFAULT)

        if time_span > gap_threshold_secs:
            if gap_mode == GAP_HANDLING_SKIP:
                pass
            elif gap_mode == GAP_HANDLING_EXTRAPOLATE:
                last_p = self._last_power or 0
                self._state += (last_p * time_span) / 3_600_000
            elif gap_mode == GAP_HANDLING_AVERAGE:
                last_p = self._last_power or 0
                avg_power = (last_p + current_power) / 2
                self._state += (avg_power * time_span) / 3_600_000
        else:
            avg_power = ((self._last_power or 0) + current_power) / 2
            self._state += (avg_power * time_span) / 3_600_000

        self._last_update_time = now
        self._last_power = current_power


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
        self._consecutive_none: int = 0
        self._use_hw_counters: bool | None = None
        self._last_update_time: float | None = None
        self._last_power: float | None = None
        self._accept_next_value: bool = False
        self._consecutive_decrease: int = 0

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
            if "use_hw_counters" in attrs:
                self._use_hw_counters = attrs["use_hw_counters"]
            if "energy_key" in attrs and attrs["energy_key"]:
                self._energy_key = attrs["energy_key"]

    async def async_reset_baseline(self, value: float | None = None, baseline: float | None = None) -> None:
        current = self._state
        if baseline is not None:
            self._midnight_baseline = baseline
            if hasattr(self, '_monotonic_reject_since'):
                self._monotonic_reject_since = None
            self.async_write_ha_state()

        if value is not None:
            self._state = value
            self._accept_next_value = False
            self._consecutive_decrease = 0
            if hasattr(self, '_monotonic_reject_since'):
                self._monotonic_reject_since = None
            self.async_write_ha_state()
            
        elif baseline is None and value is None:
            self._accept_next_value = True
            self._consecutive_decrease = 0
            if hasattr(self, '_monotonic_reject_since'):
                self._monotonic_reject_since = None
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
        attributes["energy_key"] = self._energy_key
        attributes["use_hw_counters"] = self._use_hw_counters
        if self._last_update_time is not None:
            attributes["last_update_time"] = self._last_update_time
        return attributes

    def _get_ct_consumption(self) -> float | None:
        if not self.coordinator.data or "cts" not in self.coordinator.data:
            return None
        ct_data = self.coordinator.data["cts"].get(self.breaker_data["id"])
        if ct_data is None:
            return None
        val = ct_data.get(self._energy_key)
        if val is None:
            return None
        try:
            fval = float(val)
            if fval == 0.0 and self._midnight_baseline and self._midnight_baseline > 1.0:
                return None
            return fval
        except (ValueError, TypeError):
            return None

    def _detect_ct_mode(self) -> bool:
        if hasattr(self.coordinator, '_service') and self.coordinator._service:
            panel_id = self.breaker_data.get("panel_id")
            if panel_id:
                return self.coordinator._service.panel_has_hw_counters(panel_id)
        consumption = self._get_ct_consumption()
        return consumption is not None and consumption > 0

    @callback
    def _state_update(self):
        if not self.coordinator.data:
            return
        try:
            if self._use_hw_counters is None:
                self._use_hw_counters = self._detect_ct_mode()
            today = dt_util.now().date()
            is_new_day = self._last_date is not None and self._last_date != today
            if self._use_hw_counters:
                self._update_ct_hw(today, is_new_day)
            else:
                self._update_ct_pxt(today, is_new_day)
        except Exception:
            return
        self.async_write_ha_state()

    def _update_ct_hw(self, today: datetime.date, is_new_day: bool):
        consumption = self._get_ct_consumption()
        if consumption is None:
            self._consecutive_none += 1
            if self._consecutive_none >= HW_COUNTER_NONE_TOLERANCE:
                pass
            return
        self._consecutive_none = 0

        if is_new_day:
            if self._midnight_baseline is not None and self._midnight_baseline > 10.0 and consumption < 1.0:
                self._state = 0.0
                self._last_date = today
                return
            self._midnight_baseline = consumption
            self._state = 0.0
            self._last_date = today
            return

        if self._midnight_baseline is None:
            if self._energy_key == "consumption":
                ct_id = self.breaker_data["id"]
                ct = self.coordinator.data.get("cts", {}).get(ct_id, {})
                imp = float(ct.get("import", 0) or 0)
                cons = float(ct.get("consumption", 0) or 0)
                if imp > cons and imp > 1.0:
                    self._energy_key = "import"
                    consumption = self._get_ct_consumption()
                    if consumption is None:
                        return
            self._midnight_baseline = consumption
            self._state = 0.0
            self._last_date = today
            return

        daily = consumption - self._midnight_baseline
        if daily < 0:
            return
        if daily > MAX_DAILY_ENERGY_KWH:
            self._midnight_baseline = consumption
            daily = 0.0
        if self._state is not None and self._state > 0.5 and daily < self._state - 0.05:
            if getattr(self, '_monotonic_reject_since', None) is None:
                self._monotonic_reject_since = time.time()
            if time.time() - self._monotonic_reject_since < 300:
                return
            else:
                self._monotonic_reject_since = None

        if getattr(self, '_monotonic_reject_since', None) is not None:
            self._monotonic_reject_since = None

        self._state = daily
        self._last_date = today

    def _update_ct_pxt(self, today: datetime.date, is_new_day: bool):
        if not self.coordinator.data or "cts" not in self.coordinator.data:
            return
        ct_data = self.coordinator.data["cts"].get(self.breaker_data["id"])
        if ct_data is None:
            return
        try:
            current_power = abs(float(ct_data.get("power", 0)))
        except (ValueError, TypeError):
            return

        now = time.time()
        options = self.coordinator.config_entry.options

        if is_new_day:
            self._state = 0.0
            self._last_update_time = now
            self._last_power = current_power
            self._last_date = today
            return

        if self._last_update_time is None or self._state is None:
            self._last_update_time = now
            self._last_power = current_power
            self._last_date = today
            if self._state is None:
                self._state = 0.0
            return

        time_span = now - self._last_update_time
        if time_span <= 0:
            return

        gap_threshold_secs = options.get(GAP_THRESHOLD, GAP_THRESHOLD_DEFAULT) * 60
        gap_mode = options.get(GAP_HANDLING, GAP_HANDLING_DEFAULT)

        if time_span > gap_threshold_secs:
            if gap_mode == GAP_HANDLING_SKIP:
                pass
            elif gap_mode == GAP_HANDLING_EXTRAPOLATE:
                last_p = self._last_power or 0
                self._state += (last_p * time_span) / 3_600_000
            elif gap_mode == GAP_HANDLING_AVERAGE:
                last_p = self._last_power or 0
                avg_power = (last_p + current_power) / 2
                self._state += (avg_power * time_span) / 3_600_000
        else:
            avg_power = ((self._last_power or 0) + current_power) / 2
            self._state += (avg_power * time_span) / 3_600_000

        self._last_update_time = now
        self._last_power = current_power
        self._last_date = today


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
        self._pending_state = None
        self._accept_next_value: bool = False
        self._consecutive_decrease: int = 0

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

    async def async_reset_baseline(self, value: float | None = None, baseline: float | None = None) -> None:
        if value is not None:
            self._state = value
            self._accept_next_value = False
            self._consecutive_decrease = 0
            self.async_write_ha_state()
        elif baseline is None and value is None:
            self._accept_next_value = True
            self._consecutive_decrease = 0
            self.async_write_ha_state()

    @callback
    def _state_update(self):
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    raw = new_data.get(self.entity_description.key)
                    if raw is None:
                        return
                    new_value = float(raw)
                    ROUNDING_TOLERANCE = 0.05
                    if new_value == 0.0 and self._state is not None and self._state > 1.0:
                        return
                    if self._state is None:
                        self._state = new_value
                        self.async_write_ha_state()
                        return
                    if self._accept_next_value:
                        self._state = new_value
                        self._accept_next_value = False
                        self._consecutive_decrease = 0
                        self.async_write_ha_state()
                        return
                    if (float(self._state) - new_value) > ROUNDING_TOLERANCE:
                        self._consecutive_decrease += 1
                        return
                    if new_value < float(self._state):
                        new_value = float(self._state)
                    new_state, self._pending_state, accepted = _check_spike_and_update(
                        self._state, self._pending_state, new_value,
                        self.entity_id, _log_data_warnings_enabled(self.coordinator),
                    )
                    if accepted:
                        self._state = new_state
        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            return
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
            else:
                self._state = None
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
        self._pending_state = None
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
                    new_value = float(new_data[self.entity_description.key])
                    log_enabled = _log_data_warnings_enabled(self.coordinator)
                    is_potential_spike = False
                    if self._state is None:
                        if abs(new_value) > 3000:
                            is_potential_spike = True
                    else:
                        previous_state = float(self._state)
                        if previous_state == 0 and abs(new_value) > 3000:
                            is_potential_spike = True
                        elif previous_state != 0 and abs(new_value) > (abs(previous_state) * 10) and abs(new_value - previous_state) > 2000:
                            is_potential_spike = True
                    if is_potential_spike:
                        if self._pending_state is not None:
                            if self._pending_state != 0 and abs(new_value - self._pending_state) / abs(self._pending_state) < 0.15:
                                self._state = new_value
                                self._pending_state = None
                            else:
                                self._pending_state = new_value
                        else:
                            self._pending_state = new_value
                    else:
                        self._pending_state = None
                        self._state = new_value
                else:
                    self._state = None
            else:
                self._state = None
        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            self._state = None
            self._pending_state = None
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
        self._pending_state = None
        self._consecutive_decrease: int = 0
        self._accept_next_value: bool = False
    
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

    async def async_reset_baseline(self, value: float | None = None, baseline: float | None = None) -> None:
        if value is not None:
            self._state = value
            self._accept_next_value = False
            self._consecutive_decrease = 0
            self.async_write_ha_state()
        elif baseline is None and value is None:
            self._accept_next_value = True
            self._consecutive_decrease = 0
            self.async_write_ha_state()

    @callback
    def _state_update(self):
        try:
            if cts := self.coordinator.data.get("cts"):
                if new_data := cts.get(self.ct_data["id"]):
                    new_value = float(new_data[self.entity_description.key])
                    ROUNDING_TOLERANCE = 0.05
                    if new_value == 0.0 and self._state is not None and self._state > 1.0:
                        return
                    if self._state is None:
                        self._state = new_value
                        self.async_write_ha_state()
                        return
                    if self._accept_next_value:
                        self._state = new_value
                        self._accept_next_value = False
                        self._consecutive_decrease = 0
                        self.async_write_ha_state()
                        return
                    if (float(self._state) - new_value) > ROUNDING_TOLERANCE:
                        if self._state > 10.0 and new_value < self._state * 0.1:
                            return
                        self._consecutive_decrease += 1
                        return
                    self._consecutive_decrease = 0
                    if new_value < float(self._state):
                        new_value = float(self._state)
                    new_state, self._pending_state, accepted = _check_spike_and_update(
                        self._state, self._pending_state, new_value,
                        self.entity_id, _log_data_warnings_enabled(self.coordinator),
                    )
                    if accepted:
                        self._state = new_state
        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            return
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