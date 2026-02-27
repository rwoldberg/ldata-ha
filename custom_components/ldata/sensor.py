"""Support for power sensors in LDATA devices."""

from __future__ import annotations

import copy
import datetime
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
        # Add lifetime Import and Consumption sensors for breakers that have
        # hardware energy counters. These are TOTAL_INCREASING and feed the
        # HA Energy dashboard directly (solar production via Import, grid
        # consumption via Consumption). Created unconditionally — if a breaker
        # doesn't have hw counters, the sensor stays at 0/None harmlessly.
        entities_to_add.append(
            LDATABreakerEnergyUsageSensor(coordinator, breaker_data, SENSOR_TYPES[4])
        )
        entities_to_add.append(
            LDATABreakerEnergyUsageSensor(coordinator, breaker_data, SENSOR_TYPES[5])
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
    """Sensor that tracks daily usage for an LDATA device.
    
    Dual-mode operation:
    1. Hardware counters (primary): Uses energyConsumption lifetime kWh totals.
       Daily energy = current_consumption - midnight_baseline.
       Available on firmware 2.0+ panels.
    2. Power×time integration (fallback): For older firmware without hardware
       counters. Integrates power over time with configurable gap handling.
    
    Mode is auto-detected per panel based on whether energyConsumption data
    is available.
    """

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
        self._last_reported: float | None = None  # Monotonic clamp for TOTAL_INCREASING
        self.panel_total = panelTotal
        self.panel_id = which_panel
        # --- Hardware counter mode ---
        self._midnight_baseline: float | None = None
        self._last_date: datetime.date | None = None
        # For panel total: per-breaker baselines {breaker_id: baseline_consumption}
        self._panel_baselines: dict[str, float] = {}
        # --- Power×time fallback mode ---
        self._last_update_time: float | None = None  # time.time() of last update
        self._last_power: float | None = None  # Last known power in watts
        # Track which mode this sensor is using (set on first update)
        self._use_hw_counters: bool | None = None
        # Which energy counter to use: "consumption" for normal breakers,
        # "import" for solar breakers (auto-detected on first update).
        self._energy_key: str | None = None
        # Consecutive None readings from _get_breaker_consumption — used to
        # distinguish transient reconnect glitches from genuine hw counter loss.
        self._consecutive_none: int = 0

    async def async_added_to_hass(self) -> None:
        """Handle entity which is added to hass to restore state on startup."""
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass
            
            attrs = last_state.attributes or {}
            # Restore hardware counter state
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
            # Restore panel baselines
            if panel_baselines_str := attrs.get("panel_baselines"):
                try:
                    import json
                    self._panel_baselines = {k: float(v) for k, v in json.loads(panel_baselines_str).items()}
                except (ValueError, TypeError, json.JSONDecodeError):
                    self._panel_baselines = {}
            # Restore power×time fallback state
            try:
                self._last_update_time = float(attrs["last_update_time"])
            except (KeyError, ValueError, TypeError):
                self._last_update_time = None
            # Restore mode flag
            if "use_hw_counters" in attrs:
                self._use_hw_counters = attrs["use_hw_counters"]
            # Restore energy key (consumption vs import)
            if "energy_key" in attrs:
                self._energy_key = attrs["energy_key"]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra attributes for state restoration."""
        import json
        attributes = super().extra_state_attributes
        attributes["midnight_baseline"] = self._midnight_baseline
        attributes["last_date"] = self._last_date.isoformat() if self._last_date else None
        attributes["use_hw_counters"] = self._use_hw_counters
        attributes["energy_key"] = self._energy_key
        if self._last_update_time is not None:
            attributes["last_update_time"] = self._last_update_time
        if self.panel_total and self._panel_baselines:
            attributes["panel_baselines"] = json.dumps(self._panel_baselines)
        return attributes

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
            val = round(self._state, 2)
            # TOTAL_INCREASING clamp: never report a decrease within a day.
            # Hardware counter jitter (e.g. 21.31→21.30) or rounding can
            # cause tiny dips that trigger HA recorder warnings.
            # Midnight resets (val near 0 while _last_reported is high) are
            # allowed — HA handles those natively for TOTAL_INCREASING.
            if self._last_reported is not None and val < self._last_reported:
                # A midnight reset looks like a large drop (e.g. 21.3 → 0.1).
                # A jitter dip is a tiny drop (e.g. 0.18 → 0.17 or 21.31 → 21.30).
                # Use ratio: if new value is less than 50% of previous, it's a reset.
                if self._last_reported > 0 and val / self._last_reported > 0.5:
                    return self._last_reported  # Jitter — hold previous value
            self._last_reported = val
            return val
        return 0.0

    def _detect_energy_key(self) -> str:
        """Detect whether this breaker is solar (uses import) or normal (uses consumption).
        
        Solar breakers have energyImport >> energyConsumption.
        Normal breakers have energyConsumption >> energyImport.
        """
        if breakers := self.coordinator.data.get("breakers"):
            if breaker := breakers.get(self.breaker_data["id"]):
                imp = float(breaker.get("import", 0) or 0)
                cons = float(breaker.get("consumption", 0) or 0)
                if imp > cons and imp > 1.0:
                    _LOGGER.info(
                        "Daily sensor %s: detected as solar breaker "
                        "(import=%.1f >> consumption=%.1f) — using energyImport",
                        self.entity_id, imp, cons
                    )
                    return "import"
        return "consumption"

    def _get_breaker_consumption(self, breaker_id: str) -> float | None:
        """Get the current lifetime energy counter for a breaker, or None if unavailable.
        
        Uses energyImport for solar breakers, energyConsumption for normal breakers.
        Returns None for zero values when the breaker hasn't been seen yet,
        since none_to_zero converts missing values to 0.0 during parse_panels
        or reconnect — a false reading, not a real counter.
        """
        if breakers := self.coordinator.data.get("breakers"):
            if breaker := breakers.get(breaker_id):
                key = self._energy_key or "consumption"
                val = breaker.get(key)
                if val is not None:
                    try:
                        fval = float(val)
                        # Reject 0.0 if we have a non-zero baseline — this is
                        # almost certainly a stale/missing value from parse_panels
                        # where none_to_zero converted None → 0.0, not a real
                        # counter that happens to be exactly zero.
                        if fval == 0.0 and self._midnight_baseline and self._midnight_baseline > 1.0:
                            return None
                        return fval
                    except (ValueError, TypeError):
                        pass
        return None

    def _detect_mode(self) -> bool:
        """Detect whether to use hardware counters or power×time fallback.
        
        Returns True for hardware counters, False for power×time.
        """
        # Check if ldata_service detected hw counters for this panel
        if hasattr(self.coordinator, '_service') and self.coordinator._service:
            return self.coordinator._service.panel_has_hw_counters(self.panel_id)
        # Fallback: check if consumption data exists on this breaker
        if not self.panel_total:
            consumption = self._get_breaker_consumption(self.breaker_data["id"])
            return consumption is not None and consumption > 0
        return False

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        if not self.coordinator.data:
            return

        try:
            # Auto-detect mode on first update
            if self._use_hw_counters is None:
                self._use_hw_counters = self._detect_mode()
                if self._use_hw_counters:
                    _LOGGER.debug("Daily sensor %s: using hardware energy counters", self.entity_id)
                else:
                    _LOGGER.debug("Daily sensor %s: using power×time fallback", self.entity_id)

            # Auto-detect energy key on first update (solar vs normal breaker)
            if self._energy_key is None and not self.panel_total:
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
            if self.coordinator.config_entry.options.get("log_warnings", True):
                _LOGGER.exception("Error updating daily usage sensor for %s", self.entity_id)
        self.async_write_ha_state()

    # ── Hardware counter mode ────────────────────────────────────────────

    def _update_single_breaker_hw(self, today: datetime.date, is_new_day: bool):
        """Update daily energy for a single breaker using hardware counter.
        
        Uses energyImport for solar breakers, energyConsumption for normal
        breakers (auto-detected via _energy_key).
        """
        consumption = self._get_breaker_consumption(self.breaker_data["id"])
        if consumption is None:
            self._consecutive_none += 1
            if self._consecutive_none >= HW_COUNTER_NONE_TOLERANCE:
                self._use_hw_counters = False
                self._consecutive_none = 0
                _LOGGER.warning(
                    "Hardware counter unavailable for %s after %d consecutive reads "
                    "— switching to power×time fallback",
                    self.entity_id, HW_COUNTER_NONE_TOLERANCE
                )
            else:
                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                    _LOGGER.debug(
                        "Transient None for %s (count=%d/%d) — skipping update",
                        self.entity_id, self._consecutive_none, HW_COUNTER_NONE_TOLERANCE
                    )
            return

        self._consecutive_none = 0

        if is_new_day:
            if self._midnight_baseline is not None and self._midnight_baseline > 10.0 and consumption < 1.0:
                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                    _LOGGER.warning(
                        "New-day reset for %s: consumption=%.3f is suspiciously low "
                        "(previous baseline=%.3f) — carrying forward old baseline",
                        self.entity_id, consumption, self._midnight_baseline
                    )
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
            if consumption < 1.0 and self._midnight_baseline > 10.0:
                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                    _LOGGER.debug(
                        "Ignoring suspicious consumption=%.3f for %s (baseline=%.3f) — likely transient",
                        consumption, self.entity_id, self._midnight_baseline
                    )
                return

            if self.coordinator.config_entry.options.get("log_data_warnings", True):
                _LOGGER.warning(
                    "Consumption counter reset for %s: was %.3f, now %.3f — re-baselining",
                    self.entity_id, self._midnight_baseline, consumption
                )
            self._midnight_baseline = consumption
            daily = 0.0

        if daily > MAX_DAILY_ENERGY_KWH:
            if self.coordinator.config_entry.options.get("log_data_warnings", True):
                _LOGGER.warning(
                    "Daily energy %.1f kWh for %s exceeds sanity cap (%.0f kWh) "
                    "— likely corrupted baseline (%.3f). Re-baselining.",
                    daily, self.entity_id, MAX_DAILY_ENERGY_KWH, self._midnight_baseline
                )
            self._midnight_baseline = consumption
            daily = 0.0

        self._state = daily

    def _update_panel_total_hw(self, today: datetime.date, is_new_day: bool):
        """Update daily energy for the panel total by summing all breaker deltas.
        
        Uses energyImport for solar breakers, energyConsumption for normal.
        """
        breakers = self.coordinator.data.get("breakers", {})
        if not breakers:
            return

        if is_new_day:
            new_baselines = {}
            for b_id, b_data in breakers.items():
                if b_data.get("panel_id") == self.panel_id:
                    # Pick the right energy key per breaker
                    imp = float(b_data.get("import", 0) or 0)
                    cons = float(b_data.get("consumption", 0) or 0)
                    key = "import" if (imp > cons and imp > 1.0) else "consumption"
                    val = b_data.get(key)
                    if val is not None:
                        try:
                            fval = float(val)
                            old_baseline = self._panel_baselines.get(b_id)
                            if old_baseline is not None and old_baseline > 10.0 and fval < 1.0:
                                _LOGGER.debug(
                                    "Panel total new-day: keeping old baseline for breaker %s "
                                    "(value=%.3f, old_baseline=%.3f)",
                                    b_id, fval, old_baseline
                                )
                                new_baselines[b_id] = old_baseline
                            else:
                                new_baselines[b_id] = fval
                        except (ValueError, TypeError):
                            pass
            self._panel_baselines = new_baselines
            self._state = 0.0
            return

        # Build baselines for new breakers
        for b_id, b_data in breakers.items():
            if b_data.get("panel_id") == self.panel_id and b_id not in self._panel_baselines:
                imp = float(b_data.get("import", 0) or 0)
                cons = float(b_data.get("consumption", 0) or 0)
                key = "import" if (imp > cons and imp > 1.0) else "consumption"
                val = b_data.get(key)
                if val is not None:
                    try:
                        self._panel_baselines[b_id] = float(val)
                    except (ValueError, TypeError):
                        pass

        # Sum deltas
        total_daily = 0.0
        for b_id, baseline in self._panel_baselines.items():
            if b_id in breakers:
                b_data = breakers[b_id]
                imp = float(b_data.get("import", 0) or 0)
                cons = float(b_data.get("consumption", 0) or 0)
                key = "import" if (imp > cons and imp > 1.0) else "consumption"
                val = b_data.get(key)
                if val is not None:
                    try:
                        fval = float(val)
                        if fval == 0.0 and baseline > 1.0:
                            continue
                        delta = fval - baseline
                        if delta > 0:
                            if delta > MAX_DAILY_ENERGY_KWH:
                                if self.coordinator.config_entry.options.get("log_data_warnings", True):
                                    _LOGGER.warning(
                                        "Panel total: breaker %s delta %.1f kWh exceeds cap — "
                                        "re-baselining (baseline=%.3f, value=%.3f)",
                                        b_id, delta, baseline, fval
                                    )
                                self._panel_baselines[b_id] = fval
                                continue
                            total_daily += delta
                    except (ValueError, TypeError):
                        pass

        self._state = total_daily

    # ── Power×time fallback mode ─────────────────────────────────────────

    def _update_single_breaker_pxt(self, today: datetime.date, is_new_day: bool):
        """Update daily energy for a single breaker using power×time integration."""
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
            # First run — establish baseline
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
            # Gap detected
            if gap_mode == GAP_HANDLING_SKIP:
                # Don't accumulate energy during the gap
                if options.get("log_data_warnings", True):
                    _LOGGER.debug(
                        "Gap detected for %s: %.1fs (threshold %.1fs) — skipping",
                        self.entity_id, time_span, gap_threshold_secs
                    )
            elif gap_mode == GAP_HANDLING_EXTRAPOLATE:
                # Assume last known power continued through the gap
                last_p = self._last_power or 0
                energy_kwh = (last_p * time_span) / 3_600_000
                self._state += energy_kwh
            elif gap_mode == GAP_HANDLING_AVERAGE:
                # Average of last known and recovery power
                last_p = self._last_power or 0
                avg_power = (last_p + current_power) / 2
                energy_kwh = (avg_power * time_span) / 3_600_000
                self._state += energy_kwh
        else:
            # Normal integration: power × time
            avg_power = ((self._last_power or 0) + current_power) / 2
            energy_kwh = (avg_power * time_span) / 3_600_000
            self._state += energy_kwh

        self._last_update_time = now
        self._last_power = current_power

    def _update_panel_total_pxt(self, today: datetime.date, is_new_day: bool):
        """Update daily energy for panel total using totalPower × time integration."""
        try:
            current_power = abs(float(
                self.coordinator.data.get(self.panel_id + "totalPower", 0)
            ))
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
                pass  # Don't accumulate
            elif gap_mode == GAP_HANDLING_EXTRAPOLATE:
                last_p = self._last_power or 0
                energy_kwh = (last_p * time_span) / 3_600_000
                self._state += energy_kwh
            elif gap_mode == GAP_HANDLING_AVERAGE:
                last_p = self._last_power or 0
                avg_power = (last_p + current_power) / 2
                energy_kwh = (avg_power * time_span) / 3_600_000
                self._state += energy_kwh
        else:
            avg_power = ((self._last_power or 0) + current_power) / 2
            energy_kwh = (avg_power * time_span) / 3_600_000
            self._state += energy_kwh

        self._last_update_time = now
        self._last_power = current_power


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
        if self.last_update_date.date() != current_date.date():
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
        if not self.coordinator.data or "breakers" not in self.coordinator.data:
            return 0.0

        # Fast path: totalPower is pre-calculated and maintained by all update paths.
        # Use it for the common case (total power, both legs) to avoid iterating all breakers.
        if self.entity_description.key == "power" and self.leg_to_total == "both" and not self.is_average:
            key = self.entity_data["serialNumber"] + "totalPower"
            try:
                return float(self.coordinator.data.get(key, 0))
            except (ValueError, TypeError):
                return 0.0

        # General path: iterate breakers for per-leg totals, current totals, averages
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
                        val = breaker_data[
                            self.entity_description.key + self.leg_to_total
                        ]
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
            val = self.breaker_data[self.entity_description.key]
            self._state = float(val) if val is not None else None
        except (ValueError, TypeError):
            self._state = None
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


class LDATABreakerEnergyUsageSensor(LDATAEntity, SensorEntity, RestoreEntity):
    """Lifetime energy counter for a breaker (Import or Consumption).

    Exposes the hardware energyImport / energyConsumption counters as
    TOTAL_INCREASING sensors so HA's Energy dashboard can track per-breaker
    grid consumption and solar production without any user configuration.

    For solar breakers the Import counter tracks energy flowing back to the
    grid (production) while Consumption tracks energy drawn from the grid.
    """

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
        self.breaker_data = data
        self._state = None
        self._pending_state = None

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self.coordinator.last_update_success or self._state is not None

    async def async_added_to_hass(self) -> None:
        """Handle entity which is added to hass to restore state on startup."""
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    raw = new_data.get(self.entity_description.key)
                    if raw is None:
                        return  # Field missing — keep last state
                    new_value = float(raw)
                    ROUNDING_TOLERANCE = 0.05

                    # First update — accept unconditionally
                    if self._state is None:
                        self._state = new_value
                        self.async_write_ha_state()
                        return

                    # Decrease guard — TOTAL_INCREASING must never go backward
                    if (float(self._state) - new_value) > ROUNDING_TOLERANCE:
                        if self.coordinator.config_entry.options.get("log_data_warnings", True):
                            _LOGGER.warning(
                                "Ignoring decreasing value for %s: new=%s, old=%s",
                                self.entity_id, new_value, self._state
                            )
                        return

                    # Hold minor decreases within tolerance
                    if new_value < float(self._state):
                        new_value = float(self._state)

                    # Spike detection — same logic as CT version
                    is_potential_spike = False
                    if float(self._state) <= 1 and new_value > 100:
                        is_potential_spike = True
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
                    if self.coordinator.config_entry.options.get("log_warnings", True):
                        _LOGGER.debug("Breaker %s not found in update.", self.breaker_data["id"])
            else:
                if self.coordinator.config_entry.options.get("log_warnings", True):
                    _LOGGER.debug("No 'breakers' data found in coordinator update.")

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
        """Return the energy value."""
        if self._state is not None:
            return round(self._state, 2)
        return self._state


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
                    ROUNDING_TOLERANCE = 0.05

                    # Initialize state on the very first update if not already set by restore.
                    if self._state is None:
                        self._state = new_value
                        self.async_write_ha_state()
                        return

                    # --- Data Validation ---
                    # Check for a significant decrease, ignoring minor rounding/jitter.
                    if (float(self._state) - new_value) > ROUNDING_TOLERANCE:
                        if self.coordinator.config_entry.options.get("log_data_warnings", True):
                            _LOGGER.warning(
                                "Ignoring decreasing value for %s: new=%s, old=%s",
                                self.entity_id, new_value, self._state
                            )
                        return # Exit without updating.
                    
                    # For minor decreases within tolerance, hold the previous value
                    # to maintain TOTAL_INCREASING contract with HA.
                    if new_value < float(self._state):
                        new_value = float(self._state)

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