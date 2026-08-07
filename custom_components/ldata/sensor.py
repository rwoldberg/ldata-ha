"""Support for power sensors in LDATA devices."""

from __future__ import annotations

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
    STATE_UNAVAILABLE,
    STATE_UNKNOWN,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfFrequency,
    UnitOfPower,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.typing import StateType
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    LOGGER_NAME,
    DECORA_MODELS_GFCI,
    ENABLE_DECORA,
    ENABLE_DECORA_DEFAULT,
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
from .decora_entity import DecoraEntity, add_entities_grouped_by_decora_room
from .ldata_base_entity import add_entities_grouped_by_panel, find_panel
from .ldata_ct_entity import LDATACTEntity
from .ldata_entity import LDATAEntity

_LOGGER = logging.getLogger(LOGGER_NAME)

# Daily energy sensors round to 2 decimal places; a true hardware/rounding
# jitter dip is on the order of a hundredth of a kWh (e.g. 21.31 -> 21.30).
# Used by the TOTAL_INCREASING native_value clamp below to distinguish real
# jitter from a legitimate drop (midnight reset OR a mid-day correction from
# a monotonic-guard/re-baseline/spike-rejection flow) — a ratio-based check
# can't tell those apart since corrections aren't always near-zero.
_DAILY_JITTER_EPSILON_KWH = 0.05


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
    """Shared spike detection with pending-state confirmation.

    Returns (new_state, new_pending_state, accepted).
    If accepted is True, new_state holds the value to write.
    If False, the caller should skip the write.
    """
    is_potential_spike = False
    if state is None:
        # First update — no spike detection possible
        return new_value, None, True

    current = float(state)
    if current <= low_threshold and new_value > high_absolute:
        is_potential_spike = True
    elif current > low_threshold and new_value > (current * high_ratio):
        is_potential_spike = True

    if not is_potential_spike:
        return new_value, None, True

    # Spike detected — check pending confirmation
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
    """Check if data value warning logging is enabled."""
    return coordinator.config_entry.options.get("log_data_warnings", True)


def _log_warnings_enabled(coordinator) -> bool:
    """Check if general warning logging is enabled."""
    return coordinator.config_entry.options.get("log_warnings", True)


# ── Spike-detection threshold ─────────────────────────────────────────────────
# Used by LDATACTOutputSensor to catch genuine firmware glitches.
# Any reading above this is implausible on a residential service:
# 200 A × 240 V = 48 kW theoretical maximum; 25 kW leaves ample headroom
# for simultaneous EV charging, HVAC, and cooking while still flagging
# absurd values.  The previous zero-to-high (> 3 kW) and ratio-based (10×)
# checks produced false positives on the grid CT, which legitimately swings
# from near-zero (solar covering load) to 6+ kW the moment a large appliance
# starts — instantaneous power can jump by any amount in one tick.
_CT_POWER_MAX_W = 25_000

# Hard ceiling — no residential/light-commercial CT clamp reading should ever
# get close to this. Unlike _CT_POWER_MAX_W (which only holds a reading
# pending until a second, similarly-sized reading "confirms" it), values past
# this are discarded outright with no confirmation path at all. This closes
# a real gap: if the cloud ever emits the same badly-corrupted value twice in
# a row (observed in practice — a repeatable-looking glitch, not one-off
# noise), the ordinary pending/confirm dance would otherwise accept it.
_CT_POWER_HARD_MAX_W = 50_000


def _calc_pxt_energy(
    time_span: float,
    last_power: float | None,
    current_power: float,
    current_state: float,
    options: dict,
    entity_id: str,
    log_enabled: bool,
) -> float:
    """Apply gap-handling policy and return new cumulative energy (kWh).

    Args:
        time_span:     Seconds since last update.
        last_power:    Last recorded power reading in Watts (None = unknown).
        current_power: Current power reading in Watts.
        current_state: Current accumulated energy in kWh.
        options:       Config-entry options dict (for gap threshold/mode).
        entity_id:     Entity ID string (for log messages).
        log_enabled:   Whether data-warning debug logs are enabled.
    """
    gap_threshold_secs = options.get(GAP_THRESHOLD, GAP_THRESHOLD_DEFAULT) * 60
    gap_mode = options.get(GAP_HANDLING, GAP_HANDLING_DEFAULT)

    if time_span > gap_threshold_secs:
        if gap_mode == GAP_HANDLING_SKIP:
            if log_enabled:
                _LOGGER.debug(
                    "Gap detected for %s: %.1fs (threshold %.1fs) — skipping",
                    entity_id, time_span, gap_threshold_secs,
                )
            return current_state  # no change
        elif gap_mode == GAP_HANDLING_EXTRAPOLATE:
            energy_kwh = ((last_power or 0) * time_span) / 3_600_000.0
        elif gap_mode == GAP_HANDLING_AVERAGE:
            avg_power = ((last_power or 0) + current_power) / 2.0
            energy_kwh = (avg_power * time_span) / 3_600_000.0
        else:
            energy_kwh = 0.0
    else:
        avg_power = ((last_power or 0) + current_power) / 2.0
        energy_kwh = (avg_power * time_span) / 3_600_000.0

    # Sanity-cap a single update's energy delta. Daily sensors already clamp
    # their cumulative total via MAX_DAILY_ENERGY_KWH downstream, but lifetime
    # (TOTAL_INCREASING) accumulators have no other cap — an unbounded gap
    # (e.g. from a host clock jumping forward after an NTP resync) would
    # otherwise inject an implausible one-shot spike that permanently
    # inflates the Energy dashboard total with no recovery path.
    energy_kwh = max(0.0, min(energy_kwh, MAX_DAILY_ENERGY_KWH))

    return current_state + energy_kwh


@dataclass(frozen=True, kw_only=True)
class SensorDescription(SensorEntityDescription):
    """SensorEntityDescription for LDATA entities."""

    unique_id_suffix: str | None = None
    name: str | None = None


# Indices into SENSOR_TYPES below — named so call sites read as
# SENSOR_TYPES[POWER] instead of an unexplained SENSOR_TYPES[POWER].
POWER, VOLTAGE, CURRENT, FREQUENCY, IMPORT, CONSUMPTION = range(6)

SENSOR_TYPES = (
    SensorDescription(  # POWER
        device_class=SensorDeviceClass.POWER,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfPower.WATT,
        name="Watts",
        key="power",
        unique_id_suffix="_watts",
    ),
    SensorDescription(  # VOLTAGE
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        name="Volts",
        key="voltage",
        unique_id_suffix="_volts",
    ),
    SensorDescription(  # CURRENT
        device_class=SensorDeviceClass.CURRENT,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        name="Amps",
        key="current",
        unique_id_suffix="_amps",
    ),
    SensorDescription(  # FREQUENCY
        device_class=SensorDeviceClass.FREQUENCY,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfFrequency.HERTZ,
        name="Frequency",
        key="frequency",
        unique_id_suffix="_hz",
    ),
    SensorDescription(  # IMPORT
        device_class=SensorDeviceClass.ENERGY,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        name="Import",
        key="import",
        unique_id_suffix="_Import_kWh",
    ),
    SensorDescription(  # CONSUMPTION
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
            LDATAEnergyUsageSensor(coordinator, ct_data, SENSOR_TYPES[IMPORT])
        )
        entities_to_add.append(
            LDATAEnergyUsageSensor(coordinator, ct_data, SENSOR_TYPES[CONSUMPTION])
        )
        entities_to_add.append(
            LDATACTOutputSensor(coordinator, ct_data, SENSOR_TYPES[CURRENT])
        )
        entities_to_add.append(
            LDATACTOutputSensor(coordinator, ct_data, SENSOR_TYPES[POWER])
        )
        entities_to_add.append(
            LDATACTDailyUsageSensor(coordinator, ct_data)
        )
        entities_to_add.append(
            LDATACTDailyUsageSensor(coordinator, ct_data, energy_key="import")
        )

    ent_reg = er.async_get(hass)

    def _breaker_has_hw_counters(b_data) -> bool:
        """Return True if the breaker's panel uses hw energy counters (v1 firmware).

        On v2+ firmware, energyImport is a PERIOD counter that is non-zero for
        every breaker — including pure loads.  The _imp > 0 gate is only
        meaningful on v1 panels where energyImport is a monotonic lifetime
        counter that proves the breaker has exported energy to the grid.
        """
        panel_id = b_data.get("panel_id")
        if panel_id and hasattr(coordinator, '_service') and coordinator._service:
            return coordinator._service.panel_has_hw_counters(panel_id)
        return True  # unknown firmware — assume v1 to be conservative

    def _remove_registry_entry(uid: str) -> None:
        """Remove an entity from the registry by unique_id if it exists."""
        eid = ent_reg.async_get_entity_id("sensor", DOMAIN, uid)
        if eid:
            ent_reg.async_remove(eid)
            _LOGGER.info("Removed spurious import sensor from registry: %s", eid)

    for breaker_id, breaker_data in coordinator.data.get("breakers", {}).items():
        # NOTE: the daily consumption sensor is added AFTER solar classification
        # so we can pass is_solar_breaker correctly (see below).

        # Cache once — called in 3 places below (v1/v2 firmware detection).
        _has_hw_counters = _breaker_has_hw_counters(breaker_data)

        _imp  = float(breaker_data.get("import", 0) or 0)
        _cons = float(breaker_data.get("consumption", 0) or 0)
        _daily_import_uid    = f"{coordinator.user}-ldata_{breaker_id}_todaymw_import"
        _lifetime_import_uid = f"{coordinator.user}-ldata_{breaker_id}__Import_kWh"
        _has_daily_import    = ent_reg.async_get_entity_id("sensor", DOMAIN, _daily_import_uid)    is not None
        _has_lifetime_import = ent_reg.async_get_entity_id("sensor", DOMAIN, _lifetime_import_uid) is not None

        # ── Import-sensor creation gates ──────────────────────────────────────
        #
        # v1 panels: energyImport is a monotonic lifetime counter.
        #   Non-zero at startup proves this breaker has exported energy (solar/
        #   generator).  Use it as the primary creation gate.
        #
        # v2 panels: energyImport is a PERIOD counter.
        #   It resets every bandwidth toggle (~5 min) and is non-zero for ANY
        #   breaker — including pure loads like an oven.  The _imp > 0 check is
        #   meaningless here; instead use the ratio of import to consumption:
        #
        #     • Solar breaker  → period import >> period consumption
        #       (the breaker exports; its consumption ≈ 0 or very small)
        #     • Load breaker   → period import ≈ period consumption
        #       (the firmware mirrors consumption into import as an artifact)
        #
        # Registry fallback (both v1 and v2): if a sensor already exists in
        #   the entity registry from a prior legitimate run, keep recreating it
        #   even when the current period counter returns null or 0.
        #
        # Spurious v2 registry cleanup: when import ≈ consumption AND both are
        #   non-trivially non-zero, the registry entry is a load-breaker
        #   artifact.  Actively remove it so HA orphans the entity and the user
        #   can delete it — or it simply disappears on the next restart.
        # ─────────────────────────────────────────────────────────────────────

        # v1: non-zero lifetime counter = confirmed solar/generator
        _imp_valid = _imp > 0 and _has_hw_counters

        # v2: detect solar/generator breakers.
        #
        # PRIMARY — branchType field (API 1.57.1+):
        #   Set by the user in the Leviton app; 'Solar' is authoritative.
        #   Works at any time of day regardless of current period-counter values.
        _branch_type = breaker_data.get("branch_type", "")
        _branch_is_solar = _branch_type == "Solar"
        #
        # FALLBACK — period-counter ratio heuristic (older firmware / missing field):
        #   Solar:  energyImport >> energyConsumption (exporting to bus).
        #   Load:   energyImport ≈ energyConsumption (firmware mirrors cons→imp).
        #   Require _imp > 0.05 to filter noise when the device is off (_cons = 0
        #   makes the ratio check trivially True for any tiny artifact value).
        _v2_ratio_signal = (
            not _has_hw_counters
            and not _branch_type           # only use when branchType is absent
            and _imp > 0.05               # non-trivial export (not just noise)
            and _imp > _cons * 3          # import far exceeds consumption
        )
        _v2_solar_signal = _branch_is_solar or _v2_ratio_signal

        # ── Persisted load suppression ─────────────────────────────────────────
        # suppressed_import_uids: breakers confirmed as load artifacts.
        # Suppression is permanent — survives restarts even when appliance is off
        # (and thus _cons ≈ 0, making runtime ratio detection unreliable).
        _suppressed_uids: set = set(
            config_entry.options.get("suppressed_import_uids", [])
        )
        _already_suppressed = (
            _daily_import_uid in _suppressed_uids
            or _lifetime_import_uid in _suppressed_uids
        )

        # ── Persisted solar confirmation ───────────────────────────────────────
        # confirmed_solar_import_uids: breakers positively identified as solar/
        # generator exporters.  On v2 panels this replaces the raw registry
        # fallback (_has_daily_import / _has_lifetime_import) so that a
        # historical registry entry for a load breaker (oven, dryer, …) does
        # NOT cause its import entity to be recreated.
        _confirmed_solar_uids: set = set(
            config_entry.options.get("confirmed_solar_import_uids", [])
        )
        _is_confirmed_solar = (
            _daily_import_uid in _confirmed_solar_uids
            or _lifetime_import_uid in _confirmed_solar_uids
        )

        # Persist solar classification the first time we detect it.
        if _v2_solar_signal and not _is_confirmed_solar:
            _confirmed_solar_uids.add(_daily_import_uid)
            _confirmed_solar_uids.add(_lifetime_import_uid)
            hass.config_entries.async_update_entry(
                config_entry,
                options={**config_entry.options,
                         "confirmed_solar_import_uids": list(_confirmed_solar_uids)},
            )
            _is_confirmed_solar = True
            _LOGGER.info(
                "Breaker '%s': confirmed solar/generator exporter — "
                "import sensors will persist across restarts",
                breaker_data.get("name", breaker_id),
            )

        # v2: import ≈ consumption = load-breaker firmware artifact.
        # Never fires for breakers explicitly classified as solar by branchType —
        # a solar breaker with small counter values (e.g. early morning) must not
        # be misidentified as a load and have its import entities suppressed.
        _v2_load_artifact = (not _branch_is_solar) and (
            _already_suppressed or (
                not _has_hw_counters
                and _imp > 0
                and _cons > 0.01          # both counters are non-trivially non-zero
                and _imp <= _cons * 3     # import is not significantly above consumption
            )
        )

        if _v2_load_artifact:
            # Remove any spurious registry entries so these entities become
            # orphaned (enabling deletion) and are not recreated.
            _remove_registry_entry(_daily_import_uid)
            _remove_registry_entry(_lifetime_import_uid)
            _has_daily_import    = False
            _has_lifetime_import = False
            _is_confirmed_solar  = False
            # Persist the suppression so it survives restarts even when the
            # appliance is off (and thus _cons ≈ 0 next time).
            options_patch: dict = {}
            if not _already_suppressed:
                _suppressed_uids.add(_daily_import_uid)
                _suppressed_uids.add(_lifetime_import_uid)
                options_patch["suppressed_import_uids"] = list(_suppressed_uids)
            # Also evict from confirmed_solar if somehow present (defensive).
            if _daily_import_uid in _confirmed_solar_uids or _lifetime_import_uid in _confirmed_solar_uids:
                _confirmed_solar_uids.discard(_daily_import_uid)
                _confirmed_solar_uids.discard(_lifetime_import_uid)
                options_patch["confirmed_solar_import_uids"] = list(_confirmed_solar_uids)
            if options_patch:
                hass.config_entries.async_update_entry(
                    config_entry,
                    options={**config_entry.options, **options_patch},
                )
            _LOGGER.info(
                "Breaker '%s': v2 load artifact detected "
                "(import=%.3f kWh ≈ consumption=%.3f kWh) — "
                "suppressing import sensors permanently",
                breaker_data.get("name", breaker_id), _imp, _cons,
            )

        # For v2 panels, the registry fallback is replaced by the explicit
        # confirmed-solar list.  A historical registry entry alone (from a
        # load breaker that was spuriously created in a prior run) is no
        # longer sufficient to recreate import entities.
        # For v1 panels, the registry fallback is kept as-is (safe, since
        # v1 only created import entities for genuine exporters).
        _import_fallback = (
            (_has_daily_import or _has_lifetime_import)
            if _has_hw_counters
            else _is_confirmed_solar
        )

        # ── Breaker Daily Consumption sensor ──────────────────────────────────
        # For solar breakers: tracks inverter standby draw (max(-power, 0)) so
        # the sensor accumulates near-zero during the day and a few watts at
        # night — NOT solar generation.  is_solar_breaker bypasses the fragile
        # period-counter detection (_detect_energy_key) used for v1 panels.
        _is_solar = _v2_solar_signal or _is_confirmed_solar or _imp_valid
        entities_to_add.append(
            LDATADailyUsageSensor(coordinator, breaker_data, False, "",
                                  is_solar_breaker=_is_solar)
        )

        # Breaker Daily Import sensor
        if _imp_valid or _v2_solar_signal or _import_fallback:
            entities_to_add.append(
                LDATADailyUsageSensor(coordinator, breaker_data, False, "",
                                      breaker_energy_key="import")
            )
        entities_to_add.append(
            LDATAOutputSensor(coordinator, breaker_data, SENSOR_TYPES[POWER])
        )
        entities_to_add.append(
            LDATAOutputSensor(coordinator, breaker_data, SENSOR_TYPES[CURRENT])
        )
        # Breaker Lifetime Import sensor
        if _imp_valid or _v2_solar_signal or _import_fallback:
            entities_to_add.append(
                LDATABreakerEnergyUsageSensor(coordinator, breaker_data, SENSOR_TYPES[IMPORT])
            )
        entities_to_add.append(
            LDATABreakerEnergyUsageSensor(coordinator, breaker_data, SENSOR_TYPES[CONSUMPTION])
        )
        # Diagnostic sensors
        entities_to_add.append(
            LDATABreakerOperationalStateSensor(coordinator, breaker_data)
        )
        entities_to_add.append(
            LDATABreakerBleRSSISensor(coordinator, breaker_data)
        )
        entities_to_add.append(
            LDATABreakerPositionSensor(coordinator, breaker_data)
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
            LDATADailyUsageSensor(
                coordinator, entity_data, True, which_panel=panel["id"],
                panel_energy_key="import"
            )
        )
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data, SENSOR_TYPES[POWER], which_leg="both"
            )
        )
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data, SENSOR_TYPES[CURRENT], which_leg="both"
            )
        )
        entities_to_add.append(
            LDATAPanelOutputSensor(
                coordinator, entity_data, SENSOR_TYPES[FREQUENCY], which_leg="1"
            )
        )
        entities_to_add.append(
            LDATAPanelOutputSensor(
                coordinator, entity_data, SENSOR_TYPES[FREQUENCY], which_leg="2"
            )
        )
        entities_to_add.append(
            LDATAPanelOutputSensor(
                coordinator, entity_data, SENSOR_TYPES[VOLTAGE], which_leg="1"
            )
        )
        entities_to_add.append(
            LDATAPanelOutputSensor(
                coordinator, entity_data, SENSOR_TYPES[VOLTAGE], which_leg="2"
            )
        )
        
        # Panel diagnostic sensors
        entities_to_add.append(
            LDATAPanelWifiRSSISensor(coordinator, entity_data)
        )
        
        entity_data_leg1 = {**entity_data, "poles": 1, "position": 1}
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data_leg1, SENSOR_TYPES[POWER], which_leg="1"
            )
        )
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data_leg1, SENSOR_TYPES[CURRENT], which_leg="1"
            )
        )
        
        entity_data_leg2 = {**entity_data, "poles": 1, "position": 3}
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data_leg2, SENSOR_TYPES[POWER], which_leg="2"
            )
        )
        entities_to_add.append(
            LDATATotalUsageSensor(
                coordinator, entity_data_leg2, SENSOR_TYPES[CURRENT], which_leg="2"
            )
        )

    add_entities_grouped_by_panel(config_entry, async_add_entities, entities_to_add)

    # ── Decora Smart Wi-Fi device sensors ──
    enable_decora = config_entry.options.get(
        ENABLE_DECORA,
        config_entry.data.get(ENABLE_DECORA, ENABLE_DECORA_DEFAULT),
    )
    if enable_decora:
        decora_entities = []
        for dev_id, dev_data in coordinator.data.get("decora_devices", {}).items():
            decora_entities.append(DecoraSignalSensor(coordinator, dev_data))
            # GFCI fault status enum sensor
            if dev_data.get("model") in DECORA_MODELS_GFCI:
                decora_entities.append(DecoraGFCIStatusSensor(coordinator, dev_data))

        add_entities_grouped_by_decora_room(config_entry, async_add_entities, decora_entities)


class _DailyEnergySensorMixin:
    """Shared TOTAL_INCREASING config, jitter-clamp, and monotonic-guard logic.

    Used by both LDATADailyUsageSensor (breaker/panel-total) and
    LDATACTDailyUsageSensor (CT). Their hw-counter/power×time update state
    machines differ enough (different data sources, different re-baseline
    rules) that they stay separate — only the display-layer clamp and the
    backwards-jump guard are truly identical between them.
    """

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR

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
                # Only hold back genuinely tiny dips (hardware/rounding jitter,
                # e.g. 21.31 -> 21.30). Any larger drop is a real change —
                # either a midnight reset or a legitimate mid-day correction —
                # and must be reported, not frozen at a stale high value.
                if (self._last_reported - val) <= _DAILY_JITTER_EPSILON_KWH:
                    return self._last_reported  # Jitter — hold previous value
            self._last_reported = val
            return val
        return 0.0

    def _apply_monotonic_guard(
        self, daily: float, *, label: str = "consumption", extra_log_context: str = ""
    ) -> float | None:
        """Reject a daily-energy update that would look like a backwards jump.

        Daily energy can only increase within the same day. Returns the
        accepted `daily` value, or None if this update should be skipped this
        cycle (a stale/bad reading is suspected). Auto-releases after 5
        minutes of sustained rejection, in case the drop turns out to be a
        real correction rather than transient bad data.
        """
        if not (
            self._state is not None
            and self._state > 0.5
            and daily < self._state - 0.05
        ):
            if self._monotonic_reject_since is not None:
                self._monotonic_reject_since = None
            return daily

        now = time.time()
        if self._monotonic_reject_since is None:
            self._monotonic_reject_since = now
        elapsed = now - self._monotonic_reject_since
        if elapsed < 300:
            if _log_data_warnings_enabled(self.coordinator):
                _LOGGER.debug(
                    "Rejecting stale %s for %s: daily would decrease %.2f -> %.2f%s",
                    label, self.entity_id, self._state, daily, extra_log_context
                )
            return None

        if _log_data_warnings_enabled(self.coordinator):
            _LOGGER.warning(
                "Releasing monotonic guard for %s after %.0fs: %.2f -> %.2f",
                self.entity_id, elapsed, self._state, daily
            )
        self._monotonic_reject_since = None
        return daily


class LDATADailyUsageSensor(_DailyEnergySensorMixin, LDATAEntity, SensorEntity, RestoreEntity):
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

    def __init__(
        self, coordinator: LDATAUpdateCoordinator, data, panelTotal, which_panel: str,
        panel_energy_key: str = "consumption",
        breaker_energy_key: str = "",
        is_solar_breaker: bool = False,
    ) -> None:
        """Init sensor."""
        self.panel_total = panelTotal
        self._panel_energy_key: str = panel_energy_key
        # Must be set before super().__init__() — ldata_entity calls name_suffix
        # during construction to build the entity name.
        self._is_forced_import: bool = False
        self._energy_key: str | None = None
        if not panelTotal and breaker_energy_key:
            self._energy_key = breaker_energy_key
            self._is_forced_import = (breaker_energy_key == "import")
        # True when this consumption sensor belongs to a solar/generator breaker.
        # Used in PXT mode to track inverter standby draw (max(-power, 0)) instead
        # of abs(power), bypassing the unreliable period-counter detection.
        self._is_solar_breaker: bool = is_solar_breaker
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state: float | None = None
        self._last_reported: float | None = None  # Monotonic clamp for TOTAL_INCREASING
        self.panel_id = which_panel
        # --- Hardware counter mode ---
        self._midnight_baseline: float | None = None
        self._last_date: datetime.date | None = None
        # --- Power×time fallback mode ---
        self._last_update_time: float | None = None  # time.time() of last update
        self._last_power: float | None = None  # Last known power in watts
        # Track which mode this sensor is using (set on first update)
        self._use_hw_counters: bool | None = None
        # Consecutive None readings from _get_breaker_consumption — used to
        # distinguish transient reconnect glitches from genuine hw counter loss.
        self._consecutive_none: int = 0
        # Manual override: set via ldata.reset_energy_baseline service
        self._accept_next_value: bool = False
        self._consecutive_decrease: int = 0
        # Monotonic-guard timeout: set when a backwards-jump is first detected
        self._monotonic_reject_since: float | None = None

    async def async_added_to_hass(self) -> None:
        """Handle entity which is added to hass to restore state on startup."""
        # Restore saved state BEFORE calling super(). CoordinatorEntity registers
        # _handle_coordinator_update as a listener and fires it immediately when
        # coordinator already has data. Without pre-restoring here, _state_update
        # runs with _midnight_baseline=None, overwrites it with the current counter
        # value, and the daily total resets to 0.
        if last_state := await self.async_get_last_state():
            if last_state.state in (STATE_UNAVAILABLE, STATE_UNKNOWN):
                _LOGGER.warning(
                    "Restore for %s: last recorded state was '%s' — daily total "
                    "could not be restored across this restart and will "
                    "re-baseline from the next reading.",
                    self.entity_id, last_state.state
                )
            else:
                try:
                    restored = float(last_state.state)
                    # Clamp implausible restored values (e.g. a corrupted recorder
                    # entry) to the same sanity range live updates are held to.
                    self._state = max(0.0, min(restored, MAX_DAILY_ENERGY_KWH))
                except (ValueError, TypeError):
                    pass

            attrs = last_state.attributes or {}
            try:
                self._midnight_baseline = float(attrs["midnight_baseline"])
            except (KeyError, ValueError, TypeError):
                self._midnight_baseline = None
            if date_str := attrs.get("last_date"):
                try:
                    self._last_date = datetime.date.fromisoformat(date_str)
                except (ValueError, TypeError):
                    self._last_date = None
            # _last_update_time is intentionally NOT restored across a restart
            # (matches LDATACTDailyUsageSensor) — restoring it would expose the
            # entire HA-downtime window to gap-handling policy on the very next
            # update, and in EXTRAPOLATE/AVERAGE mode could inject a large
            # one-shot energy delta for time HA was simply offline. The next
            # pxt update instead establishes a fresh baseline with no delta.
            # NOTE: _use_hw_counters is intentionally NOT restored.
            # Mode is re-detected on first update so that firmware changes
            # (e.g. v1 → v2) and code fixes take effect immediately after
            # an HA restart without stale cached mode overriding the detection.
            if "energy_key" in attrs:
                self._energy_key = attrs["energy_key"]

        await super().async_added_to_hass()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Route coordinator updates through our custom state-update logic."""
        self._state_update()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra attributes for state restoration."""
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
        """Suffix to append to the LDATA device's name."""
        if (self.panel_total and self._panel_energy_key == "import") or self._is_forced_import:
            return "Daily Import"
        return "Daily Consumption"

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        if (self.panel_total and self._panel_energy_key == "import") or self._is_forced_import:
            return "todaymw_import"
        return "todaymw"

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
                        # Reject near-zero values when baseline is well above zero.
                        # The bandwidth toggle (1→0→1) causes transient null/near-zero
                        # readings for both energyConsumption and energyImport — this
                        # guard covers both keys since _energy_key selects which field
                        # is read.  A genuine counter can't drop from >1 kWh to <1 kWh
                        # between poll cycles.
                        if fval < 1.0 and self._midnight_baseline and self._midnight_baseline > 1.0:
                            return None
                        return fval
                    except (ValueError, TypeError):
                        pass
        return None

    def _detect_mode(self) -> bool:
        """Detect whether to use hardware counters or power×time fallback.

        Returns True for hardware counters, False for power×time.

        On firmware 2.x panels _panel_has_hw_counters is always False because
        energyConsumption changed to a period counter (resets with bandwidth
        toggle) and energyImport cannot reliably represent daily load-breaker
        consumption.  All daily energy sensors on v2+ panels therefore use
        power×time integration regardless of the energy key.
        """
        # Defer to the service's per-panel hw-counter flag.
        # parse_panels() sets this False for all v2+ panels.
        if hasattr(self.coordinator, '_service') and self.coordinator._service:
            return self.coordinator._service.panel_has_hw_counters(self.panel_id)
        # Service unavailable — default to power×time (safe fallback).
        # The old fallback of consumption > 0 is removed: in v2 firmware
        # energyConsumption is a period counter that is non-zero between polls,
        # which would incorrectly trigger hw-counter mode.
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
            if _log_warnings_enabled(self.coordinator):
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
                if _log_data_warnings_enabled(self.coordinator):
                    _LOGGER.debug(
                        "Transient None for %s (count=%d/%d) — skipping update",
                        self.entity_id, self._consecutive_none, HW_COUNTER_NONE_TOLERANCE
                    )
            return

        self._consecutive_none = 0

        if is_new_day:
            if consumption < 1.0:
                # energyConsumption is null/0 at midnight — bandwidth toggle hasn't
                # run yet.  Defer baseline to the first real REST poll value so we
                # don't set baseline=0 and lose the morning's energy to a
                # MAX_DAILY_ENERGY_KWH re-baseline when the real value arrives.
                self._midnight_baseline = None
                self._state = 0.0
                return

            self._midnight_baseline = consumption
            self._state = 0.0
            return

        if self._midnight_baseline is None:
            # Deferred from midnight (null CT values) or lost on restart.
            if self._state is not None:
                # _state already reflects today's accumulated total (e.g.
                # restored after an HA restart) — derive the baseline from
                # it instead of wiping the daily total back to 0.
                self._midnight_baseline = consumption - self._state
            else:
                # First real poll value becomes the baseline.
                self._midnight_baseline = consumption
                self._state = 0.0
            return

        daily = consumption - self._midnight_baseline
        if daily < 0:
            if _log_data_warnings_enabled(self.coordinator):
                _LOGGER.debug(
                    "Skipping negative daily for %s: consumption=%.3f "
                    "< baseline=%.3f — waiting for correction",
                    self.entity_id, consumption, self._midnight_baseline
                )
            return

        if daily > MAX_DAILY_ENERGY_KWH:
            if _log_data_warnings_enabled(self.coordinator):
                _LOGGER.warning(
                    "Daily energy %.1f kWh for %s exceeds sanity cap (%.0f kWh) "
                    "— likely corrupted baseline (%.3f). Re-baselining.",
                    daily, self.entity_id, MAX_DAILY_ENERGY_KWH, self._midnight_baseline
                )
            self._midnight_baseline = consumption
            daily = 0.0

        daily = self._apply_monotonic_guard(
            daily,
            extra_log_context=f" (consumption={consumption:.3f}, baseline={self._midnight_baseline:.3f})"
        )
        if daily is None:
            return

        self._state = daily

    def _update_panel_total_hw(self, today: datetime.date, is_new_day: bool):
        """Update daily energy for the panel total by summing all lifetime counters.
        
        This relies natively on the monotonic guard to protect against partial sums 
        (e.g., if a CT/breaker temporarily drops to 0.0, the sum drops, and the guard 
        holds the daily total steady).
        """
        key = self._panel_energy_key
        
        # 1. Check if we should use CTs instead of breakers
        cts = self.coordinator.data.get("cts", {})
        panel_cts = {b_id: b_data for b_id, b_data in cts.items() if b_data.get("panel_id") == self.panel_id}
        
        if panel_cts:
            data_to_sum = panel_cts
            source_name = "CT"
        else:
            breakers = self.coordinator.data.get("breakers", {})
            data_to_sum = {b_id: b_data for b_id, b_data in breakers.items() if b_data.get("panel_id") == self.panel_id}
            source_name = "breaker"

        if not data_to_sum:
            return

        # Sum the current lifetime counters of all underlying entities
        current_lifetime_sum = 0.0
        for b_id, b_data in data_to_sum.items():
            val = b_data.get(key)
            if val is not None:
                try:
                    fval = float(val)
                    current_lifetime_sum += fval
                except (ValueError, TypeError):
                    pass

        # ─── Standard Single-Baseline Logic ───
        if is_new_day:
            if current_lifetime_sum < 1.0:
                # CT/breaker energy counters return 0 at midnight — the bandwidth
                # toggle hasn't run yet so energyConsumption is still null/0.
                # Setting baseline=0 here would cause a massive spike (e.g. 14000+
                # kWh) when the first real CT poll arrives, tripping the
                # MAX_DAILY_ENERGY_KWH re-baseline and losing the entire morning.
                # Defer: leave baseline=None so it is set by the first real poll
                # value after midnight.  We lose at most one CT poll interval
                # (~5 min) of morning data, which is acceptable.
                self._midnight_baseline = None
                self._state = 0.0
                _LOGGER.debug(
                    "New-day baseline deferred for %s — CT/breaker sum is %.3f "
                    "(pre-toggle null). Baseline will be set on first real poll.",
                    self.entity_id, current_lifetime_sum,
                )
                return

            self._midnight_baseline = current_lifetime_sum
            self._state = 0.0
            return

        if self._midnight_baseline is None:
            # Baseline was deferred (CT null at midnight) or lost on restart.
            if self._state is not None:
                # _state already reflects today's accumulated total (e.g.
                # restored after an HA restart) — derive the baseline from
                # it instead of wiping the daily total back to 0.
                self._midnight_baseline = current_lifetime_sum - self._state
                _LOGGER.debug(
                    "Deferred midnight baseline set for %s at %.3f "
                    "(preserving restored state %.3f)",
                    self.entity_id, self._midnight_baseline, self._state,
                )
            else:
                self._midnight_baseline = current_lifetime_sum
                self._state = 0.0
                _LOGGER.debug(
                    "Deferred midnight baseline set for %s at %.3f",
                    self.entity_id, current_lifetime_sum,
                )
            return

        daily = current_lifetime_sum - self._midnight_baseline
        
        if daily < 0:
            if _log_data_warnings_enabled(self.coordinator):
                _LOGGER.debug(
                    "Skipping negative daily for %s: sum=%.3f "
                    "< baseline=%.3f — waiting for correction",
                    self.entity_id, current_lifetime_sum, self._midnight_baseline
                )
            return

        if daily > MAX_DAILY_ENERGY_KWH:
            # Most likely cause: midnight baseline was 0 (CT null before first
            # bandwidth toggle) and the deferred-baseline path above wasn't reached
            # yet.  Re-baseline to current so accumulation starts from now.
            _LOGGER.warning(
                "Panel total daily %.1f kWh for %s exceeds sanity cap (%.0f kWh) "
                "— midnight baseline (%.3f) was likely set before CT values were "
                "available. Re-baselining to %.3f; today's data starts from now.",
                daily, self.entity_id, MAX_DAILY_ENERGY_KWH,
                self._midnight_baseline, current_lifetime_sum,
            )
            self._midnight_baseline = current_lifetime_sum
            daily = 0.0

        # Panel daily total can only increase within the same day. This also
        # naturally protects against partial sums if a CT/breaker temporarily
        # drops to 0.0.
        daily = self._apply_monotonic_guard(daily, label="panel total")
        if daily is None:
            return

        self._state = daily

    def _update_single_breaker_pxt(self, today: datetime.date, is_new_day: bool):
        """Update daily energy for a single breaker using power×time integration.

        Power direction handling for bidirectional (solar/import) breakers:
          • _is_forced_import = True  → Daily Import sensor.
            The LDATA panel reports positive watts when the breaker feeds power
            INTO the panel bus (solar generation).  Clamp to max(power, 0) so
            that inverter standby draw (negative watts) does not corrupt the
            daily solar total.

          • _is_solar_breaker = True (or _energy_key == "import" on v1 auto-detect)
            → Daily Consumption sensor on a solar breaker.
            Tracks inverter standby draw: power pulled FROM the panel bus through
            the breaker (negative watts direction, typically near 0 W during the day).
            Clamped to max(-power, 0) so solar generation (positive watts) is never
            counted as consumption.
            _is_solar_breaker is set from branchType / confirmed_solar at setup time,
            bypassing the unreliable period-counter ratio used by _detect_energy_key.

          • Neither flag set → regular load breaker.
            Always consumes from the panel (positive watts).
            abs() handles the rare firmware transient that briefly sends a negative
            value for a load breaker.
        """
        new_data = self.coordinator.data.get("breakers", {}).get(self.breaker_data["id"])
        if not new_data:
            return

        try:
            raw_power = float(new_data.get("power", 0))
            if self._is_forced_import:
                # Daily Import sensor: solar generation flows into the panel bus
                # as positive watts.  Ignore the negative (consumption) direction.
                current_power = max(raw_power, 0.0)
            elif self._is_solar_breaker or self._energy_key == "import":
                # Daily Consumption sensor on a solar breaker.
                # Inverter standby draw flows FROM the panel (negative watts).
                # Clamp to max(-power, 0) — generation (positive) must not accumulate here.
                current_power = max(-raw_power, 0.0)
            else:
                # Regular load breaker — always positive; abs() covers transients.
                current_power = abs(raw_power)
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
            # First pxt run after startup or a hw→pxt mode switch.
            # Preserve any restored _state (hw-counter or prior pxt session) —
            # both represent today's accumulated energy and should NOT be wiped.
            # Only initialise to 0 if there is genuinely no prior state at all.
            if self._state is None:
                self._state = 0.0
            self._last_update_time = now
            self._last_power = current_power
            return

        time_span = now - self._last_update_time
        if time_span <= 0:
            return

        self._state = _calc_pxt_energy(
            time_span, self._last_power, current_power,
            self._state or 0.0,
            options, self.entity_id,
            _log_data_warnings_enabled(self.coordinator),
        )
        self._last_update_time = now
        self._last_power = current_power

    def _update_panel_total_pxt(self, today: datetime.date, is_new_day: bool):
        """Update daily energy for panel total using power×time integration.

        Sums each breaker's power contribution in the direction matching
        this sensor's _panel_energy_key, mirroring the per-breaker sign
        convention in _update_single_breaker_pxt: solar breakers
        (branch_type == "Solar") contribute positive power to Import and
        max(-power, 0) (inverter standby draw) to Consumption; regular
        breakers only ever contribute to Consumption. Using the panel's raw
        totalPower here (as an earlier version did) fed the exact same
        number into both the Import and Consumption sensors, since
        totalPower doesn't distinguish direction.
        """
        breakers = self.coordinator.data.get("breakers", {})
        is_import = self._panel_energy_key == "import"
        current_power = 0.0
        for b_data in breakers.values():
            if b_data.get("panel_id") != self.panel_id:
                continue
            try:
                raw_power = float(b_data.get("power") or 0.0)
            except (ValueError, TypeError):
                continue
            if b_data.get("branch_type") == "Solar":
                if is_import:
                    current_power += max(raw_power, 0.0)
                else:
                    current_power += max(-raw_power, 0.0)
            elif not is_import:
                current_power += abs(raw_power)
            # Regular (non-solar) breakers never contribute to Import.

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

        self._state = _calc_pxt_energy(
            time_span, self._last_power, current_power,
            self._state or 0.0,
            options, self.entity_id,
            _log_data_warnings_enabled(self.coordinator),
        )
        self._last_update_time = now
        self._last_power = current_power


class LDATACTDailyUsageSensor(_DailyEnergySensorMixin, LDATACTEntity, SensorEntity, RestoreEntity):
    """Sensor that tracks daily usage from a CT clamp's lifetime total."""

    def __init__(
        self, coordinator: LDATAUpdateCoordinator, data,
        energy_key: str = "consumption",
    ) -> None:
        """Init sensor."""
        self._energy_key: str = energy_key
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state: float | None = None
        self._last_reported: float | None = None  # Monotonic clamp for TOTAL_INCREASING
        # --- Midnight-baseline mode (matches breaker daily sensor) ---
        self._midnight_baseline: float | None = None
        self._last_date: datetime.date | None = None
        self._consecutive_none: int = 0
        # --- Dual mode: hw counters vs power×time fallback ---
        self._use_hw_counters: bool | None = None
        self._last_update_time: float | None = None
        self._last_power: float | None = None
        # Manual override: set via ldata.reset_energy_baseline service
        self._accept_next_value: bool = False
        self._consecutive_decrease: int = 0
        # Monotonic-guard timeout: set when a backwards-jump is first detected
        self._monotonic_reject_since: float | None = None

    async def async_added_to_hass(self) -> None:
        """Handle entity which is added to hass to restore state on startup."""
        # Restore saved state BEFORE calling super() for the same reason as
        # LDATADailyUsageSensor — the immediate coordinator listener callback
        # would overwrite _midnight_baseline with the current counter value.
        if last_state := await self.async_get_last_state():
            if last_state.state in (STATE_UNAVAILABLE, STATE_UNKNOWN):
                _LOGGER.warning(
                    "Restore for %s: last recorded state was '%s' — daily total "
                    "could not be restored across this restart and will "
                    "re-baseline from the next reading.",
                    self.entity_id, last_state.state
                )
            else:
                try:
                    restored = float(last_state.state)
                    self._state = max(0.0, min(restored, MAX_DAILY_ENERGY_KWH))
                except (ValueError, TypeError):
                    pass

            attrs = last_state.attributes or {}
            try:
                self._midnight_baseline = float(attrs["midnight_baseline"])
            except (KeyError, ValueError, TypeError):
                self._midnight_baseline = None
            if date_str := attrs.get("last_date"):
                try:
                    self._last_date = datetime.date.fromisoformat(date_str)
                except (ValueError, TypeError):
                    self._last_date = None
            # NOTE: _use_hw_counters is intentionally NOT restored.
            # Mode is re-detected on first update so that firmware changes
            # (e.g. v1 → v2) and code fixes take effect immediately after
            # an HA restart without stale cached mode overriding the detection.
            if "energy_key" in attrs and attrs["energy_key"]:
                self._energy_key = attrs["energy_key"]

        await super().async_added_to_hass()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Route coordinator updates through our custom state-update logic."""
        self._state_update()

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        if self._energy_key == "import":
            return "Daily Import"
        return "Daily Consumption"

    @property
    def unique_id_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's unique ID."""
        if self._energy_key == "import":
            return "daily_import"
        return "todaymw"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra attributes for state restoration."""
        attributes = super().extra_state_attributes
        attributes["midnight_baseline"] = self._midnight_baseline
        attributes["last_date"] = self._last_date.isoformat() if self._last_date else None
        attributes["energy_key"] = self._energy_key
        attributes["use_hw_counters"] = self._use_hw_counters
        if self._last_update_time is not None:
            attributes["last_update_time"] = self._last_update_time
        return attributes

    def _get_ct_consumption(self) -> float | None:
        """Get current lifetime energy counter for this CT, or None if unavailable.

        Returns None for zero values when a non-zero baseline exists -- the API
        sometimes returns 0.0 for stale/missing data rather than a real counter.
        """
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
        """Detect whether to use hardware counters or power×time fallback.

        Returns True for hardware counters, False for power×time.

        The authoritative source is the service's _panel_has_hw_counters flag,
        which parse_panels() sets False for all v2+ panels.

        The old fallback of checking consumption > 0 is intentionally removed:
        in v2 firmware energyConsumption is a period counter that resets with
        every bandwidth toggle — it is non-zero between polls even though no
        lifetime hw counters are available, so the check gives a false True.
        """
        if hasattr(self.coordinator, '_service') and self.coordinator._service:
            panel_id = self.breaker_data.get("panel_id")
            if panel_id:
                return self.coordinator._service.panel_has_hw_counters(panel_id)
        # Service unavailable — default to power×time (safe fallback).
        return False

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        if not self.coordinator.data:
            return

        try:
            # Auto-detect mode on first update
            if self._use_hw_counters is None:
                self._use_hw_counters = self._detect_ct_mode()
                if self._use_hw_counters:
                    _LOGGER.debug("CT daily sensor %s: using hardware energy counters", self.entity_id)
                else:
                    _LOGGER.debug("CT daily sensor %s: using power×time fallback", self.entity_id)

            today = dt_util.now().date()
            is_new_day = self._last_date is not None and self._last_date != today

            if self._use_hw_counters:
                self._update_ct_hw(today, is_new_day)
            else:
                self._update_ct_pxt(today, is_new_day)

        except Exception:
            if _log_warnings_enabled(self.coordinator):
                _LOGGER.exception(
                    "Error updating CT daily usage sensor for %s",
                    self.entity_id
                )
            return

        self.async_write_ha_state()

    def _update_ct_hw(self, today: datetime.date, is_new_day: bool):
        """Update daily energy using hardware energy counters (midnight-baseline)."""
        consumption = self._get_ct_consumption()
        if consumption is None:
            self._consecutive_none += 1
            if self._consecutive_none >= HW_COUNTER_NONE_TOLERANCE:
                if _log_data_warnings_enabled(self.coordinator):
                    _LOGGER.warning(
                        "CT consumption unavailable for %s after %d consecutive reads",
                        self.entity_id, self._consecutive_none
                    )
            else:
                if _log_data_warnings_enabled(self.coordinator):
                    _LOGGER.debug(
                        "Transient None for %s (count=%d/%d) -- skipping update",
                        self.entity_id, self._consecutive_none, HW_COUNTER_NONE_TOLERANCE
                    )
            return

        self._consecutive_none = 0

        # --- Midnight reset ---
        if is_new_day:
            if consumption < 1.0:
                # CT energyConsumption is null/0 at midnight — bandwidth toggle
                # hasn't run yet.  Defer baseline to the first real poll value.
                self._midnight_baseline = None
                self._state = 0.0
                self._last_date = today
                return

            self._midnight_baseline = consumption
            self._state = 0.0
            self._last_date = today
            return

        # --- First reading or deferred baseline ---
        if self._midnight_baseline is None:
            
            # Auto-detect energy key if set to "consumption" but import
            # is the active counter (import >> consumption means the
            # consumption counter is stale/frozen on this CT).
            if self._energy_key == "consumption":
                ct_id = self.breaker_data["id"]
                cts = self.coordinator.data.get("cts", {})
                ct = cts.get(ct_id, {})
                imp = float(ct.get("import", 0) or 0)
                cons = float(ct.get("consumption", 0) or 0)
                if imp > cons and imp > 1.0:
                    if _log_data_warnings_enabled(self.coordinator):
                        _LOGGER.info(
                            "CT daily %s: auto-switching to 'import' key "
                            "(import=%.1f >> consumption=%.1f)",
                            self.entity_id, imp, cons
                        )
                    self._energy_key = "import"
                    consumption = self._get_ct_consumption()
                    if consumption is None:
                        return

            if self._state is not None:
                # _state already reflects today's accumulated total (e.g.
                # restored after an HA restart) — derive the baseline from
                # it instead of wiping the daily total back to 0.
                self._midnight_baseline = consumption - self._state
            else:
                self._midnight_baseline = consumption
                self._state = 0.0
            self._last_date = today
            return

        # --- Normal intra-day update ---
        daily = consumption - self._midnight_baseline

        if daily < 0:
            # Negative daily means the consumption reading is stale, partial,
            # or from a reconnect burst.  The midnight baseline is correct —
            # just skip this update and wait for the next good reading.
            # The counter will self-correct when a full update arrives.
            if _log_data_warnings_enabled(self.coordinator):
                _LOGGER.debug(
                    "Skipping negative daily for %s: consumption=%.3f "
                    "< baseline=%.3f (delta=%.3f) -- waiting for correction",
                    self.entity_id, consumption, self._midnight_baseline, daily
                )
            return

        if daily > MAX_DAILY_ENERGY_KWH:
            if _log_data_warnings_enabled(self.coordinator):
                _LOGGER.warning(
                    "Daily energy %.1f kWh for %s exceeds sanity cap "
                    "(%.0f kWh) -- likely corrupted baseline (%.3f). "
                    "Re-baselining.",
                    daily, self.entity_id, MAX_DAILY_ENERGY_KWH,
                    self._midnight_baseline
                )
            self._midnight_baseline = consumption
            daily = 0.0

        daily = self._apply_monotonic_guard(
            daily,
            extra_log_context=f" (consumption={consumption:.3f}, baseline={self._midnight_baseline:.3f})"
        )
        if daily is None:
            return

        self._state = daily
        self._last_date = today

    def _update_ct_pxt(self, today: datetime.date, is_new_day: bool):
        """Update daily energy using power×time integration (v2+ firmware path).

        Uses the CT's combined power (power1 + power2) integrated over time.

        Power direction handling for the GRID CT:

          The CT sits on the main supply lines between the utility meter and
          the panel bus.  The sign convention is:
            positive watts → grid feeding the house (normal consumption)
            negative watts → solar generation exceeds house load; excess
                             flows back through the CT to the grid ("import"
                             from the grid's perspective / solar export)

          • _energy_key == "consumption"  → Daily Consumption sensor.
            Tracks energy drawn FROM the grid: max(power, 0).
            Accumulates whenever the house is buying from the utility.

          • _energy_key == "import"  → Daily Import sensor.
            Tracks solar energy pushed back INTO the grid: max(-power, 0).
            Only accumulates when watts go negative (solar > house load).
            Will be 0 on days without surplus solar.
        """
        if not self.coordinator.data or "cts" not in self.coordinator.data:
            return
        ct_data = self.coordinator.data["cts"].get(self.breaker_data["id"])
        if ct_data is None:
            return

        try:
            raw_power = float(ct_data.get("power", 0))
            if self._energy_key == "import":
                # Solar export: only when CT watts are negative
                current_power = max(-raw_power, 0.0)
            else:
                # Grid consumption: only when CT watts are positive
                current_power = max(raw_power, 0.0)
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
            # First pxt run after startup or mode switch.  Any _state value
            # restored from a previous hw-counter session is meaningless in
            # pxt mode (hw mode reads a period counter; pxt integrates from 0).
            # Reset to 0 so the sensor accumulates cleanly from this point.
            self._state = 0.0
            self._last_reported = None  # clear native_value monotonic clamp too
            self._last_update_time = now
            self._last_power = current_power
            self._last_date = today
            return

        time_span = now - self._last_update_time
        if time_span <= 0:
            return

        self._state = _calc_pxt_energy(
            time_span, self._last_power, current_power,
            self._state or 0.0,
            options, self.entity_id,
            _log_data_warnings_enabled(self.coordinator),
        )
        self._last_update_time = now
        self._last_power = current_power
        self._last_date = today

class LDATATotalUsageSensor(LDATAEntity, SensorEntity):
    """Sensor that reads all outputs from all LDATA devices based on the passed in description."""

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
        self._state = self.total_values()
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    def _panel_leg_totals(self) -> dict:
        """Sum power/current across all breakers on this panel, once per coordinator update.

        Shared by the up-to-5 sibling LDATATotalUsageSensor entities per
        panel (Watts/Amps x leg1/leg2, plus the Amps "both" total) that would
        otherwise each independently scan every breaker on every coordinator
        update. Cached on the coordinator and invalidated whenever
        coordinator.data is replaced with a new object — coordinator.data is
        always swapped wholesale on update, never mutated in place.
        """
        data = self.coordinator.data
        cache = getattr(self.coordinator, "_panel_leg_totals_cache", None)
        if cache is None or cache.get("_data_id") != id(data):
            cache = {"_data_id": id(data)}
            self.coordinator._panel_leg_totals_cache = cache

        panel_serial = self.entity_data["serialNumber"]
        totals = cache.get(panel_serial)
        if totals is not None:
            return totals

        totals = {
            "power1": 0.0, "power2": 0.0,
            "current1": 0.0, "current2": 0.0, "current_both": 0.0,
        }
        if data and "breakers" in data:
            for breaker_data in data["breakers"].values():
                if breaker_data.get("panel_id") != panel_serial:
                    continue

                def _num(key):
                    try:
                        val = breaker_data[key]
                        return float(val) if val is not None else 0.0
                    except (ValueError, KeyError, TypeError):
                        return 0.0

                p1, p2 = _num("power1"), _num("power2")
                c1, c2 = _num("current1"), _num("current2")

                totals["power1"] += max(p1, 0.0)
                totals["power2"] += max(p2, 0.0)
                totals["current1"] += max(c1, 0.0)
                totals["current2"] += max(c2, 0.0)
                # breaker_data["current"] is deliberately de-duplicated for
                # 2-pole breakers (both legs of a 240V circuit carry the same
                # physical current) — but current1/current2 are genuine
                # per-leg bus totals. Sum those here instead so the panel
                # total "Amps" always equals "Amps Leg 1" + "Amps Leg 2",
                # matching how Watts is already additive across both legs.
                totals["current_both"] += max(c1 + c2, 0.0)

        cache[panel_serial] = totals
        return totals

    def total_values(self) -> float:
        """Total value for all breakers."""
        if not self.coordinator.data or "breakers" not in self.coordinator.data:
            return 0.0

        # Fast path: totalPower is pre-calculated and maintained by all update paths.
        # Use it for the common case (total power, both legs) to avoid iterating all breakers.
        if self.entity_description.key == "power" and self.leg_to_total == "both":
            key = self.entity_data["serialNumber"] + "totalPower"
            try:
                return float(self.coordinator.data.get(key, 0))
            except (ValueError, TypeError):
                return 0.0

        totals = self._panel_leg_totals()
        if self.entity_description.key == "current":
            if self.leg_to_total == "both":
                return totals["current_both"]
            return totals.get(f"current{self.leg_to_total}", 0.0)
        return totals.get(f"power{self.leg_to_total}", 0.0)

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
        # Manual override: set via ldata.reset_energy_baseline service
        self._accept_next_value: bool = False
        self._consecutive_decrease: int = 0
        # Power×time tracking for v2 panels (hw counters unavailable)
        self._last_power: float | None = None
        self._last_update_time: float | None = None  # time.time() epoch seconds

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self.coordinator.last_update_success or self._state is not None

    async def async_added_to_hass(self) -> None:
        """Handle entity which is added to hass to restore state on startup."""
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            try:
                self._state = float(last_state.state)
            except (ValueError, TypeError):
                pass

    def _use_pxt_mode(self) -> bool:
        """Return True if this panel has no hw counters and we should integrate power×time."""
        if hasattr(self.coordinator, '_service') and self.coordinator._service:
            panel_id = self.breaker_data.get("panel_id")
            if panel_id:
                return not self.coordinator._service.panel_has_hw_counters(panel_id)
        return False  # default: hw counter path (safe for v1)

    def _update_pxt(self, new_data) -> None:
        """Accumulate lifetime energy from instantaneous power (used on v2 panels).

        Called instead of the hardware-counter path when the panel firmware
        reports period counters instead of monotonically-increasing lifetime
        counters (firmware ≥ 2.x).

        Direction conventions
        ─────────────────────
        Import sensor  (key="import"):
            Solar breaker — positive watts = solar generation flowing INTO the
            panel bus.  Clamp to max(power, 0) to ignore inverter standby draw.

        Consumption sensor  (key="consumption"):
            Load breaker  — power is virtually always positive (consuming from
            the panel bus).  abs() absorbs rare firmware transients.
        """
        try:
            raw_power = float(new_data.get("power", 0) or 0)
        except (ValueError, TypeError):
            return

        if self.entity_description.key == "import":
            current_power = max(raw_power, 0.0)
        else:
            current_power = abs(raw_power)

        now = time.time()
        options = self.coordinator.config_entry.options

        if self._last_update_time is None:
            # First update after startup — establish baseline, no delta yet.
            self._last_update_time = now
            self._last_power = current_power
            if self._state is None:
                self._state = 0.0
                self.async_write_ha_state()
            return

        time_span = now - self._last_update_time
        if time_span <= 0:
            return

        self._state = _calc_pxt_energy(
            time_span, self._last_power, current_power,
            self._state or 0.0,
            options, self.entity_id,
            _log_data_warnings_enabled(self.coordinator),
        )
        self._last_update_time = now
        self._last_power = current_power
        self.async_write_ha_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Route coordinator updates through our custom state-update logic."""
        self._state_update()

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    # On v2 panels the hw counters are period counters — integrate
                    # power×time to build a monotonically-increasing lifetime total.
                    if self._use_pxt_mode():
                        self._update_pxt(new_data)
                        return

                    # ── v1 hardware counter path ──────────────────────────────
                    raw = new_data.get(self.entity_description.key)
                    if raw is None:
                        return  # Field missing — keep last state
                    new_value = float(raw)
                    ROUNDING_TOLERANCE = 0.05

                    # Reject near-zero values when state is well above zero —
                    # bandwidth toggle / reconnect bursts return energyConsumption=0
                    # (or a transient near-zero like 0.04) for breakers that
                    # haven't responded yet.  A genuine counter can't drop from
                    # >1 kWh to <1 kWh in a single poll cycle.
                    if new_value < 1.0 and self._state is not None and self._state > 1.0:
                        return

                    # First update — accept unconditionally
                    if self._state is None:
                        self._state = new_value
                        self.async_write_ha_state()
                        return

                    # Manual override: accept unconditionally after service call
                    if self._accept_next_value:
                        _LOGGER.info(
                            "Accepting reset value for %s: %s (was %s)",
                            self.entity_id, new_value, self._state
                        )
                        self._state = new_value
                        self._accept_next_value = False
                        self._consecutive_decrease = 0
                        self.async_write_ha_state()
                        return

                    # Decrease guard — TOTAL_INCREASING must never go backward
                    if (float(self._state) - new_value) > ROUNDING_TOLERANCE:
                        self._consecutive_decrease += 1
                        if _log_data_warnings_enabled(self.coordinator):
                            log_fn = _LOGGER.warning if self._consecutive_decrease <= 1 else _LOGGER.debug
                            log_fn(
                                "Ignoring decreasing value for %s: new=%s, old=%s "
                                "(use ldata.reset_energy_baseline service to override)",
                                self.entity_id, new_value, self._state
                            )
                        return

                    # Hold minor decreases within tolerance
                    if new_value < float(self._state):
                        new_value = float(self._state)

                    # Spike detection using shared helper
                    new_state, self._pending_state, accepted = _check_spike_and_update(
                        self._state, self._pending_state, new_value,
                        self.entity_id, _log_data_warnings_enabled(self.coordinator),
                    )
                    if accepted:
                        self._state = new_state
                else:
                    if _log_warnings_enabled(self.coordinator):
                        _LOGGER.debug("Breaker %s not found in update.", self.breaker_data["id"])
            else:
                if _log_warnings_enabled(self.coordinator):
                    _LOGGER.debug("No 'breakers' data found in coordinator update.")

        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            if _log_warnings_enabled(self.coordinator):
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
            if self.coordinator.data.get("panels"):
                panel = find_panel(self.coordinator, self.panel_data["id"])
                if panel is not None:
                    self._state = panel[self.entity_description.key + self.leg_to_total]
                # else: no matching panel this cycle — leave prior state as-is
            else:
                self._state = None  # No panel data in coordinator
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
                    log_enabled = _log_data_warnings_enabled(self.coordinator)

                    # Hard reject: no confirmation path, no pending state — this is
                    # never a real reading for a residential/light-commercial CT.
                    if abs(new_value) > _CT_POWER_HARD_MAX_W:
                        _LOGGER.error(
                            "Discarding impossible value for %s: %s (exceeds hard "
                            "ceiling of %s W) — not entering spike-confirmation, "
                            "this is never a real CT reading",
                            self.entity_id, new_value, _CT_POWER_HARD_MAX_W
                        )
                        self._pending_state = None
                    else:
                        # Spike detection: only flag readings that exceed the residential
                        # service ceiling (_CT_POWER_MAX_W).  The previous zero-to-high
                        # and ratio-based checks caused false positives on the grid CT,
                        # which legitimately swings from near-zero (solar covering load)
                        # to 5–8 kW when a large appliance starts.
                        is_potential_spike = abs(new_value) > _CT_POWER_MAX_W

                        if is_potential_spike:
                            if self._pending_state is not None:
                                if self._pending_state != 0 and abs(new_value - self._pending_state) / abs(self._pending_state) < 0.15:
                                    if log_enabled:
                                        _LOGGER.info("Accepting consistent high value for %s: %s", self.entity_id, new_value)
                                    self._state = new_value
                                    self._pending_state = None
                                else:
                                    if log_enabled:
                                        _LOGGER.warning("Discarding inconsistent spike for %s: new=%s, pending=%s", self.entity_id, new_value, self._pending_state)
                                    self._pending_state = new_value
                            else:
                                if log_enabled:
                                    _LOGGER.warning("High value detected for %s. Pending verification: %s", self.entity_id, new_value)
                                self._pending_state = new_value
                        else:
                            self._pending_state = None
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
        # Track consecutive decreases — if the API consistently reports a
        # lower value than the restored state, the restored state was
        # corrupted and we should accept the real value.
        self._consecutive_decrease: int = 0
        # Manual override: set via ldata.reset_energy_baseline service
        self._accept_next_value: bool = False
        # Power×time tracking for v2 panels (hw counters unavailable)
        self._last_power: float | None = None
        self._last_update_time: float | None = None  # time.time() epoch seconds

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

    def _use_pxt_mode(self) -> bool:
        """Return True if this CT's panel has no hw counters — use power×time integration."""
        if hasattr(self.coordinator, '_service') and self.coordinator._service:
            panel_id = self.ct_data.get("panel_id")
            if panel_id:
                return not self.coordinator._service.panel_has_hw_counters(panel_id)
        return False  # default: hw counter path (safe for v1)

    def _update_pxt(self, new_data) -> None:
        """Accumulate lifetime energy from instantaneous CT power (used on v2 panels).

        Called instead of the hardware-counter path when the panel firmware
        reports period counters instead of monotonically-increasing lifetime
        counters (firmware ≥ 2.x).

        Direction conventions (Grid CT sign convention)
        ────────────────────────────────────────────────
        Consumption sensor  (key="consumption"):
            Positive CT watts = power flowing grid → house.
            Clamp to max(power, 0) — ignore negative (solar return) direction.

        Import / return sensor  (key="import"):
            Negative CT watts = solar excess flowing house → grid.
            Clamp to max(-power, 0) — only accumulate when CT is negative.
        """
        try:
            raw_power = float(new_data.get("power", 0) or 0)
        except (ValueError, TypeError):
            return

        if self.entity_description.key == "import":
            # Solar return: CT negative = house → grid
            current_power = max(-raw_power, 0.0)
        else:
            # Grid consumption: CT positive = grid → house
            current_power = max(raw_power, 0.0)

        now = time.time()
        options = self.coordinator.config_entry.options

        if self._last_update_time is None:
            # First update after startup — establish baseline, no delta yet.
            self._last_update_time = now
            self._last_power = current_power
            if self._state is None:
                self._state = 0.0
                self.async_write_ha_state()
            return

        time_span = now - self._last_update_time
        if time_span <= 0:
            return

        self._state = _calc_pxt_energy(
            time_span, self._last_power, current_power,
            self._state or 0.0,
            options, self.entity_id,
            _log_data_warnings_enabled(self.coordinator),
        )
        self._last_update_time = now
        self._last_power = current_power
        self.async_write_ha_state()

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            # Add safety check for coordinator.data
            if cts := self.coordinator.data.get("cts"):
                if new_data := cts.get(self.ct_data["id"]):
                    # On v2 panels the hw counters are period counters — integrate
                    # power×time to build a monotonically-increasing lifetime total.
                    if self._use_pxt_mode():
                        self._update_pxt(new_data)
                        return

                    # ── v1 hardware counter path ──────────────────────────────
                    new_value = float(new_data[self.entity_description.key])
                    ROUNDING_TOLERANCE = 0.05

                    # Reject near-zero values when state is well above zero —
                    # bandwidth toggle / reconnect bursts return 0 (or a
                    # transient near-zero) for CTs that haven't responded yet.
                    # A genuine counter can't drop from >1 kWh to <1 kWh in
                    # a single poll cycle.
                    if new_value < 1.0 and self._state is not None and self._state > 1.0:
                        return

                    # Initialize state on the very first update if not already set by restore.
                    if self._state is None:
                        self._state = new_value
                        self.async_write_ha_state()
                        return

                    # --- Data Validation ---
                    # Manual override: accept unconditionally after service call
                    if self._accept_next_value:
                        _LOGGER.info(
                            "Accepting reset value for %s: %s (was %s)",
                            self.entity_id, new_value, self._state
                        )
                        self._state = new_value
                        self._accept_next_value = False
                        self._consecutive_decrease = 0
                        self.async_write_ha_state()
                        return

                    # Check for a significant decrease, ignoring minor rounding/jitter.
                    if (float(self._state) - new_value) > ROUNDING_TOLERANCE:
                        # Never accept a decrease to near-zero — this is a
                        # reconnect burst, not a genuine counter correction.
                        # A real corrupted restore would show a plausible
                        # counter value (>10% of old), not 0.0 or near-zero.
                        if self._state > 10.0 and new_value < self._state * 0.1:
                            if _log_data_warnings_enabled(self.coordinator):
                                _LOGGER.debug(
                                    "Ignoring near-zero value for %s: new=%s, old=%s "
                                    "(likely reconnect burst)",
                                    self.entity_id, new_value, self._state
                                )
                            return # Exit without updating or counting.

                        self._consecutive_decrease += 1
                        if _log_data_warnings_enabled(self.coordinator):
                            log_fn = _LOGGER.warning if self._consecutive_decrease <= 1 else _LOGGER.debug
                            log_fn(
                                "Ignoring decreasing value for %s: new=%s, old=%s "
                                "(use ldata.reset_energy_baseline service to override)",
                                self.entity_id, new_value, self._state
                            )
                        return # Exit without updating.

                    self._consecutive_decrease = 0

                    # For minor decreases within tolerance, hold the previous value
                    # to maintain TOTAL_INCREASING contract with HA.
                    if new_value < float(self._state):
                        new_value = float(self._state)

                    # Spike detection using shared helper
                    new_state, self._pending_state, accepted = _check_spike_and_update(
                        self._state, self._pending_state, new_value,
                        self.entity_id, _log_data_warnings_enabled(self.coordinator),
                    )
                    if accepted:
                        self._state = new_state
                else:
                    # CT data not found, do not change state
                    if _log_warnings_enabled(self.coordinator):
                        _LOGGER.debug("Data for CT %s not found in update.", self.ct_data["id"])
            else:
                # No CT data in coordinator, do not change state
                if _log_warnings_enabled(self.coordinator):
                    _LOGGER.debug("No 'cts' data found in coordinator update.")

        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            if _log_warnings_enabled(self.coordinator):
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


# ── Breaker diagnostic sensors ───────────────────────────────────────


class LDATABreakerOperationalStateSensor(LDATAEntity, SensorEntity):
    """Breaker operational state diagnostic sensor.

    Reports the operationalState field from the Leviton API.
    Normally "Normal"; other values indicate a fault condition.
    """

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get("operationalState", "Normal")
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
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
    """Breaker BLE signal strength diagnostic sensor.

    Reports the bleRSSI field — the Bluetooth Low Energy signal strength
    between the breaker and the panel hub. Lower (more negative) values
    indicate weaker signal. Useful for diagnosing communication issues.
    """

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_native_unit_of_measurement = "dBm"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get("bleRSSI")
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
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


class LDATABreakerPositionSensor(LDATAEntity, SensorEntity):
    """Breaker panel slot position diagnostic sensor.

    The Status binary sensor already carries `position` as an extra
    attribute, but attributes aren't visible on a device's page without
    opening that entity's own dialog — this surfaces it as its own row
    on the breaker's device page instead.
    """

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:numeric"

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get("position")
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    self._state = new_data.get("position")
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def native_value(self) -> StateType:
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "Position"

    @property
    def unique_id_suffix(self) -> str | None:
        return "position"


# ── Panel diagnostic sensors ────────────────────────────────────────


class LDATAPanelWifiRSSISensor(LDATAEntity, SensorEntity):
    """Panel WiFi signal strength diagnostic sensor.

    Reports the rssi field from the IotWhem device — the WiFi signal
    strength of the panel's connection to the router. Lower (more negative)
    values indicate weaker signal. Updated via WebSocket in real-time.
    """

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_native_unit_of_measurement = "dBm"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH

    def __init__(self, coordinator, data) -> None:
        """Init sensor."""
        super().__init__(data=data, coordinator=coordinator)
        self.panel_data = data
        self._panel_id = data["data"]["id"]
        self._state = data["data"].get("rssi")
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            panel = find_panel(self.coordinator, self._panel_id)
            if panel is not None:
                val = panel.get("rssi")
                if val is not None:
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


class DecoraSignalSensor(DecoraEntity, SensorEntity):
    """Signal strength sensor for a Decora Smart Wi-Fi device."""

    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "dBm"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init DecoraSignalSensor."""
        super().__init__(data=data, coordinator=coordinator)
        self._state = data.get("rssi")

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        device = self._get_device_data()
        if device:
            self._state = device.get("rssi")
        self.async_write_ha_state()

    @property
    def native_value(self) -> StateType:
        """Return the signal strength value."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the device's name."""
        return "Signal Strength"

    @property
    def unique_id_suffix(self) -> str | None:
        """Return the unique id suffix."""
        return "rssi"

    @property
    def icon(self) -> str:
        """Return the icon."""
        return "mdi:wifi"


GFCI_STATUS_MAP = {
    "": "Protected",
    "GFCI_FAULT": "Fault",
    "MANUAL_TRIP": "Test",
}

GFCI_STATUS_OPTIONS = ["Fault", "Protected", "Test", "Unknown"]


class DecoraGFCIStatusSensor(DecoraEntity, SensorEntity):
    """GFCI fault status enum sensor for D2GF1/D2GF2."""

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_options = GFCI_STATUS_OPTIONS

    def __init__(self, coordinator, data) -> None:
        """Init DecoraGFCIStatusSensor."""
        super().__init__(data=data, coordinator=coordinator)
        fault = data.get("fault", "")
        self._state = GFCI_STATUS_MAP.get(fault, "Unknown") if fault is not None else "Unknown"

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        device = self._get_device_data()
        if device:
            fault = device.get("fault", "")
            self._state = GFCI_STATUS_MAP.get(fault, "Unknown") if fault is not None else "Unknown"
        self.async_write_ha_state()

    @property
    def native_value(self) -> str | None:
        """Return the fault status."""
        return self._state

    @property
    def name_suffix(self) -> str | None:
        return "Fault Status"

    @property
    def unique_id_suffix(self) -> str | None:
        return "fault_status"
        return "mdi:wifi-strength-off-outline"