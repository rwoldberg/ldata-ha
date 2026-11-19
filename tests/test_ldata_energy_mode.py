"""LDATA energy tracking mode: lifetime counter until a panel shows hourly deltas."""

import datetime
import random
from types import SimpleNamespace
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import pytest

from custom_components.ldata import ldata_service, sensor
from custom_components.ldata.const import ENERGY_TRACKING_MODE
from custom_components.ldata.ldata_energy import (
    DELTA_EVIDENCE_HOURS,
    HourlyDeltaDetector,
    LDATAEnergyLedger,
    hourly_bound_kwh,
)
from custom_components.ldata.ldata_service import LDATAService
from homeassistant.util import dt as dt_util

TZ = ZoneInfo("America/Los_Angeles")
PANEL = "LDATA-1"


def _ts(day: int, hour: int, minute: int = 0, second: int = 0) -> float:
    return datetime.datetime(2026, 10, day, hour, minute, second, tzinfo=TZ).timestamp()


@pytest.fixture(autouse=True)
def _pacific_time():
    previous = dt_util.get_default_time_zone()
    dt_util.set_default_time_zone(TZ)
    yield
    dt_util.set_default_time_zone(previous)


@pytest.fixture
def clock(monkeypatch):
    now = SimpleNamespace(value=_ts(14, 9, 10))
    monkeypatch.setattr(ldata_service.time, "time", lambda: now.value)
    monkeypatch.setattr(sensor.time, "time", lambda: now.value)
    return now


def _raw_breaker(breaker_id: str, rating: int, ec1, ec2=None, position: int = 1) -> dict:
    return {
        "id": breaker_id,
        "name": breaker_id,
        "model": "LB120-DST",
        "currentRating": rating,
        "position": position,
        "poles": 1,
        "serialNumber": "x",
        "hwVersion": "1",
        "firmwareVersionMeter": "1",
        "canRemoteOn": False,
        "currentState": "ManualON",
        "remoteState": "",
        "power": 1000.0,
        "energyConsumption": ec1,
        "energyConsumption2": ec2,
        "energyImport": None,
        "energyImport2": None,
    }


def _ldata_panel(breakers: list[dict], panel_id: str = PANEL) -> dict:
    return {
        "id": panel_id,
        "name": "Panel",
        "model": "DAU",
        "status": "READY",
        "ModuleType": "LDATA",
        "updateVersion": "0.1.91",
        "rmsVoltage": 121.0,
        "rmsVoltage2": 121.0,
        "residentialBreakers": breakers,
    }


def _service(options: dict | None = None, stored: dict | None = None) -> LDATAService:
    entry = SimpleNamespace(options=options or {}, data={})
    service = LDATAService("", "", entry)
    if stored is not None:
        service.energy_ledger.load(stored)
    return service


def _ws_energy(service: LDATAService, breaker_id: str, ec1, ec2=None) -> None:
    data = {"energyConsumption": ec1}
    if ec2 is not None:
        data["energyConsumption2"] = ec2
    service._update_from_websocket(
        {"modelName": "ResidentialBreaker", "modelId": breaker_id, "data": data}
    )


class _Coordinator:
    def __init__(self, service: LDATAService) -> None:
        self._service = service
        self.last_update_success = True
        self.user = "test-user"
        self.config_entry = SimpleNamespace(options={})

    @property
    def data(self) -> dict:
        return self._service.status_data

    def async_add_listener(self, update_callback, context=None):
        return lambda: None


def _sensors(service: LDATAService, breaker_id: str):
    """A Lifetime and a Daily consumption sensor of the breaker, on the real service."""
    coordinator = _Coordinator(service)
    breaker = dict(service.status_data["breakers"][breaker_id])
    lifetime = sensor.LDATABreakerEnergyUsageSensor(
        coordinator, breaker, sensor.SENSOR_TYPES[sensor.CONSUMPTION]
    )
    daily = sensor.LDATADailyUsageSensor(coordinator, breaker, False, "")
    for entity in (lifetime, daily):
        entity.async_write_ha_state = MagicMock()
    return lifetime, daily


def _update(*entities) -> None:
    for entity in entities:
        entity._state_update()


# ── Detector ───────────────────────────────────────────────────────────


def test_a_rising_counter_is_never_evidence() -> None:
    detector = HourlyDeltaDetector()
    value = 0.3
    for step in range(200):
        value += 0.1
        assert detector.observe(PANEL, "b", {"1": round(value, 1)}, "WS", _ts(14, 0) + step * 600) is False
    assert detector.evidence_hours(PANEL) == 0


def test_a_counter_reset_is_not_evidence() -> None:
    # Breaker or hub replaced: every leg drops once, in different hours.
    detector = HourlyDeltaDetector()
    for leg_offset, key in enumerate(("a", "b", "c", "d")):
        when = _ts(14, 0)
        detector.observe(PANEL, key, {"1": 300.0, "2": 280.0}, "WS", when)
        detector.observe(PANEL, key, {"1": 0.2, "2": 0.1}, "WS", when + (leg_offset + 1) * 3600)
        detector.observe(PANEL, key, {"1": 0.4, "2": 0.3}, "WS", when + (leg_offset + 2) * 3600)
    assert detector.evidence_hours(PANEL) == 0


def test_listing_and_websocket_values_are_not_compared() -> None:
    # A listing that lags the WebSocket by one counter step is not a drop.
    detector = HourlyDeltaDetector()
    for hour in range(10):
        when = _ts(14, hour)
        detector.observe(PANEL, "b", {"1": 0.2 + hour}, "WS", when)
        detector.observe(PANEL, "b", {"1": 0.1 + hour}, "REST", when + 300)
    assert detector.evidence_hours(PANEL) == 0


def test_transient_zeros_are_not_evidence() -> None:
    detector = HourlyDeltaDetector()
    for hour in range(10):
        detector.observe(PANEL, "b", {"1": 4.0 + hour}, "WS", _ts(14, hour))
        detector.observe(PANEL, "b", {"1": 0.0, "2": None}, "WS", _ts(14, hour, 30))
    assert detector.evidence_hours(PANEL) == 0


def test_repeated_drops_in_distinct_hours_are_evidence() -> None:
    detector = HourlyDeltaDetector()
    values = [0.40, 0.10, 0.50, 0.12, 0.60, 0.20, 0.70, 0.30]
    results = [
        detector.observe(PANEL, "b", {"1": value}, "WS", _ts(14, hour, 0, 36))
        for hour, value in enumerate(values)
    ]
    # Drops at hours 1 (first, not counted), 3, 5 and 7.
    assert detector.evidence_hours(PANEL) == 3
    assert results.index(True) == 7
    assert DELTA_EVIDENCE_HOURS == 3


def test_drops_in_one_hour_count_once() -> None:
    detector = HourlyDeltaDetector()
    for key in "abcdef":
        detector.observe(PANEL, key, {"1": 0.4}, "WS", _ts(14, 1, 0, 36))
        detector.observe(PANEL, key, {"1": 0.1}, "WS", _ts(14, 2, 0, 36))
        detector.observe(PANEL, key, {"1": 0.4}, "WS", _ts(14, 3, 0, 36))
        detector.observe(PANEL, key, {"1": 0.1}, "WS", _ts(14, 4, 0, 36))
    # Hour 2: first drops of several breakers; hour 4: repeated drops.
    assert detector.evidence_hours(PANEL) == 2


def test_a_hub_reset_is_at_most_one_hour_of_evidence() -> None:
    # Hub replaced: every breaker drops in the same poll, then counts up.
    detector = HourlyDeltaDetector()
    for key in "abcdef":
        detector.observe(PANEL, key, {"1": 300.0, "2": 250.0}, "WS", _ts(14, 1, 59, 50))
    for minute in range(0, 600, 5):
        when = _ts(14, 2) + minute * 60
        for key in "abcdef":
            detector.observe(PANEL, key, {"1": 0.1 + minute / 100, "2": 0.1 + minute / 200}, "WS", when)
    assert detector.evidence_hours(PANEL) == 1


# ── Lifetime counter panels stay on the counter path ───────────────────


def _run_counter_panel(clock, start_kwh: float, hours: int = 48, kw: float = 1.0):
    """A hub that sends a true lifetime counter (0.1 kWh steps) every 5 minutes."""
    service = _service()
    clock.value = _ts(14, 9, 10)
    true_total = start_kwh
    service.parse_panels([_ldata_panel([_raw_breaker("b20", 20, round(true_total, 1))])])
    lifetime, daily = _sensors(service, "b20")
    _update(lifetime, daily)
    start_state = lifetime._state
    for _ in range(hours * 12):
        clock.value += 300
        true_total += kw * 300 / 3600
        _ws_energy(service, "b20", int(true_total * 10) / 10)
        _update(lifetime, daily)
        assert service.panel_uses_hourly_energy(PANEL) is False
    return service, lifetime, daily, start_state, true_total - start_kwh


def test_new_breaker_counter_below_the_hourly_bound_stays_on_the_counter_path(clock) -> None:
    """The review's stress case: 20 A breaker, counter from 0.3 kWh, 48 h at 1 kW."""
    assert hourly_bound_kwh(20) == pytest.approx(4.8)
    service, lifetime, _daily, start_state, used = _run_counter_panel(clock, 0.3)

    assert used == pytest.approx(48.0)
    assert service.energy_ledger.panel_mode(PANEL) is None
    assert service._delta_detector.evidence_hours(PANEL) == 0
    # The lifetime sensor follows the hardware counter: 48 kWh, not 85.
    assert lifetime._state - start_state == pytest.approx(48.0, abs=0.1)
    assert lifetime._ledger_ref is None


def test_large_counter_panel_stays_on_the_counter_path(clock) -> None:
    service, lifetime, _daily, start_state, used = _run_counter_panel(clock, 300.0)

    assert service.energy_ledger.panel_mode(PANEL) is None
    assert lifetime._state - start_state == pytest.approx(used, abs=0.1)


def test_counter_panel_is_not_read_for_missed_hours(clock) -> None:
    service, *_ = _run_counter_panel(clock, 0.3, hours=3)
    clock.value += 600
    assert service.needs_ldata_energy_recovery() is False


# ── Hourly-delta panels (DAU) switch to the ledger ─────────────────────


# Eleven breakers, as on the DAU this was captured from.
DAU_BREAKERS = [(f"b{n}", 15 if n % 2 else 20) for n in range(1, 12)]


def _dau_service(clock, options=None, stored=None):
    service = _service(options, stored)
    clock.value = _ts(14, 9, 10)
    service.parse_panels(
        [_ldata_panel([_raw_breaker(b, r, 0.05, position=n) for n, (b, r) in enumerate(DAU_BREAKERS)])]
    )
    return service


def _dau_hour(service, clock, rng, day: int, hour: int, lifetime_sized: bool = False) -> dict:
    """One hour of a DAU: a burst of hourly deltas at HH:00:36, maybe a lifetime counter at HH:17."""
    clock.value = _ts(day, hour, 0, 36)
    deltas = {}
    for breaker_id, rating in DAU_BREAKERS:
        deltas[breaker_id] = round(rng.uniform(0.001, 0.25 * hourly_bound_kwh(rating)), 6)
        _ws_energy(service, breaker_id, deltas[breaker_id])
    if lifetime_sized:
        clock.value = _ts(day, hour, 17, 42)
        _ws_energy(service, "b1", 314.1)
    return deltas


def test_dau_like_deltas_switch_the_panel_within_hours(clock) -> None:
    rng = random.Random(116)
    service = _dau_service(clock)
    switched_at = None
    for hour in range(10, 22):
        _dau_hour(service, clock, rng, 14, hour, lifetime_sized=hour == 11)
        if service.panel_uses_hourly_energy(PANEL):
            switched_at = hour
            break
    # Three evidence hours; the first burst has nothing to compare with, so
    # the earliest switch is at the 4th burst.
    assert switched_at is not None and 4 <= switched_at - 10 + 1 <= 8
    assert service._delta_detector.evidence_hours(PANEL) == DELTA_EVIDENCE_HOURS
    assert service.panel_has_hw_counters(PANEL) is False
    assert service.energy_ledger.panel_mode(PANEL) == "hourly"
    assert service.energy_ledger.dirty is True
    # A lifetime-sized value afterwards does not move the panel back.
    clock.value = _ts(14, switched_at, 23)
    _ws_energy(service, "b1", 314.2)
    assert service.panel_uses_hourly_energy(PANEL) is True


def test_dau_detection_ignores_values_while_the_panel_is_offline(clock) -> None:
    rng = random.Random(7)
    service = _dau_service(clock)
    service.status_data["panels"][0]["connected"] = False
    for hour in range(10, 22):
        _dau_hour(service, clock, rng, 14, hour)
    assert service._delta_detector.evidence_hours(PANEL) == 0
    assert service.panel_uses_hourly_energy(PANEL) is False


def test_switch_keeps_lifetime_and_daily_continuous(clock) -> None:
    rng = random.Random(116)
    service = _dau_service(clock)
    lifetime, daily = _sensors(service, "b2")
    _update(lifetime, daily)
    hour = 10
    while not service.panel_uses_hourly_energy(PANEL):
        before = (lifetime._state, daily._state)
        _dau_hour(service, clock, rng, 14, hour)
        if not service.panel_uses_hourly_energy(PANEL):
            clock.value += 60
            _update(lifetime, daily)
        hour += 1
    # The coordinator persists the ledger (sensors read the saved copy).
    service.energy_ledger.mark_saved(service.energy_ledger.take_unsaved())
    clock.value += 60
    _update(lifetime, daily)
    # The first update on the ledger keeps both states.
    assert (lifetime._state, daily._state) == before
    at_switch = (lifetime._state, daily._state)
    assert lifetime._ledger_ref == pytest.approx(service.energy_ledger.lifetime("b2"))

    booked = 0.0
    for later in range(hour, hour + 4):
        booked += _dau_hour(service, clock, rng, 14, later)["b2"]
        service.energy_ledger.mark_saved(service.energy_ledger.take_unsaved())
        clock.value += 60
        _update(lifetime, daily)
    # From there on both grow by exactly the booked hourly deltas.
    assert lifetime._state - at_switch[0] == pytest.approx(booked)
    assert daily._state - at_switch[1] == pytest.approx(booked)


def _detected_service(clock):
    rng = random.Random(116)
    service = _dau_service(clock)
    hour = 10
    while not service.panel_uses_hourly_energy(PANEL):
        _dau_hour(service, clock, rng, 14, hour)
        hour += 1
    return service


# ── Persistence ────────────────────────────────────────────────────────


def test_detected_mode_survives_a_restart(clock) -> None:
    stored = _detected_service(clock).energy_ledger.take_unsaved()
    assert stored["panel_modes"] == {PANEL: "hourly"}

    service = _dau_service(clock, stored=stored)

    assert service.panel_uses_hourly_energy(PANEL) is True
    assert service.panel_has_hw_counters(PANEL) is False
    assert service._delta_detector.evidence_hours(PANEL) == 0


def test_undecided_panel_restarts_undecided(clock) -> None:
    service, *_ = _run_counter_panel(clock, 0.3, hours=2)
    stored = service.energy_ledger.as_dict()
    assert stored["panel_modes"] == {}

    restarted = _dau_service(clock, stored=stored)

    assert restarted.panel_uses_hourly_energy(PANEL) is False


def test_ledger_stored_before_panel_modes_stays_hourly_without_learning(clock) -> None:
    # Stored by the version that booked every LDATA panel in the ledger
    # (no panel_modes): its sensors already follow the ledger.
    legacy = LDATAEnergyLedger()
    legacy.apply("b1", 15, {"1": 0.03}, _ts(14, 8, 0, 36), "WS")
    stored = legacy.as_dict()
    del stored["panel_modes"]

    service = _dau_service(clock, stored=stored)

    assert service.panel_uses_hourly_energy(PANEL) is True
    assert service.panel_has_hw_counters(PANEL) is False
    assert service.needs_breaker_poll is False
    # The startup listing value (the 08-09h delta) is booked on top.
    assert service.energy_ledger.lifetime("b1") == pytest.approx(0.08)
    saved = service.energy_ledger.take_unsaved()
    assert saved["panel_modes"] == {PANEL: "hourly"}
    # Stored with the mode from now on: a later panel is not adopted.
    other = _service(stored=saved)
    other.parse_panels([_ldata_panel([_raw_breaker("x1", 15, 0.4)], panel_id="LDATA-2")])
    assert other.panel_uses_hourly_energy("LDATA-2") is False


def test_ledger_stored_before_panel_modes_only_adopts_its_own_panels(clock) -> None:
    legacy = LDATAEnergyLedger()
    legacy.apply("other", 15, {"1": 0.03}, _ts(14, 8, 0, 36), "WS")
    stored = legacy.as_dict()
    del stored["panel_modes"]

    service = _dau_service(clock, stored=stored)

    assert service.panel_uses_hourly_energy(PANEL) is False


def test_garbage_panel_modes_are_dropped() -> None:
    ledger = LDATAEnergyLedger()
    ledger.load({"panel_modes": {"a": "hourly", "b": "sideways", "c": 3}, "breakers": {}})
    assert ledger.panel_mode("a") == "hourly"
    assert ledger.panel_mode("b") is None
    assert ledger.panel_mode("c") is None
    assert ledger.booked_before_modes("a") is False


# ── Option ─────────────────────────────────────────────────────────────


def test_option_hourly_uses_the_ledger_at_once(clock) -> None:
    service = _dau_service(clock, options={ENERGY_TRACKING_MODE: "hourly"})

    assert service.panel_uses_hourly_energy(PANEL) is True
    assert service.panel_has_hw_counters(PANEL) is False
    # The option is not stored as a detected mode.
    assert service.energy_ledger.panel_mode(PANEL) is None


def test_option_counter_never_uses_the_ledger(clock) -> None:
    stored = _detected_service(clock).energy_ledger.take_unsaved()
    service = _dau_service(clock, options={ENERGY_TRACKING_MODE: "counter"}, stored=stored)
    booked = service.energy_ledger.as_dict()["breakers"]
    rng = random.Random(3)
    for hour in range(10, 22):
        _dau_hour(service, clock, rng, 15, hour)

    assert service.panel_uses_hourly_energy(PANEL) is False
    # Nothing is booked or detected.
    assert service.energy_ledger.as_dict()["breakers"] == booked
    assert service._delta_detector.evidence_hours(PANEL) == 0
    clock.value += 600
    assert service.needs_ldata_energy_recovery() is False
    # The detected mode is kept for when the option goes back to auto.
    assert service.energy_ledger.panel_mode(PANEL) == "hourly"
    service.entry.options = {ENERGY_TRACKING_MODE: "auto"}
    assert service.panel_uses_hourly_energy(PANEL) is True


@pytest.mark.parametrize("value", [None, "", "sideways", 3])
def test_unknown_option_value_is_auto(clock, value) -> None:
    service = _dau_service(clock, options={ENERGY_TRACKING_MODE: value})
    assert service._energy_tracking_option() == "auto"
    assert service.panel_uses_hourly_energy(PANEL) is False


def test_option_does_not_affect_whems_panels(clock) -> None:
    service = _service({ENERGY_TRACKING_MODE: "hourly"})
    whems = _ldata_panel([_raw_breaker("w1", 15, 1234.5)], panel_id="1000_ABCD")
    whems.update({"ModuleType": "WHEMS", "model": "LWHEM", "connected": True, "updateVersion": "1.7.6"})
    service.parse_panels([whems])

    assert service.panel_uses_hourly_energy("1000_ABCD") is False
    assert service.energy_tracking_modes() == {}


def test_energy_tracking_modes_reports_each_ldata_panel(clock) -> None:
    service = _detected_service(clock)
    assert service.energy_tracking_modes() == {PANEL: "hourly"}
    assert _dau_service(clock).energy_tracking_modes() == {PANEL: "counter"}


# ── Sensors switching back and forth ───────────────────────────────────


def test_sensor_leaving_the_ledger_drops_its_reference(clock) -> None:
    # Option set to counter after hourly: when the ledger is used again, the
    # sensor continues from its state then, not from the old reference.
    service = _dau_service(clock, options={ENERGY_TRACKING_MODE: "hourly"})
    lifetime, daily = _sensors(service, "b2")
    service.energy_ledger.mark_saved(service.energy_ledger.as_dict())
    _update(lifetime, daily)
    assert lifetime._ledger_ref is not None and daily._ledger_ref is not None

    service.entry.options = {ENERGY_TRACKING_MODE: "counter"}
    _update(lifetime, daily)
    assert lifetime._ledger_ref is None and daily._ledger_ref is None
    assert "ledger_ref" not in lifetime.extra_state_attributes
