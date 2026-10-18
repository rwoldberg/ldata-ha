"""Hardware energy counters are trusted only while they behave like lifetime counters."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from custom_components.ldata import sensor
from custom_components.ldata.const import HW_COUNTER_DEMOTE_EVIDENCE
from custom_components.ldata.ldata_service import LDATAService

PANEL = "panel-1"
BREAKER_ID = "b1"
START = 1_760_000_000.0


@pytest.fixture
def clock(monkeypatch):
    """Drive time.time() in the service and the sensor module."""
    now = SimpleNamespace(value=START)
    monkeypatch.setattr("custom_components.ldata.ldata_service.time.time", lambda: now.value)
    monkeypatch.setattr(sensor.time, "time", lambda: now.value)
    return now


def _breaker(**overrides) -> dict:
    return {
        "id": BREAKER_ID,
        "name": "Dryer",
        "panel_id": PANEL,
        "poles": 2,
        "rating": 30,
        "position": 1,
        "power": 0.0,
        "consumption": 1000.0,
        "consumption1": 500.0,
        "consumption2": 500.0,
        **overrides,
    }


def _service(hw: bool = True) -> LDATAService:
    service = LDATAService("", "", None)
    service._panel_has_hw_counters[PANEL] = hw
    return service


def _feed(service: LDATAService, existing: dict, kwh: float) -> None:
    """Deliver one REST reading of ``kwh`` (split across the two poles)."""
    service._apply_breaker_update(
        BREAKER_ID,
        existing,
        {"energyConsumption": kwh / 2, "energyConsumption2": kwh / 2},
        source="REST",
    )


# ── Service: evidence and demotion ─────────────────────────────────────


def test_steady_counter_is_never_demoted(clock) -> None:
    service = _service()
    existing = _breaker()
    _feed(service, existing, 1000.0)
    for step in range(1, 20):
        clock.value += 300
        _feed(service, existing, 1000.0 + step * 0.5)
    assert service.panel_has_hw_counters(PANEL) is True


def test_repeated_decreases_demote_the_panel(clock) -> None:
    service = _service()
    existing = _breaker()
    _feed(service, existing, 5000.0)
    value = 5000.0
    for _ in range(HW_COUNTER_DEMOTE_EVIDENCE):
        assert service.panel_has_hw_counters(PANEL) is True
        clock.value += 300
        value -= 100.0
        _feed(service, existing, value)
    assert service.panel_has_hw_counters(PANEL) is False


def test_implausible_rises_demote_the_panel(clock) -> None:
    service = _service()
    existing = _breaker()
    _feed(service, existing, 10.0)
    value = 10.0
    for _ in range(HW_COUNTER_DEMOTE_EVIDENCE):
        clock.value += 300
        value += 4000.0  # a 30 A breaker cannot pass this in five minutes
        _feed(service, existing, value)
    assert service.panel_has_hw_counters(PANEL) is False


def test_a_few_odd_readings_do_not_demote(clock) -> None:
    service = _service()
    existing = _breaker()
    _feed(service, existing, 1000.0)
    for kwh in (900.0, 1000.0, 1001.0):  # one dip, then normal
        clock.value += 300
        _feed(service, existing, kwh)
    assert service.panel_has_hw_counters(PANEL) is True


def test_transient_zeros_are_not_evidence(clock) -> None:
    service = _service()
    existing = _breaker()
    _feed(service, existing, 1000.0)
    for _ in range(10):
        clock.value += 300
        _feed(service, existing, 0.0)  # bandwidth toggle burst
        clock.value += 300
        _feed(service, existing, 1000.0)
    assert service.panel_has_hw_counters(PANEL) is True


def test_a_rounding_sized_dip_is_not_evidence(clock) -> None:
    service = _service()
    existing = _breaker()
    _feed(service, existing, 1000.0)
    for _ in range(10):
        clock.value += 300
        _feed(service, existing, 999.98)
        clock.value += 300
        _feed(service, existing, 1000.0)
    assert service.panel_has_hw_counters(PANEL) is True


def test_a_panel_is_never_promoted(clock) -> None:
    service = _service(hw=False)
    existing = _breaker()
    for step in range(10):
        clock.value += 300
        _feed(service, existing, 1000.0 + step)
    assert service.panel_has_hw_counters(PANEL) is False


def test_max_plausible_energy_scales_with_rating_poles_and_time() -> None:
    service = _service()
    thirty_amp_double = service.max_plausible_energy_kwh({"rating": 30, "poles": 2}, 3600)
    twenty_amp_single = service.max_plausible_energy_kwh({"rating": 20, "poles": 1}, 3600)
    assert thirty_amp_double > twenty_amp_single
    # 30 A x 240 V = 7.2 kW; an hour with margin and floor stays in the same order.
    assert 7.2 < thirty_amp_double < 15
    # No rating falls back to the default rather than refusing every rise.
    assert service.max_plausible_energy_kwh({}, 3600) > 0
    assert service.max_plausible_energy_kwh({"rating": 30}, 7200) > service.max_plausible_energy_kwh({"rating": 30}, 3600)


# ── Lifetime sensor: plausibility guard ────────────────────────────────


def _lifetime(service: LDATAService, existing: dict):
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"breakers": {BREAKER_ID: existing}}
    coordinator.config_entry.options = {}
    coordinator._service = service
    coordinator.async_add_listener.return_value = MagicMock()
    entity = sensor.LDATABreakerEnergyUsageSensor(
        coordinator, dict(existing), sensor.SENSOR_TYPES[sensor.CONSUMPTION]
    )
    entity.entity_id = "sensor.dryer_consumption"
    entity.async_write_ha_state = lambda: None
    return entity


def _publish(entity, kwh: float) -> None:
    entity.coordinator.data["breakers"][BREAKER_ID]["consumption"] = kwh
    entity._state_update()


def test_normal_growth_is_accepted(clock) -> None:
    entity = _lifetime(_service(), _breaker())
    _publish(entity, 1000.0)
    for step in range(1, 6):
        clock.value += 300
        _publish(entity, 1000.0 + step * 0.4)
    assert entity._state == pytest.approx(1002.0)


def test_a_stable_lifetime_sized_jump_is_rejected(clock) -> None:
    """The #115 case: a huge value that repeats must not be accepted on the second sighting."""
    entity = _lifetime(_service(), _breaker(consumption=12.0))
    _publish(entity, 12.0)
    for _ in range(5):
        clock.value += 300
        _publish(entity, 9_000.0)
    assert entity._state == 12.0
    assert entity._implausible_rejections == 5


def test_a_long_gap_allows_a_proportionally_larger_rise(clock) -> None:
    entity = _lifetime(_service(), _breaker())
    _publish(entity, 1000.0)
    clock.value += 3 * 24 * 3600  # Home Assistant was off for three days
    _publish(entity, 1030.0)
    _publish(entity, 1030.0)  # the spike check wants a second matching reading
    assert entity._state == pytest.approx(1030.0)


def test_restored_state_timestamp_bounds_the_first_rise(clock) -> None:
    entity = _lifetime(_service(), _breaker())
    entity._state = 100.0
    entity._last_accepted_ts = START - 600  # last saved ten minutes ago
    clock.value = START
    _publish(entity, 5_000.0)
    _publish(entity, 5_000.0)
    assert entity._state == 100.0


def test_reset_service_accepts_an_implausible_value(clock) -> None:
    entity = _lifetime(_service(), _breaker())
    _publish(entity, 100.0)
    clock.value += 300
    _publish(entity, 9_000.0)
    assert entity._state == 100.0
    entity._accept_next_value = True
    _publish(entity, 9_000.0)
    assert entity._state == 9_000.0
    assert entity._implausible_rejections == 0


def test_demoted_panel_switches_the_lifetime_sensor_to_power_x_time(clock) -> None:
    service = _service()
    entity = _lifetime(service, _breaker())
    _publish(entity, 1000.0)
    service._panel_has_hw_counters[PANEL] = False
    assert entity._use_pxt_mode() is True


# ── Daily sensors follow the demotion ──────────────────────────────────


def _daily(service: LDATAService):
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"breakers": {BREAKER_ID: _breaker(power=120.0)}}
    coordinator.config_entry.options = {}
    coordinator._service = service
    coordinator.async_add_listener.return_value = MagicMock()
    entity = sensor.LDATADailyUsageSensor(coordinator, _breaker(), False, PANEL)
    entity.entity_id = "sensor.dryer_daily"
    entity.async_write_ha_state = lambda: None
    return entity


def test_daily_sensor_follows_a_demotion_and_keeps_todays_total(clock, monkeypatch) -> None:
    import datetime

    monkeypatch.setattr(sensor.dt_util, "now", lambda: datetime.datetime.fromtimestamp(clock.value, datetime.timezone.utc))
    service = _service()
    entity = _daily(service)
    entity._state_update()
    assert entity._use_hw_counters is True

    entity._state = 3.5
    service._panel_has_hw_counters[PANEL] = False
    clock.value += 60
    entity._state_update()

    assert entity._use_hw_counters is False
    assert entity._state == pytest.approx(3.5)

    for _ in range(30):  # an hour of 2-minute polls at 120 W adds about 0.12 kWh
        clock.value += 120
        entity._state_update()
    assert 3.5 < entity._state < 3.7


def test_ct_daily_sensor_follows_a_demotion(clock, monkeypatch) -> None:
    import datetime

    monkeypatch.setattr(sensor.dt_util, "now", lambda: datetime.datetime.fromtimestamp(clock.value, datetime.timezone.utc))
    service = _service()
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"cts": {"ct-1": {"id": "ct-1", "panel_id": PANEL, "power": 0.0, "consumption": 500.0}}}
    coordinator.config_entry.options = {}
    coordinator._service = service
    coordinator.async_add_listener.return_value = MagicMock()
    entity = sensor.LDATACTDailyUsageSensor(
        coordinator, {"id": "ct-1", "panel_id": PANEL, "name": "Grid", "channel": 1}
    )
    entity.entity_id = "sensor.grid_daily"
    entity.async_write_ha_state = lambda: None
    entity._state_update()
    assert entity._use_hw_counters is True

    service._panel_has_hw_counters[PANEL] = False
    entity._state_update()
    assert entity._use_hw_counters is False
