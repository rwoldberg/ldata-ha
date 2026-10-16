"""The daily energy jitter clamp holds tiny dips within a day, never the day's reset."""

import asyncio
import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from zoneinfo import ZoneInfo

import pytest
from homeassistant.core import State
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from custom_components import ldata as init
from custom_components.ldata import sensor

TZ = ZoneInfo("America/Los_Angeles")
DAY14 = datetime.date(2026, 10, 14)
DAY15 = datetime.date(2026, 10, 15)
BREAKER = {"id": "b1", "name": "Fire Place", "panel_id": "panel-1", "poles": 1, "position": 1}
CT = {"id": "ct-1", "panel_id": "panel-1", "name": "Grid", "channel": 1}


def _dt(day: int, hour: int, minute: int = 0, second: int = 0) -> datetime.datetime:
    return datetime.datetime(2026, 10, day, hour, minute, second, tzinfo=TZ)


@pytest.fixture
def clock(monkeypatch):
    """Drive dt_util.now() and time.time() in the sensor module."""
    now = SimpleNamespace(value=_dt(14, 23, 50))
    monkeypatch.setattr(sensor.dt_util, "now", lambda: now.value)
    monkeypatch.setattr(sensor.time, "time", lambda: now.value.timestamp())
    return now


def _coordinator(hw_counters: bool = False) -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {
        "breakers": {"b1": {**BREAKER, "power": 0.0, "consumption": 100.0}},
        "cts": {"ct-1": {**CT, "power": 0.0, "consumption": 500.0}},
    }
    coordinator.config_entry.options = {}
    coordinator._service.panel_has_hw_counters.return_value = hw_counters
    coordinator.async_add_listener.return_value = MagicMock()
    return coordinator


def _reporting(entity):
    """Record what HA would store: async_write_ha_state reads native_value."""
    entity.entity_id = "sensor.test_daily"
    entity.reported = []
    entity.async_write_ha_state = lambda: entity.reported.append(entity.native_value)
    return entity


def _breaker_daily(hw_counters: bool = False, panel_total: bool = False):
    coordinator = _coordinator(hw_counters)
    if panel_total:
        data = {"id": "panel-1", "name": "Panel", "serialNumber": "panel-1", "poles": 2}
        entity = sensor.LDATADailyUsageSensor(coordinator, data, True, "panel-1")
    else:
        entity = sensor.LDATADailyUsageSensor(coordinator, dict(BREAKER), False, "panel-1")
    return _reporting(entity)


def _ct_daily(hw_counters: bool = False):
    return _reporting(sensor.LDATACTDailyUsageSensor(_coordinator(hw_counters), dict(CT)))


def _end_day_at(entity, clock, value: float) -> None:
    """Leave the sensor reporting ``value`` for the 14th, as before midnight."""
    clock.value = _dt(14, 23, 50)
    entity._state = value
    entity._last_date = DAY14
    entity.async_write_ha_state()
    assert entity.reported[-1] == value


# ── Day rollover ───────────────────────────────────────────────────────


@pytest.mark.parametrize("panel_total", [False, True])
def test_breaker_daily_resets_to_zero_after_a_small_day(clock, panel_total) -> None:
    entity = _breaker_daily(panel_total=panel_total)
    entity._state_update()  # first update: picks power×time mode
    _end_day_at(entity, clock, 0.02)

    clock.value = _dt(15, 0, 0, 26)
    entity._state_update()

    assert entity._state == 0.0
    assert entity.reported[-1] == 0.0
    assert entity._last_date == DAY15


def test_breaker_daily_hw_counter_resets_to_zero_after_a_small_day(clock) -> None:
    entity = _breaker_daily(hw_counters=True)
    entity._midnight_baseline = 99.98
    entity._state_update()
    _end_day_at(entity, clock, 0.02)

    clock.value = _dt(15, 0, 0, 26)
    entity.coordinator.data["breakers"]["b1"]["consumption"] = 100.0
    entity._state_update()

    assert entity.reported[-1] == 0.0
    assert entity._midnight_baseline == 100.0


def test_small_breaker_hw_counter_starts_the_day_once(clock) -> None:
    # A lifetime counter still below 1 kWh takes the deferred-baseline branch.
    entity = _breaker_daily(hw_counters=True)
    breaker = entity.coordinator.data["breakers"]["b1"]
    breaker["consumption"] = 0.22
    entity._midnight_baseline = 0.2
    entity._state_update()
    _end_day_at(entity, clock, 0.02)

    for minute, consumption in ((0, 0.25), (1, 0.3), (2, 0.35)):
        clock.value = _dt(15, 0, minute, 26)
        breaker["consumption"] = consumption
        entity._state_update()
        assert entity._last_date == DAY15

    assert entity.reported[-3:] == [0.0, 0.0, 0.05]


@pytest.mark.parametrize("midnight_sum", [500.0, 0.0])
def test_panel_total_hw_counter_starts_the_day_once(clock, midnight_sum) -> None:
    entity = _breaker_daily(hw_counters=True, panel_total=True)
    ct = entity.coordinator.data["cts"]["ct-1"]
    entity._midnight_baseline = 499.98
    entity._state_update()
    _end_day_at(entity, clock, 0.02)

    clock.value = _dt(15, 0, 0, 26)
    ct["consumption"] = midnight_sum  # 0.0: CT counters still null
    entity._state_update()
    assert entity.reported[-1] == 0.0
    assert entity._last_date == DAY15

    for minute, consumption in ((1, 500.0), (2, 500.04)):
        clock.value = _dt(15, 0, minute)
        ct["consumption"] = consumption
        entity._state_update()

    assert entity.reported[-1] == 0.04


@pytest.mark.parametrize("hw_counters", [False, True])
def test_ct_daily_resets_to_zero_after_a_small_day(clock, hw_counters) -> None:
    entity = _ct_daily(hw_counters)
    entity._midnight_baseline = 499.95
    entity._state_update()
    _end_day_at(entity, clock, 0.05)

    clock.value = _dt(15, 0, 0, 26)
    entity._state_update()

    assert entity.reported[-1] == 0.0
    assert entity._last_date == DAY15


def test_first_reading_of_the_day_below_yesterday_is_reported(clock) -> None:
    # The day's reset is not only to 0: the first value of the new day can
    # be a small positive number that is still below yesterday's total.
    entity = _breaker_daily(hw_counters=True)
    entity._midnight_baseline = 99.96
    entity._state_update()
    _end_day_at(entity, clock, 0.04)

    clock.value = _dt(15, 0, 0, 26)
    entity._state_update()  # new-day baseline: 100.0
    entity.coordinator.data["breakers"]["b1"]["consumption"] = 100.01
    clock.value = _dt(15, 0, 5)
    entity._state_update()

    assert entity.reported[-2:] == [0.0, 0.01]


# ── Same-day jitter ────────────────────────────────────────────────────


@pytest.mark.parametrize("make", [_breaker_daily, _ct_daily])
def test_same_day_dip_is_still_clamped(clock, make) -> None:
    entity = make()
    entity._last_date = DAY14
    for state in (21.31, 21.29, 21.30, 21.33):
        entity._state = state
        entity.async_write_ha_state()

    assert entity.reported == [21.31, 21.31, 21.31, 21.33]


def test_same_day_dip_after_the_reset_is_clamped(clock) -> None:
    entity = _breaker_daily()
    entity._state_update()
    _end_day_at(entity, clock, 0.02)
    clock.value = _dt(15, 0, 0, 26)
    entity._state_update()

    entity._state = 0.05
    entity.async_write_ha_state()
    entity._state = 0.03
    entity.async_write_ha_state()

    assert entity.reported[-3:] == [0.0, 0.05, 0.05]


def test_larger_same_day_drop_is_reported(clock) -> None:
    entity = _breaker_daily()
    entity._last_date = DAY14
    entity._state = 3.0
    entity.async_write_ha_state()
    entity._state = 2.9
    entity.async_write_ha_state()

    assert entity.reported == [3.0, 2.9]


# ── Restore across midnight ────────────────────────────────────────────


async def _add(entity, state: str, last_date: datetime.date, data: bool = True, **attrs) -> None:
    """Restore ``state`` and add the entity the way HA does.

    async_added_to_hass runs one update right away when the coordinator
    has data; HA then writes the state. Without data (the first refresh
    has not arrived yet) HA writes the restored value.
    """
    entity.hass = MagicMock()
    entity.async_get_last_state = AsyncMock(
        return_value=State(
            "sensor.test_daily", state, {"last_date": last_date.isoformat(), **attrs}
        )
    )
    coordinator_data = entity.coordinator.data
    if not data:
        entity.coordinator.data = {}
    await entity.async_added_to_hass()
    entity.async_write_ha_state()
    entity.coordinator.data = coordinator_data


@pytest.fixture
def no_coordinator_listener(monkeypatch):
    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())


@pytest.mark.parametrize("make", [_breaker_daily, _ct_daily])
def test_restore_after_midnight_before_first_data_does_not_carry_yesterday(
    clock, no_coordinator_listener, make
) -> None:
    entity = make()
    clock.value = _dt(15, 0, 3)

    asyncio.run(_add(entity, "0.02", DAY14, data=False))
    assert entity.reported == [0.02]

    entity._state_update()

    assert entity.reported[-1] == 0.0
    assert entity._last_date == DAY15


@pytest.mark.parametrize("make", [_breaker_daily, _ct_daily])
def test_restore_after_midnight_with_data_does_not_carry_yesterday(
    clock, no_coordinator_listener, make
) -> None:
    entity = make()
    clock.value = _dt(15, 0, 3)

    asyncio.run(_add(entity, "0.02", DAY14))

    assert entity.reported == [0.0, 0.0]
    assert entity._last_date == DAY15


def test_restore_after_midnight_hw_counter_does_not_carry_yesterday(
    clock, no_coordinator_listener
) -> None:
    entity = _breaker_daily(hw_counters=True)
    clock.value = _dt(15, 0, 3)

    asyncio.run(_add(entity, "0.03", DAY14, data=False, midnight_baseline=99.97))
    entity._state_update()

    assert entity.reported == [0.03, 0.0]
    assert entity._midnight_baseline == 100.0


@pytest.mark.parametrize(
    ("make", "source", "key", "baseline", "computed"),
    [
        (_breaker_daily, "breakers", "b1", 98.68, 99.98),
        (_ct_daily, "cts", "ct-1", 498.68, 499.98),
    ],
)
def test_same_day_restore_with_data_keeps_the_clamp(
    clock, no_coordinator_listener, make, source, key, baseline, computed
) -> None:
    # Recorded 1.32; the first update after the restart computes 1.30.
    entity = make(hw_counters=True)
    entity.coordinator.data[source][key]["consumption"] = computed
    clock.value = _dt(14, 18, 0)

    asyncio.run(_add(entity, "1.32", DAY14, midnight_baseline=baseline))

    assert entity._state == pytest.approx(1.30)
    assert entity.reported == [1.32, 1.32]


@pytest.mark.parametrize(
    ("make", "source", "key", "baseline"),
    [(_breaker_daily, "breakers", "b1", 99.97), (_ct_daily, "cts", "ct-1", 499.97)],
)
def test_restore_after_midnight_with_data_hw_counter_resets(
    clock, no_coordinator_listener, make, source, key, baseline
) -> None:
    entity = make(hw_counters=True)
    clock.value = _dt(15, 0, 3)

    asyncio.run(_add(entity, "0.03", DAY14, midnight_baseline=baseline))

    assert entity.reported == [0.0, 0.0]
    assert entity._last_date == DAY15


def test_restore_on_the_same_day_keeps_the_clamp(clock, no_coordinator_listener) -> None:
    entity = _breaker_daily(hw_counters=True)
    clock.value = _dt(14, 18, 0)

    asyncio.run(_add(entity, "1.32", DAY14, data=False, midnight_baseline=98.68))
    entity.coordinator.data["breakers"]["b1"]["consumption"] = 99.98  # 1.30 today
    entity._state_update()

    assert entity.reported == [1.32, 1.32]


# ── Rollover without a usable reading ──────────────────────────────────


def test_midnight_null_counter_does_not_carry_yesterday(clock) -> None:
    entity = _breaker_daily(hw_counters=True)
    entity._midnight_baseline = 98.0
    entity._state_update()
    assert entity._state == 2.0

    # Counters read null right after midnight: _get_breaker_consumption
    # rejects the near-zero value, so the day cannot start yet.
    breaker = entity.coordinator.data["breakers"]["b1"]
    breaker["consumption"] = 0.0
    for second in (26, 40):
        clock.value = _dt(15, 0, 0, second)
        entity._state_update()
        assert entity._last_date == DAY14
        assert entity._midnight_baseline == 98.0

    # The first real reading starts the day and becomes its baseline.
    clock.value = _dt(15, 0, 5)
    breaker["consumption"] = 100.1
    entity._state_update()
    assert entity.reported[-1] == 0.0
    assert entity._last_date == DAY15

    clock.value = _dt(15, 0, 10)
    breaker["consumption"] = 100.3
    entity._state_update()
    assert entity._state == pytest.approx(0.2)


def test_midnight_without_breaker_data_does_not_carry_yesterday(clock) -> None:
    entity = _breaker_daily()
    breakers = entity.coordinator.data["breakers"]
    breakers["b1"]["power"] = 1000.0
    clock.value = _dt(14, 23, 59, 50)
    entity._state_update()
    entity._state = 1.5
    entity.async_write_ha_state()

    # No breaker data in the first update of the day: the day cannot start yet.
    clock.value = _dt(15, 0, 0, 26)
    entity.coordinator.data["breakers"] = {}
    entity._state_update()
    assert entity._last_date == DAY14

    # The next reading starts the day; power×time counts from there, not
    # from the last update before midnight.
    entity.coordinator.data["breakers"] = breakers
    clock.value = _dt(15, 0, 0, 40)
    entity._state_update()
    assert entity.reported[-1] == 0.0
    clock.value = _dt(15, 0, 1, 40)
    entity._state_update()

    assert entity._state == pytest.approx(1000.0 / 60 / 1000)


# ── reset_energy_baseline ──────────────────────────────────────────────


@pytest.mark.parametrize("make", [_breaker_daily, _ct_daily])
def test_forced_value_below_the_reported_value_is_reported(clock, make) -> None:
    entity = make()
    entity._last_date = DAY14
    entity._state = 0.04
    entity.async_write_ha_state()

    # What the service's forced-value path does.
    entity._state = 0.0
    entity._accept_next_value = False
    entity.async_write_ha_state()

    assert entity.reported == [0.04, 0.0]


@pytest.mark.parametrize("make", [_breaker_daily, _ct_daily])
def test_full_reset_below_the_reported_value_is_reported(clock, make) -> None:
    entity = make()
    entity._last_date = DAY14
    entity._state = 0.04
    entity.async_write_ha_state()

    init._reset_energy_entity(entity, "sensor.test_daily")

    assert entity.reported == [0.04, 0.0]
