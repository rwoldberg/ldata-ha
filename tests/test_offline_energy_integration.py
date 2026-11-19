"""A panel or breaker that is offline adds no power×time energy.

The coordinator re-publishes the last readings while a hub is down. On a panel
without hardware counters the energy sensors integrate power over time, so
those repeats would add the last power times the whole outage: a 3 kW circuit
adds 18 kWh in six hours, which Home Assistant's Energy dashboard can't take
back. What the circuit drew meanwhile is unknown, so it is not counted.
"""

import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import pytest

from custom_components.ldata import sensor
from custom_components.ldata.ldata_base_entity import is_source_offline

TZ = ZoneInfo("America/Los_Angeles")
DAY14 = datetime.date(2026, 10, 14)
DAY15 = datetime.date(2026, 10, 15)
PANEL = "panel-1"
WATTS = 3000.0
KWH_PER_MINUTE = WATTS / 60_000.0
BREAKER = {"id": "b1", "name": "Dryer", "panel_id": PANEL, "poles": 2, "position": 1}
OTHER = {"id": "b2", "name": "Oven", "panel_id": PANEL, "poles": 2, "position": 3}
CT = {"id": "ct-1", "panel_id": PANEL, "name": "Grid", "channel": 1}


def _dt(day: int, hour: int, minute: int = 0, second: int = 0) -> datetime.datetime:
    return datetime.datetime(2026, 10, day, hour, minute, second, tzinfo=TZ)


@pytest.fixture
def clock(monkeypatch):
    """Drive dt_util.now() and time.time() in the sensor module."""
    now = SimpleNamespace(value=_dt(14, 12))
    monkeypatch.setattr(sensor.dt_util, "now", lambda: now.value)
    monkeypatch.setattr(sensor.time, "time", lambda: now.value.timestamp())
    monkeypatch.setattr(sensor.time, "monotonic", lambda: now.value.timestamp())
    return now


def _coordinator() -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {
        "panels": [{"id": PANEL, "connected": True}],
        "breakers": {
            "b1": {**BREAKER, "power": WATTS},
            "b2": {**OTHER, "power": 0.0},
        },
        "cts": {"ct-1": {**CT, "power": WATTS}},
    }
    coordinator.config_entry.options = {}
    coordinator._service.panel_has_hw_counters.return_value = False  # power×time
    coordinator.async_add_listener.return_value = MagicMock()
    return coordinator


def _quiet(entity):
    entity.entity_id = "sensor.test_energy"
    entity.async_write_ha_state = lambda: None
    return entity


def _lifetime_breaker():
    return _quiet(
        sensor.LDATABreakerEnergyUsageSensor(
            _coordinator(), dict(BREAKER), sensor.SENSOR_TYPES[sensor.CONSUMPTION]
        )
    )


def _lifetime_ct():
    return _quiet(
        sensor.LDATAEnergyUsageSensor(_coordinator(), dict(CT), sensor.SENSOR_TYPES[sensor.CONSUMPTION])
    )


def _daily_breaker():
    return _quiet(sensor.LDATADailyUsageSensor(_coordinator(), dict(BREAKER), False, PANEL))


def _daily_panel_total():
    data = {"id": PANEL, "name": "Panel", "serialNumber": PANEL, "poles": 2}
    return _quiet(sensor.LDATADailyUsageSensor(_coordinator(), data, True, PANEL))


def _daily_ct():
    return _quiet(sensor.LDATACTDailyUsageSensor(_coordinator(), dict(CT)))


# Every power×time path: the lifetime and daily sensors of a breaker, a CT and a panel total.
ALL = {
    "lifetime breaker": _lifetime_breaker,
    "lifetime CT": _lifetime_ct,
    "daily breaker": _daily_breaker,
    "daily panel total": _daily_panel_total,
    "daily CT": _daily_ct,
}
DAILY = {name: make for name, make in ALL.items() if name.startswith("daily")}


def _set_online(entity, online: bool) -> None:
    entity.coordinator.data["panels"] = [{"id": PANEL, "connected": online}]


def _run(entity, clock, minutes: int) -> None:
    """One coordinator update a minute, the last power re-published each time."""
    for _ in range(minutes):
        clock.value += datetime.timedelta(minutes=1)
        entity._state_update()


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_an_online_source_integrates_its_power(clock, make) -> None:
    entity = make()
    entity._state_update()  # the first update only sets the clock
    _run(entity, clock, 60)
    assert entity._state == pytest.approx(60 * KWH_PER_MINUTE)


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_a_six_hour_outage_adds_nothing(clock, make) -> None:
    """3 kW for six hours would have added 18 kWh."""
    entity = make()
    entity._state_update()
    _run(entity, clock, 10)
    before = entity._state
    assert before == pytest.approx(10 * KWH_PER_MINUTE)

    _set_online(entity, False)
    _run(entity, clock, 6 * 60)
    assert entity._state == pytest.approx(before)

    # Back online: the first reading only restarts the clock, the next ones count.
    _set_online(entity, True)
    entity._state_update()
    assert entity._state == pytest.approx(before)
    _run(entity, clock, 10)
    assert entity._state == pytest.approx(before + 10 * KWH_PER_MINUTE)


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_the_interval_around_an_outage_is_not_counted(clock, make) -> None:
    """The last reading before the outage and the first after it are hours apart."""
    entity = make()
    entity._state_update()
    _run(entity, clock, 5)
    before = entity._state

    _set_online(entity, False)
    _run(entity, clock, 1)
    clock.value += datetime.timedelta(hours=2)
    _set_online(entity, True)
    entity._state_update()

    assert entity._state == pytest.approx(before)


@pytest.mark.parametrize("make", [_lifetime_breaker, _daily_breaker], ids=["lifetime", "daily"])
def test_a_breaker_reporting_itself_offline_stops_counting(clock, make) -> None:
    entity = make()
    entity._state_update()
    _run(entity, clock, 10)
    before = entity._state

    entity.coordinator.data["breakers"]["b1"]["connected"] = False  # its panel stays online
    _run(entity, clock, 120)
    assert entity._state == pytest.approx(before)

    entity.coordinator.data["breakers"]["b1"]["connected"] = True
    entity._state_update()
    _run(entity, clock, 10)
    assert entity._state == pytest.approx(before + 10 * KWH_PER_MINUTE)


def test_the_panel_total_leaves_out_a_breaker_that_is_offline(clock) -> None:
    entity = _daily_panel_total()
    breakers = entity.coordinator.data["breakers"]
    breakers["b2"]["power"] = 1000.0
    breakers["b2"]["connected"] = False  # the panel and its other breaker are online
    entity._state_update()
    _run(entity, clock, 60)

    assert entity._state == pytest.approx(60 * KWH_PER_MINUTE)  # b1's 3 kW only

    breakers["b2"]["connected"] = True
    _run(entity, clock, 60)
    assert entity._state == pytest.approx(60 * KWH_PER_MINUTE + 60 * (WATTS + 1000.0) / 60_000.0, abs=0.05)


def test_a_missing_connected_flag_counts_as_online(clock) -> None:
    entity = _lifetime_breaker()
    entity.coordinator.data.pop("panels")
    assert "connected" not in entity.coordinator.data["breakers"]["b1"]
    entity._state_update()
    _run(entity, clock, 30)
    assert entity._state == pytest.approx(30 * KWH_PER_MINUTE)


@pytest.mark.parametrize("make", DAILY.values(), ids=DAILY.keys())
def test_midnight_passes_for_an_offline_source(clock, make) -> None:
    """The day starts at 0 while the panel is offline and counts on once it is back."""
    entity = make()
    entity._state_update()
    _run(entity, clock, 10)
    assert entity._state > 0

    clock.value = _dt(14, 23, 58)
    entity._state_update()
    assert entity._last_date == DAY14
    _set_online(entity, False)

    clock.value = _dt(15, 0, 1)
    entity._state_update()
    assert entity._state == 0.0
    assert entity._last_date == DAY15

    _run(entity, clock, 180)
    assert entity._state == 0.0

    _set_online(entity, True)
    entity._state_update()
    _run(entity, clock, 10)
    assert entity._state == pytest.approx(10 * KWH_PER_MINUTE)


# ── The shared check ───────────────────────────────────────────────────


def _coordinator_with(*panels: dict) -> MagicMock:
    coordinator = MagicMock()
    coordinator.data = {"panels": list(panels)}
    return coordinator


def test_a_source_is_offline_when_its_panel_is() -> None:
    coordinator = _coordinator_with({"id": PANEL, "connected": False})
    assert is_source_offline(coordinator, {"panel_id": PANEL}) is True


def test_a_source_is_offline_when_it_says_so_itself() -> None:
    coordinator = _coordinator_with({"id": PANEL, "connected": True})
    assert is_source_offline(coordinator, {"panel_id": PANEL, "connected": False}) is True


@pytest.mark.parametrize(
    "data",
    [
        {"panel_id": PANEL},  # no flag of its own
        {"panel_id": PANEL, "connected": True},
        {"panel_id": "unknown-panel"},  # a panel the coordinator doesn't list
        {},
    ],
)
def test_everything_else_counts_as_online(data) -> None:
    coordinator = _coordinator_with({"id": PANEL, "connected": True})
    assert is_source_offline(coordinator, data) is False
