"""Durations use the monotonic clock, so setting the system clock can't stretch or swallow them.

The 10 s wait between logins and the intervals that power×time energy
integrates over were measured with time.time(), which jumps when the system
clock is set (an NTP correction, for example). After a step back, the next
login slept for as long as the clock had moved back, holding the lock every
LDATA entry shares, and energy counted nothing until the clock caught up. A
step forward shorter than the gap threshold was counted as if the circuit had
drawn its power all along.
"""

import datetime
from types import SimpleNamespace

import pytest

from custom_components.ldata import ldata_service, sensor
from custom_components.ldata.ldata_service import LDATAService

from test_offline_energy_integration import ALL, KWH_PER_MINUTE, _dt


def test_a_clock_step_back_does_not_stall_the_next_login(monkeypatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(ldata_service.time, "sleep", slept.append)
    monkeypatch.setattr(LDATAService, "_last_login_attempt_time", 4_600.0)
    # The last login was at 4 600 s on both clocks. 400 s later the wall
    # clock is set back an hour; the monotonic clock only moves forward.
    monkeypatch.setattr(ldata_service.time, "monotonic", lambda: 5_000.0)
    monkeypatch.setattr(ldata_service.time, "time", lambda: 1_400.0)

    LDATAService("", "", None)._check_rate_limit()

    assert slept == []


def test_logins_are_still_ten_seconds_apart(monkeypatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(ldata_service.time, "sleep", slept.append)
    monkeypatch.setattr(LDATAService, "_last_login_attempt_time", 4_996.0)
    monkeypatch.setattr(ldata_service.time, "monotonic", lambda: 5_000.0)
    monkeypatch.setattr(ldata_service.time, "time", lambda: 5_000.0)

    LDATAService("", "", None)._check_rate_limit()

    assert slept == [pytest.approx(6.0)]


@pytest.fixture
def clocks(monkeypatch):
    """A wall clock the test sets, and a monotonic clock that only moves forward."""
    clocks = SimpleNamespace(wall=_dt(14, 12), mono=1_000.0)
    monkeypatch.setattr(sensor.dt_util, "now", lambda: clocks.wall)
    monkeypatch.setattr(sensor.time, "time", lambda: clocks.wall.timestamp())
    monkeypatch.setattr(sensor.time, "monotonic", lambda: clocks.mono)
    return clocks


def _run(entity, clocks, minutes: int, *, step_at: int, step: datetime.timedelta) -> None:
    """One update a minute at 3 kW; at update `step_at` the wall clock is also set by `step`."""
    entity._state_update()  # the first update only sets the clock
    for minute in range(1, minutes + 1):
        clocks.mono += 60
        clocks.wall += datetime.timedelta(minutes=1)
        if minute == step_at:
            clocks.wall += step
        entity._state_update()


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_energy_keeps_counting_when_the_clock_steps_back(clocks, make) -> None:
    entity = make()
    _run(entity, clocks, 30, step_at=10, step=-datetime.timedelta(hours=1))
    assert entity._state == pytest.approx(30 * KWH_PER_MINUTE)


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_a_small_clock_step_forward_adds_no_energy(clocks, make) -> None:
    entity = make()
    _run(entity, clocks, 10, step_at=5, step=datetime.timedelta(minutes=3))
    assert entity._state == pytest.approx(10 * KWH_PER_MINUTE)
