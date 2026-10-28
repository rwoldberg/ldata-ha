"""Ledger-backed energy sensors restore their unrounded state across a restart.

The recorded state is rounded to 0.01 kWh, while a ledger-backed sensor
adds exact ledger increments to its state. Restoring the rounded value
shifted the state against the ledger by up to 0.005 kWh at every restart
(2026-10-20, one restart at 22:35: the panel's Daily Consumption ended the
day at 38.80 kWh against a ledger total of 38.7916 kWh), and the shift went
into the long-term statistics.
"""

import asyncio
import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.core import State
from homeassistant.helpers.restore_state import RestoredExtraData
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from tests.test_ldata_hourly_energy import (  # noqa: F401  (fixtures)
    BREAKER,
    LDATAEnergyLedger,
    _daily_sensor,
    _lifetime_sensor,
    _pacific_time,
    _record_followups,
    _record_writes,
    _ts,
    sensor_clock,
)

DAY14 = datetime.date(2026, 10, 14)
DAY15 = datetime.date(2026, 10, 15)

# Hourly bursts of the 14th whose sum has more than two decimals.
BURSTS_14 = [1.2345671, 2.3456782, 0.0113457]


def _ledger(bursts=BURSTS_14, start_hour=13) -> LDATAEnergyLedger:
    ledger = LDATAEnergyLedger()
    for offset, kwh in enumerate(bursts):
        ledger.apply("tech", 15, {"1": kwh}, _ts(14, start_hour, 0, 29) + offset * 3600, "WS")
    return ledger


def _two_breaker_ledger() -> tuple[LDATAEnergyLedger, dict]:
    ledger = _ledger()
    ledger.apply("other", 15, {"1": 0.7777771}, _ts(14, 13, 0, 29), "WS")
    breakers = {
        "tech": dict(BREAKER),
        "other": {**BREAKER, "id": "other", "stable_id": "other", "name": "Other", "position": 3},
    }
    return ledger, breakers


def _saved(entity) -> tuple[State, RestoredExtraData | None]:
    """Return what Home Assistant's restore cache keeps for ``entity`` at shutdown."""
    state = State(
        "sensor.tech_energy", str(entity.native_value), dict(entity.extra_state_attributes)
    )
    extra = entity.extra_restore_state_data
    return state, None if extra is None else RestoredExtraData(extra.as_dict())


def _restart(entity, state: State, extra: RestoredExtraData | None, monkeypatch) -> None:
    """Add ``entity`` to Home Assistant with ``state`` and ``extra`` as the restore data."""
    entity.hass = MagicMock()
    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    entity.async_get_last_state = AsyncMock(return_value=state)
    entity.async_get_last_extra_data = AsyncMock(return_value=extra)
    asyncio.run(entity.async_added_to_hass())


def _daily(ledger, keys=("tech",), day=DAY14) -> float:
    values = [ledger.daily(key, day) for key in keys]
    return values[0] if len(values) == 1 else sum(values)


# ── Daily Consumption ──────────────────────────────────────────────────


@pytest.mark.parametrize("panel_total", [False, True])
def test_daily_sensor_restart_restores_the_unrounded_state(
    sensor_clock, monkeypatch, panel_total  # noqa: F811
) -> None:
    ledger, breakers = _two_breaker_ledger()
    keys = ("tech", "other") if panel_total else ("tech",)
    entity = _daily_sensor(ledger, breakers, panel_total=panel_total)
    sensor_clock.value = _ts(14, 15, 10)
    entity._state_update()
    assert entity._state == _daily(ledger, keys)
    state, extra = _saved(entity)
    assert extra is not None
    assert float(state.state) != entity._state  # The recorded state is rounded.

    restarted = _daily_sensor(ledger, breakers, panel_total=panel_total)
    _restart(restarted, state, extra, monkeypatch)
    assert restarted._state == _daily(ledger, keys)

    # It keeps following the ledger exactly.
    ledger.apply("tech", 15, {"1": 0.0234567}, _ts(14, 16, 0, 29), "WS")
    sensor_clock.value = _ts(14, 16, 1)
    restarted._state_update()
    assert restarted._state == _daily(ledger, keys)


@pytest.mark.parametrize("panel_total", [False, True])
def test_daily_sensor_restart_without_restore_data_takes_the_ledger_total(
    sensor_clock, monkeypatch, panel_total  # noqa: F811
) -> None:
    """A state saved by an earlier version: only the rounded recorded state.

    2026-10-20: 38.38 recorded with a ledger_ref of 38.375731 at the 22:35
    restart; the day then ended at 38.80 against a ledger total of 38.7916.
    """
    ledger, breakers = _two_breaker_ledger()
    keys = ("tech", "other") if panel_total else ("tech",)
    value = _daily(ledger, keys)
    state = State(
        "sensor.tech_daily_consumption",
        str(round(value, 2)),
        {"last_date": "2026-10-14", "ledger_ref": value},
    )
    entity = _daily_sensor(ledger, breakers, panel_total=panel_total)
    sensor_clock.value = _ts(14, 15, 10)
    _restart(entity, state, None, monkeypatch)
    assert entity._state == value

    ledger.apply("tech", 15, {"1": 0.0234567}, _ts(14, 16, 0, 29), "WS")
    sensor_clock.value = _ts(14, 16, 1)
    entity._state_update()
    assert entity._state == _daily(ledger, keys)


def test_daily_sensor_restart_removes_the_rounding_of_earlier_restarts(
    sensor_clock, monkeypatch  # noqa: F811
) -> None:
    """The state recorded after an earlier restart is 0.0084 kWh above the ledger."""
    ledger = _ledger()
    value = ledger.daily("tech", DAY14)
    entity = _daily_sensor(ledger)
    writes = _record_writes(entity, added=False)
    sensor_clock.value = _ts(14, 15, 10)
    _restart(
        entity,
        State(
            "sensor.tech_daily_consumption",
            str(round(value + 0.0084, 2)),
            {"last_date": "2026-10-14", "ledger_ref": value},
        ),
        None,
        monkeypatch,
    )
    assert entity._state == value
    assert round(value, 2) < round(value + 0.0084, 2)

    # The value Home Assistant last recorded is not followed by a lower one
    # (the jitter clamp holds it) until the ledger total passes it.
    entity.added = True
    entity.async_write_ha_state()
    assert writes == [(round(value + 0.0084, 2), "2026-10-14", value)]
    ledger.apply("tech", 15, {"1": 0.05}, _ts(14, 16, 0, 29), "WS")
    sensor_clock.value = _ts(14, 16, 1)
    entity._state_update()
    assert entity._state == ledger.daily("tech", DAY14)
    assert writes[-1][0] == round(ledger.daily("tech", DAY14), 2)


def test_daily_sensor_restart_keeps_a_real_difference_to_the_ledger(
    sensor_clock, monkeypatch  # noqa: F811
) -> None:
    """The first day under the ledger keeps the state it had before (an upgrade)."""
    ledger = _ledger()
    value = ledger.daily("tech", DAY14)
    entity = _daily_sensor(ledger)
    sensor_clock.value = _ts(14, 15, 10)
    _restart(
        entity,
        State(
            "sensor.tech_daily_consumption",
            str(round(value + 1.5, 2)),
            {"last_date": "2026-10-14", "ledger_ref": value},
        ),
        None,
        monkeypatch,
    )
    assert entity._state == round(value + 1.5, 2)

    # With restore data the difference comes back exactly.
    entity._state = value + 1.5
    state, extra = _saved(entity)
    restarted = _daily_sensor(ledger)
    _restart(restarted, state, extra, monkeypatch)
    assert restarted._state == value + 1.5


def test_daily_sensor_ignores_restore_data_of_another_ledger_reference(
    sensor_clock, monkeypatch  # noqa: F811
) -> None:
    ledger = _ledger()
    value = ledger.daily("tech", DAY14)
    entity = _daily_sensor(ledger)
    sensor_clock.value = _ts(14, 15, 10)
    _restart(
        entity,
        State(
            "sensor.tech_daily_consumption",
            str(round(value, 2)),
            {"last_date": "2026-10-14", "ledger_ref": value},
        ),
        RestoredExtraData({"ledger_state": 99.0, "ledger_ref": 1.0}),
        monkeypatch,
    )
    assert entity._state == value


def test_daily_sensor_restart_before_one_stays_on_the_day(sensor_clock, monkeypatch) -> None:  # noqa: F811
    """Shut down at 00:58, back at 00:59: the 14th is still being filled."""
    ledger = _ledger(start_hour=22)  # 21:00-24:00 on the 14th
    entity = _daily_sensor(ledger)
    sensor_clock.value = _ts(15, 0, 58)
    entity._state_update()
    state, extra = _saved(entity)

    restarted = _daily_sensor(ledger)
    writes = _record_writes(restarted, added=False)
    sensor_clock.value = _ts(15, 0, 59)
    _restart(restarted, state, extra, monkeypatch)
    assert restarted._state == ledger.daily("tech", DAY14)
    assert restarted._last_date == DAY14

    # 01:00: the day's reset, then the new day's ledger total.
    scheduled = _record_followups(monkeypatch)
    restarted.added = True
    ledger.apply("tech", 15, {"1": 0.0456789}, _ts(15, 1, 0, 29), "WS")
    sensor_clock.value = _ts(15, 1, 0, 40)
    restarted._state_update()
    assert writes[-1] == (0.0, "2026-10-15", 0.0)
    assert len(scheduled) == 1
    sensor_clock.value = _ts(15, 1, 0, 41)
    scheduled[0].action(None)
    assert restarted._state == ledger.daily("tech", DAY15)


@pytest.mark.parametrize("with_extra", [True, False])
def test_daily_sensor_restart_across_one_resets_then_takes_the_new_day(
    sensor_clock, monkeypatch, with_extra  # noqa: F811
) -> None:
    """Shut down at 00:59, back at 01:01 after the 01:00 burst was stored."""
    ledger = _ledger(start_hour=22)
    entity = _daily_sensor(ledger)
    sensor_clock.value = _ts(15, 0, 59)
    entity._state_update()
    state, extra = _saved(entity)

    ledger.apply("tech", 15, {"1": 0.0456789}, _ts(15, 1, 0, 29), "WS")
    restarted = _daily_sensor(ledger)
    writes = _record_writes(restarted, added=False)
    scheduled = _record_followups(monkeypatch)
    sensor_clock.value = _ts(15, 1, 1)
    _restart(restarted, state, extra if with_extra else None, monkeypatch)
    restarted.added = True
    restarted.async_write_ha_state()  # Entity.add_to_platform_finish
    assert writes == [(0.0, "2026-10-15", 0.0)]

    sensor_clock.value = _ts(15, 1, 1, 1)
    scheduled[0].action(None)
    assert restarted._state == ledger.daily("tech", DAY15)
    assert restarted._last_date == DAY15


def test_daily_sensor_restart_just_after_the_reset(sensor_clock, monkeypatch) -> None:  # noqa: F811
    """Shut down at 01:00:10 (state 0 for the 15th), back at 01:01 after the 01:00 burst."""
    ledger = _ledger(start_hour=22)
    entity = _daily_sensor(ledger)
    sensor_clock.value = _ts(15, 0, 59)
    entity._state_update()
    sensor_clock.value = _ts(15, 1, 0, 10)
    entity._state_update()
    assert (entity._state, entity._last_date) == (0.0, DAY15)
    state, extra = _saved(entity)

    ledger.apply("tech", 15, {"1": 0.0456789}, _ts(15, 1, 0, 29), "WS")
    restarted = _daily_sensor(ledger)
    sensor_clock.value = _ts(15, 1, 1)
    _restart(restarted, state, extra, monkeypatch)
    assert restarted._state == ledger.daily("tech", DAY15)
    assert restarted._last_date == DAY15


def test_whems_daily_sensor_restore_is_unchanged(sensor_clock, monkeypatch) -> None:  # noqa: F811
    """A daily sensor that does not follow the ledger saves no restore data and restores as before."""
    entity = _daily_sensor(LDATAEnergyLedger(), hourly=False)
    entity._state = 1.23456
    assert entity.extra_restore_state_data is None

    restarted = _daily_sensor(LDATAEnergyLedger(), hourly=False)
    restarted.hass = MagicMock()
    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    restarted.async_get_last_state = AsyncMock(
        return_value=State("sensor.tech_daily_consumption", "1.23", {"last_date": "2026-10-14"})
    )
    restarted.async_get_last_extra_data = AsyncMock(return_value=None)
    asyncio.run(restarted.async_added_to_hass())
    restarted.async_get_last_extra_data.assert_not_awaited()
    assert restarted._ledger_ref is None


# ── Consumption (lifetime) ─────────────────────────────────────────────


def test_lifetime_sensor_restart_restores_the_unrounded_state(monkeypatch) -> None:
    ledger = _ledger()
    entity = _lifetime_sensor(ledger)
    entity._state = 1156.3  # Kept from before the ledger.
    entity._state_update()
    entity._ledger_ref = 0.0  # The ledger started at 0 under this sensor.
    entity._state_update()
    exact = entity._state
    state, extra = _saved(entity)
    assert float(state.state) != exact

    restarted = _lifetime_sensor(ledger)
    _restart(restarted, state, extra, monkeypatch)
    assert restarted._state == exact

    # Without restore data (saved by an earlier version): the recorded value.
    restarted = _lifetime_sensor(ledger)
    _restart(restarted, state, None, monkeypatch)
    assert restarted._state == float(state.state)


def test_whems_lifetime_sensor_saves_no_restore_data() -> None:
    entity = _lifetime_sensor(LDATAEnergyLedger(), hourly=False)
    entity._state = 12.3456
    assert entity.extra_restore_state_data is None
