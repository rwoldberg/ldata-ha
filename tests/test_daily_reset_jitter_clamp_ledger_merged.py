"""The daily jitter clamp over ledger-backed Daily Consumption sensors.

Needs both fix/ldata-hourly-energy (the ledger and its 01:00 day rollover)
and fix/ldata-daily-reset-jitter-clamp (the day-aware clamp), so it is
added by whichever of the two PRs merges second.
"""

import asyncio
import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.core import State
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from tests.test_ldata_hourly_energy import (  # noqa: F401  (fixtures)
    LDATAEnergyLedger,
    _daily_sensor,
    _pacific_time,
    _reset_baseline,
    _ts,
    sensor_clock,
)

DAY14 = datetime.date(2026, 10, 14)
DAY15 = datetime.date(2026, 10, 15)


def _reporting(entity):
    """Record what HA would store: async_write_ha_state reads native_value."""
    entity.reported = []
    entity.async_write_ha_state = MagicMock(
        side_effect=lambda: entity.reported.append(entity.native_value)
    )
    return entity


@pytest.mark.parametrize("panel_total", [False, True])
def test_ledger_daily_resets_at_one_after_a_small_day(sensor_clock, panel_total) -> None:  # noqa: F811
    ledger = LDATAEnergyLedger()
    entity = _reporting(_daily_sensor(ledger, panel_total=panel_total))
    ledger.apply("tech", 15, {"1": 0.01}, _ts(14, 23, 0, 29), "WS")
    sensor_clock.value = _ts(14, 23, 1, 30)
    entity._state_update()

    # The 00:00:29 burst still counts for the 14th; no reset at midnight.
    ledger.apply("tech", 15, {"1": 0.01}, _ts(15, 0, 0, 29), "WS")
    sensor_clock.value = _ts(15, 0, 1, 30)
    entity._state_update()
    assert entity.reported == [0.01, 0.02]

    # The ledger day changes at 01:00: the 14th ended at 0.02 kWh.
    sensor_clock.value = _ts(15, 1, 0, 5)
    entity._state_update()
    assert entity._last_date == DAY15
    assert entity.reported[-1] == 0.0

    # Within the 15th the clamp still holds back a small dip.
    ledger.apply("tech", 15, {"1": 0.04}, _ts(15, 1, 0, 29), "WS")
    sensor_clock.value = _ts(15, 1, 1, 30)
    entity._state_update()
    entity._state -= 0.01
    entity.async_write_ha_state()
    assert entity.reported[-2:] == [0.04, 0.04]


def test_ledger_daily_small_day_resets_when_the_new_day_has_energy(sensor_clock) -> None:  # noqa: F811
    """The 01:00:29 burst is stored before the first update past 01:00.

    The day change reports 0 for one update before the day's total; the
    clamp must not hold back that 0 after a day that ended at 0.03 kWh.
    """
    ledger = LDATAEnergyLedger()
    entity = _reporting(_daily_sensor(ledger))
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 23, 0, 29), "WS")
    sensor_clock.value = _ts(14, 23, 1)
    entity._state_update()

    ledger.apply("tech", 15, {"1": 0.5}, _ts(15, 1, 0, 29), "WS")
    sensor_clock.value = _ts(15, 1, 0, 40)
    entity._state_update()
    sensor_clock.value = _ts(15, 1, 1, 40)
    entity._state_update()

    assert entity.reported == [0.03, 0.0, 0.5]


def test_ledger_daily_upgrade_after_midnight_resets_at_one(sensor_clock) -> None:  # noqa: F811
    ledger = LDATAEnergyLedger()
    entity = _reporting(_daily_sensor(ledger))
    # The old code reset at 00:00 and stored the calendar date.
    entity._state = 0.03
    entity._last_date = DAY15
    entity.async_write_ha_state()
    ledger.apply("tech", 15, {"1": 0.05}, _ts(15, 0, 0, 29), "WS")
    sensor_clock.value = _ts(15, 0, 30)
    entity._state_update()
    assert entity._last_date == DAY14
    assert entity.reported[-1] == 0.03

    sensor_clock.value = _ts(15, 1, 0, 5)
    entity._state_update()
    assert entity.reported[-1] == 0.0


def test_ledger_daily_restore_after_one_does_not_carry_yesterday(
    sensor_clock, monkeypatch  # noqa: F811
) -> None:
    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03}, _ts(15, 0, 0, 29), "WS")
    entity = _reporting(_daily_sensor(ledger))
    entity.hass = MagicMock()
    entity.async_get_last_state = AsyncMock(
        return_value=State(
            "sensor.tech_daily_consumption",
            "0.03",
            {"last_date": DAY14.isoformat(), "ledger_ref": 0.03},
        )
    )
    sensor_clock.value = _ts(15, 1, 5)

    # Restored before the first coordinator data: HA writes the restored value.
    coordinator_data = entity.coordinator.data
    entity.coordinator.data = {}
    asyncio.run(entity.async_added_to_hass())
    entity.async_write_ha_state()
    entity.coordinator.data = coordinator_data
    assert entity.reported == [0.03]

    entity._state_update()

    assert entity._last_date == DAY15
    assert entity.reported[-1] == 0.0


@pytest.mark.parametrize(
    ("now", "restored", "last_date", "ledger_ref", "expected"),
    [
        # Restart after 01:00 with data present: the 15th starts at 0.
        (_ts(15, 1, 5), "0.03", DAY14, 0.03, [0.0, 0.0]),
        # Same ledger day: the restored value stays.
        (_ts(14, 23, 30), "0.08", DAY14, 0.08, [0.08, 0.08]),
    ],
)
def test_ledger_daily_restore_with_data(
    sensor_clock, monkeypatch, now, restored, last_date, ledger_ref, expected  # noqa: F811
) -> None:
    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.05}, _ts(14, 22, 0, 29), "WS")
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 23, 0, 29), "WS")
    entity = _reporting(_daily_sensor(ledger))
    entity.hass = MagicMock()
    entity.async_get_last_state = AsyncMock(
        return_value=State(
            "sensor.tech_daily_consumption",
            restored,
            {"last_date": last_date.isoformat(), "ledger_ref": ledger_ref},
        )
    )
    sensor_clock.value = now

    # The first update runs inside async_added_to_hass; HA then writes the state.
    asyncio.run(entity.async_added_to_hass())
    entity.async_write_ha_state()

    assert entity.reported == expected


@pytest.mark.asyncio
async def test_forced_value_just_below_the_state_is_reported(sensor_clock) -> None:  # noqa: F811
    entity = _reporting(_daily_sensor(LDATAEnergyLedger(), hourly=False))
    entity._last_date = DAY14
    entity._state = 0.04
    entity.async_write_ha_state()

    await _reset_baseline(entity, value=0.0)

    assert entity.reported == [0.04, 0.0]
