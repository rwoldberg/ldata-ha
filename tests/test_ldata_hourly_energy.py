"""LDATA breaker energy: hourly deltas booked into a persisted lifetime/daily ledger."""

import datetime
import http.client
import json
import math
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from zoneinfo import ZoneInfo

import pytest
import requests
from homeassistant.core import State
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from custom_components import ldata as init
from custom_components.ldata import ldata_energy, ldata_service, sensor
from custom_components.ldata.coordinator import LDATAUpdateCoordinator
from custom_components.ldata.ldata_energy import (
    LDATAEnergyLedger,
    current_daily_date,
    hourly_bound_kwh,
)
from custom_components.ldata.ldata_service import LDATAService

TZ = ZoneInfo("America/Los_Angeles")


def _ts(day: int, hour: int, minute: int = 0, second: int = 0) -> float:
    """Epoch seconds for 2026-10-<day> <hour>:<minute>:<second> Pacific time."""
    return datetime.datetime(2026, 10, day, hour, minute, second, tzinfo=TZ).timestamp()


@pytest.fixture(autouse=True)
def _pacific_time():
    previous = dt_util.get_default_time_zone()
    dt_util.set_default_time_zone(TZ)
    yield
    dt_util.set_default_time_zone(previous)


def _today(ledger: LDATAEnergyLedger, key: str, day: int) -> float | None:
    return ledger.daily(key, datetime.date(2026, 10, day))


# ── Ledger ─────────────────────────────────────────────────────────────


def test_hourly_bound_uses_breaker_rating_with_fallback() -> None:
    assert hourly_bound_kwh(15) == pytest.approx(3.6)
    assert hourly_bound_kwh(30) == pytest.approx(7.2)
    for missing in (None, 0, "", "n/a", float("nan")):
        assert hourly_bound_kwh(missing) == pytest.approx(14.4)


def test_hourly_bursts_accumulate_into_lifetime_and_daily() -> None:
    ledger = LDATAEnergyLedger()

    # Values from the capture: one breaker's bursts at 16:00:29 and 17:00:29.
    assert ledger.apply("tech", 15, {"1": 0.032349, "2": 0.0}, _ts(14, 16, 0, 29), "WS")
    assert ledger.apply("tech", 15, {"1": 0.032470, "2": 0.0}, _ts(14, 17, 0, 29), "WS")

    assert ledger.lifetime("tech") == pytest.approx(0.064819)
    assert _today(ledger, "tech", 14) == pytest.approx(0.064819)
    assert ledger.dirty


def test_same_hour_is_booked_once() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.032349, "2": 0.0}, _ts(14, 16, 0, 29), "WS")

    # A duplicate WS frame and the rounded listing value later in the hour.
    assert not ledger.apply("tech", 15, {"1": 0.032349, "2": 0.0}, _ts(14, 16, 0, 30), "WS")
    assert not ledger.apply("tech", 15, {"1": 0.03, "2": 0.0}, _ts(14, 16, 31), "REST")

    assert ledger.lifetime("tech") == pytest.approx(0.032349)


def test_legs_are_tracked_separately() -> None:
    ledger = LDATAEnergyLedger()

    # A 240 V breaker where only leg 2 draws. A message with only leg 1 does not block leg 2.
    ledger.apply("twopole", 30, {"1": 0.0}, _ts(14, 16, 0, 29), "WS")
    ledger.apply("twopole", 30, {"2": 0.000499}, _ts(14, 16, 0, 29), "WS")

    assert ledger.lifetime("twopole") == pytest.approx(0.000499)
    assert ledger.has_delta_for("twopole", int(_ts(14, 15)))


def test_midnight_burst_counts_for_previous_day() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 23, 0, 29), "WS")
    ledger.apply("tech", 15, {"1": 0.05}, _ts(15, 0, 0, 29), "WS")
    ledger.apply("tech", 15, {"1": 0.07}, _ts(15, 1, 0, 29), "WS")

    assert _today(ledger, "tech", 14) == pytest.approx(0.08)
    assert _today(ledger, "tech", 15) == pytest.approx(0.07)
    # The daily total moves to the new date at 01:00.
    assert current_daily_date(_ts(15, 0, 30)) == datetime.date(2026, 10, 14)
    assert current_daily_date(_ts(15, 1, 0)) == datetime.date(2026, 10, 15)


def test_listing_value_in_first_minutes_of_hour_is_ignored() -> None:
    ledger = LDATAEnergyLedger()

    # At 17:02 the listing may still show the 15-16h delta.
    assert not ledger.apply("tech", 15, {"1": 0.03, "2": 0.0}, _ts(14, 17, 2), "REST")
    # From 17:05 it is the 16-17h delta.
    assert ledger.apply("tech", 15, {"1": 0.03, "2": 0.0}, _ts(14, 17, 5), "REST")
    assert ledger.has_delta_for("tech", int(_ts(14, 16)))


def test_invalid_values_are_ignored() -> None:
    ledger = LDATAEnergyLedger()

    assert not ledger.apply("tech", 15, {"1": None, "2": -0.5}, _ts(14, 16, 0, 29), "WS")
    assert not ledger.apply("tech", 15, {"1": float("nan"), "2": "x"}, _ts(14, 16, 0, 29), "WS")
    assert ledger.lifetime("tech") == 0.0


def test_first_lifetime_counter_is_only_a_reference() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 16, 0, 29), "WS")

    # 1156.3 kWh arrives at 17:42 (after a hub reconnect).
    assert ledger.apply("tech", 15, {"1": 1156.3}, _ts(14, 17, 42), "WS")

    assert ledger.lifetime("tech") == pytest.approx(0.03)
    assert _today(ledger, "tech", 14) == pytest.approx(0.03)


def test_lifetime_counter_within_rounding_changes_nothing() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1156.3}, _ts(14, 12, 5), "WS")
    for hour in range(13, 17):
        ledger.apply("tech", 15, {"1": 0.032}, _ts(14, hour, 0, 29), "WS")

    # Expected counter 1156.3 + 0.128; the hub reports 1156.4.
    ledger.apply("tech", 15, {"1": 1156.4}, _ts(14, 16, 30), "WS")

    assert ledger.lifetime("tech") == pytest.approx(0.128)


def test_lifetime_counter_adds_missed_bursts_and_blocks_current_hour() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1156.3}, _ts(14, 12, 5), "WS")
    ledger.apply("tech", 15, {"1": 0.5}, _ts(14, 13, 0, 29), "WS")

    # Bursts for 13-14h, 14-15h and 15-16h were missed; the counter at 16:20
    # is 1.4 kWh above the ledger. The reference only puts the cloud total
    # in 1156.3..1156.4, so 1.3 kWh is proven missing and added.
    assert ledger.apply("tech", 15, {"1": 1158.2}, _ts(14, 16, 20), "WS")
    assert ledger.lifetime("tech") == pytest.approx(1.8)
    assert _today(ledger, "tech", 14) == pytest.approx(1.8)

    # The counter covered 16:00-16:20, so the 16-17h burst is not booked again.
    assert not ledger.apply("tech", 15, {"1": 0.6}, _ts(14, 17, 0, 29), "WS")
    assert ledger.apply("tech", 15, {"1": 0.6}, _ts(14, 18, 0, 29), "WS")
    assert ledger.lifetime("tech") == pytest.approx(2.4)


def test_lower_lifetime_counter_never_lowers_the_ledger() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1156.3}, _ts(14, 12, 5), "WS")
    ledger.apply("tech", 15, {"1": 0.5}, _ts(14, 13, 0, 29), "WS")

    ledger.apply("tech", 15, {"1": 1156.5}, _ts(14, 13, 30), "WS")
    assert ledger.lifetime("tech") == pytest.approx(0.5)
    # The cloud total is below 1156.6 and the ledger holds 0.5 kWh, so the
    # offset is at most 1156.1 (it was at most 1156.4).
    assert _leg(ledger)["offset_max"] == pytest.approx(1156.1)
    # That is below the bottom of the reference window (1156.3), so the
    # bottom restarts from this counter.
    assert _leg(ledger)["offset"] == pytest.approx(1156.0)

    # The bursts for 13-14h and 14-15h are missed. With the lowered bound
    # the counter at 15:10 proves 1158.6 - 0.5 - 1156.1 = 2.0 kWh missing,
    # not 1.7.
    ledger.apply("tech", 15, {"1": 1158.6}, _ts(14, 15, 10), "WS")
    assert ledger.lifetime("tech") == pytest.approx(2.5)


def test_implausible_lifetime_jump_adds_nothing() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1156.3}, _ts(14, 12, 5), "WS")
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 13, 0, 29), "WS")

    # 7194.6 kWh on a 15 A breaker one hour later is not physical.
    ledger.apply("tech", 15, {"1": 7194.6}, _ts(14, 13, 30), "WS")
    assert ledger.lifetime("tech") == pytest.approx(0.03)

    # It becomes the new reference.
    ledger.apply("tech", 15, {"1": 7194.6}, _ts(14, 14, 30), "WS")
    assert ledger.lifetime("tech") == pytest.approx(0.03)


def test_stray_zero_before_burst_does_not_claim_the_hour() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1.0, "2": 0.0}, _ts(14, 1, 0, 29), "WS")

    # A zero inside the burst window, just before the burst.
    ledger.apply("tech", 15, {"1": 0.0, "2": 0.0}, _ts(14, 2, 0, 25), "WS-bulk")
    ledger.apply("tech", 15, {"1": 1.0, "2": 0.0}, _ts(14, 2, 0, 29), "WS")

    assert ledger.lifetime("tech") == pytest.approx(2.0)


def test_websocket_delta_outside_the_burst_window_is_not_booked() -> None:
    ledger = LDATAEnergyLedger()

    # The 16-17h burst arrives after the window has closed. An unrounded
    # value outside the window is neither a delta nor a lifetime counter.
    assert not ledger.apply("tech", 15, {"1": 0.032349, "2": 0.0}, _ts(14, 17, 1, 30), "WS")
    assert ledger.as_dict()["breakers"]["tech"]["legs"]["1"]["last_counter"] is None
    # The listing recovery books the hour instead.
    assert ledger.apply("tech", 15, {"1": 0.03, "2": 0.0}, _ts(14, 17, 6), "REST")
    assert ledger.lifetime("tech") == pytest.approx(0.03)


def test_burst_window_bounds() -> None:
    ledger = LDATAEnergyLedger()

    assert ledger.apply("a", 15, {"1": 0.032}, _ts(14, 17, 0, 0), "WS")
    assert ledger.apply("b", 15, {"1": 0.032}, _ts(14, 17, 0, 20), "WS")
    assert ledger.apply("c", 15, {"1": 0.032}, _ts(14, 17, 1, 29) + 0.999, "WS")
    assert not ledger.apply("d", 15, {"1": 0.032}, _ts(14, 17, 1, 30), "WS")
    assert not ledger.apply("e", 15, {"1": 0.032}, _ts(14, 16, 59, 59) + 0.999, "WS")


# Arrival times of the hourly burst on live (dev8, 2026-10-16/18; the first
# breaker of each burst) and the Outlets Outside / Fire place deltas booked
# for the hours that were booked. Before 2026-10-16 every burst came at
# HH:00:29.
REAL_BURSTS = [
    (16, 18, 0, 1.907),
    (16, 19, 0, 1.912),
    (16, 20, 0, 1.031),
    # No burst at 21:00 (WebSocket up, panel online).
    (16, 22, 0, 2.016),
    (16, 23, 0, 1.204),
    (17, 0, 0, 1.118),
    (17, 1, 0, 1.087),
    (17, 2, 0, 3.104),
    (17, 9, 0, 36.402),
    (17, 14, 0, 36.917),
    (18, 3, 0, 36.409),
    (18, 9, 0, 36.988),
]


def test_real_burst_arrival_times_are_in_the_window() -> None:
    ledger = LDATAEnergyLedger()
    for day, hour, minute, second in REAL_BURSTS:
        received = _ts(day, hour, minute) + second
        assert ledger.apply(f"b{day}{hour}", 15, {"1": 0.001202}, received, "WS"), (day, hour, second)


def test_burst_moving_from_hh0001_to_hh0036_books_each_hour_once() -> None:
    # Outlets Outside, 2026-10-17: bursts at 20:00:36 and 21:00:36, none at
    # 22:00, then 23:00:36 and 00:00:36. Each value is booked for the hour
    # before it; the missing 21-22h hour stops complete_until.
    ledger = LDATAEnergyLedger()
    bursts = [
        (_ts(17, 20, 0, 36) + 0.497, 1.461426),
        (_ts(17, 21, 0, 36) + 0.512, 1.457519),
        (_ts(17, 23, 0, 36) + 0.488, 1.452637),
        (_ts(18, 0, 0, 36) + 0.501, 1.459472),
    ]
    for received, value in bursts:
        assert ledger.apply("outside", 30, {"1": value, "2": 0.0}, received, "WS")
        # The same message again, as a duplicate frame a moment later.
        assert not ledger.apply("outside", 30, {"1": value, "2": 0.0}, received + 0.4, "WS")

    assert ledger.lifetime("outside") == pytest.approx(sum(v for _, v in bursts))
    assert _today(ledger, "outside", 17) == pytest.approx(sum(v for _, v in bursts))
    state = _leg(ledger, "outside")
    assert state["last_hour"] == int(_ts(17, 23))
    assert state["complete_until"] is None or state["complete_until"] < int(_ts(17, 21))


def test_cached_delta_right_after_a_websocket_reconnect_is_not_booked() -> None:
    ledger = LDATAEnergyLedger()
    # Fire place, a constant load: the same delta every hour.
    ledger.apply("fire", 15, {"1": 0.001202, "2": 0.0}, _ts(18, 2, 0, 36) + 0.4, "WS")

    # 2026-10-18 03:00:28.541: the WebSocket reconnected and re-sent its
    # subscriptions. A copy of the last delta 1.3 s later (the subscription
    # replies arrive within that time) may be the cached delta, not the
    # 02-03h burst.
    ledger.note_ws_connected(_ts(18, 3, 0, 28) + 0.541)
    assert not ledger.apply("fire", 15, {"1": 0.001202, "2": 0.0}, _ts(18, 3, 0, 29) + 0.8, "WS")
    assert not ledger.has_delta_for("fire", int(_ts(18, 2)))

    # The real burst came at 03:00:36.416, 7.9 s after the reconnect: booked,
    # although it repeats the last delta.
    assert ledger.apply("fire", 15, {"1": 0.001202, "2": 0.0}, _ts(18, 3, 0, 36) + 0.416, "WS")
    assert ledger.lifetime("fire") == pytest.approx(0.002404)
    assert ledger.has_delta_for("fire", int(_ts(18, 2)))


def test_a_new_value_right_after_a_reconnect_is_booked() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("outside", 30, {"1": 1.461426, "2": 0.0}, _ts(17, 20, 0, 36), "WS")
    ledger.note_ws_connected(_ts(17, 21, 0, 33))

    # Not the last delta: it cannot be the cached one.
    assert ledger.apply("outside", 30, {"1": 1.457519, "2": 0.0}, _ts(17, 21, 0, 36), "WS")
    # Zero after a booked zero, inside the guard: left to the listing.
    ledger.apply("idle", 15, {"1": 0.0}, _ts(17, 20, 0, 36), "WS")
    assert not ledger.apply("idle", 15, {"1": 0.0}, _ts(17, 21, 0, 36), "WS")
    # The guard ends WS_RECONNECT_GUARD_SECS after the connect.
    ledger.apply("const", 15, {"1": 0.0018}, _ts(17, 20, 0, 36), "WS")
    assert ledger.apply(
        "const", 15, {"1": 0.0018},
        _ts(17, 21, 0, 33) + ldata_energy.WS_RECONNECT_GUARD_SECS, "WS",
    )


def test_stale_value_before_the_burst_does_not_claim_the_hour() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.032349, "2": 0.0}, _ts(14, 16, 0, 29), "WS")

    # At 17:00:10 a reconnect re-sends the 15-16h delta; the 16-17h burst
    # follows at 17:00:29.
    ledger.note_ws_connected(_ts(14, 17, 0, 9))
    assert not ledger.apply("tech", 15, {"1": 0.032349, "2": 0.0}, _ts(14, 17, 0, 10), "WS-bulk")
    assert ledger.apply("tech", 15, {"1": 0.032470, "2": 0.0}, _ts(14, 17, 0, 29), "WS")

    assert ledger.lifetime("tech") == pytest.approx(0.064819)
    assert ledger.as_dict()["breakers"]["tech"]["legs"]["1"]["last_value"] == 0.032470


def test_small_lifetime_counter_after_a_zero_burst_is_not_a_delta() -> None:
    ledger = LDATAEnergyLedger()
    # An idle breaker: the 16-17h burst is zero.
    ledger.apply("idle", 15, {"1": 0.0, "2": 0.0}, _ts(14, 17, 0, 29), "WS")

    # Its lifetime counter, 0.3 kWh, arrives at 17:05 over the WebSocket and
    # at 17:10 in the listing. Neither replaces the zero.
    assert ledger.apply("idle", 15, {"1": 0.3}, _ts(14, 17, 5), "WS")
    ledger.apply("idle", 15, {"1": 0.3}, _ts(14, 17, 10), "REST")
    assert ledger.lifetime("idle") == 0.0
    assert ledger.as_dict()["breakers"]["idle"]["legs"]["1"]["last_counter"] == pytest.approx(0.3)


def test_listing_value_never_replaces_a_booked_zero() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("idle", 15, {"1": 0.0, "2": 0.0}, _ts(14, 17, 0, 29), "WS")

    assert not ledger.apply("idle", 15, {"1": 0.04}, _ts(14, 17, 10), "REST")
    assert ledger.lifetime("idle") == 0.0


def test_ambiguous_listing_value_is_not_booked() -> None:
    ledger = LDATAEnergyLedger()

    # 0.3 kWh in the listing: a rounded delta or a small lifetime counter.
    assert not ledger.apply("a", 15, {"1": 0.3}, _ts(14, 17, 10), "REST")
    assert not ledger.has_delta_for("a", int(_ts(14, 16)))
    # 0.1 kWh and values that are not multiples of 0.1 are booked.
    assert ledger.apply("b", 15, {"1": 0.1}, _ts(14, 17, 10), "REST")
    assert ledger.apply("c", 15, {"1": 0.32}, _ts(14, 17, 10), "REST")
    assert ledger.lifetime("b") == pytest.approx(0.1)
    assert ledger.lifetime("c") == pytest.approx(0.32)
    # The same value in the burst is a delta.
    assert ledger.apply("d", 15, {"1": 0.3}, _ts(14, 17, 0, 29), "WS")
    assert ledger.lifetime("d") == pytest.approx(0.3)


def test_lifetime_counter_mid_hour_without_a_gap_is_left_to_the_burst() -> None:
    """Steady 1 kW load; the cloud counter is 1000 + kWh since 13:00:40."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1.0}, _ts(14, 13, 0, 29), "WS")
    ledger.apply("tech", 15, {"1": 1000.0}, _ts(14, 13, 0, 40), "WS")
    ledger.apply("tech", 15, {"1": 1.0}, _ts(14, 14, 0, 29), "WS")

    # The counter at 14:40 is 0.7 kWh above the ledger, all of it 14-15h.
    assert ledger.apply("tech", 15, {"1": 1001.7}, _ts(14, 14, 40), "WS")
    assert ledger.lifetime("tech") == pytest.approx(2.0)
    assert not ledger.has_delta_for("tech", int(_ts(14, 15)))

    # The 14-15h burst is booked in full.
    assert ledger.apply("tech", 15, {"1": 1.0}, _ts(14, 15, 0, 29), "WS")
    assert ledger.lifetime("tech") == pytest.approx(3.0)
    assert _today(ledger, "tech", 14) == pytest.approx(3.0)

    # The 15-16h and 16-17h bursts are missed. The counter at 17:10 (1004.2)
    # is compared with the reference from 13:00:40 (offset at most 999.1),
    # not with one raised by the partial hour at 14:40: 2.1 kWh is added.
    assert ledger.apply("tech", 15, {"1": 1004.2}, _ts(14, 17, 10), "WS")
    assert ledger.lifetime("tech") == pytest.approx(5.1)


def test_small_websocket_value_outside_burst_is_not_a_delta() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("new", 15, {"1": 0.02, "2": 0.0}, _ts(14, 9, 0, 29), "WS")

    # A small lifetime counter (3.0 kWh, below the 3.6 kWh bound) at 10:20.
    ledger.apply("new", 15, {"1": 3.0}, _ts(14, 10, 20), "WS")

    assert ledger.lifetime("new") == pytest.approx(0.02)
    assert not ledger.has_delta_for("new", int(_ts(14, 9)))


def test_repeated_stale_counter_does_not_double_count() -> None:
    ledger = LDATAEnergyLedger()
    # 1 kWh/h load. Counter at 10:20, then the 10-11h burst.
    ledger.apply("tech", 15, {"1": 1000.0}, _ts(14, 10, 20), "WS")
    ledger.apply("tech", 15, {"1": 1.0}, _ts(14, 11, 0, 29), "WS")
    # The same counter seen again from the listing at 11:10.
    ledger.apply("tech", 15, {"1": 1000.0}, _ts(14, 11, 10), "REST")
    for hour in range(12, 16):
        ledger.apply("tech", 15, {"1": 1.0}, _ts(14, hour, 0, 29), "WS")

    # Counter at 15:20: 1000 + 0.67 (10:20-11) + 4 hours + 0.33 (15:00-15:20).
    ledger.apply("tech", 15, {"1": 1005.0}, _ts(14, 15, 20), "WS")

    assert ledger.lifetime("tech") == pytest.approx(5.0)


def test_single_pole_null_leg_does_not_trigger_recovery() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03, "2": None}, _ts(14, 17, 0, 29), "WS")

    assert ledger.has_delta_for("tech", int(_ts(14, 16)))
    assert not ledger.has_delta_for("tech", int(_ts(14, 17)))


def _leg(ledger: LDATAEnergyLedger, key: str = "tech", leg: str = "1") -> dict:
    return ledger.as_dict()["breakers"][key]["legs"][leg]


def test_missed_hours_followed_by_booked_hours_are_recovered() -> None:
    """1 kW load on a 10 A breaker, 1.23 kWh in 06-07h; the counter is 1000 + kWh since 00:00."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 10, {"1": 1000.0}, _ts(14, 0, 0, 5), "WS")
    ledger.apply("tech", 10, {"1": 1.0}, _ts(14, 1, 0, 29), "WS")
    ledger.apply("tech", 10, {"1": 1.0}, _ts(14, 2, 0, 29), "WS")
    # Home Assistant is down from 03:00 to 07:10: the 02-03h to 05-06h bursts
    # are missed. The listing at 07:10 books 06-07h, the bursts book every
    # hour after it.
    assert ledger.apply("tech", 10, {"1": 1.23}, _ts(14, 7, 10), "REST")
    for hour in range(8, 30):
        ledger.apply("tech", 10, {"1": 1.0}, _ts(14 + hour // 24, hour % 24, 0, 29), "WS")
    assert ledger.lifetime("tech") == pytest.approx(25.23)
    assert _leg(ledger)["complete_until"] == int(_ts(14, 1))

    # Counter at 05:25 on the 15th: 29.23 kWh up to 05:00 plus 0.42 since.
    # The 4.27 kWh it proves missing (4.37 above the bottom of the
    # reference's window) is more than a 10 A leg can use since 04:00 (the
    # last booked hour) but not since 02:00 (the last complete hour).
    assert ledger.apply("tech", 10, {"1": 1029.6}, _ts(15, 5, 25), "WS")

    assert ledger.lifetime("tech") == pytest.approx(29.5)
    assert _today(ledger, "tech", 15) == pytest.approx(5.0 + 4.27)


def test_counter_after_a_gap_fill_adds_the_rest_of_the_claimed_hour() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 10, {"1": 1000.0}, _ts(14, 0, 0, 5), "WS")
    ledger.apply("tech", 10, {"1": 1.0}, _ts(14, 1, 0, 29), "WS")
    ledger.apply("tech", 10, {"1": 1.0}, _ts(14, 2, 0, 29), "WS")
    ledger.apply("tech", 10, {"1": 1.23}, _ts(14, 7, 10), "REST")
    for hour in range(8, 30):
        ledger.apply("tech", 10, {"1": 1.0}, _ts(14 + hour // 24, hour % 24, 0, 29), "WS")
    ledger.apply("tech", 10, {"1": 1029.6}, _ts(15, 5, 25), "WS")
    # The counter claims 05-06h; the ledger is complete up to 04-05h.
    assert _leg(ledger)["last_hour"] == int(_ts(15, 5))
    assert _leg(ledger)["complete_until"] == int(_ts(15, 4))

    # The 05-06h burst is not booked again; 06-07h is.
    assert not ledger.apply("tech", 10, {"1": 1.0}, _ts(15, 6, 0, 29), "WS")
    assert ledger.apply("tech", 10, {"1": 1.0}, _ts(15, 7, 0, 29), "WS")
    assert ledger.lifetime("tech") == pytest.approx(30.5)
    assert _leg(ledger)["complete_until"] == int(_ts(15, 4))

    # Counter at 07:30: 31.23 kWh up to 07:00 plus 0.5 since. The rest of
    # 05-06h (05:25-06:00) and 07:00-07:30 are added.
    assert ledger.apply("tech", 10, {"1": 1031.7}, _ts(15, 7, 30), "WS")
    assert ledger.lifetime("tech") == pytest.approx(31.6)


def test_counter_in_step_completes_the_ledger_over_an_idle_missed_hour() -> None:
    """1 kW load except 13-14h (idle); the counter is 1000 + kWh since 13:00:40."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1.0}, _ts(14, 13, 0, 29), "WS")
    ledger.apply("tech", 15, {"1": 1000.0}, _ts(14, 13, 0, 40), "WS")
    # The 13-14h burst (0 kWh) is missed; 14-15h is booked.
    ledger.apply("tech", 15, {"1": 1.0}, _ts(14, 15, 0, 29), "WS")
    assert _leg(ledger)["complete_until"] == int(_ts(14, 12))

    # The counter at 15:03 matches the ledger: nothing was missing.
    ledger.apply("tech", 15, {"1": 1001.0}, _ts(14, 15, 3), "WS")
    assert _leg(ledger)["complete_until"] == int(_ts(14, 14))

    # The counter at 15:40 is 0.7 kWh above the ledger, all of it 15-16h.
    ledger.apply("tech", 15, {"1": 1001.7}, _ts(14, 15, 40), "WS")
    assert ledger.lifetime("tech") == pytest.approx(2.0)
    assert ledger.apply("tech", 15, {"1": 1.0}, _ts(14, 16, 0, 29), "WS")
    assert ledger.lifetime("tech") == pytest.approx(3.0)


def test_ledger_stored_without_complete_until_is_migrated() -> None:
    """A ledger written before complete_until existed."""
    def leg(**values):
        return {
            "lifetime": 0.0, "last_hour": None, "offset": None, "anchor_time": None,
            "last_value": None, "last_source": None, "last_counter": None, **values,
        }

    stored = {
        "breakers": {
            # Last hour booked by a burst.
            "tech": {
                "legs": {
                    "1": leg(lifetime=2.0, last_hour=int(_ts(14, 14)), offset=999.0,
                             anchor_time=_ts(14, 13, 0, 40), last_value=1.0,
                             last_source="WS", last_counter=1000.0),
                    "2": leg(),
                },
                "daily": {"2026-10-14": 2.0},
            },
            # 16-17h claimed by a counter at 16:20.
            "claimed": {
                "legs": {
                    "1": leg(lifetime=5.0, last_hour=int(_ts(14, 16)), offset=1000.0,
                             anchor_time=_ts(14, 16, 20), last_counter=1005.0),
                    "2": leg(),
                },
                "daily": {"2026-10-14": 5.0},
            },
            # Only a reference.
            "ref": {
                "legs": {
                    "1": leg(offset=1000.0, anchor_time=_ts(14, 16, 20), last_counter=1000.0),
                    "2": leg(),
                },
                "daily": {},
            },
        }
    }
    ledger = LDATAEnergyLedger()
    ledger.load(json.loads(json.dumps(stored)))

    assert _leg(ledger)["complete_until"] == int(_ts(14, 14))
    assert _leg(ledger, "tech", "2")["complete_until"] is None
    assert _leg(ledger, "claimed")["complete_until"] == int(_ts(14, 15))
    assert _leg(ledger, "ref")["complete_until"] == int(_ts(14, 15))

    # As before: a counter at 15:40 without a gap is left to the burst.
    ledger.apply("tech", 15, {"1": 1001.7}, _ts(14, 15, 40), "WS")
    assert ledger.lifetime("tech") == pytest.approx(2.0)
    # The rest of the claimed hour comes with the next counter (1 kW load),
    # less the 0.1 kWh window of the stored offset.
    assert _leg(ledger, "claimed")["offset_max"] == pytest.approx(1000.1)
    assert not ledger.apply("claimed", 15, {"1": 1.0}, _ts(14, 17, 0, 29), "WS")
    ledger.apply("claimed", 15, {"1": 1006.2}, _ts(14, 17, 30), "WS")
    assert ledger.lifetime("claimed") == pytest.approx(6.1)


def test_listing_value_equal_to_the_last_delta_is_not_booked() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.032349, "2": 0.0}, _ts(14, 16, 0, 29), "WS")

    # The hub is offline across 17:00:29. The listing at 17:10 still shows
    # the 15-16h values; neither is booked, also not the zero on leg 2, so
    # 16-17h stays incomplete on both legs.
    assert not ledger.apply("tech", 15, {"1": 0.03, "2": 0.0}, _ts(14, 17, 10), "REST")
    assert ledger.lifetime("tech") == pytest.approx(0.032349)
    for leg in ("1", "2"):
        assert _leg(ledger, "tech", leg)["last_hour"] == int(_ts(14, 15))
        assert _leg(ledger, "tech", leg)["complete_until"] is None

    # A listing value outside rounding of the last delta is booked; so is
    # the same value in the burst.
    assert ledger.apply("tech", 15, {"1": 0.04}, _ts(14, 18, 10), "REST")
    assert ledger.apply("tech", 15, {"1": 0.04}, _ts(14, 19, 0, 29), "WS")
    assert ledger.lifetime("tech") == pytest.approx(0.112349)

    # The skipped hour is recovered by the next lifetime counter, as far as
    # it proves it missing: 1000.2 - 0.05 - 1000.1.
    ledger.apply("idle", 15, {"1": 1000.0}, _ts(14, 16, 5), "WS")
    ledger.apply("idle", 15, {"1": 0.05}, _ts(14, 17, 0, 29), "WS")
    assert not ledger.apply("idle", 15, {"1": 0.05}, _ts(14, 18, 10), "REST")
    ledger.apply("idle", 15, {"1": 1000.2}, _ts(14, 19, 10), "WS")
    assert ledger.lifetime("idle") == pytest.approx(0.1)


def test_stale_zero_listing_does_not_hide_a_missed_hour() -> None:
    """An EV charger (40 A) uses 1.2 kWh in 11-12h while the hub is offline."""
    ledger = LDATAEnergyLedger()
    ledger.apply("EV", 40, {"1": 1000.0}, _ts(14, 10, 30), "WS")
    ledger.apply("EV", 40, {"1": 0.0}, _ts(14, 11, 0, 29), "WS")

    # The 12:00:29 burst is missed; at 12:06:40 the listing still shows the
    # 10-11h zero. It is not booked, so 11-12h stays incomplete.
    assert not ledger.apply("EV", 40, {"1": 0.0}, _ts(14, 12, 6, 40), "REST")
    assert _leg(ledger, "EV")["last_hour"] == int(_ts(14, 10))
    assert _leg(ledger, "EV")["complete_until"] == int(_ts(14, 10))

    # The hub reconnects: 1000 + 1.2 (11-12h) + 0.1 (12-13h so far). The
    # 1.2 kWh it proves missing (beyond the reference's 0.1 kWh window) is
    # below what a 40 A leg can use since 12:00 (1.87 kWh): had the zero been
    # booked, 11-12h would count as complete and all of it would be left to
    # the 13:00:29 burst, which books only 12-13h.
    ledger.apply("EV", 40, {"1": 1001.3}, _ts(14, 12, 11, 40), "WS")
    assert ledger.lifetime("EV") == pytest.approx(1.2)
    assert _leg(ledger, "EV")["complete_until"] == int(_ts(14, 11))
    # 12-13h (0.6 kWh) is claimed by the counter; its burst is not booked.
    assert not ledger.apply("EV", 40, {"1": 0.6}, _ts(14, 13, 0, 29), "WS")
    for hour in range(14, 24):
        ledger.apply("EV", 40, {"1": 0.0}, _ts(14, hour, 0, 29), "WS")
    for hour in range(16):
        ledger.apply("EV", 40, {"1": 0.0}, _ts(15, hour, 0, 29), "WS")

    # The next counter adds the rest of 12-13h (0.5 kWh).
    ledger.apply("EV", 40, {"1": 1001.8}, _ts(15, 16, 15), "WS")
    assert ledger.lifetime("EV") == pytest.approx(1.7)
    assert _today(ledger, "EV", 14) == pytest.approx(1.2)
    assert _today(ledger, "EV", 15) == pytest.approx(0.5)


def test_counter_above_the_current_hour_bound_fills_an_untracked_gap() -> None:
    """A migrated ledger is complete up to its last hour but missed 11-14h."""
    stored = {
        "breakers": {
            "tech": {
                "legs": {
                    "1": {
                        "lifetime": 0.7, "last_hour": int(_ts(14, 14)), "offset": 1000.0,
                        "anchor_time": _ts(14, 10, 30), "last_value": 0.2,
                        "last_source": "WS", "last_counter": 1000.0,
                    },
                },
                "daily": {"2026-10-14": 0.7},
            },
        }
    }
    ledger = LDATAEnergyLedger()
    ledger.load(stored)
    assert _leg(ledger)["complete_until"] == int(_ts(14, 14))

    # 1000 + 0.5 (10-11h) + 3.0 (missed) + 0.2 (14-15h) + 0.1 (15-16h so
    # far). The 3.0 kWh it proves missing is more than a 15 A breaker uses
    # in 20 minutes (1.2 kWh), so it is missed energy, not the current hour's.
    assert ledger.apply("tech", 15, {"1": 1003.8}, _ts(14, 15, 20), "WS")
    assert ledger.lifetime("tech") == pytest.approx(3.7)
    assert _leg(ledger)["last_hour"] == int(_ts(14, 15))
    assert _leg(ledger)["complete_until"] == int(_ts(14, 14))
    assert _leg(ledger)["offset"] == 1000.0

    # Within the bound (0.1 kWh in 100 s) the proven excess is still the
    # current hour's; above it, it is a gap.
    for key, counter, lifetime in (("within", 1000.2, 0.08), ("above", 1000.4, 0.3)):
        ledger.apply(key, 15, {"1": 1000.0}, _ts(14, 13, 30), "WS")
        ledger.apply(key, 15, {"1": 0.08}, _ts(14, 14, 0, 29), "WS")
        assert _leg(ledger, key)["complete_until"] == int(_ts(14, 13))
        ledger.apply(key, 15, {"1": counter}, _ts(14, 14, 1, 40), "WS")
        assert ledger.lifetime(key) == pytest.approx(lifetime)
        assert _leg(ledger, key)["offset"] == 1000.0


def test_ledger_round_trips_through_storage() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1156.3}, _ts(14, 12, 5), "WS")
    ledger.apply("tech", 15, {"1": 0.03, "2": 0.0}, _ts(14, 13, 0, 29), "WS")

    restored = LDATAEnergyLedger()
    restored.load(json.loads(json.dumps(ledger.as_dict())))

    assert restored.as_dict() == ledger.as_dict()
    assert _leg(restored)["complete_until"] == int(_ts(14, 12))
    assert not restored.dirty
    # Dedup state survives the restart.
    assert not restored.apply("tech", 15, {"1": 0.03}, _ts(14, 13, 20), "REST")


def test_load_ignores_garbage() -> None:
    ledger = LDATAEnergyLedger()
    ledger.load({"breakers": {"a": "x", "b": {"legs": {"1": {"lifetime": "bad"}}, "daily": {"d": "x"}}}})

    assert ledger.lifetime("a") is None
    assert ledger.lifetime("b") == 0.0
    ledger.load(None)
    assert ledger.lifetime("b") is None
    for garbage in ([], "x", {"breakers": []}, {"breakers": {"c": {"legs": [], "daily": []}}}):
        ledger.load(garbage)
    assert ledger.lifetime("c") == 0.0


def test_daily_history_is_bounded() -> None:
    ledger = LDATAEnergyLedger()
    for day in range(1, 10):
        ledger.apply("tech", 15, {"1": 0.01}, _ts(day, 12, 0, 29), "WS")

    assert len(ledger.as_dict()["breakers"]["tech"]["daily"]) == ldata_energy.DAILY_KEEP_DAYS


# ── Regression: 2026-10-16 hub outage ─────────────────────────────────
#
# The hub was offline 01:58-07:21, 07:42-12:00, 12:21-15:05 and from 15:34.
# Lifetime counters arrived at each reconnect (07:21, 12:00:21, 15:05). The
# leg states below are the stored ledger after the 07:21 reconnect (ledger
# file of 2.0.12.dev6, written before offset_max existed).


def _outage_ledger(key: str, lifetime: float, offset: float, counter: float, last_value: float) -> LDATAEnergyLedger:
    ledger = LDATAEnergyLedger()
    ledger.load(
        {
            "breakers": {
                key: {
                    "legs": {
                        "1": {
                            "lifetime": lifetime,
                            "last_hour": int(_ts(16, 0)),
                            "complete_until": int(_ts(16, 6)),
                            "offset": offset,
                            "anchor_time": _ts(16, 7, 21, 13),
                            "last_value": last_value,
                            "last_source": "WS",
                            "last_counter": counter,
                        },
                        "2": {
                            "lifetime": 0.0, "last_hour": int(_ts(16, 0)), "complete_until": None,
                            "offset": None, "anchor_time": None, "last_value": 0.0,
                            "last_source": "WS", "last_counter": None,
                        },
                    },
                    "daily": {"2026-10-16": 0.0},
                }
            }
        }
    )
    return ledger


@pytest.mark.parametrize(
    ("key", "lifetime", "offset", "reference", "counter"),
    [
        # Lights outside: 19.1 - (18.988 + 0.012) = 0.10000000000000142. The
        # old rule added 0.1 kWh here (12:00:22) for a 1 W load.
        ("lights_outside", 0.012, 18.988, 19.0, 19.1),
        # Microwave: 400.4 - (400.287976 + 0.012024) = 0.0999999999999659. The
        # old rule added nothing here, only by rounding luck.
        ("microwave", 0.012024, 400.287976, 400.3, 400.4),
        # Outlets tech cabinet: 1157.9 - (1157.391582 + 0.408418) =
        # 0.10000000000013642. The old rule added 0.1 kWh.
        ("tech_cabinet", 0.408418, 1157.391582, 1157.8, 1157.9),
    ],
)
def test_one_counter_step_after_a_reconnect_adds_nothing(key, lifetime, offset, reference, counter) -> None:
    ledger = _outage_ledger(key, lifetime, offset, reference, 0.0012)
    raw_missing = counter - (offset + lifetime)
    assert raw_missing != 0.1  # Whichever side of 0.1 the float lands on ...

    # ... one counter step is quantization, not missed energy: the cloud
    # total was anywhere in [reference, reference + 0.1) at 07:21 and in
    # [counter, counter + 0.1) at 12:00:21.
    ledger.apply(key, 15, {"1": counter}, _ts(16, 12, 0, 21), "WS")

    assert ledger.lifetime(key) == pytest.approx(lifetime, abs=1e-9)
    assert _today(ledger, key, 16) == 0.0
    # Not claimed: the 11-12h burst eight seconds later is booked.
    assert ledger.apply(key, 15, {"1": 0.0012}, _ts(16, 12, 0, 29), "WS")
    assert ledger.lifetime(key) == pytest.approx(lifetime + 0.0012)


def test_offset_window_is_migrated_from_a_stored_ledger() -> None:
    ledger = _outage_ledger("lights_outside", 0.012, 18.988, 19.0, 0.0012)
    assert _leg(ledger, "lights_outside")["offset_max"] == pytest.approx(19.088)
    # An unquantized counter (seen from the 2-pole dryer) has no window.
    dryer = LDATAEnergyLedger()
    dryer.load(
        {
            "breakers": {
                "dryer": {
                    "legs": {
                        "2": {
                            "lifetime": 0.0056, "last_hour": int(_ts(16, 0)), "complete_until": int(_ts(16, 6)),
                            "offset": 694.6626239999241, "anchor_time": _ts(16, 7, 21, 1),
                            "last_value": 0.0005, "last_source": "WS", "last_counter": 694.6682239999227,
                        }
                    },
                    "daily": {},
                }
            }
        }
    )
    assert _leg(dryer, "dryer", "2")["offset_max"] == pytest.approx(694.6626239999241)
    assert dryer.as_dict()["breakers"]["dryer"]["legs"]["2"]["offset_max"] == pytest.approx(694.6626239999241)


def test_shortfall_within_one_step_is_added_by_a_later_counter() -> None:
    """Outlets counter 1: counter 1285.5 at 07:21:05, 1285.6 at 12:00:21."""
    ledger = _outage_ledger("counter1", 0.751924, 1284.748076, 1285.5, 0.00354)

    # 0.1 above the expected 1285.5: within the window, nothing is added.
    ledger.apply("counter1", 15, {"1": 1285.6}, _ts(16, 12, 0, 21), "WS")
    assert ledger.lifetime("counter1") == pytest.approx(0.751924)
    ledger.apply("counter1", 15, {"1": 0.024048}, _ts(16, 12, 0, 29), "WS")
    assert ledger.lifetime("counter1") == pytest.approx(0.775972)

    # The old rule then took the ledger as complete and kept comparing with
    # the bottom of the 07:21 window (expected 1285.524). The window's top
    # (offset_max 1284.848076) does not move with what is added, so energy
    # missed in the next outages is added as soon as a counter proves it:
    # 1285.7 at 15:05 proves 1285.7 - 0.775972 - 1284.848076 kWh.
    ledger.apply("counter1", 15, {"1": 1285.7}, _ts(16, 15, 5, 0), "WS")
    assert ledger.lifetime("counter1") == pytest.approx(1285.7 - 1284.848076)
    assert _leg(ledger, "counter1")["offset_max"] == pytest.approx(1284.848076)


def _replay_outages(power_kw, total_at_reference, days, quantize, ledger=None):
    """Replay the 2026-10-16 outage pattern on a steady load for ``days`` days.

    The cloud total is total_at_reference + power x time since 07:21:05 on
    the 16th. Bursts (the exact delta of the cloud total) arrive at HH:00:29
    while the hub is online; each reconnect brings the quantized total; the
    listing is read at HH:06 and shows the last burst again while the hub
    is offline. Returns (ledger, [(time, booked - cloud energy) ...]).
    """
    ledger = ledger or LDATAEnergyLedger()
    t_ref = _ts(16, 7, 21, 5)

    def total(t):
        return total_at_reference + power_kw * (t - t_ref) / 3600.0

    offline = []
    for day in range(days):
        base = _ts(16, 0) + day * 86400
        for start, end in (((1, 58, 0), (7, 21, 5)), ((7, 42, 0), (12, 0, 21)), ((12, 21, 0), (15, 5, 0)), ((15, 34, 0), (23, 40, 0))):
            offline.append(
                (base + start[0] * 3600 + start[1] * 60 + start[2], base + end[0] * 3600 + end[1] * 60 + end[2])
            )

    def online(t):
        return not any(a <= t < b for a, b in offline)

    events = [(t_ref, "counter")]
    for a, b in offline:
        if b > t_ref:
            events.append((b, "counter"))
    hour = ldata_energy.hour_start(t_ref) + 3600
    end = offline[-1][1] + 3 * 3600
    while hour < end:
        events.append((hour + 29, "burst"))
        events.append((hour + 360, "listing"))
        hour += 3600
    events.sort()

    baseline = total(ldata_energy.hour_start(t_ref))  # the ledger books the reference hour in full
    last_burst = 0.0
    errors = []
    for t, kind in events:
        if kind == "counter":
            ledger.apply("leg", 15, {"1": quantize(total(t))}, t, "WS")
        elif kind == "burst" and online(t):
            h = ldata_energy.hour_start(t)
            last_burst = total(h) - total(h - 3600)
            ledger.apply("leg", 15, {"1": last_burst}, t, "WS")
        elif kind == "listing":
            ledger.apply("leg", 15, {"1": round(last_burst, 2)}, t, "REST", connected=online(t))
        errors.append((t, kind, ledger.lifetime("leg") - (total(t) - baseline)))
    return ledger, errors


def _floor_counter(total):
    return math.floor(total * 10 + 1e-9) / 10


def _round_counter(total):
    return round(total, 1)


@pytest.mark.parametrize("quantize", [_floor_counter, _round_counter])
@pytest.mark.parametrize(
    ("power_kw", "total_at_reference"),
    [
        (0.0035, 1285.59),  # Outlets counter 1 (3.5 W), near the top of its 07:21 window
        (0.0035, 1285.501),  # ... and near the bottom
        (0.001, 19.0951),  # Lights outside (1 W): 19.0 at 07:21, 19.1 at 12:00:21
        (0.034, 1157.84),  # Outlets tech cabinet (34 W)
        (0.4, 2134.55),  # A heavier load
    ],
)
def test_repeated_outages_neither_invent_nor_lose_energy(quantize, power_kw, total_at_reference) -> None:
    _, errors = _replay_outages(power_kw, total_at_reference, 30, quantize)

    # Never more than the cloud counted (allowing the 1e-6 kWh rounding).
    assert max(error for _, _, error in errors) <= 1e-6
    # At each reconnect, what the ledger is short stays below two counter
    # steps, plus the energy used in the reference hour before 07:21:05
    # (which the reference cannot place) and in the current hour so far
    # (which its burst brings). It does not grow with the number of outages.
    allowance = 0.2 + power_kw * (21 / 60 + 1) + 1e-6
    after_counters = [error for _, kind, error in errors if kind == "counter"][1:]
    assert len(after_counters) == 4 * 30 - 1
    assert min(after_counters) >= -allowance


def test_listing_is_not_booked_while_the_panel_is_offline() -> None:
    """Outlets tech cabinet, 12:00-16:06 on 2026-10-16."""
    ledger = _outage_ledger("tech_cabinet", 0.408418, 1157.391582, 1157.8, 0.035889)
    ledger.apply("tech_cabinet", 15, {"1": 1157.9}, _ts(16, 12, 0, 22), "WS")
    ledger.apply("tech_cabinet", 15, {"1": 0.0321}, _ts(16, 12, 0, 29), "WS")
    assert ledger.lifetime("tech_cabinet") == pytest.approx(0.440518)

    # Offline from 12:21. The listing still shows a delta of 0.03 kWh at
    # 14:06:52; dev7 booked it as 13-14h.
    assert not ledger.apply("tech_cabinet", 15, {"1": 0.03}, _ts(16, 14, 6, 52), "REST", connected=False)
    # A WebSocket value in the burst window is not booked either.
    assert not ledger.apply("tech_cabinet", 15, {"1": 0.0321}, _ts(16, 15, 0, 29), "WS", connected=False)
    assert ledger.lifetime("tech_cabinet") == pytest.approx(0.440518)

    # The reconnect counter at 15:05 (before the panel is reported online)
    # adds what it proves missing and claims 15-16h.
    assert ledger.apply("tech_cabinet", 15, {"1": 1158.0}, _ts(16, 15, 5, 0), "WS", connected=False)
    assert ledger.lifetime("tech_cabinet") == pytest.approx(1158.0 - 1157.491582)
    assert _leg(ledger, "tech_cabinet")["last_source"] == ldata_energy.COUNTER_CLAIM_SOURCE

    # Offline again from 15:34: the 16:06:30 listing is not booked.
    assert not ledger.apply("tech_cabinet", 15, {"1": 0.04}, _ts(16, 16, 6, 30), "REST", connected=False)
    assert ledger.lifetime("tech_cabinet") == pytest.approx(1158.0 - 1157.491582)


def test_stale_listing_guard_holds_after_a_counter_claim() -> None:
    ledger = _outage_ledger("tech_cabinet", 0.408418, 1157.391582, 1157.8, 0.035889)
    ledger.apply("tech_cabinet", 15, {"1": 0.0321}, _ts(16, 12, 0, 29), "WS")
    # The counter at 12:00:40 claims 12-13h.
    ledger.apply("tech_cabinet", 15, {"1": 1158.0}, _ts(16, 12, 0, 40), "WS")
    claimed = ledger.lifetime("tech_cabinet")
    assert _leg(ledger, "tech_cabinet")["last_source"] == ldata_energy.COUNTER_CLAIM_SOURCE
    # The last delta stays the reference for the stale-listing guard (dev7
    # cleared it, and booked the next listing value whatever it was).
    assert _leg(ledger, "tech_cabinet")["last_value"] == pytest.approx(0.0321)

    # The 13:00:29 burst for the claimed hour is not booked, but the listing
    # shows it from then on, so it becomes the guard's reference.
    assert not ledger.apply("tech_cabinet", 15, {"1": 0.0279}, _ts(16, 13, 0, 29), "WS")
    assert _leg(ledger, "tech_cabinet")["last_value"] == pytest.approx(0.0279)
    assert not ledger.apply("tech_cabinet", 15, {"1": 0.03}, _ts(16, 13, 6), "REST")

    # Panel online, but the 14:00:29 burst is missed (WebSocket reconnect):
    # the listing at 14:06 still shows 0.03 for 12-13h and is not booked
    # as 13-14h.
    assert not ledger.apply("tech_cabinet", 15, {"1": 0.03}, _ts(16, 14, 6), "REST")
    assert ledger.lifetime("tech_cabinet") == pytest.approx(claimed)
    # A new value is booked.
    assert ledger.apply("tech_cabinet", 15, {"1": 0.05}, _ts(16, 15, 6), "REST")


# ── Service ────────────────────────────────────────────────────────────


def _raw_breaker(breaker_id: str, rating: int, ec1, ec2=0.0, position: int = 1) -> dict:
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
        "power": 30.0,
        "energyConsumption": ec1,
        "energyConsumption2": ec2,
        "energyImport": None,
        "energyImport2": None,
    }


def _ldata_panel(breakers: list[dict]) -> dict:
    return {
        "id": "LDATA-1",
        "name": "Panel",
        "model": "DAU",
        "status": "READY",
        "ModuleType": "LDATA",
        "updateVersion": "0.1.91",
        "rmsVoltage": 121.0,
        "rmsVoltage2": 121.0,
        "residentialBreakers": breakers,
    }


def _whems_panel(breakers: list[dict]) -> dict:
    return {
        "id": "1000_ABCD",
        "name": "Whem",
        "model": "LWHEM",
        "connected": True,
        "ModuleType": "WHEMS",
        "updateVersion": "1.7.6",
        "rmsVoltage": 121.0,
        "rmsVoltage2": 121.0,
        "residentialBreakers": breakers,
    }


@pytest.fixture
def clock(monkeypatch):
    now = SimpleNamespace(value=_ts(14, 17, 10))
    monkeypatch.setattr(ldata_service.time, "time", lambda: now.value)
    return now


def test_ldata_panel_does_not_guess_hardware_counters(clock) -> None:
    service = LDATAService("", "", None)

    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 0.03)])])

    assert service.panel_has_hw_counters("LDATA-1") is False
    assert service.panel_uses_hourly_energy("LDATA-1") is True
    # The startup listing value is the 16-17h delta.
    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.03)


def test_ldata_panel_ignores_hardware_counter_trust_evidence(clock) -> None:
    """The ledger, not the hardware-counter trust check, owns LDATA energy."""
    service = LDATAService("", "", None)
    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 1156.3)])])

    for _ in range(5):
        clock.value += 60
        service.report_hw_counter_untrusted("LDATA-1", "tech read 1.3 against 314.1")

    assert service._hw_counter_evidence.get("LDATA-1", 0) == 0
    assert service.panel_has_hw_counters("LDATA-1") is False
    assert service.panel_uses_hourly_energy("LDATA-1") is True


def test_whems_panel_is_still_demoted_by_trust_evidence(clock) -> None:
    service = LDATAService("", "", None)
    service.parse_panels([_whems_panel([_raw_breaker("w1", 15, 1234.5)])])

    for _ in range(5):
        clock.value += 60
        service.report_hw_counter_untrusted("1000_ABCD", "w1 read 1.3 against 1234.5")

    assert service.panel_has_hw_counters("1000_ABCD") is False


def test_ldata_startup_lifetime_counter_is_not_booked_as_energy(clock) -> None:
    service = LDATAService("", "", None)

    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 1156.3)])])

    assert service.energy_ledger.lifetime("tech") == 0.0


def test_whems_panel_is_unchanged(clock) -> None:
    service = LDATAService("", "", None)

    service.parse_panels([_whems_panel([_raw_breaker("w1", 15, 1234.5)])])

    assert service.panel_has_hw_counters("1000_ABCD") is True
    assert service.panel_uses_hourly_energy("1000_ABCD") is False
    assert service.energy_ledger.lifetime("w1") is None
    assert service.status_data["breakers"]["w1"]["consumption"] == 1234.5


def test_ldata_panel_does_not_enable_the_breaker_energy_poll(clock) -> None:
    # Hourly energy arrives over the WebSocket; the breaker poll has no LDATA
    # endpoint. A v1 WHEMS panel still needs it.
    service = LDATAService("", "", None)
    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 0.03)])])
    assert service.needs_breaker_poll is False

    whems = _whems_panel([_raw_breaker("w1", 15, 1234.5)])
    whems["updateVersion"] = "1.7.6"
    service = LDATAService("", "", None)
    service.parse_panels([whems])
    assert service.needs_breaker_poll is True


def test_websocket_burst_is_booked_for_ldata_breakers_only(clock) -> None:
    service = LDATAService("", "", None)
    service.parse_panels(
        [
            _ldata_panel([_raw_breaker("tech", 15, 0.03)]),
            _whems_panel([_raw_breaker("w1", 15, 1234.5)]),
        ]
    )
    clock.value = _ts(14, 18, 0, 29)

    for breaker_id, value in (("tech", 0.032470), ("w1", 1235.0)):
        service._update_from_websocket(
            {
                "modelName": "ResidentialBreaker",
                "modelId": breaker_id,
                "data": {"energyConsumption": value, "energyConsumption2": 0.0},
            }
        )

    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.06247)
    assert service.energy_ledger.lifetime("w1") is None
    assert service.status_data["breakers"]["w1"]["consumption"] == 1235.0


def _listing_service(clock, listing_value: float) -> LDATAService:
    service = LDATAService("", "", None)
    service.auth_token = "token"
    service.residence_id_list = ["res-1"]
    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 0.03)])])
    service.session = MagicMock()
    service.session.get.return_value = SimpleNamespace(
        status_code=200,
        json=lambda: [_ldata_panel([_raw_breaker("tech", 15, listing_value)])],
    )
    return service


def test_missed_burst_is_recovered_from_the_listing(clock) -> None:
    service = _listing_service(clock, 0.04)
    # The 18:00:29 burst never arrived (WebSocket reconnect).
    clock.value = _ts(14, 18, 4)
    assert not service.needs_ldata_energy_recovery()
    clock.value = _ts(14, 18, 6)
    assert service.needs_ldata_energy_recovery()

    assert service.refresh_ldata_energy() is True

    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.07)
    headers = service.session.get.call_args.kwargs["headers"]
    assert headers["filter"] == '{"include":["residentialBreakers"]}'
    # Once per hour.
    clock.value = _ts(14, 18, 30)
    assert not service.needs_ldata_energy_recovery()
    assert service.refresh_ldata_energy() is False
    assert service.session.get.call_count == 1


def test_recovery_retries_the_listing_once_on_a_dropped_connection(clock) -> None:
    # my.leviton.com closes idle keep-alive connections; a GET that races the
    # close fails before any response and is sent again on a new connection.
    service = _listing_service(clock, 0.04)
    listing = service.session.get.return_value
    service.session.get.side_effect = [
        requests.exceptions.ConnectionError(
            ("Connection aborted.", http.client.RemoteDisconnected("Remote end closed connection without response"))
        ),
        listing,
    ]
    clock.value = _ts(14, 18, 6)

    assert service.refresh_ldata_energy() is True

    assert service.session.get.call_count == 2
    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.07)
    assert not service.needs_ldata_energy_recovery()


def test_recovery_does_not_retry_a_read_timeout(clock) -> None:
    service = _listing_service(clock, 0.04)
    service.session.get.side_effect = requests.exceptions.ReadTimeout("Read timed out.")
    clock.value = _ts(14, 18, 6)

    with pytest.raises(requests.exceptions.ReadTimeout):
        service.refresh_ldata_energy()

    assert service.session.get.call_count == 1
    # The hour is not marked as read, so the next cycle tries again.
    assert service.needs_ldata_energy_recovery()


def test_recovery_reads_the_listing_once_per_hour_when_it_does_not_fill(clock) -> None:
    # The listing has no value for the missed hour (energyConsumption null).
    service = _listing_service(clock, None)
    clock.value = _ts(14, 18, 6)

    service.refresh_ldata_energy()
    assert service.session.get.call_count == 1
    assert not service.energy_ledger.has_delta_for("tech", int(_ts(14, 17)))
    assert service.needs_ldata_energy_recovery() is False
    for minute in (8, 10, 30, 59):
        clock.value = _ts(14, 18, minute)
        assert service.refresh_ldata_energy() is False
    assert service.session.get.call_count == 1

    # The next hour is checked again.
    clock.value = _ts(14, 19, 6)
    assert service.needs_ldata_energy_recovery() is True
    service.refresh_ldata_energy()
    assert service.session.get.call_count == 2


def test_recovery_does_not_book_a_listing_value_left_from_the_previous_hour(clock) -> None:
    # The startup listing at 17:10 books 0.03 for 16-17h. The hub is offline
    # across 18:00:29, and at 18:06 the listing still shows 0.03.
    service = _listing_service(clock, 0.03)
    clock.value = _ts(14, 18, 6)

    # Only the zero on leg 2 is booked.
    service.refresh_ldata_energy()

    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.03)
    assert not service.energy_ledger.has_delta_for("tech", int(_ts(14, 17)))
    assert service.session.get.call_count == 1
    assert not service.needs_ldata_energy_recovery()


def test_no_recovery_when_burst_arrived(clock) -> None:
    service = _listing_service(clock, 0.04)
    clock.value = _ts(14, 18, 0, 29)
    service._update_from_websocket(
        {"modelName": "ResidentialBreaker", "modelId": "tech", "data": {"energyConsumption": 0.04, "energyConsumption2": 0.0}}
    )
    clock.value = _ts(14, 18, 6)

    assert not service.needs_ldata_energy_recovery()
    assert service.refresh_ldata_energy() is False
    service.session.get.assert_not_called()


def test_websocket_rating_refresh_feeds_the_hourly_bound(clock) -> None:
    service = LDATAService("", "", None)
    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 0.03)])])
    clock.value = _ts(14, 18, 0, 29)

    # 5 kWh is above the 15 A bound (3.6 kWh) but below the 30 A bound
    # (7.2 kWh). The rating in the same payload is applied first.
    service._update_from_websocket(
        {
            "modelName": "ResidentialBreaker",
            "modelId": "tech",
            "data": {"currentRating": 30, "energyConsumption": 5.0, "energyConsumption2": 0.0},
        }
    )

    assert service.status_data["breakers"]["tech"]["rating"] == 30
    assert service.energy_ledger.lifetime("tech") == pytest.approx(5.03)


def test_listing_recovery_uses_the_listing_rating(clock) -> None:
    service = LDATAService("", "", None)
    service.auth_token = "token"
    service.residence_id_list = ["res-1"]
    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 0.03)])])
    service.session = MagicMock()
    service.session.get.return_value = SimpleNamespace(
        status_code=200,
        json=lambda: [_ldata_panel([_raw_breaker("tech", 30, 5.04)])],
    )
    clock.value = _ts(14, 18, 6)

    assert service.refresh_ldata_energy() is True

    assert service.energy_ledger.lifetime("tech") == pytest.approx(5.07)



def _offline(panel: dict) -> dict:
    """The panel as the listing shows it while the hub is offline."""
    return {**panel, "status": "NOT_READY", "online": None, "offline": "2026-10-16T19:21:00.000Z"}


def test_recovery_does_not_book_the_listing_of_an_offline_panel(clock) -> None:
    # 2026-10-16: the hub went offline at 12:21; at 14:06:52 the listing
    # still showed a delta of 0.03 kWh, and dev7 booked it as 13-14h.
    service = _listing_service(clock, 0.03)
    service.session.get.return_value = SimpleNamespace(
        status_code=200,
        json=lambda: [_offline(_ldata_panel([_raw_breaker("tech", 15, 0.04)]))],
    )
    clock.value = _ts(14, 18, 6)

    assert service.refresh_ldata_energy() is False

    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.03)
    assert not service.energy_ledger.has_delta_for("tech", int(_ts(14, 17)))
    # The hour is not marked as read: once the panel is back the listing is
    # read again.
    assert service.needs_ldata_energy_recovery()


def test_recovery_waits_while_the_cached_panel_state_is_offline(clock) -> None:
    service = _listing_service(clock, 0.04)
    service.status_data["panels"][0]["connected"] = False
    clock.value = _ts(14, 18, 6)

    assert not service.needs_ldata_energy_recovery()
    assert service.refresh_ldata_energy() is False
    service.session.get.assert_not_called()

    # Back online within the hour: the missed burst is read from the
    # listing, once the panel has been back for PANEL_RECONNECT_SETTLE_SECS.
    service.status_data["panels"][0]["connected"] = True
    assert not service.needs_ldata_energy_recovery()
    clock.value = _ts(14, 18, 6) + ldata_energy.PANEL_RECONNECT_SETTLE_SECS - 1
    assert not service.needs_ldata_energy_recovery()
    clock.value = _ts(14, 18, 6) + ldata_energy.PANEL_RECONNECT_SETTLE_SECS
    assert service.needs_ldata_energy_recovery()
    assert service.refresh_ldata_energy() is True
    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.07)


def test_offline_listing_still_applies_a_lifetime_counter(clock) -> None:
    service = _listing_service(clock, 0.03)
    service.energy_ledger.apply("tech", 15, {"1": 1156.3}, _ts(14, 12, 5), "WS")
    service.session.get.return_value = SimpleNamespace(
        status_code=200,
        json=lambda: [_offline(_ldata_panel([_raw_breaker("tech", 15, 1158.2)]))],
    )
    clock.value = _ts(14, 18, 6)

    assert service.refresh_ldata_energy() is True

    assert service.energy_ledger.lifetime("tech") > 0.03


def test_websocket_burst_for_an_offline_panel_is_not_booked(clock) -> None:
    service = LDATAService("", "", None)
    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 0.03)])])
    service.status_data["panels"][0]["connected"] = False
    clock.value = _ts(14, 18, 0, 29)

    service._update_from_websocket(
        {"modelName": "ResidentialBreaker", "modelId": "tech", "data": {"energyConsumption": 0.04, "energyConsumption2": 0.0}}
    )

    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.03)



def _ws_energy(service: LDATAService, breaker_id: str, ec1: float, ec2: float = 0.0) -> None:
    service._update_from_websocket(
        {"modelName": "ResidentialBreaker", "modelId": breaker_id,
         "data": {"energyConsumption": ec1, "energyConsumption2": ec2}}
    )


def test_hub_upload_after_an_outage_is_not_booked(clock) -> None:
    # 2026-10-17: the hub was offline 02:17-04:56. At 04:56:38 it came back
    # (first panel frame), at 04:56:48 the kitchen cabinets breaker sent its
    # lifetime counter, and at 05:00:07.558, 05:00:08.088 and 05:00:19.620
    # every breaker got an energyConsumption message, three per breaker,
    # none saying which hour it covers.
    service = LDATAService("", "", None)
    clock.value = _ts(17, 1, 6, 54)
    service.parse_panels([_ldata_panel([
        _raw_breaker("cabinets", 15, 0.0101), _raw_breaker("tech", 15, 0.0401, position=3),
    ])])
    clock.value = _ts(17, 2, 17, 34)
    service.status_data["panels"][0]["connected"] = False
    service.observe_ldata_panels()
    clock.value = _ts(17, 4, 56, 38)
    service.status_data["panels"][0]["connected"] = True
    clock.value = _ts(17, 4, 56, 40)
    service.observe_ldata_panels()

    ledger = service.energy_ledger
    ledger.apply("cabinets", 15, {"1": 457.9}, _ts(16, 17, 27, 6), "WS")
    clock.value = _ts(17, 4, 56, 48) + 0.985
    _ws_energy(service, "cabinets", 458.1, 0.0)
    cabinets = ledger.lifetime("cabinets")
    assert cabinets > 0.0101  # The counter is applied while the panel settles.

    for second, tech, cab in ((7.558, 0.0398, 0.0102), (8.088, 0.0402, 0.0099), (19.620, 0.0396, 0.0101)):
        clock.value = _ts(17, 5, 0, 0) + second
        _ws_energy(service, "tech", tech)
        _ws_energy(service, "cabinets", cab)
    assert ledger.lifetime("tech") == pytest.approx(0.0401)
    assert ledger.lifetime("cabinets") == pytest.approx(cabinets)
    assert not ledger.has_delta_for("tech", int(_ts(17, 4)))

    # The listing is not read while the panel settles either, nor booked if
    # read for another panel.
    clock.value = _ts(17, 5, 6)
    assert not service.needs_ldata_energy_recovery()
    service.auth_token = "token"
    service.residence_id_list = ["res-1"]
    service.session = MagicMock()
    service.session.get.return_value = SimpleNamespace(
        status_code=200,
        json=lambda: [_ldata_panel([_raw_breaker("tech", 15, 0.04, position=3)])],
    )
    assert service._refresh_ldata_energy_locked() is False
    assert ledger.lifetime("tech") == pytest.approx(0.0401)
    assert service._energy_recovery_hour is None

    # Ten minutes after the hub came back, deltas are booked again.
    clock.value = _ts(17, 4, 56, 40) + ldata_energy.PANEL_RECONNECT_SETTLE_SECS
    assert service._ldata_panel_connected("LDATA-1")
    clock.value = _ts(17, 6, 0, 36) + 0.4
    _ws_energy(service, "tech", 0.0399)
    assert ledger.lifetime("tech") == pytest.approx(0.08)


def test_hub_reconnect_is_noticed_without_an_energy_value(clock) -> None:
    # The coordinator calls observe_ldata_panels on every push, so the
    # settle period starts when the panel is seen online, not at the next
    # burst.
    service = LDATAService("", "", None)
    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 0.03)])])
    service.status_data["panels"][0]["connected"] = False
    clock.value = _ts(17, 8, 25, 0)
    service.observe_ldata_panels()
    service.status_data["panels"][0]["connected"] = True
    clock.value = _ts(17, 8, 26, 39)
    service.observe_ldata_panels()

    # The upload at 08:30:50 and the 09:00:36 burst, 34 minutes later.
    clock.value = _ts(17, 8, 26, 39) + ldata_energy.PANEL_RECONNECT_SETTLE_SECS - 1
    assert not service._ldata_panel_connected("LDATA-1")
    clock.value = _ts(17, 9, 0, 36) + 0.4
    _ws_energy(service, "tech", 0.0328)
    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.0628)


def test_panel_online_at_startup_does_not_settle(clock) -> None:
    service = LDATAService("", "", None)
    service.parse_panels([_ldata_panel([_raw_breaker("tech", 15, 0.03)])])
    clock.value = _ts(14, 18, 0, 36)

    _ws_energy(service, "tech", 0.04)

    assert service.energy_ledger.lifetime("tech") == pytest.approx(0.07)


def test_startup_listing_of_an_offline_panel_is_not_booked(clock) -> None:
    service = LDATAService("", "", None)

    service.parse_panels([_offline(_ldata_panel([_raw_breaker("tech", 15, 0.03)]))])

    assert service.status_data["panels"][0]["connected"] is False
    assert service.energy_ledger.lifetime("tech") in (None, 0.0)

# ── Coordinator persistence ────────────────────────────────────────


def _ledger_coordinator(stored: dict | None) -> LDATAUpdateCoordinator:
    """A coordinator with only the energy-ledger parts; run its methods inside a loop."""
    import asyncio

    coordinator = LDATAUpdateCoordinator.__new__(LDATAUpdateCoordinator)
    coordinator._service = SimpleNamespace(
        energy_ledger=LDATAEnergyLedger(), version="test", _shutdown_requested=False
    )
    coordinator._energy_store = MagicMock()
    coordinator._energy_store.async_load = AsyncMock(return_value=stored)
    coordinator.written = []

    async def save(data):
        coordinator.written.append(json.loads(json.dumps(data)))

    coordinator._energy_store.async_save = AsyncMock(side_effect=save)
    coordinator._energy_loaded = False
    coordinator._energy_save_task = None
    coordinator._hass = SimpleNamespace(
        async_create_task=lambda coro, name=None: asyncio.get_running_loop().create_task(coro)
    )
    coordinator.async_update_listeners = MagicMock()
    return coordinator


def test_coordinator_push_tracks_the_ldata_panel_state() -> None:
    coordinator = LDATAUpdateCoordinator.__new__(LDATAUpdateCoordinator)
    coordinator._service = MagicMock(version="test", _shutdown_requested=False)
    coordinator._service.status_data = {"breakers": {}, "cts": {}}
    coordinator._hass = SimpleNamespace(loop=MagicMock())
    coordinator.config_entry = SimpleNamespace(options={})
    coordinator._websocket_connected = True
    coordinator._debounce_timer = None
    coordinator.async_set_updated_data = MagicMock()
    coordinator._save_energy_ledger = MagicMock()
    coordinator._log_data_if_enabled = MagicMock()

    coordinator._apply_debounced_update()

    coordinator._service.observe_ldata_panels.assert_called_once_with()
    coordinator.async_set_updated_data.assert_called_once()


def _stored_ledger() -> dict:
    stored = LDATAEnergyLedger()
    stored.apply("tech", 15, {"1": 0.5, "2": 0.0}, _ts(14, 16, 0, 29), "WS")
    return json.loads(json.dumps(stored.as_dict()))


def test_coordinator_loads_once_and_saves_each_change() -> None:
    import asyncio

    coordinator = _ledger_coordinator(_stored_ledger())
    ledger = coordinator._service.energy_ledger

    async def run():
        # Nothing is saved before the ledger is loaded (it would wipe the file).
        ledger.dirty = True
        coordinator._save_energy_ledger()
        assert coordinator._energy_save_task is None

        await coordinator._async_load_energy_ledger()
        await coordinator._async_load_energy_ledger()
        assert coordinator._energy_store.async_load.await_count == 1
        assert ledger.lifetime("tech") == pytest.approx(0.5)

        coordinator._save_energy_ledger()
        assert coordinator._energy_save_task is None

        # A booking is written right away, and the sensors see it only then.
        ledger.apply("tech", 15, {"1": 0.1, "2": 0.0}, _ts(14, 17, 0, 29), "WS")
        assert ledger.lifetime("tech") == pytest.approx(0.5)
        coordinator._save_energy_ledger()
        await coordinator._energy_save_task
        assert len(coordinator.written) == 1
        assert coordinator.written[0]["breakers"]["tech"]["legs"]["1"]["lifetime"] == pytest.approx(0.6)
        assert ledger.lifetime("tech") == pytest.approx(0.6)
        assert _today(ledger, "tech", 14) == pytest.approx(0.6)
        coordinator.async_update_listeners.assert_called_once()
        assert not ledger.dirty

    asyncio.run(run())


def test_coordinator_save_includes_bookings_made_while_writing() -> None:
    import asyncio

    coordinator = _ledger_coordinator(None)
    ledger = coordinator._service.energy_ledger
    written = coordinator.written

    async def run():
        write_done = asyncio.Event()

        async def save(data):
            written.append(json.loads(json.dumps(data)))
            if len(written) == 1:
                # A REST poll books from an executor thread during the write
                # and asks for a save.
                ledger.apply("island", 20, {"1": 0.23}, _ts(14, 17, 10), "REST")
                coordinator._save_energy_ledger()
                await write_done.wait()

        coordinator._energy_store.async_save.side_effect = save
        await coordinator._async_load_energy_ledger()
        ledger.apply("tech", 15, {"1": 0.1}, _ts(14, 17, 0, 29), "WS")
        coordinator._save_energy_ledger()
        first = coordinator._energy_save_task
        for _ in range(5):
            await asyncio.sleep(0)
        write_done.set()
        await first
        await coordinator._energy_save_task

    asyncio.run(run())

    # The second booking is written after the first write, in order.
    assert len(written) == 2
    assert "island" not in written[0]["breakers"]
    assert "island" in written[1]["breakers"]
    assert ledger.lifetime("tech") == pytest.approx(0.1)
    assert ledger.lifetime("island") == pytest.approx(0.23)
    assert not ledger.dirty


def test_crash_before_the_save_does_not_count_an_hour_twice(sensor_clock) -> None:
    """The sensors never get ahead of the stored ledger."""
    import asyncio

    sensor_clock.value = _ts(14, 17, 5)

    async def run(coordinator, steps):
        await coordinator._async_load_energy_ledger()
        steps(coordinator._service.energy_ledger)
        if coordinator._energy_save_task is not None:
            await coordinator._energy_save_task

    # Before the crash: the 16-17h burst is booked, and the sensors update
    # before the ledger is written.
    before = _ledger_coordinator(_stored_ledger())
    lifetime = _lifetime_sensor(before._service.energy_ledger)
    lifetime._state = 10.0
    lifetime._ledger_ref = 0.5
    daily = _daily_sensor(before._service.energy_ledger)
    daily._state = 0.5
    daily._ledger_ref = 0.5
    daily._last_date = datetime.date(2026, 10, 14)

    def book_burst(ledger):
        ledger.apply("tech", 15, {"1": 0.1, "2": 0.0}, _ts(14, 17, 0, 29), "WS")
        lifetime._state_update()
        daily._state_update()

    asyncio.run(run(before, book_burst))
    restored = [(e._state, e._ledger_ref) for e in (lifetime, daily)]

    # Home Assistant crashes before the write: the restart loads the stored
    # ledger without 16-17h and the sensor states saved before the crash.
    after = _ledger_coordinator(_stored_ledger())
    lifetime = _lifetime_sensor(after._service.energy_ledger)
    daily = _daily_sensor(after._service.energy_ledger)
    (lifetime._state, lifetime._ledger_ref), (daily._state, daily._ledger_ref) = restored
    daily._last_date = datetime.date(2026, 10, 14)
    sensor_clock.value = _ts(14, 17, 10)

    def recover(ledger):
        # The first update after the restart, then the listing recovery
        # books 16-17h again.
        lifetime._state_update()
        daily._state_update()
        ledger.apply("tech", 15, {"1": 0.1, "2": 0.0}, _ts(14, 17, 10), "REST")
        after._save_energy_ledger()

    asyncio.run(run(after, recover))
    lifetime._state_update()
    daily._state_update()

    assert lifetime._state == pytest.approx(10.1)
    assert daily._state == pytest.approx(0.6)


def _shutdown_ready(coordinator: LDATAUpdateCoordinator) -> LDATAUpdateCoordinator:
    """Add the state async_shutdown needs to a _ledger_coordinator."""
    # DataUpdateCoordinator state that the base async_shutdown uses.
    coordinator._unsub_refresh = None
    coordinator._unsub_shutdown = None
    coordinator._debounced_refresh = MagicMock()
    for task in (
        "_rest_poll_task", "_ct_poll_task", "_panel_status_task", "_energy_task",
        "_websocket_task", "_debounce_timer",
    ):
        setattr(coordinator, task, None)
    return coordinator


def test_coordinator_shutdown_writes_the_ledger() -> None:
    import asyncio

    coordinator = _shutdown_ready(_ledger_coordinator(None))
    ledger = coordinator._service.energy_ledger

    async def run():
        await coordinator._async_load_energy_ledger()
        # A booking whose save has not started yet.
        ledger.apply("tech", 15, {"1": 0.5, "2": 0.0}, _ts(14, 16, 0, 29), "WS")
        expected = ledger.as_dict()
        await coordinator.async_shutdown()
        assert coordinator.written == [expected]
        assert not ledger.dirty
        assert ledger.lifetime("tech") == pytest.approx(0.5)
        # Unload calls async_shutdown twice; the second call does nothing.
        await coordinator.async_shutdown()
        assert len(coordinator.written) == 1

    asyncio.run(run())

    # Not loaded: nothing is written (it would wipe the stored ledger).
    coordinator = _shutdown_ready(_ledger_coordinator(None))
    coordinator._service.energy_ledger.apply("tech", 15, {"1": 0.5}, _ts(14, 16, 0, 29), "WS")
    asyncio.run(coordinator.async_shutdown())
    coordinator._energy_store.async_save.assert_not_awaited()


def test_coordinator_shutdown_waits_for_a_running_save() -> None:
    import asyncio

    coordinator = _shutdown_ready(_ledger_coordinator(None))
    ledger = coordinator._service.energy_ledger
    written = coordinator.written
    write_started = asyncio.Event()
    write_done = asyncio.Event()
    in_flight = []

    async def save(data):
        # Writes never overlap: a late one could replace a newer file.
        assert not in_flight
        in_flight.append(data)
        if not written:
            write_started.set()
            await write_done.wait()
        written.append(json.loads(json.dumps(data)))
        in_flight.pop()

    coordinator._energy_store.async_save.side_effect = save

    async def run():
        await coordinator._async_load_energy_ledger()
        ledger.apply("tech", 15, {"1": 0.1}, _ts(14, 17, 0, 29), "WS")
        coordinator._save_energy_ledger()
        save_task = coordinator._energy_save_task
        await write_started.wait()
        # Booked while the first write runs (REST poll executor thread).
        ledger.apply("island", 20, {"1": 0.23}, _ts(14, 17, 10), "REST")

        shutdown = asyncio.ensure_future(coordinator.async_shutdown())
        for _ in range(5):
            await asyncio.sleep(0)
        assert not shutdown.done()
        # No save starts once the shutdown has begun.
        coordinator._save_energy_ledger()
        assert coordinator._energy_save_task is None
        write_done.set()
        await shutdown
        assert save_task.done()

    asyncio.run(run())

    # The running write finished, then its loop wrote the later booking;
    # the final save had nothing left. No task is left behind.
    assert len(written) == 2
    assert "island" not in written[0]["breakers"]
    assert "island" in written[1]["breakers"]
    assert not ledger.dirty
    assert ledger.lifetime("island") == pytest.approx(0.23)


def test_coordinator_shutdown_retries_a_failed_save() -> None:
    import asyncio

    coordinator = _shutdown_ready(_ledger_coordinator(None))
    ledger = coordinator._service.energy_ledger
    written = coordinator.written
    attempts = []

    async def save(data):
        attempts.append(data)
        if len(attempts) <= 2:
            raise OSError("disk full")
        written.append(json.loads(json.dumps(data)))

    coordinator._energy_store.async_save.side_effect = save

    async def run():
        await coordinator._async_load_energy_ledger()
        ledger.apply("tech", 15, {"1": 0.1}, _ts(14, 17, 0, 29), "WS")
        coordinator._save_energy_ledger()
        for _ in range(3):
            await asyncio.sleep(0)
        assert coordinator._energy_save_task.done()
        assert ledger.dirty
        # The failed save is logged; the final write fails too and raises.
        with pytest.raises(OSError):
            await coordinator.async_shutdown()
        assert ledger.dirty
        # The failed call left the shutdown undone: the next one writes.
        await coordinator.async_shutdown()

    asyncio.run(run())

    assert len(attempts) == 3
    assert len(written) == 1
    assert written[0]["breakers"]["tech"]["legs"]["1"]["lifetime"] == pytest.approx(0.1)
    assert not ledger.dirty


def test_coordinator_shutdown_and_cancelled_saves() -> None:
    import asyncio

    coordinator = _shutdown_ready(_ledger_coordinator(None))
    ledger = coordinator._service.energy_ledger
    written = coordinator.written
    block = asyncio.Event()

    async def save(data):
        if not block.is_set():
            await asyncio.Event().wait()  # Never finishes.
        written.append(json.loads(json.dumps(data)))

    coordinator._energy_store.async_save.side_effect = save

    async def run():
        await coordinator._async_load_energy_ledger()

        # A save cancelled by someone else: the shutdown still writes.
        ledger.apply("tech", 15, {"1": 0.1}, _ts(14, 17, 0, 29), "WS")
        coordinator._save_energy_ledger()
        await asyncio.sleep(0)
        coordinator._energy_save_task.cancel()
        block.set()
        await coordinator.async_shutdown()
        assert len(written) == 1
        assert "tech" in written[0]["breakers"]
        assert not ledger.dirty

        # A cancelled shutdown (e.g. Home Assistant stopping) stays cancelled.
        # Start from a running coordinator again.
        block.clear()
        coordinator._service._shutdown_requested = False
        coordinator._shutdown_done = False
        ledger.apply("tech", 15, {"1": 0.2}, _ts(14, 18, 0, 29), "WS")
        coordinator._save_energy_ledger()
        shutdown = asyncio.ensure_future(coordinator.async_shutdown())
        for _ in range(3):
            await asyncio.sleep(0)
        shutdown.cancel()
        with pytest.raises(asyncio.CancelledError):
            await shutdown
        assert len(written) == 1
        assert ledger.dirty

    asyncio.run(run())


# ── Sensors ────────────────────────────────────────────────────────────


class _Coordinator:
    def __init__(self, service, breakers: dict) -> None:
        self._service = service
        self.data = {"breakers": breakers}
        self.last_update_success = True
        self.user = "test-user"
        self.config_entry = SimpleNamespace(options={})

    def async_add_listener(self, update_callback, context=None):
        return lambda: None


BREAKER = {"id": "tech", "stable_id": "tech", "name": "Tech", "panel_id": "LDATA-1", "poles": 1, "position": 1}


def _hourly_service(ledger: LDATAEnergyLedger, hourly: bool = True):
    return SimpleNamespace(
        energy_ledger=ledger,
        panel_uses_hourly_energy=lambda panel_id: hourly,
        panel_has_hw_counters=lambda panel_id: False,
    )


def _lifetime_sensor(ledger, hourly=True):
    coordinator = _Coordinator(_hourly_service(ledger, hourly), {"tech": dict(BREAKER)})
    entity = sensor.LDATABreakerEnergyUsageSensor(
        coordinator, dict(BREAKER), sensor.SENSOR_TYPES[sensor.CONSUMPTION]
    )
    entity.async_write_ha_state = MagicMock()
    return entity


def test_lifetime_sensor_continues_from_restored_value_without_jump() -> None:
    ledger = LDATAEnergyLedger()
    entity = _lifetime_sensor(ledger)
    # Restored from before the upgrade: an inflated lifetime value, no ledger reference.
    entity._state = 1156.3

    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 16, 0, 29), "WS")
    entity._state_update()
    assert entity.native_value == 1156.3

    ledger.apply("tech", 15, {"1": 0.05}, _ts(14, 17, 0, 29), "WS")
    entity._state_update()
    assert entity._state == pytest.approx(1156.35)
    assert entity.extra_state_attributes["ledger_ref"] == pytest.approx(0.08)

    # A lifetime counter in the stream does not move the sensor.
    ledger.apply("tech", 15, {"1": 1156.3}, _ts(14, 17, 42), "WS")
    entity._state_update()
    assert entity._state == pytest.approx(1156.35)


def test_lifetime_sensor_never_drops_when_ledger_is_lost() -> None:
    ledger = LDATAEnergyLedger()
    entity = _lifetime_sensor(ledger)
    entity._state = 20.0
    entity._ledger_ref = 5.0

    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 16, 0, 29), "WS")
    entity._state_update()
    assert entity._state == 20.0

    ledger.apply("tech", 15, {"1": 0.02}, _ts(14, 17, 0, 29), "WS")
    entity._state_update()
    assert entity._state == pytest.approx(20.02)


def test_lifetime_sensor_restart_picks_up_energy_booked_meanwhile(monkeypatch) -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.5}, _ts(14, 16, 0, 29), "WS")
    entity = _lifetime_sensor(ledger)
    entity.hass = MagicMock()
    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    # The last saved state matched a ledger total of 0.3.
    entity.async_get_last_state = AsyncMock(
        return_value=State("sensor.tech_consumption", "10.0", {"ledger_ref": 0.3})
    )

    import asyncio

    asyncio.run(entity.async_added_to_hass())
    assert entity._state == 10.0

    entity._state_update()
    assert entity._state == pytest.approx(10.2)


def test_lifetime_sensor_first_start_without_restore_starts_at_ledger() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 16, 0, 29), "WS")
    entity = _lifetime_sensor(ledger)

    entity._state_update()

    assert entity._state == pytest.approx(0.03)


def test_lifetime_sensor_waits_for_first_ledger_data() -> None:
    entity = _lifetime_sensor(LDATAEnergyLedger())
    entity._state = 42.0

    entity._state_update()

    assert entity._state == 42.0
    entity.async_write_ha_state.assert_not_called()


def _daily_sensor(ledger, breakers=None, panel_total=False, hourly=True):
    breakers = breakers or {"tech": dict(BREAKER)}
    coordinator = _Coordinator(_hourly_service(ledger, hourly), breakers)
    if panel_total:
        data = {"id": "LDATA-1", "name": "Panel", "serialNumber": "LDATA-1", "poles": 2}
        entity = sensor.LDATADailyUsageSensor(coordinator, data, True, which_panel="LDATA-1")
    else:
        entity = sensor.LDATADailyUsageSensor(coordinator, dict(BREAKER), False, "")
    entity.async_write_ha_state = MagicMock()
    return entity


@pytest.fixture
def sensor_clock(monkeypatch):
    now = SimpleNamespace(value=_ts(14, 17, 10))
    monkeypatch.setattr(sensor.time, "time", lambda: now.value)
    return now


def test_daily_sensor_follows_ledger_and_switches_day_at_one(sensor_clock) -> None:
    ledger = LDATAEnergyLedger()
    entity = _daily_sensor(ledger)
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 23, 0, 29), "WS")
    sensor_clock.value = _ts(14, 23, 10)
    entity._state_update()
    assert entity._state == pytest.approx(0.03)

    # The 00:00:29 burst still belongs to the 14th.
    ledger.apply("tech", 15, {"1": 0.05}, _ts(15, 0, 0, 29), "WS")
    sensor_clock.value = _ts(15, 0, 1)
    entity._state_update()
    assert entity._state == pytest.approx(0.08)

    sensor_clock.value = _ts(15, 1, 0, 5)
    entity._state_update()
    assert entity._state == 0.0
    assert entity._last_date == datetime.date(2026, 10, 15)


def _record_writes(entity, added=True) -> list[tuple]:
    """Make async_write_ha_state record (state, last_date, ledger_ref) as Home Assistant would.

    Home Assistant drops a state write until the entity is added
    (EntityPlatformState.ADDED is set after async_added_to_hass returns, see
    Entity.add_to_platform_finish), then writes the state once itself.
    Set ``entity.added`` to True to model that.
    """
    writes = []
    entity.added = added

    def write():
        if not entity.added:
            return
        attrs = entity.extra_state_attributes
        writes.append((entity.native_value, attrs["last_date"], attrs.get("ledger_ref")))

    entity.async_write_ha_state = MagicMock(side_effect=write)
    return writes


def test_daily_sensor_restart_across_day_change_reports_a_reset_first(
    sensor_clock, monkeypatch
) -> None:
    """Home Assistant down across 01:00: the new day already has energy at the first update.

    The recorder takes a TOTAL_INCREASING drop as a new cycle only below
    90 % of the previous state; 1.55 -> 1.50 would lose the new day's
    1.50 kWh from the long-term statistics. The first update runs inside
    async_added_to_hass, where a state write is dropped, so the state Home
    Assistant writes after adding the entity must be the 0.
    """
    ledger = LDATAEnergyLedger()
    for hour in range(1, 4):  # 00:00-03:00 on the 15th
        ledger.apply("tech", 15, {"1": 0.5}, _ts(15, hour, 0, 29), "WS")
    entity = _daily_sensor(ledger)
    writes = _record_writes(entity, added=False)
    entity.hass = MagicMock()
    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    entity.async_get_last_state = AsyncMock(
        return_value=State(
            "sensor.tech_daily_consumption",
            "1.55",
            {"last_date": "2026-10-14", "ledger_ref": 1.63},
        )
    )
    sensor_clock.value = _ts(15, 3, 1)

    import asyncio

    asyncio.run(entity.async_added_to_hass())
    assert writes == []
    entity.added = True
    entity.async_write_ha_state()  # Entity.add_to_platform_finish

    assert writes == [(0.0, "2026-10-15", 0.0)]
    assert entity._last_date == datetime.date(2026, 10, 15)

    # The next update adds the day's ledger total.
    sensor_clock.value = _ts(15, 3, 2)
    entity._state_update()
    assert writes[1:] == [(pytest.approx(1.5), "2026-10-15", pytest.approx(1.5))]

    # The day continues from the ledger total.
    ledger.apply("tech", 15, {"1": 0.25}, _ts(15, 4, 0, 29), "WS")
    sensor_clock.value = _ts(15, 4, 1)
    entity._state_update()
    assert writes[2:] == [(pytest.approx(1.75), "2026-10-15", pytest.approx(1.75))]


def test_daily_sensor_day_change_with_stored_energy_reports_a_reset_first(sensor_clock) -> None:
    """Running: the 01:00:29 burst is stored before the first update past 01:00."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1.5}, _ts(14, 23, 0, 29), "WS")
    entity = _daily_sensor(ledger)
    writes = _record_writes(entity)
    sensor_clock.value = _ts(14, 23, 1)
    entity._state_update()
    assert writes == [(1.5, "2026-10-14", 1.5)]

    ledger.apply("tech", 15, {"1": 1.4}, _ts(15, 1, 0, 29), "WS")
    sensor_clock.value = _ts(15, 1, 0, 40)
    entity._state_update()
    sensor_clock.value = _ts(15, 1, 1, 40)
    entity._state_update()
    assert writes[1:] == [
        (0.0, "2026-10-15", 0.0),
        (pytest.approx(1.4), "2026-10-15", pytest.approx(1.4)),
    ]


def test_daily_sensor_day_change_without_stored_energy_writes_once(sensor_clock) -> None:
    """The usual 01:00 day change: the new day has no stored energy yet, one write of 0."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1.5}, _ts(14, 23, 0, 29), "WS")
    entity = _daily_sensor(ledger)
    writes = _record_writes(entity)
    sensor_clock.value = _ts(14, 23, 1)
    entity._state_update()
    assert writes == [(1.5, "2026-10-14", 1.5)]

    sensor_clock.value = _ts(15, 1, 0, 5)
    entity._state_update()
    assert writes[1:] == [(0.0, "2026-10-15", 0.0)]

    ledger.apply("tech", 15, {"1": 0.06}, _ts(15, 1, 0, 29), "WS")
    sensor_clock.value = _ts(15, 1, 0, 56)
    entity._state_update()
    assert writes[2:] == [(0.06, "2026-10-15", pytest.approx(0.06))]


def _record_followups(monkeypatch) -> list:
    """Capture the follow-up updates the daily sensor schedules with async_call_later."""
    scheduled = []

    def call_later(hass, delay, action):
        unsub = MagicMock()
        scheduled.append(SimpleNamespace(delay=delay, action=action, unsub=unsub))
        return unsub

    monkeypatch.setattr(sensor, "async_call_later", call_later)
    return scheduled


def test_daily_sensor_reset_is_followed_up_without_a_coordinator_update(
    sensor_clock, monkeypatch
) -> None:
    """After the restart reset, the day's ledger total follows without waiting for a push.

    Pushes stop while the WebSocket is down, and the cadence can be up to
    600 s: the sensor must not show 0 for the day until one arrives.
    """
    ledger = LDATAEnergyLedger()
    for hour in range(1, 4):
        ledger.apply("tech", 15, {"1": 0.5}, _ts(15, hour, 0, 29), "WS")
    entity = _daily_sensor(ledger)
    writes = _record_writes(entity, added=False)
    scheduled = _record_followups(monkeypatch)
    entity.hass = MagicMock()
    monkeypatch.setattr(CoordinatorEntity, "async_added_to_hass", AsyncMock())
    entity.async_get_last_state = AsyncMock(
        return_value=State(
            "sensor.tech_daily_consumption",
            "1.55",
            {"last_date": "2026-10-14", "ledger_ref": 1.63},
        )
    )
    sensor_clock.value = _ts(15, 3, 1)

    import asyncio

    asyncio.run(entity.async_added_to_hass())
    entity.added = True
    entity.async_write_ha_state()  # Entity.add_to_platform_finish
    assert writes == [(0.0, "2026-10-15", 0.0)]
    assert len(scheduled) == 1 and scheduled[0].delay > 0

    sensor_clock.value = _ts(15, 3, 1, 1)
    scheduled[0].action(None)
    assert writes[1:] == [(pytest.approx(1.5), "2026-10-15", pytest.approx(1.5))]
    assert len(scheduled) == 1

    # A coordinator update after the follow-up adds nothing twice.
    entity._state_update()
    assert writes[-1] == (pytest.approx(1.5), "2026-10-15", pytest.approx(1.5))


def test_daily_sensor_reset_follow_up_is_cancelled_on_removal(sensor_clock, monkeypatch) -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1.5}, _ts(14, 23, 0, 29), "WS")
    entity = _daily_sensor(ledger)
    _record_writes(entity)
    scheduled = _record_followups(monkeypatch)
    entity.hass = MagicMock()
    sensor_clock.value = _ts(14, 23, 1)
    entity._state_update()
    ledger.apply("tech", 15, {"1": 1.4}, _ts(15, 1, 0, 29), "WS")
    sensor_clock.value = _ts(15, 1, 0, 40)
    entity._state_update()
    assert len(scheduled) == 1

    import asyncio

    asyncio.run(entity.async_will_remove_from_hass())
    scheduled[0].unsub.assert_called_once_with()


def test_daily_sensor_day_change_from_zero_writes_the_day_once(sensor_clock, monkeypatch) -> None:
    """Yesterday ended at 0: the new day's stored energy is an increase, no reset cycle."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.0}, _ts(14, 23, 0, 29), "WS")
    entity = _daily_sensor(ledger)
    writes = _record_writes(entity)
    scheduled = _record_followups(monkeypatch)
    entity.hass = MagicMock()
    sensor_clock.value = _ts(14, 23, 1)
    entity._state_update()
    assert writes == [(0.0, "2026-10-14", 0.0)]

    ledger.apply("tech", 15, {"1": 1.4}, _ts(15, 1, 0, 29), "WS")
    sensor_clock.value = _ts(15, 1, 0, 40)
    entity._state_update()
    assert writes[1:] == [(pytest.approx(1.4), "2026-10-15", pytest.approx(1.4))]
    assert scheduled == []

    sensor_clock.value = _ts(15, 1, 1, 40)
    entity._state_update()
    assert writes[2:] == [(pytest.approx(1.4), "2026-10-15", pytest.approx(1.4))]


def test_daily_sensor_upgrade_day_keeps_restored_value(sensor_clock) -> None:
    ledger = LDATAEnergyLedger()
    entity = _daily_sensor(ledger)
    # Restored from the old code on the same day, no ledger reference.
    entity._state = 4.2
    entity._last_date = datetime.date(2026, 10, 14)

    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 17, 0, 29), "WS")
    entity._state_update()
    assert entity._state == 4.2

    ledger.apply("tech", 15, {"1": 0.05}, _ts(14, 18, 0, 29), "WS")
    sensor_clock.value = _ts(14, 18, 10)
    entity._state_update()
    assert entity._state == pytest.approx(4.25)


def test_daily_sensor_upgrade_just_after_midnight_keeps_restored_value(sensor_clock) -> None:
    ledger = LDATAEnergyLedger()
    entity = _daily_sensor(ledger)
    # The old code reset at 00:00 and stored the calendar date.
    entity._state = 0.1
    entity._last_date = datetime.date(2026, 10, 15)
    ledger.apply("tech", 15, {"1": 0.05}, _ts(15, 0, 0, 29), "WS")
    sensor_clock.value = _ts(15, 0, 30)

    entity._state_update()
    assert entity._state == 0.1

    sensor_clock.value = _ts(15, 1, 0, 5)
    entity._state_update()
    assert entity._state == 0.0


def test_daily_sensor_keeps_state_when_ledger_total_drops(sensor_clock) -> None:
    ledger = LDATAEnergyLedger()
    breakers = {"tech": dict(BREAKER), "island": {**BREAKER, "id": "island", "stable_id": "island"}}
    ledger.apply("tech", 15, {"1": 0.3}, _ts(14, 17, 0, 29), "WS")
    ledger.apply("island", 20, {"1": 0.2}, _ts(14, 17, 0, 29), "WS")
    entity = _daily_sensor(ledger, breakers, panel_total=True)
    entity._state_update()
    assert entity._state == pytest.approx(0.5)

    # The island breaker leaves the panel: the ledger total drops to 0.3.
    del entity.coordinator.data["breakers"]["island"]
    entity._state_update()
    assert entity._state == pytest.approx(0.5)
    assert entity._ledger_ref == pytest.approx(0.3)

    # Later increments are added from the lower total.
    ledger.apply("tech", 15, {"1": 0.1}, _ts(14, 18, 0, 29), "WS")
    sensor_clock.value = _ts(14, 18, 10)
    entity._state_update()
    assert entity._state == pytest.approx(0.6)


def test_panel_daily_is_sum_of_breaker_dailies(sensor_clock) -> None:
    ledger = LDATAEnergyLedger()
    breakers = {
        "tech": dict(BREAKER),
        "island": {**BREAKER, "id": "island", "stable_id": "island"},
        "other": {**BREAKER, "id": "other", "stable_id": "other", "panel_id": "LDATA-2"},
    }
    ledger.apply("tech", 15, {"1": 0.032470}, _ts(14, 17, 0, 29), "WS")
    ledger.apply("island", 20, {"1": 0.022400}, _ts(14, 17, 0, 29), "WS")
    ledger.apply("other", 20, {"1": 5.0}, _ts(14, 17, 0, 29), "WS")
    entity = _daily_sensor(ledger, breakers, panel_total=True)

    entity._state_update()

    assert entity._state == pytest.approx(0.05487)


def test_import_and_whems_sensors_do_not_use_the_ledger(sensor_clock) -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 17, 0, 29), "WS")

    coordinator = _Coordinator(_hourly_service(ledger), {"tech": dict(BREAKER)})
    daily_import = sensor.LDATADailyUsageSensor(
        coordinator, dict(BREAKER), False, "", breaker_energy_key="import"
    )
    panel_import = sensor.LDATADailyUsageSensor(
        coordinator, {"id": "LDATA-1", "name": "Panel", "serialNumber": "LDATA-1", "poles": 2},
        True, which_panel="LDATA-1", panel_energy_key="import",
    )
    lifetime_import = sensor.LDATABreakerEnergyUsageSensor(
        coordinator, dict(BREAKER), sensor.SENSOR_TYPES[sensor.IMPORT]
    )
    assert daily_import._hourly_ledger() is None
    assert panel_import._hourly_ledger() is None
    assert sensor._hourly_energy_ledger(coordinator, "LDATA-1") is ledger
    lifetime_import.async_write_ha_state = MagicMock()
    lifetime_import._state_update()
    assert lifetime_import._ledger_ref is None

    whems = _daily_sensor(ledger, hourly=False)
    assert whems._hourly_ledger() is None
    whems_lifetime = _lifetime_sensor(ledger, hourly=False)
    whems_lifetime._state_update()
    assert whems_lifetime._ledger_ref is None
    assert "ledger_ref" not in whems_lifetime.extra_state_attributes


def _import_sensors(hourly: bool, branch_type: str):
    breaker = {**BREAKER, "power": 30.0, "branch_type": branch_type}
    ledger = LDATAEnergyLedger()
    coordinator = _Coordinator(_hourly_service(ledger, hourly), {"tech": breaker})
    lifetime = sensor.LDATABreakerEnergyUsageSensor(coordinator, dict(breaker), sensor.SENSOR_TYPES[sensor.IMPORT])
    daily = sensor.LDATADailyUsageSensor(coordinator, dict(breaker), False, "", breaker_energy_key="import")
    panel = sensor.LDATADailyUsageSensor(
        coordinator, {"id": "LDATA-1", "name": "Panel", "serialNumber": "LDATA-1", "poles": 2},
        True, which_panel="LDATA-1", panel_energy_key="import",
    )
    for entity in (lifetime, daily, panel):
        entity.async_write_ha_state = MagicMock()
    return lifetime, daily, panel


def _run_import_sensors(sensor_clock, entities) -> list[float]:
    # Two updates 5 minutes apart at a steady 30 W.
    for minute in (10, 15):
        sensor_clock.value = _ts(14, 17, minute)
        for entity in entities:
            entity._state_update()
    return [entity._state for entity in entities]


@pytest.mark.parametrize("hourly", [True, False])
def test_ldata_load_breaker_import_stays_zero(sensor_clock, hourly) -> None:
    """A load breaker's watts are consumption, never import."""
    entities = _import_sensors(hourly, "Outlets")

    states = _run_import_sensors(sensor_clock, entities)

    # Panel Daily Import counts only solar breakers; the breaker sensors agree.
    if hourly:
        assert states == [0.0, 0.0, 0.0]
    else:
        # Other panels (v2 WHEMS) keep max(power, 0) on the breaker sensors.
        assert states[0] == pytest.approx(0.0025)
        assert states[1] == pytest.approx(0.0025)


def test_ldata_solar_breaker_import_counts_generation(sensor_clock) -> None:
    entities = _import_sensors(True, "Solar")

    states = _run_import_sensors(sensor_clock, entities)

    assert states == pytest.approx([0.0025, 0.0025, 0.0025])


def test_mock_service_is_not_mistaken_for_ldata() -> None:
    coordinator = MagicMock()
    assert sensor._hourly_energy_ledger(coordinator, "LDATA-1") is None


def test_time_module_is_real() -> None:
    # Guard against the clock fixtures leaking.
    assert abs(time.time() - datetime.datetime.now().timestamp()) < 5


def test_ldata_import_entities_keep_v1_gating(monkeypatch) -> None:
    """Existing LDATA import entities are recreated and never suppressed."""
    import asyncio

    service = LDATAService("", "", None)
    service._ldata_panel_ids.add("LDATA-1")
    service._panel_has_hw_counters["LDATA-1"] = False
    breaker = {
        **BREAKER,
        "rating": 15,
        # Restart in the evening: hourly import/consumption values that the
        # v2 "load artifact" heuristic would misread.
        "import": 0.05,
        "consumption": 0.02,
        "branch_type": "",
        "power": 30.0,
        "current": 0.25,
        "state": "ManualON",
        "voltage": 121.0,
        "frequency": 60.0,
    }
    coordinator = _Coordinator(service, {"tech": breaker})
    coordinator.data["panels"] = []
    entry = SimpleNamespace(entry_id="e1", options={}, data={})
    hass = MagicMock()
    hass.data = {sensor.DOMAIN: {"e1": coordinator}}

    registry = MagicMock()
    registry.async_get_entity_id.side_effect = lambda domain, platform, uid: f"sensor.{uid}"
    monkeypatch.setattr(sensor.er, "async_get", lambda _hass: registry)
    added = []
    monkeypatch.setattr(
        sensor, "add_entities_grouped_by_panel", lambda _entry, _add, entities: added.extend(entities)
    )

    asyncio.run(sensor.async_setup_entry(hass, entry, MagicMock()))

    registry.async_remove.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    keys = {
        (type(e).__name__, getattr(getattr(e, "entity_description", None), "key", None), getattr(e, "_is_forced_import", None))
        for e in added
    }
    assert ("LDATABreakerEnergyUsageSensor", "import", None) in keys
    assert ("LDATADailyUsageSensor", None, True) in keys


# ── Reset services ─────────────────────────────────────────────────────


def _ledger_with_today(sensor_clock):
    """A ledger with 0.08 kWh on the 14th for "tech", read at 18:10."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 16, 0, 29), "WS")
    ledger.apply("tech", 15, {"1": 0.05}, _ts(14, 17, 0, 29), "WS")
    sensor_clock.value = _ts(14, 18, 10)
    return ledger


def test_reset_sets_ledger_daily_to_the_ledger_total(sensor_clock) -> None:
    ledger = _ledger_with_today(sensor_clock)
    entity = _daily_sensor(ledger)
    # Restored upgrade-day value that does not match the ledger.
    entity._state = 4.2
    entity._last_date = datetime.date(2026, 10, 14)

    summary = init._reset_energy_entity(entity, "sensor.tech_daily")

    assert "energy ledger" in summary
    assert entity._state == pytest.approx(0.08)
    assert entity._ledger_ref == pytest.approx(0.08)
    assert entity._last_date == datetime.date(2026, 10, 14)
    entity.async_write_ha_state.assert_called_once()

    # The day keeps counting from the ledger: nothing used before the reset
    # is lost and the next hour is added.
    ledger.apply("tech", 15, {"1": 0.02}, _ts(14, 18, 0, 29), "WS")
    entity._state_update()
    assert entity._state == pytest.approx(0.10)


def test_reset_reports_a_ledger_total_just_below_the_daily_state(sensor_clock) -> None:
    ledger = _ledger_with_today(sensor_clock)
    entity = _daily_sensor(ledger)
    entity._state = 0.1
    entity._last_date = datetime.date(2026, 10, 14)
    assert entity.native_value == 0.1

    init._reset_energy_entity(entity, "sensor.tech_daily")

    # 0.02 kWh below the reported value: not held back as counter jitter.
    assert entity.native_value == pytest.approx(0.08)


def test_reset_sets_ledger_panel_daily_to_the_panel_total(sensor_clock) -> None:
    ledger = _ledger_with_today(sensor_clock)
    ledger.apply("island", 20, {"1": 0.02}, _ts(14, 17, 0, 29), "WS")
    breakers = {
        "tech": dict(BREAKER),
        "island": {**BREAKER, "id": "island", "stable_id": "island"},
    }
    entity = _daily_sensor(ledger, breakers, panel_total=True)
    entity._state = 9.9

    init._reset_energy_entity(entity, "sensor.panel_daily")

    assert entity._state == pytest.approx(0.10)
    assert entity._ledger_ref == pytest.approx(0.10)


def test_reset_leaves_ledger_daily_alone_without_ledger_data(sensor_clock) -> None:
    entity = _daily_sensor(LDATAEnergyLedger())
    entity._state = 1.5

    summary = init._reset_energy_entity(entity, "sensor.tech_daily")

    assert "no ledger data" in summary
    assert entity._state == 1.5
    assert entity._ledger_ref is None


def test_reset_is_a_no_op_for_ledger_lifetime() -> None:
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 16, 0, 29), "WS")
    entity = _lifetime_sensor(ledger)
    entity._state = 120.0
    entity._ledger_ref = 0.03
    entity._accept_next_value = False

    summary = init._reset_energy_entity(entity, "sensor.tech_consumption")

    assert "nothing to reset" in summary
    assert (entity._state, entity._ledger_ref) == (120.0, 0.03)
    assert entity._accept_next_value is False
    entity.async_write_ha_state.assert_not_called()


def test_reset_of_non_ledger_daily_still_zeroes(sensor_clock) -> None:
    entity = _daily_sensor(LDATAEnergyLedger(), hourly=False)
    entity._state = 3.0

    summary = init._reset_energy_entity(entity, "sensor.tech_daily")

    assert "daily cleared" in summary
    assert entity._state == 0.0


async def _reset_baseline(entity, **data):
    registry = MagicMock()
    registry.async_get.return_value = SimpleNamespace(config_entry_id="entry-1")
    hass = MagicMock()
    hass.data = {init.DOMAIN: {"entry-1": object()}}
    with (
        patch.object(init.er, "async_get", return_value=registry),
        patch.object(init, "_get_sensor_entity", return_value=entity),
    ):
        await init._async_reset_energy_baseline(
            hass, {"entity_id": "sensor.tech_daily", **data}
        )


@pytest.mark.asyncio
async def test_reset_energy_baseline_service_uses_the_ledger(sensor_clock) -> None:
    daily = _daily_sensor(_ledger_with_today(sensor_clock))
    daily._state = 4.2
    await _reset_baseline(daily)
    assert daily._state == pytest.approx(0.08)

    lifetime = _lifetime_sensor(_ledger_with_today(sensor_clock))
    lifetime._state = 120.0
    await _reset_baseline(lifetime)
    assert lifetime._state == 120.0


@pytest.mark.asyncio
async def test_reset_energy_baseline_rejects_a_baseline_in_ledger_mode(
    sensor_clock, caplog
) -> None:
    entity = _daily_sensor(_ledger_with_today(sensor_clock))
    entity._state = 4.2

    await _reset_baseline(entity, baseline=1.0)

    assert entity._midnight_baseline is None
    assert entity._state == 4.2
    assert "follows the energy ledger" in caplog.text


@pytest.mark.asyncio
async def test_reset_energy_baseline_forced_value_keeps_following_the_ledger(
    sensor_clock,
) -> None:
    ledger = _ledger_with_today(sensor_clock)
    entity = _daily_sensor(ledger)
    entity._state_update()
    assert entity._state == pytest.approx(0.08)

    await _reset_baseline(entity, value=5.0)
    ledger.apply("tech", 15, {"1": 0.02}, _ts(14, 18, 0, 29), "WS")
    entity._state_update()

    assert entity._state == pytest.approx(5.02)
