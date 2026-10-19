"""Hours only a lifetime counter can add do not hold complete_until back.

Up to a leg's history_floor no hour is taken from the energy history, and
no delta is booked for an hour before the leg's last booked hour. A missed
hour there is added only by a lifetime counter, so complete_until stopped
before it for good when no counter came (Outlets counter 1 leg 1, from
2026-10-19 19:00 on). Such an hour is now unsettled instead: complete_until
moves on, and the next counter adds all the energy it proves missing.
"""

import copy
import json

import pytest

from tests.test_ldata_hourly_energy import (  # noqa: F401  (fixtures)
    LDATAEnergyLedger,
    _leg,
    _pacific_time,
    _ts,
)

H = 3600

# Outlets counter 1 (4C4556C2E8D9) leg 1 in the stored ledger at 2026-10-21
# 10:21: complete_until 10-19 19:00 since the counter of 10-19 20:10:03.
OUTLETS_1 = {
    "lifetime": 4.3309519999999155,
    "last_hour": 1792598400,  # 10-21 09:00
    "complete_until": 1792461600,  # 10-19 19:00
    "offset": 1284.7480759999999,
    "offset_max": 1284.8480759999998,
    "anchor_time": 1792465803.1481557,  # 10-19 20:10:03
    "last_value": 0.022093999999924563,
    "last_source": "WS",
    "last_counter": 1288.0,
    "booked_hours": list(range(1792468800, 1792598400 + H, H)),  # 10-19 21:00 .. 10-21 09:00
    "history_floor": 1792465200,  # 10-19 20:00
    "claim": None,
}
OUTLETS_1_DAILY = {
    "2026-10-19": 0.8969480000001175,
    "2026-10-20": 0.7270019999999022,
    "2026-10-21": 0.06725999999980559,
}


def _stored_outlets_1() -> dict:
    return {
        "breakers": {
            "outlets1": {
                "legs": {"1": copy.deepcopy(OUTLETS_1), "2": {"lifetime": 0.0}},
                "daily": dict(OUTLETS_1_DAILY),
            }
        }
    }


# ── Unbookable hours ───────────────────────────────────────────────────


def _reference_then_gap() -> LDATAEnergyLedger:
    """A steady 0.4 kWh/h; the cloud total is 1000.02 kWh at the 10:30 reference."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 1000.0}, _ts(14, 10, 30), "WS")
    # The 10-11h burst is missed; 11-12h is the first delta of the leg.
    ledger.apply("tech", 15, {"1": 0.4}, _ts(14, 12, 0, 29), "WS")
    return ledger


def test_gap_before_the_first_delta_is_unsettled() -> None:
    ledger = _reference_then_gap()
    state = _leg(ledger)
    assert state["history_floor"] == int(_ts(14, 10))
    assert state["complete_until"] == int(_ts(14, 11))
    assert state["unsettled_from"] == int(_ts(14, 10))
    assert state["booked_hours"] == []
    # The history does not book the hour: it would count the part before
    # the reference twice.
    assert ledger.history_hours_needed("tech", int(_ts(14, 8)), int(_ts(14, 11))) == []

    ledger.apply("tech", 15, {"1": 0.4}, _ts(14, 13, 0, 29), "WS")
    assert _leg(ledger)["complete_until"] == int(_ts(14, 12))


def test_next_counter_adds_what_it_proves_missing_for_an_unsettled_hour() -> None:
    ledger = _reference_then_gap()
    ledger.apply("tech", 15, {"1": 0.4}, _ts(14, 13, 0, 29), "WS")

    # 13:15: the cloud total is 1001.12 kWh. The ledger (0.8) misses
    # 10:30-11:00 and 13:00-13:15 (0.3 kWh); the counter proves
    # 1001.1 - 0.8 - 1000.1 = 0.2 of it. complete_until is at the last
    # hour, but the hour before the first delta is unsettled: the counter
    # adds it instead of leaving it to the 13-14h burst.
    assert ledger.apply("tech", 15, {"1": 1001.1}, _ts(14, 13, 15), "WS")
    assert ledger.lifetime("tech") == pytest.approx(1.0)
    assert ledger.lifetime("tech") <= 1001.12 - 1000.02
    state = _leg(ledger)
    assert state["unsettled_from"] is None
    assert state["complete_until"] == int(_ts(14, 12))
    assert state["last_hour"] == int(_ts(14, 13))


def test_counter_proving_nothing_missing_settles_the_hours() -> None:
    ledger = _reference_then_gap()
    ledger.apply("tech", 15, {"1": 0.4}, _ts(14, 13, 0, 29), "WS")

    # 13:02: the cloud total is 1000.95 kWh; nothing is proven missing.
    assert ledger.apply("tech", 15, {"1": 1000.9}, _ts(14, 13, 2), "WS")
    assert ledger.lifetime("tech") == pytest.approx(0.8)
    state = _leg(ledger)
    assert state["unsettled_from"] is None
    assert state["complete_until"] == int(_ts(14, 12))


def test_stuck_ledger_is_settled_on_load() -> None:
    """The stored ledger of 2026-10-21: Outlets counter 1 leg 1 stuck at 10-19 19:00."""
    ledger = LDATAEnergyLedger()
    ledger.load(json.loads(json.dumps(_stored_outlets_1())))

    state = _leg(ledger, "outlets1")
    assert state["complete_until"] == int(_ts(21, 9))
    assert state["unsettled_from"] == int(_ts(19, 20))
    assert state["booked_hours"] == []
    # Nothing is booked: the energy and the daily totals are as stored.
    assert ledger.lifetime("outlets1") == OUTLETS_1["lifetime"]
    for day, kwh in OUTLETS_1_DAILY.items():
        assert ledger.as_dict()["breakers"]["outlets1"]["daily"][day] == kwh
    # The settled state is saved.
    assert ledger.dirty
    assert ledger.take_unsaved()["breakers"]["outlets1"]["legs"]["1"]["complete_until"] == int(_ts(21, 9))

    # Loading the saved ledger again changes nothing.
    again = LDATAEnergyLedger()
    again.load(json.loads(json.dumps(ledger.as_dict())))
    assert not again.dirty
    assert _leg(again, "outlets1") == state


def test_stuck_ledger_does_not_book_the_unsettled_hour_twice() -> None:
    ledger = LDATAEnergyLedger()
    ledger.load(_stored_outlets_1())
    lifetime = ledger.lifetime("outlets1")

    # Neither a delta nor the history books 10-19 20:00 again.
    assert not ledger.apply("outlets1", 20, {"1": 0.002685}, _ts(19, 21, 0, 37), "WS")
    assert not ledger.apply_history("outlets1", int(_ts(19, 20)), 0.01)
    assert ledger.history_hours_needed("outlets1", int(_ts(19, 18)), int(_ts(21, 9))) == []
    assert ledger.lifetime("outlets1") == lifetime

    # The next burst is booked once, and complete_until follows it.
    assert ledger.apply("outlets1", 20, {"1": 0.021}, _ts(21, 11, 0, 37), "WS")
    assert not ledger.apply("outlets1", 20, {"1": 0.021}, _ts(21, 11, 0, 38), "WS")
    assert not ledger.apply("outlets1", 20, {"1": 0.02}, _ts(21, 11, 6), "REST")
    assert ledger.lifetime("outlets1") == pytest.approx(lifetime + 0.021)
    assert _leg(ledger, "outlets1")["complete_until"] == int(_ts(21, 10))


def test_stuck_ledger_next_counter_adds_the_proven_shortfall() -> None:
    ledger = LDATAEnergyLedger()
    ledger.load(_stored_outlets_1())
    ledger.apply("outlets1", 20, {"1": 0.02}, _ts(21, 11, 0, 37), "WS")
    lifetime = ledger.lifetime("outlets1")

    # A counter at 11:30, 0.000972 kWh above the ledger and its window: with
    # complete_until at the last hour this would be the current hour's
    # energy, left to the burst. The leg is unsettled, so it is added.
    missing = 1289.2 - lifetime - OUTLETS_1["offset_max"]
    assert 0 < missing < 0.01
    assert ledger.apply("outlets1", 20, {"1": 1289.2}, _ts(21, 11, 30), "WS")
    assert ledger.lifetime("outlets1") == pytest.approx(lifetime + missing)
    state = _leg(ledger, "outlets1")
    assert state["unsettled_from"] is None
    assert state["complete_until"] == int(_ts(21, 10))


def test_booked_hours_dropped_from_the_list_are_not_taken_from_the_history() -> None:
    """A leg that had one lifetime counter, after a missed hour and 72 booked ones."""
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"2": 500.0}, _ts(14, 9, 30), "WS")
    ledger.apply("tech", 15, {"1": 0.0, "2": 0.0}, _ts(14, 10, 0, 29), "WS")
    # 10-11h is missed on leg 2; 72 hours after it are booked.
    ledger.apply("tech", 15, {"1": 0.0}, _ts(14, 11, 0, 29), "WS")
    start = _ts(14, 12, 0, 29)
    for n in range(72):
        ledger.apply("tech", 15, {"1": 0.0, "2": 0.0}, start + n * H, "WS")
    state = _leg(ledger, "tech", "2")
    assert state["complete_until"] == int(_ts(14, 9))
    assert len(state["booked_hours"]) == 72
    assert ledger.history_hours_needed("tech", int(_ts(14, 10)), int(_ts(14, 12))) == [int(_ts(14, 10))]

    # The 73rd drops 11-12h from the list: it is not taken for a missed hour.
    ledger.apply("tech", 15, {"1": 0.0, "2": 0.0}, start + 72 * H, "WS")
    state = _leg(ledger, "tech", "2")
    assert state["history_floor"] == int(_ts(14, 11))
    assert state["complete_until"] == int(_ts(17, 11))
    assert state["unsettled_from"] == int(_ts(14, 10))
    assert state["booked_hours"] == []
    assert ledger.history_hours_needed("tech", int(_ts(14, 9)), int(_ts(17, 11))) == []


def test_stored_leg_whose_first_booked_hour_was_dropped_recovers_at_the_next_burst() -> None:
    """2026-10-21: the leg-2 states with 72 booked hours after 10-18 10:00 was dropped."""
    hours = list(range(int(_ts(18, 11)), int(_ts(21, 10)) + H, H))
    assert len(hours) == 72
    leg = {
        "lifetime": 0.0, "last_hour": hours[-1], "complete_until": int(_ts(16, 0)),
        "offset": None, "offset_max": None, "anchor_time": None, "last_value": 0.0,
        "last_source": "WS", "last_counter": None, "booked_hours": hours,
        "history_floor": int(_ts(18, 9)),
    }
    ledger = LDATAEnergyLedger()
    ledger.load({"breakers": {"tech": {"legs": {"1": dict(leg), "2": dict(leg)}, "daily": {}}}})
    assert _leg(ledger)["complete_until"] == int(_ts(18, 9))

    ledger.apply("tech", 15, {"1": 0.0, "2": 0.0}, _ts(21, 12, 0, 29), "WS")
    state = _leg(ledger)
    assert state["complete_until"] == int(_ts(21, 11))
    assert state["unsettled_from"] == int(_ts(16, 1))
    assert state["booked_hours"] == []

