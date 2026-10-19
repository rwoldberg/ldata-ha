"""Hourly energy ledger for LDATA (ResidentialBreakerPanel) breakers.

An LDATA hub does not report a lifetime energy counter in normal operation.
The breaker ``energyConsumption``/``energyConsumption2`` fields, both in the
WebSocket burst the cloud sends at the start of every hour (HH:00:01 to
HH:00:37 so far) and in the REST panel listing, carry the kWh each leg used
in the hour that just ended. Now and then
(most likely after the hub reconnects to the cloud) the same fields carry the
breaker's lifetime counter instead, with 0.1 kWh resolution.

This ledger turns those values into a lifetime total and daily totals per
breaker and leg:

- A value above what the breaker can physically use in one hour is a lifetime
  counter. A WebSocket value is an hourly delta only inside the burst window
  (the first 90 s of the hour); outside it, a multiple of 0.1 kWh is a
  lifetime counter and anything else (a stale delta) is ignored. Inside the
  window, a value equal to the leg's last delta that arrives within seconds
  of a WebSocket (re)connect is ignored too: it may be the cached last
  delta, not the burst. A listing value is an hourly
  delta, except a multiple of 0.1 kWh above 0.1 kWh, which may be a small
  lifetime counter and is ignored.
- Each delta is applied once per (breaker, leg, hour): the hour it covers is
  recorded, and a value for that hour or an earlier one is a duplicate. Only
  a non-zero burst value replaces a zero booked for the same hour. A
  lifetime counter not newer than the last one is ignored.
- The listing keeps its last value while the hub is offline, so a listing
  value within rounding of the last booked delta (also a zero after a
  booked zero) is not booked: it may be that hour's value again. The hour
  is left to the next lifetime counter. No delta at all is booked while the
  panel is reported offline (``connected=False``, which the service also
  reports for a while after the panel comes back online, see
  PANEL_RECONNECT_SETTLE_SECS); lifetime counters still are.
- Each leg tracks ``complete_until``, the last hour up to which the ledger
  has all of the leg's energy. It advances over hours booked one after
  another, and when a lifetime counter matches the ledger or becomes the
  reference. A missed hour stops it, also when later hours are booked.
- A lifetime counter never lowers the ledger. The counter is the cloud's
  lifetime total quantized to 0.1 kWh, so it only says that the true total
  lies in a 0.1 kWh window. The ledger keeps the offset between the cloud
  total and its own total as a window too, ``offset`` .. ``offset_max``:
  the first counter sets it to [counter, counter + 0.1] - ledger, and every
  later counter lowers ``offset_max`` to counter + 0.1 - ledger if that is
  smaller (the cloud total never runs behind the ledger, so this always
  holds). A counter adds only the energy it proves missing,
  counter - ledger - ``offset_max`` (energy from missed hours, e.g. while
  the hub or Home Assistant was offline), never the quantization noise.
  ``offset_max`` is not moved by what is added, so a shortfall too small to
  prove at one counter is added by a later one: what the ledger is short
  never exceeds 0.2 kWh per leg (plus, until a later counter narrows the
  window, what the leg used in the hour of the first counter before it
  arrived), however many outages there are. The
  energy is added only when ``complete_until`` is before the hour before
  the current one, or when it is more than the breaker can have used in the
  current hour so far; otherwise it is the current hour's energy so far,
  which that hour's burst will bring. The added energy also covers the
  current hour up to now, so that hour is claimed (its burst is not booked)
  while ``complete_until`` stays at the hour before it: the next counter
  adds the rest of the claimed hour.
- Daily totals are bucketed by the local date of the hour the energy was used
  in, so the burst just after 00:00 counts for the previous day.

The ledger is plain data (see ``as_dict``/``load``) so the coordinator can
persist it across restarts. Once the coordinator persists it (``mark_saved``),
``lifetime`` and ``daily`` report the totals as of the last save, so a sensor
never counts energy that a crash before the next save would take out of the
ledger again.
"""

from __future__ import annotations

import datetime
import logging
import math
import threading
from typing import Any

from homeassistant.util import dt as dt_util

from .const import LOGGER_NAME

_LOGGER = logging.getLogger(LOGGER_NAME)

HOUR_SECS = 3600

# Nominal leg-to-neutral voltage. LDATA panels are North American split-phase
# (120/240 V); the per-leg energy fields are each leg's share.
NOMINAL_LEG_VOLTAGE = 120.0
# Headroom over rating x voltage x 1 h: covers high line voltage and a breaker
# carrying more than its rating for a while before it trips. The bound only has
# to separate an hourly delta (at most a few kWh) from a lifetime counter
# (typically hundreds or thousands of kWh).
HOURLY_BOUND_MARGIN = 2.0
# Used when a breaker has no usable currentRating. Above the rating of typical
# residential branch breakers, so a real hourly delta is never mistaken for a
# lifetime counter.
FALLBACK_RATING_AMPS = 60.0

# Lifetime counters are the cloud's lifetime total quantized to 0.1 kWh: a
# counter C means the total is somewhere in a window C + a .. C + a + 0.1,
# with a = 0 if the cloud truncates and a = -0.05 if it rounds. The ledger
# only ever compares counters with each other (through the offset recorded
# from the first one), so a cancels out and the two cases are handled alike.
# A counter that is not a multiple of 0.1 kWh (seen from a 2-pole breaker,
# e.g. 694.6682239999227) is the unquantized total: its window is empty.
COUNTER_STEP_KWH = 0.1

# Energy is compared and added rounded to 1e-6 kWh, the resolution of the
# hourly deltas (e.g. 0.001198). Lifetime counters and ledger totals are
# floats, so 19.1 - (18.988 + 0.012) is 0.10000000000000142, not 0.1; a
# comparison on the raw floats would decide by rounding error.
KWH_DECIMALS = 6

# last_source of an hour claimed by a lifetime counter (no delta booked).
COUNTER_CLAIM_SOURCE = "counter"

# The REST listing keeps showing the previous hour's delta until the hourly
# burst has been processed by the cloud, so listing values are only booked
# from this point in the hour on.
REST_SETTLE_SECS = 300

# The hourly burst arrives over the WebSocket in the first seconds of the
# hour, all breakers within about a second, one message per breaker carrying
# only energyConsumption and energyConsumption2 (no hour or timestamp). The
# second it arrives at moves: HH:00:29 every hour of the first capture
# (2026-10-14/16), HH:00:01-HH:00:03 from 2026-10-16 18:00 to 2026-10-17
# 02:00, HH:00:36-HH:00:37 from 2026-10-17 09:00 on. Lifetime counters and
# stale values arrive at other times. Only a WebSocket value received in
# [WS_DELTA_WINDOW_START_SECS, WS_DELTA_WINDOW_END_SECS) into the hour is an
# hourly delta (if within the physical bound). The window starts at the top
# of the hour; it ends 53 s after the latest burst seen, for delivery lag,
# and well before REST_SETTLE_SECS, so a listing value is never booked for an
# hour whose burst can still arrive. A burst outside the window is not
# booked; the listing recovery books that hour instead.
WS_DELTA_WINDOW_START_SECS = 0
WS_DELTA_WINDOW_END_SECS = 90

# The burst carries no hour of its own, so a delta the cloud re-sends from its
# cache when the WebSocket (re)subscribes would look like the new hour's
# burst inside the window. In the 42 reconnects of 2026-10-16/18 no energy
# field arrived in the 60 s after the subscriptions, except a burst 7.9 s
# after one (03:00:28.5 -> 03:00:36.4 on 2026-10-18) and a hub upload (see
# PANEL_RECONNECT_SETTLE_SECS) 60 s after another. A WebSocket delta received less than this long after the connection came up
# that equals the leg's last delta is not booked: it may be that delta
# again, and booking it would count that hour twice. The hour is then left
# to the listing recovery and the next lifetime counter.
WS_RECONNECT_GUARD_SECS = 5

# After the hub reconnects to the cloud (a hub outage, not a WebSocket
# reconnect of ours), it uploads the hourly values it could not send: each
# breaker then gets several energyConsumption messages a few seconds apart,
# none of them saying which hour it covers (3 per breaker at 2026-10-17
# 05:00:07-05:00:19, 210-222 s after the hub came back at 04:56:38, and at
# 08:30:50-08:30:51, 295 s after 08:25:56). One of them landing in the burst
# window would be booked for the wrong hour, possibly one that was already
# booked. The service therefore reports a panel as offline to the ledger
# (no deltas booked, lifetime counters applied) for this long after it sees
# the panel come back online.
PANEL_RECONNECT_SETTLE_SECS = 600

# Lifetime counters are multiples of 0.1 kWh; bursts are unrounded floats.
# The listing rounds its deltas to 0.01 kWh, so a listing value that is a
# multiple of 0.1 kWh may be a delta (one in ten rounded deltas is) or a
# small lifetime counter. Above this value such a listing value is ignored:
# a skipped delta leaves a gap that the next lifetime counter fills, while a
# counter booked as a delta adds energy nothing ever takes back. At or below
# it the delta is booked: 0.1 kWh is a common hourly delta, and a counter
# that small can add at most 0.1 kWh.
REST_AMBIGUOUS_MIN_KWH = 0.1

# The listing rounds deltas to 0.01 kWh: a listing value within this distance
# of the last booked delta may be that delta shown again (see
# LDATAEnergyLedger._may_be_stale_listing).
STALE_LISTING_TOLERANCE_KWH = 0.005 + 1e-9

# Daily totals kept per breaker (today, yesterday and one spare).
DAILY_KEEP_DAYS = 3

LEGS = ("1", "2")


def hourly_bound_kwh(rating: Any) -> float:
    """Return the most energy one leg of a breaker can use in one hour (kWh)."""
    try:
        amps = float(rating)
    except (TypeError, ValueError):
        amps = 0.0
    if not math.isfinite(amps) or amps <= 0:
        amps = FALLBACK_RATING_AMPS
    return amps * NOMINAL_LEG_VOLTAGE * HOURLY_BOUND_MARGIN / 1000.0


def hour_start(ts: float) -> int:
    """Return the epoch second of the start of the hour containing ``ts``."""
    return int(ts // HOUR_SECS) * HOUR_SECS


def delta_hour(ts: float) -> int:
    """Return the start of the hour an hourly delta received at ``ts`` covers."""
    return hour_start(ts) - HOUR_SECS


def local_date(ts: float) -> datetime.date:
    """Return the local date of epoch second ``ts``."""
    return dt_util.as_local(dt_util.utc_from_timestamp(ts)).date()


def current_daily_date(now: float) -> datetime.date:
    """Return the date whose daily total is still being filled at ``now``.

    The last hour of a day arrives just after 00:00 the next day, so the daily
    total switches to the new date at 01:00.
    """
    return local_date(delta_hour(now))


def is_counter_resolution(value: float) -> bool:
    """Return True if ``value`` is a multiple of 0.1 kWh (lifetime counter resolution)."""
    return abs(value * 10 - round(value * 10)) < 1e-6


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return number


def _kwh(value: float) -> float:
    """Return ``value`` rounded to the ledger's energy resolution (see KWH_DECIMALS)."""
    return round(value, KWH_DECIMALS) + 0.0  # + 0.0 turns -0.0 into 0.0


def counter_window_kwh(value: float) -> float:
    """Return the width of the window a lifetime counter puts the cloud total in."""
    return COUNTER_STEP_KWH if is_counter_resolution(value) else 0.0


def _hour(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _migrated_complete_until(state: dict) -> int | None:
    """Return ``complete_until`` for a leg stored before the field existed.

    That version took the leg as complete up to its last booked hour, so
    this keeps its behaviour for the stored state: no energy is added on the
    assumption of a gap it did not track. An hour claimed by a lifetime
    counter (no booked value) is not complete, so the next counter adds the
    rest of it. A leg with only a reference (no hour) is complete up to the
    hour before the reference.
    """
    if state["last_hour"] is not None:
        if state["last_value"] is None:
            return state["last_hour"] - HOUR_SECS
        return state["last_hour"]
    if state["offset"] is not None and state["anchor_time"] is not None:
        return delta_hour(state["anchor_time"])
    return None


class LDATAEnergyLedger:
    """Lifetime and daily energy per LDATA breaker, built from hourly deltas."""

    def __init__(self) -> None:
        self._breakers: dict[str, dict[str, Any]] = {}
        # Written from the WebSocket task (event loop) and the REST polls
        # (executor threads).
        self._lock = threading.Lock()
        self.dirty = False
        # Totals as of the last save (see mark_saved); None while the ledger
        # is not persisted.
        self._saved: dict[str, dict[str, Any]] | None = None
        # When the WebSocket last came up (see note_ws_connected).
        self._ws_connected_at: float | None = None

    # ── Persistence ────────────────────────────────────────────────────

    def load(self, data: dict | None) -> None:
        """Load a dict produced by ``as_dict``. Invalid entries are dropped."""
        breakers: dict[str, dict[str, Any]] = {}
        stored = data.get("breakers") if isinstance(data, dict) else None
        for key, record in (stored if isinstance(stored, dict) else {}).items():
            if not isinstance(record, dict):
                continue
            legs = {}
            stored_legs = record.get("legs") if isinstance(record.get("legs"), dict) else {}
            for leg in LEGS:
                raw = stored_legs.get(leg) if isinstance(stored_legs.get(leg), dict) else {}
                legs[leg] = {
                    "lifetime": _number(raw.get("lifetime")) or 0.0,
                    "last_hour": _hour(raw.get("last_hour")),
                    "complete_until": _hour(raw.get("complete_until")),
                    "offset": raw.get("offset") if isinstance(raw.get("offset"), (int, float)) else None,
                    "offset_max": (
                        raw.get("offset_max")
                        if isinstance(raw.get("offset_max"), (int, float))
                        and not isinstance(raw.get("offset_max"), bool)
                        else None
                    ),
                    "anchor_time": _number(raw.get("anchor_time")),
                    "last_value": _number(raw.get("last_value")),
                    "last_source": raw.get("last_source") if isinstance(raw.get("last_source"), str) else None,
                    "last_counter": _number(raw.get("last_counter")),
                }
                if "complete_until" not in raw:
                    legs[leg]["complete_until"] = _migrated_complete_until(legs[leg])
                if legs[leg]["offset"] is None:
                    legs[leg]["offset_max"] = None
                elif legs[leg]["offset_max"] is None or legs[leg]["offset_max"] < legs[leg]["offset"]:
                    # Stored before the window existed: the offset was the
                    # bottom of the last counter's window.
                    last_counter = legs[leg]["last_counter"]
                    legs[leg]["offset_max"] = legs[leg]["offset"] + (
                        COUNTER_STEP_KWH if last_counter is None else counter_window_kwh(last_counter)
                    )
            stored_daily = record.get("daily") if isinstance(record.get("daily"), dict) else {}
            daily = {
                day: _number(value)
                for day, value in stored_daily.items()
                if isinstance(day, str) and _number(value) is not None
            }
            breakers[str(key)] = {"legs": legs, "daily": daily}
        with self._lock:
            self._breakers = breakers
            self.dirty = False

    def as_dict(self) -> dict:
        """Return a JSON-serialisable copy of the ledger."""
        with self._lock:
            return self._as_dict_locked()

    def take_unsaved(self) -> dict | None:
        """Return a copy of the ledger and clear ``dirty``, or None if it is not dirty."""
        with self._lock:
            if not self.dirty:
                return None
            self.dirty = False
            return self._as_dict_locked()

    def mark_saved(self, data: dict) -> None:
        """Report ``data`` (an ``as_dict`` copy) as written to storage.

        From the first call on, ``lifetime`` and ``daily`` report the totals
        in the last saved copy instead of the live ledger.
        """
        saved = {}
        for key, record in data["breakers"].items():
            saved[key] = {
                "lifetime": sum(state["lifetime"] for state in record["legs"].values()),
                "daily": dict(record["daily"]),
            }
        with self._lock:
            self._saved = saved

    def _as_dict_locked(self) -> dict:
        return {
            "breakers": {
                key: {
                    "legs": {leg: dict(state) for leg, state in record["legs"].items()},
                    "daily": dict(record["daily"]),
                }
                for key, record in self._breakers.items()
            }
        }

    # ── Queries ────────────────────────────────────────────────────────

    def lifetime(self, key: str) -> float | None:
        """Return the breaker's lifetime kWh (both legs), or None if never seen.

        As of the last save once the ledger is persisted (see ``mark_saved``).
        """
        with self._lock:
            if self._saved is not None:
                saved = self._saved.get(key)
                return None if saved is None else saved["lifetime"]
            record = self._breakers.get(key)
            if record is None:
                return None
            return sum(state["lifetime"] for state in record["legs"].values())

    def daily(self, key: str, day: datetime.date) -> float | None:
        """Return the breaker's kWh for ``day`` (0.0 if none yet), or None if never seen.

        As of the last save once the ledger is persisted (see ``mark_saved``).
        """
        with self._lock:
            if self._saved is not None:
                record = self._saved.get(key)
            else:
                record = self._breakers.get(key)
            if record is None:
                return None
            return record["daily"].get(day.isoformat(), 0.0)

    def has_delta_for(self, key: str, hour: int) -> bool:
        """Return True if every leg that has ever had a delta has one for ``hour`` or later.

        A leg that never had a delta (energyConsumption2 null on a single-pole
        breaker) is ignored. A breaker without any delta yet returns False.
        """
        with self._lock:
            record = self._breakers.get(key)
            if record is None:
                return False
            hours = [
                state["last_hour"]
                for state in record["legs"].values()
                if state["last_hour"] is not None
            ]
            return bool(hours) and all(last >= hour for last in hours)

    # ── Updates ────────────────────────────────────────────────────────

    def note_ws_connected(self, when: float) -> None:
        """Record that the WebSocket (re)connected and subscribed at epoch ``when``.

        For WS_RECONNECT_GUARD_SECS after it, a WebSocket delta equal to the
        leg's last delta is not booked (see ``apply``).
        """
        with self._lock:
            self._ws_connected_at = when

    def apply(
        self,
        key: str,
        rating: Any,
        values: dict[str, Any],
        received: float,
        source: str,
        name: str | None = None,
        connected: bool = True,
    ) -> bool:
        """Apply energy values for one breaker.

        Args:
            key: Stable breaker id.
            rating: Breaker currentRating (A), used for the delta/lifetime bound.
            values: {"1": energyConsumption, "2": energyConsumption2}; a leg
                    that is absent, None or negative is skipped.
            received: Epoch seconds the value was received.
            source: "WS", "WS-bulk" or "REST".
            name: Breaker name, for logging only.
            connected: False if the breaker's panel is reported offline. The
                    cloud then has no new hourly data for it: a listing
                    value is the last delta shown again, so no delta is
                    booked. Lifetime counters are still applied (they are
                    absolute, and the first ones after a reconnect arrive
                    before the panel is reported online again).

        Returns True if the ledger changed.
        """
        bound = hourly_bound_kwh(rating)
        hour = delta_hour(received)
        into_hour = received - hour_start(received)
        from_websocket = source.startswith("WS")
        in_burst_window = (
            from_websocket
            and WS_DELTA_WINDOW_START_SECS <= into_hour < WS_DELTA_WINDOW_END_SECS
        )
        label = name or key
        changed = False

        with self._lock:
            record = self._breakers.setdefault(
                key,
                {
                    "legs": {
                        leg: {
                            "lifetime": 0.0,
                            "last_hour": None,
                            "complete_until": None,
                            "offset": None,
                            "offset_max": None,
                            "anchor_time": None,
                            "last_value": None,
                            "last_source": None,
                            "last_counter": None,
                        }
                        for leg in LEGS
                    },
                    "daily": {},
                },
            )
            for leg, raw in values.items():
                if leg not in record["legs"]:
                    continue
                value = _number(raw)
                if value is None:
                    continue
                state = record["legs"][leg]

                if value > bound:
                    changed |= self._apply_lifetime(record, state, value, bound, received, label, leg)
                    continue
                if from_websocket and not in_burst_window:
                    # No burst due: a lifetime counter if it has counter
                    # resolution, otherwise a stale delta.
                    if is_counter_resolution(value):
                        changed |= self._apply_lifetime(record, state, value, bound, received, label, leg)
                    continue
                if not connected:
                    continue
                if not from_websocket:
                    if into_hour < REST_SETTLE_SECS:
                        continue
                    if value > REST_AMBIGUOUS_MIN_KWH and is_counter_resolution(value):
                        continue  # A rounded delta or a small lifetime counter.

                if state["last_hour"] is not None and hour < state["last_hour"]:
                    continue
                if state["last_hour"] == hour:
                    changed |= self._correct_hour(record, state, hour, value, source, in_burst_window)
                    continue
                if from_websocket and self._may_be_cached_delta(state, value, received):
                    _LOGGER.debug(
                        "Breaker %s leg %s: WebSocket value %.6f kWh %.1f s after the "
                        "WebSocket connected equals the last delta and may be the cached "
                        "one — leaving the hour to the listing and the next lifetime "
                        "counter", label, leg, value, received - self._ws_connected_at,
                    )
                    continue
                if not from_websocket and self._may_be_stale_listing(state, value):
                    _LOGGER.debug(
                        "Breaker %s leg %s: listing value %.2f kWh matches the last booked "
                        "delta and may be stale — leaving the hour to the next lifetime "
                        "counter", label, leg, value,
                    )
                    continue
                state["lifetime"] += value
                state["last_hour"] = hour
                if state["complete_until"] == hour - HOUR_SECS:
                    # Contiguous with the complete hours. complete_until is
                    # set first by the lifetime counter reference.
                    state["complete_until"] = hour
                state["last_value"] = value
                state["last_source"] = source
                self._add_daily(record, hour, value)
                changed = True

            if changed:
                self.dirty = True
        return changed

    def _may_be_cached_delta(self, state: dict, value: float, received: float) -> bool:
        """Return True if a WebSocket delta may be the last delta re-sent after a reconnect.

        The burst carries no hour, so a delta the cloud re-sends when the
        WebSocket subscribes cannot be told from the burst by its content;
        only the time (right after the connection came up) and the value
        (the leg's last delta again) set it apart. Skipping a real burst that
        happens to repeat the last value (a constant load) costs at most that
        one hour until the next lifetime counter; booking a re-sent delta
        counts its hour twice, which nothing takes back.
        """
        connected_at = self._ws_connected_at
        last = state["last_value"]
        return (
            connected_at is not None
            and last is not None
            and 0 <= received - connected_at < WS_RECONNECT_GUARD_SECS
            and _kwh(value) == _kwh(last)
        )

    @staticmethod
    def _may_be_stale_listing(state: dict, value: float) -> bool:
        """Return True if a listing value may be the last booked delta shown again.

        The listing keeps showing a breaker's last hourly delta until the
        next burst replaces it. When the hub is offline across the hourly
        burst there is no new burst, and the listing shows the previous hour's delta
        again; neither ``requestVersionHour`` (0 in every capture) nor the
        breaker's ``lastUpdated`` (it moves with power changes, not with the
        energy fields) tells which hour the value belongs to. Booking it
        would count that energy twice, and no later counter takes it back.
        Skipping it leaves a gap that the next lifetime counter fills. This
        includes a zero after a booked zero: it adds nothing, but booking it
        would mark the hour complete, and the next lifetime counter would
        then take the energy of the missed hour as the current hour's (see
        ``_apply_lifetime``), which no burst books.
        """
        last = state["last_value"]
        return last is not None and abs(last - value) <= STALE_LISTING_TOLERANCE_KWH

    def _correct_hour(
        self,
        record: dict,
        state: dict,
        hour: int,
        value: float,
        source: str,
        in_burst_window: bool,
    ) -> bool:
        """Handle a second delta for an hour that is already booked.

        Normally a duplicate. Only a non-zero burst value replaces a booked
        zero, so a stray zero in the burst window does not claim the hour.
        A listing value never replaces anything: it is read after the burst
        window has closed and is at best a rounded copy of the burst.

        For an hour claimed by a lifetime counter nothing is booked, but the
        value is kept in ``last_value``: it is the delta the listing shows
        until the next burst, which ``_may_be_stale_listing`` compares with.
        """
        booked = state["last_value"]
        if state["last_source"] == COUNTER_CLAIM_SOURCE:
            if booked != value:
                state["last_value"] = value
                self.dirty = True
            return False
        if booked is None:
            return False  # Claimed by a counter in a ledger stored before last_source "counter".
        if not (in_burst_window and booked == 0 and value > 0):
            return False
        state["lifetime"] += value
        state["last_value"] = value
        state["last_source"] = source
        self._add_daily(record, hour, value)
        return True

    def _apply_lifetime(
        self,
        record: dict,
        state: dict,
        value: float,
        bound: float,
        received: float,
        label: str,
        leg: str,
    ) -> bool:
        """Handle a lifetime counter for one leg. Never lowers the lifetime."""
        if value <= 0:
            return False  # A zero outside the burst carries no counter information.
        last_counter = state["last_counter"]
        if last_counter is not None and value <= last_counter + 0.05:
            # The same (or an older) counter seen again, e.g. from the listing
            # after a burst was booked. Comparing it with the ledger now would
            # lower the offset by energy the counter does not contain yet.
            return False
        state["last_counter"] = value

        if state["offset"] is None:
            self._set_reference(state, value, received)
            _LOGGER.debug(
                "Breaker %s leg %s: lifetime counter %.1f kWh recorded as reference "
                "(ledger %.3f kWh)", label, leg, value, state["lifetime"],
            )
            return True

        lifetime = state["lifetime"]
        # The cloud total never runs behind the ledger (the ledger books
        # only energy the cloud counted), so the true offset is below
        # counter + its window - ledger: lower offset_max to that.
        state["offset_max"] = min(state["offset_max"], value + counter_window_kwh(value) - lifetime)
        if state["offset_max"] < state["offset"]:
            # The counter's window lies entirely below the bottom of the
            # offset window: the ledger got ahead of that bottom (e.g. the
            # first counter came in mid-hour and that hour's burst then
            # booked the part it already held). Restart the bottom from
            # this counter; offset_max already is its top.
            state["offset"] = value - lifetime

        # The energy the counter proves missing: the cloud total is at
        # least the counter, and the ledger plus the highest possible
        # offset is below it. A shortfall smaller than the window is not
        # added here, but it is not dropped either: offset_max does not
        # move up with what is added, so the next counter adds it once it
        # is proven.
        missing = _kwh(value - lifetime - state["offset_max"])
        if missing <= 0:
            # Nothing provably missing: the ledger is complete up to now.
            state["anchor_time"] = received
            state["complete_until"] = delta_hour(received)
            return True

        # The most the breaker can have used since the ledger was last known
        # to be complete: the end of the last complete hour, or the last
        # counter, whichever is later.
        known_until = state["anchor_time"] or 0.0
        if state["complete_until"] is not None:
            known_until = max(known_until, state["complete_until"] + HOUR_SECS)
        possible = bound * max(received - known_until, 0.0) / HOUR_SECS + bound
        if known_until <= 0 or missing > possible:
            # A counter jump the breaker cannot physically explain (a reset
            # or replaced hub, or a glitch). Take it as the new reference
            # without adding energy.
            self._set_reference(state, value, received)
            _LOGGER.warning(
                "Breaker %s leg %s: lifetime counter %.1f kWh is %.1f kWh above the "
                "ledger, more than the breaker can use in that time — taking it as "
                "the new reference without adding energy", label, leg, value, missing,
            )
            return True

        if (
            state["complete_until"] is not None
            and state["complete_until"] >= delta_hour(received)
            and missing <= _kwh(bound * (received - hour_start(received)) / HOUR_SECS)
        ):
            # The ledger has every hour up to the current one, so the excess
            # is the current hour's energy so far; its burst books the whole
            # hour (or, if the hour is claimed by an earlier counter, the
            # next counter adds it). More than the breaker can have used
            # since the start of the hour means complete_until is wrong (a
            # gap it did not track, e.g. in a ledger stored before the field
            # existed): the excess is added below as missed energy.
            state["anchor_time"] = received
            _LOGGER.debug(
                "Breaker %s leg %s: lifetime counter %.1f kWh is %.3f kWh above the "
                "ledger, all of it in the current hour — left to the hourly burst",
                label, leg, value, missing,
            )
            return True

        # The cloud counted energy the ledger never saw (hours missed since
        # complete_until, also ones followed by booked hours). The counter
        # also covers the current hour up to now, so that hour is claimed:
        # its burst would otherwise count the same energy twice. The ledger
        # is complete up to the hour before; complete_until stays there, so
        # the next counter finds the claimed hour incomplete and adds the
        # rest of it.
        state["lifetime"] += missing
        state["anchor_time"] = received
        current_hour = hour_start(received)
        if state["last_hour"] is None or state["last_hour"] < current_hour:
            state["last_hour"] = current_hour
        state["complete_until"] = delta_hour(received)
        # The hour is claimed by the counter: no delta to correct. The last
        # booked delta stays in last_value: the listing may still show it,
        # and _may_be_stale_listing needs it to tell.
        state["last_source"] = COUNTER_CLAIM_SOURCE
        self._add_daily(record, current_hour, missing)
        _LOGGER.info(
            "Breaker %s leg %s: lifetime counter %.1f kWh is %.3f kWh above the "
            "ledger — adding the missed energy", label, leg, value, missing,
        )
        return True

    @staticmethod
    def _set_reference(state: dict, value: float, received: float) -> None:
        # The reference takes in everything up to now, so the ledger is
        # complete up to the hour before the current one. The cloud total
        # is somewhere in the counter's window.
        state["offset"] = value - state["lifetime"]
        state["offset_max"] = value + counter_window_kwh(value) - state["lifetime"]
        state["anchor_time"] = received
        state["complete_until"] = delta_hour(received)

    @staticmethod
    def _add_daily(record: dict, hour: int, value: float) -> None:
        daily = record["daily"]
        day = local_date(hour).isoformat()
        daily[day] = max(daily.get(day, 0.0) + value, 0.0)
        for old in sorted(daily)[:-DAILY_KEEP_DAYS]:
            del daily[old]
