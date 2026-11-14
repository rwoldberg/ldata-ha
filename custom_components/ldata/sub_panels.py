"""Which breaker feeds which load center.

Leviton reports every load center of a residence on its own; nothing says
that one of them is a sub-panel fed from a breaker in another. The user says
so in the integration's options (see OptionsFlow in config_flow.py), where it
is kept as

    options["sub_panels"] = {"<sub-panel id>": {"panel": "<feeding panel id>", "position": 38, "rating": 100}}

"rating" is optional: the size of the feeding breaker in amps, which the user
gives when that breaker isn't a smart one (Leviton knows a smart breaker's).

A load center has one feed at most. The link is used in two places:

- The feeding panel's Cloud Connected entity lists its breakers that feed
  another load center, and the sub-panel's says what feeds it
  (binary_sensor.py). The panel card reads them there, so every card shows
  the link, and how much of its feeder a sub-panel uses, on a dashboard and on
  the sidebar page alike.
- The sidebar page puts a sub-panel right after the load center that feeds
  it (sidebar.py).
"""
from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN

SUB_PANELS = "sub_panels"
# The form's choice for a load center that no other one feeds.
NOT_FED = "none"


def looped(feeds: Mapping[str, tuple[str, int]]) -> set[str]:
    """Return the load centers whose chain of feeds leads back to themselves."""
    bad: set[str] = set()
    for start in feeds:
        seen: set[str] = set()
        current = feeds[start][0]
        while current in feeds and current not in seen:
            if current == start:
                bad.add(start)
                break
            seen.add(current)
            current = feeds[current][0]
    return bad


def sub_panel_feeds(options: Mapping[str, Any]) -> dict[str, tuple[str, int]]:
    """Return {sub-panel id: (feeding panel id, breaker position)}.

    Anything malformed is left out, and so is every link of a loop (A fed
    from B, B fed from A). The options form refuses a loop, but options can
    also be restored from a backup or edited by hand.
    """
    raw = options.get(SUB_PANELS)
    feeds: dict[str, tuple[str, int]] = {}
    if isinstance(raw, Mapping):
        for sub_id, feed in raw.items():
            if not isinstance(sub_id, str) or not isinstance(feed, Mapping):
                continue
            panel_id = feed.get("panel")
            if not isinstance(panel_id, str) or not panel_id or panel_id == sub_id:
                continue
            try:
                position = int(feed.get("position"))
            except (TypeError, ValueError):
                continue
            feeds[sub_id] = (panel_id, position)
    for sub_id in looped(feeds):
        feeds.pop(sub_id)
    return feeds


def amps(value: Any) -> float | None:
    """Return a breaker size in amps, or None for anything that isn't one."""
    if isinstance(value, bool):
        return None
    try:
        size = float(value)
    except (TypeError, ValueError):
        return None
    return size if math.isfinite(size) and size > 0 else None


def feed_ratings(options: Mapping[str, Any]) -> dict[str, float]:
    """Return {sub-panel id: amps} for the feeds whose breaker size the user gave."""
    raw = options.get(SUB_PANELS)
    feeds = sub_panel_feeds(options)
    sizes: dict[str, float] = {}
    if isinstance(raw, Mapping):
        for sub_id, feed in raw.items():
            if sub_id in feeds and isinstance(feed, Mapping):
                size = amps(feed.get("rating"))
                if size is not None:
                    sizes[sub_id] = size
    return sizes


def feeder_rating(options: Mapping[str, Any], data: Any, sub_id: str) -> float | None:
    """Return the size in amps of the breaker that feeds a sub-panel.

    The size the user gave wins; otherwise Leviton's rating of the breaker,
    which only a smart breaker has.
    """
    given = feed_ratings(options).get(sub_id)
    if given is not None:
        return given
    feed = sub_panel_feeds(options).get(sub_id)
    if feed is None or not isinstance(data, Mapping):
        return None
    panel_id, position = feed
    breakers = data.get("breakers")
    for breaker in breakers.values() if isinstance(breakers, Mapping) else ():
        if not isinstance(breaker, Mapping) or breaker.get("panel_id") != panel_id:
            continue
        try:
            here = int(breaker.get("position"))
        except (TypeError, ValueError):
            continue
        if here == position:
            return amps(breaker.get("rating"))
    return None


def feeds_of(options: Mapping[str, Any], panel_id: str) -> list[tuple[int, str]]:
    """Return [(breaker position, sub-panel id)] for one panel's feeder breakers."""
    return sorted(
        (position, sub_id)
        for sub_id, (feeder, position) in sub_panel_feeds(options).items()
        if feeder == panel_id
    )


def panel_device(
    dev_reg: dr.DeviceRegistry, entry: ConfigEntry, panel_id: Any
) -> dr.DeviceEntry | None:
    """Return the device registry entry of one of the entry's load centers."""
    by_identifier = getattr(dev_reg, "async_get_device_by_identifier", None)
    if by_identifier is not None:
        return by_identifier((DOMAIN, panel_id), entry.entry_id)
    # Home Assistant cores that predate the per-entry lookup, where
    # async_get_device is not deprecated yet.
    return dev_reg.async_get_device(identifiers={(DOMAIN, panel_id)})
