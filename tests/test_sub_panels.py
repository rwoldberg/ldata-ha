"""Which breaker feeds which load center: how it is stored, shown and passed on."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from homeassistant.helpers import device_registry as dr

from custom_components.ldata.binary_sensor import LdataCloudConnectedSensor
from custom_components.ldata.const import DOMAIN, SHOW_SIDEBAR_PANEL
from custom_components.ldata.sidebar import async_update_sidebar_panel
from custom_components.ldata.sub_panels import SUB_PANELS, feeds_of, looped, sub_panel_feeds

# The real-core scaffolding the sidebar tests use (tests/ is on the path, not a package).
from test_sidebar_panel import _device_id, _entry, _events, _home_assistant, _loaded, _panel


def _stored(**feeds: tuple[str, int]) -> dict:
    return {
        SUB_PANELS: {
            sub_id: {"panel": panel_id, "position": position}
            for sub_id, (panel_id, position) in feeds.items()
        }
    }


def test_feeds_are_read_from_the_options() -> None:
    options = _stored(casita=("main", 38), garage=("main", 29))

    assert sub_panel_feeds(options) == {"casita": ("main", 38), "garage": ("main", 29)}
    assert feeds_of(options, "main") == [(29, "garage"), (38, "casita")]
    assert feeds_of(options, "casita") == []
    assert sub_panel_feeds({}) == {}


def test_a_sub_panel_can_feed_another() -> None:
    options = _stored(casita=("main", 38), shed=("casita", 5))

    assert sub_panel_feeds(options) == {"casita": ("main", 38), "shed": ("casita", 5)}


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "main",
        ["casita"],
        {"casita": "main"},
        {"casita": {"panel": "main"}},
        {"casita": {"panel": "main", "position": "top"}},
        {"casita": {"panel": "", "position": 38}},
        {"casita": {"panel": None, "position": 38}},
        {"casita": {"panel": "casita", "position": 38}},  # fed from itself
        {7: {"panel": "main", "position": 38}},
    ],
)
def test_malformed_options_are_left_out(raw) -> None:
    assert sub_panel_feeds({SUB_PANELS: raw}) == {}


def test_position_restored_as_text_still_counts() -> None:
    assert sub_panel_feeds({SUB_PANELS: {"casita": {"panel": "main", "position": "38"}}}) == {
        "casita": ("main", 38)
    }


def test_load_centers_that_feed_each_other_are_left_out() -> None:
    pair = {"a": ("b", 1), "b": ("a", 2)}
    ring = {"a": ("b", 1), "b": ("c", 2), "c": ("a", 3)}

    assert looped(pair) == {"a", "b"}
    assert looped(ring) == {"a", "b", "c"}
    assert sub_panel_feeds(_stored(**pair)) == {}
    # One fed from a pair that feed each other is not part of the loop itself.
    assert looped({**pair, "d": ("a", 4)}) == {"a", "b"}
    assert sub_panel_feeds(_stored(**pair, d=("a", 4))) == {"d": ("a", 4)}
    assert looped({"casita": ("main", 38), "shed": ("casita", 5)}) == set()


# ── The feeding panel's Cloud Connected entity ────────────────────────────


def _cloud_sensor(hass, entry, panel_id: str) -> LdataCloudConnectedSensor:
    panel = {"id": panel_id, "name": panel_id, "connected": True, "serialNumber": panel_id}
    coordinator = MagicMock()
    coordinator.config_entry = entry
    coordinator.data = {"panels": [panel]}
    sensor = LdataCloudConnectedSensor(coordinator, panel)
    sensor.hass = hass
    return sensor


@pytest.mark.asyncio
async def test_feeding_panel_lists_the_breakers_that_feed_a_sub_panel() -> None:
    async with _home_assistant() as hass:
        entry = _entry(
            hass,
            options=_stored(p2=("p1", 38), p3=("p1", 29)),
            panels=[("p1", "Main Panel"), ("p2", "Casita"), ("p3", "Garage")],
        )

        main = _cloud_sensor(hass, entry, "p1").extra_state_attributes
        casita = _cloud_sensor(hass, entry, "p2").extra_state_attributes

        # By position, as the card's own device ids.
        assert main["sub_panels"] == [
            {"position": 29, "device_id": _device_id(hass, "p3")},
            {"position": 38, "device_id": _device_id(hass, "p2")},
        ]
        assert casita["sub_panels"] == []
        # What the card already read from this entity is still there.
        assert {"orientation", "panel_size", "dumb_breakers"} <= set(main)


@pytest.mark.asyncio
async def test_feed_to_a_load_center_without_a_device_is_not_listed() -> None:
    async with _home_assistant() as hass:
        entry = _entry(hass, options=_stored(gone=("p1", 12)), panels=[("p1", "Main Panel")])

        assert _cloud_sensor(hass, entry, "p1").extra_state_attributes["sub_panels"] == []


@pytest.mark.asyncio
async def test_entity_that_is_not_added_yet_lists_nothing() -> None:
    async with _home_assistant() as hass:
        entry = _entry(hass, options=_stored(p2=("p1", 38)), panels=[("p1", "Main"), ("p2", "Casita")])
        sensor = _cloud_sensor(hass, entry, "p1")
        sensor.hass = None

        assert sensor.extra_state_attributes["sub_panels"] == []


# ── The sidebar page ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_page_lists_a_sub_panel_after_the_load_center_that_feeds_it() -> None:
    async with _home_assistant() as hass:
        entry = _entry(
            hass,
            options={SHOW_SIDEBAR_PANEL: True, **_stored(p2=("p1", 38), p4=("p2", 5))},
            panels=[("p1", "Main Panel"), ("p2", "Barn"), ("p3", "Annex"), ("p4", "Shed")],
        )
        _loaded(hass, entry, ["p1", "p2", "p3", "p4"])

        await async_update_sidebar_panel(hass)

        # By name (Annex, Main Panel), each followed by what it feeds.
        assert _panel(hass)["config"]["panels"] == [
            {"device_id": _device_id(hass, "p3")},
            {"device_id": _device_id(hass, "p1")},
            {"device_id": _device_id(hass, "p2"), "fed_by": _device_id(hass, "p1")},
            {"device_id": _device_id(hass, "p4"), "fed_by": _device_id(hass, "p2")},
        ]


@pytest.mark.asyncio
async def test_page_follows_a_change_of_feed() -> None:
    async with _home_assistant() as hass:
        entry = _entry(
            hass,
            options={SHOW_SIDEBAR_PANEL: True},
            panels=[("p1", "Main Panel"), ("p2", "Casita")],
        )
        _loaded(hass, entry, ["p1", "p2"])
        await async_update_sidebar_panel(hass)
        assert _panel(hass)["config"]["panels"] == [
            {"device_id": _device_id(hass, "p2")},
            {"device_id": _device_id(hass, "p1")},
        ]
        before = await _events(hass)

        hass.config_entries.async_update_entry(
            entry, options={SHOW_SIDEBAR_PANEL: True, **_stored(p2=("p1", 38))}
        )
        await async_update_sidebar_panel(hass)

        assert _panel(hass)["config"]["panels"] == [
            {"device_id": _device_id(hass, "p1")},
            {"device_id": _device_id(hass, "p2"), "fed_by": _device_id(hass, "p1")},
        ]
        assert await _events(hass) > before


@pytest.mark.asyncio
async def test_feed_from_a_load_center_that_is_not_on_the_page_is_ignored() -> None:
    async with _home_assistant() as hass:
        entry = _entry(
            hass,
            options={SHOW_SIDEBAR_PANEL: True, **_stored(p2=("p9", 38), p1=("p2", 3), p2x=("p1", 1))},
            panels=[("p1", "Main Panel"), ("p2", "Casita")],
        )
        _loaded(hass, entry, ["p1", "p2"])

        await async_update_sidebar_panel(hass)

        # p2's feed names a panel Leviton does not report, so p2 heads the
        # list; p1 is fed from p2.
        assert _panel(hass)["config"]["panels"] == [
            {"device_id": _device_id(hass, "p2")},
            {"device_id": _device_id(hass, "p1"), "fed_by": _device_id(hass, "p2")},
        ]


@pytest.mark.asyncio
async def test_feeds_stay_within_their_own_entry() -> None:
    async with _home_assistant() as hass:
        home = _entry(
            hass,
            options={SHOW_SIDEBAR_PANEL: True, **_stored(p2=("p1", 38))},
            panels=[("p1", "Main Panel"), ("p2", "Casita")],
        )
        cabin = _entry(
            hass,
            title="Cabin",
            options={SHOW_SIDEBAR_PANEL: True, **_stored(c1=("p1", 4))},
            panels=[("c1", "Cabin Panel")],
        )
        _loaded(hass, home, ["p1", "p2"])
        _loaded(hass, cabin, ["c1"])

        await async_update_sidebar_panel(hass)

        assert _panel(hass)["config"]["panels"] == [
            {"device_id": _device_id(hass, "c1")},
            {"device_id": _device_id(hass, "p1")},
            {"device_id": _device_id(hass, "p2"), "fed_by": _device_id(hass, "p1")},
        ]


def test_device_lookup_is_shared_with_the_sidebar() -> None:
    from custom_components.ldata import sidebar, sub_panels

    assert sidebar._panel_device is sub_panels.panel_device
    registry = SimpleNamespace(async_get_device_by_identifier=MagicMock(return_value="device"))
    entry = SimpleNamespace(entry_id="entry-1")

    assert sub_panels.panel_device(registry, entry, "p1") == "device"
    registry.async_get_device_by_identifier.assert_called_once_with((DOMAIN, "p1"), "entry-1")
    assert dr is not None
