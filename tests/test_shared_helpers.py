"""Shared helpers replace repeated code, and dead code is gone."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from custom_components.ldata import const, ldata_service
from custom_components.ldata.const import DECORA_ROOM_SUBENTRY_TYPE, PANEL_SUBENTRY_TYPE
from custom_components.ldata.decora_entity import add_entities_grouped_by_decora_room
from custom_components.ldata.ldata_base_entity import (
    add_entities_grouped_by_panel,
    subentry_ids_by_unique_id,
)
from custom_components.ldata.ldata_service import LDATAService, _panel_listing_url, _panel_url


@pytest.mark.parametrize(
    ("panel_type", "url"),
    [
        ("LDATA", "https://my.leviton.com/api/ResidentialBreakerPanels/P1"),
        ("WHEMS", "https://my.leviton.com/api/IotWhems/P1"),
    ],
)
def test_panel_url(panel_type, url) -> None:
    assert _panel_url("P1", panel_type) == url


@pytest.mark.parametrize(
    ("panel_type", "url"),
    [
        ("LDATA", "https://my.leviton.com/api/Residences/R1/residentialBreakerPanels"),
        ("WHEMS", "https://my.leviton.com/api/Residences/R1/iotWhems"),
    ],
)
def test_panel_listing_url(panel_type, url) -> None:
    assert _panel_listing_url("R1", panel_type) == url


@pytest.mark.parametrize("panel_type", ["LDATA", "WHEMS"])
def test_bandwidth_toggle_patches_the_panel(panel_type) -> None:
    service = LDATAService("", "", None)
    service.session = MagicMock()
    service.session.patch.return_value = SimpleNamespace(status_code=200)

    service._bandwidth_toggle("P1", panel_type)

    urls = {call.args[0] for call in service.session.patch.call_args_list}
    assert urls == {_panel_url("P1", panel_type)}


def test_websocket_keepalive_patches_each_panel() -> None:
    service = LDATAService("", "", None)
    urls: list[str] = []

    class _Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

    session = SimpleNamespace(patch=lambda url, **_kw: urls.append(url) or _Response())
    asyncio.run(service._ws_bandwidth_put(session, [("P1", "LDATA"), ("P2", "WHEMS")]))

    assert set(urls) == {_panel_url("P1", "LDATA"), _panel_url("P2", "WHEMS")}


def _entry() -> SimpleNamespace:
    subentries = {
        "a": SimpleNamespace(subentry_type=PANEL_SUBENTRY_TYPE, unique_id="P1", subentry_id="sub-p1"),
        "b": SimpleNamespace(subentry_type=DECORA_ROOM_SUBENTRY_TYPE, unique_id="31", subentry_id="sub-r31"),
        "c": SimpleNamespace(subentry_type=PANEL_SUBENTRY_TYPE, unique_id=None, subentry_id="sub-x"),
    }
    return SimpleNamespace(subentries=subentries)


def test_subentry_ids_by_unique_id() -> None:
    assert subentry_ids_by_unique_id(_entry(), PANEL_SUBENTRY_TYPE) == {"P1": "sub-p1"}
    assert subentry_ids_by_unique_id(_entry(), DECORA_ROOM_SUBENTRY_TYPE) == {"31": "sub-r31"}
    # An HA core without config subentries.
    assert subentry_ids_by_unique_id(SimpleNamespace(), PANEL_SUBENTRY_TYPE) == {}


def test_entities_are_added_to_their_subentry() -> None:
    add = MagicMock()
    breaker = SimpleNamespace(entity_data={"panel_id": "P1"})
    device = SimpleNamespace(entity_data={"residentialRoomId": 31})

    add_entities_grouped_by_panel(_entry(), add, [breaker])
    add_entities_grouped_by_decora_room(_entry(), add, [device])

    assert add.call_args_list[0].kwargs == {"config_subentry_id": "sub-p1"}
    assert add.call_args_list[1].kwargs == {"config_subentry_id": "sub-r31"}


def test_dead_code_is_gone() -> None:
    assert not hasattr(LDATAService, "put_residential_breaker_panels")
    service = LDATAService("", "", None)
    assert not hasattr(service, "_ws_iotwhem_count")
    assert not hasattr(const, "GAP_HANDLING_OPTIONS")
