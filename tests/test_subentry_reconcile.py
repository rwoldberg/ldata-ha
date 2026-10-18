"""Tests for moving existing LDATA devices into their panel subentries."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from custom_components.ldata import (
    _async_purge_legacy_breaker_devices,
    _async_reconcile_subentries,
    _legacy_breaker_serials,
    _resolve_panel_id_for_device,
)
from custom_components.ldata.const import DOMAIN, PANEL_SUBENTRY_TYPE

PANEL_ID = "LDATA-PANEL-1"
OTHER_PANEL_ID = "LDATA-PANEL-2"
SUBENTRY_ID = "subentry-panel-1"
OTHER_SUBENTRY_ID = "subentry-panel-2"


def _device(device_id, identifier, *, via_device_id=None, config_subentry_id=None):
    return SimpleNamespace(
        id=device_id,
        name=device_id,
        identifiers={(DOMAIN, identifier)},
        via_device_id=via_device_id,
        config_subentry_id=config_subentry_id,
    )


def _entity(entity_id, device_id, config_subentry_id=None):
    return SimpleNamespace(
        entity_id=entity_id,
        device_id=device_id,
        config_subentry_id=config_subentry_id,
    )


def _dev_reg(devices):
    by_id = {device.id: device for device in devices}
    dev_reg = MagicMock()
    dev_reg.async_get.side_effect = by_id.get
    return dev_reg


def _entry():
    entry = MagicMock()
    entry.entry_id = "entry-1"
    entry.subentries = {
        SUBENTRY_ID: SimpleNamespace(
            subentry_id=SUBENTRY_ID,
            subentry_type=PANEL_SUBENTRY_TYPE,
            unique_id=PANEL_ID,
        ),
        OTHER_SUBENTRY_ID: SimpleNamespace(
            subentry_id=OTHER_SUBENTRY_ID,
            subentry_type=PANEL_SUBENTRY_TYPE,
            unique_id=OTHER_PANEL_ID,
        ),
    }
    return entry


def _coordinator(breakers):
    return SimpleNamespace(
        data={
            "panels": [{"id": PANEL_ID}, {"id": OTHER_PANEL_ID}],
            "breakers": breakers,
            "decora_devices": {},
            "rooms": {},
        }
    )


async def _reconcile(devices, entities, breakers):
    """Run the reconcile pass and return the recorded registry calls."""
    calls = MagicMock()
    dev_reg = _dev_reg(devices)
    dev_reg.async_update_device = calls.async_update_device
    ent_reg = MagicMock()
    ent_reg.async_update_entity = calls.async_update_entity
    with (
        patch("custom_components.ldata.dr.async_get", return_value=dev_reg),
        patch(
            "custom_components.ldata.dr.async_entries_for_config_entry",
            return_value=devices,
        ),
        patch("custom_components.ldata.er.async_get", return_value=ent_reg),
        patch(
            "custom_components.ldata.er.async_entries_for_config_entry",
            return_value=entities,
        ),
    ):
        await _async_reconcile_subentries(MagicMock(), _entry(), _coordinator(breakers))
    return calls


def test_breaker_without_via_link_resolves_from_live_data() -> None:
    breaker = _device("breaker", "SER001")

    assert (
        _resolve_panel_id_for_device(
            breaker, {PANEL_ID}, _dev_reg([breaker]), {"SER001": PANEL_ID}
        )
        == PANEL_ID
    )


def test_live_data_wins_over_a_stale_via_link() -> None:
    old_panel = _device("old-panel", PANEL_ID)
    breaker = _device("breaker", "SER001", via_device_id=old_panel.id)

    assert (
        _resolve_panel_id_for_device(
            breaker,
            {PANEL_ID, OTHER_PANEL_ID},
            _dev_reg([old_panel, breaker]),
            {"SER001": OTHER_PANEL_ID},
        )
        == OTHER_PANEL_ID
    )


def test_breaker_missing_from_live_data_falls_back_to_via_link() -> None:
    panel = _device("panel", PANEL_ID)
    breaker = _device("breaker", "SER001", via_device_id=panel.id)

    assert (
        _resolve_panel_id_for_device(
            breaker, {PANEL_ID}, _dev_reg([panel, breaker]), {}
        )
        == PANEL_ID
    )


def test_breaker_of_unknown_panel_is_not_resolved() -> None:
    breaker = _device("breaker", "SER001")

    assert (
        _resolve_panel_id_for_device(
            breaker, {PANEL_ID}, _dev_reg([breaker]), {"SER001": "UNKNOWN-PANEL"}
        )
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("identifier", ["SER001", "SER001_0001"])
async def test_unlinked_breaker_moves_into_its_panel_subentry(identifier, caplog) -> None:
    breaker = _device("breaker", identifier)
    entity = _entity("switch.garage_outlets", breaker.id)
    breakers = {
        "SER001_0001": {
            "id": "SER001_0001",
            "stable_id": "SER001",
            "panel_id": PANEL_ID,
        }
    }

    with caplog.at_level(logging.WARNING, logger="ldata"):
        calls = await _reconcile([breaker], [entity], breakers)

    assert "Could not resolve a panel" not in caplog.text
    calls.async_update_device.assert_called_once_with(
        breaker.id, new_config_subentry_id=SUBENTRY_ID
    )
    calls.async_update_entity.assert_called_once_with(
        entity.entity_id, config_subentry_id=SUBENTRY_ID
    )


@pytest.mark.asyncio
async def test_entities_move_before_their_device() -> None:
    # HA 2026.8+ removes a device's entities that are still in its old
    # subentry when the device moves, so the entities have to go first.
    breaker = _device("breaker", "SER001")
    entity = _entity("switch.garage_outlets", breaker.id)
    breakers = {"SER001": {"id": "SER001", "stable_id": "SER001", "panel_id": PANEL_ID}}

    calls = await _reconcile([breaker], [entity], breakers)

    assert [call[0] for call in calls.mock_calls] == [
        "async_update_entity",
        "async_update_device",
    ]


@pytest.mark.asyncio
async def test_device_already_in_its_subentry_is_not_moved() -> None:
    breaker = _device("breaker", "SER001", config_subentry_id=SUBENTRY_ID)
    entity = _entity("switch.garage_outlets", breaker.id, SUBENTRY_ID)
    breakers = {"SER001": {"id": "SER001", "stable_id": "SER001", "panel_id": PANEL_ID}}

    calls = await _reconcile([breaker], [entity], breakers)

    calls.async_update_device.assert_not_called()
    calls.async_update_entity.assert_not_called()


@pytest.mark.asyncio
async def test_breaker_unknown_to_live_data_and_unlinked_still_warns(caplog) -> None:
    breaker = _device("breaker", "SER001")

    with caplog.at_level(logging.WARNING, logger="ldata"):
        calls = await _reconcile([breaker], [], {})

    assert "Could not resolve a panel" in caplog.text
    calls.async_update_device.assert_not_called()


# Breaker devices before 2.0.9 used the serialNumber as identifier; the
# current device for the same breaker uses its stable_id.
LEGACY_BREAKERS = {
    "BRK000000001": {
        "id": "BRK000000001",
        "stable_id": "BRK000000001",
        "serialNumber": "SER001",
        "panel_id": PANEL_ID,
    }
}


def test_legacy_serials_exclude_current_ids() -> None:
    breakers = {
        **LEGACY_BREAKERS,
        "SER003": {"id": "SER003", "stable_id": "SER003", "serialNumber": "SER003"},
    }

    assert _legacy_breaker_serials(_coordinator(breakers)) == {"SER001"}


@pytest.mark.asyncio
async def test_legacy_breaker_device_is_skipped_without_warning(caplog) -> None:
    legacy = _device("legacy", "SER001")

    with caplog.at_level(logging.WARNING, logger="ldata"):
        calls = await _reconcile([legacy], [], LEGACY_BREAKERS)

    assert "Could not resolve a panel" not in caplog.text
    calls.async_update_device.assert_not_called()


async def _purge(devices, entities_by_device, live_entity_ids, breakers=None):
    entry = _entry()
    dev_reg = _dev_reg(devices)
    ent_reg = MagicMock()
    platform = SimpleNamespace(
        config_entry=SimpleNamespace(entry_id=entry.entry_id),
        entities={entity_id: object() for entity_id in live_entity_ids},
    )
    with (
        patch("custom_components.ldata.dr.async_get", return_value=dev_reg),
        patch(
            "custom_components.ldata.dr.async_entries_for_config_entry",
            return_value=devices,
        ),
        patch("custom_components.ldata.er.async_get", return_value=ent_reg),
        patch(
            "custom_components.ldata.er.async_entries_for_device",
            side_effect=lambda _reg, device_id, **_kw: entities_by_device.get(device_id, []),
        ),
        patch(
            "custom_components.ldata.entity_platform.async_get_platforms",
            return_value=[platform],
        ),
    ):
        await _async_purge_legacy_breaker_devices(
            MagicMock(), entry, _coordinator(breakers or LEGACY_BREAKERS)
        )
    return dev_reg, ent_reg


@pytest.mark.asyncio
async def test_purge_removes_legacy_device_and_its_dead_entities() -> None:
    legacy = _device("legacy", "SER001")
    current = _device("current", "BRK000000001", via_device_id="panel")
    entities = {
        legacy.id: [
            _entity("sensor.garage_outlets_frequency", legacy.id),
            _entity("switch.garage_outlets", legacy.id),
        ],
        current.id: [_entity("sensor.garage_outlets_power", current.id)],
    }

    dev_reg, ent_reg = await _purge(
        [legacy, current], entities, {"sensor.garage_outlets_power"}
    )

    dev_reg.async_remove_device.assert_called_once_with(legacy.id)
    assert sorted(call.args[0] for call in ent_reg.async_remove.call_args_list) == [
        "sensor.garage_outlets_frequency",
        "switch.garage_outlets",
    ]


@pytest.mark.asyncio
async def test_purge_keeps_legacy_device_with_a_live_entity() -> None:
    legacy = _device("legacy", "SER001")
    entities = {legacy.id: [_entity("switch.garage_outlets", legacy.id)]}

    dev_reg, ent_reg = await _purge([legacy], entities, {"switch.garage_outlets"})

    dev_reg.async_remove_device.assert_not_called()
    ent_reg.async_remove.assert_not_called()


@pytest.mark.asyncio
async def test_purge_keeps_current_and_unknown_devices() -> None:
    current = _device("current", "BRK000000001", via_device_id="panel")
    linked = _device("linked", "SER001", via_device_id="panel")
    unknown = _device("unknown", "SER004")

    dev_reg, _ent_reg = await _purge([current, linked, unknown], {}, set())

    dev_reg.async_remove_device.assert_not_called()


@pytest.mark.asyncio
async def test_purge_never_removes_a_device_keyed_by_a_current_id() -> None:
    # A breaker whose serialNumber equals its own id is not a legacy device.
    breakers = {"SER003": {"id": "SER003", "stable_id": "SER003", "serialNumber": "SER003"}}
    device = _device("breaker", "SER003")

    dev_reg, _ent_reg = await _purge([device], {}, set(), breakers)

    dev_reg.async_remove_device.assert_not_called()
