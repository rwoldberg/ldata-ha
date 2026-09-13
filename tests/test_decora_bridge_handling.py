"""Regression tests for read-only Decora bridge handling."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.ldata.button import DecoraIdentifyButton, async_setup_entry
from custom_components.ldata.const import DEVICE_TYPE_BRIDGE, DOMAIN
from custom_components.ldata.decora_entity import DecoraEntity
from custom_components.ldata.ldata_service import LDATAService


def _bridge_and_switch() -> tuple[LDATAService, dict, dict]:
    service = LDATAService("", "", None)
    bridge = service.parse_bridge_devices(
        [{"id": 123, "name": "Bridge", "connected": True}]
    )
    switch = service.parse_decora_devices(
        [{"id": 456, "name": "Switch", "model": "D215S"}]
    )
    assert bridge["bridge_123"]["device_type"] == DEVICE_TYPE_BRIDGE
    return service, bridge, switch


def test_websocket_subscriptions_exclude_decora_bridges() -> None:
    service, bridge, switch = _bridge_and_switch()
    service.status_data = {"decora_devices": {**bridge, **switch}}

    subscriptions = service._ws_build_subscriptions()

    iot_switch_ids = [
        item["subscription"]["modelId"]
        for item in subscriptions
        if item["subscription"]["modelName"] == "IotSwitch"
    ]
    assert iot_switch_ids == [456]


@pytest.mark.asyncio
async def test_identify_buttons_exclude_decora_bridges() -> None:
    _, bridge, switch = _bridge_and_switch()
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"decora_devices": {**bridge, **switch}}
    config_entry = SimpleNamespace(entry_id="entry", subentries={})
    hass = SimpleNamespace(data={DOMAIN: {config_entry.entry_id: coordinator}})
    added = []

    await async_setup_entry(hass, config_entry, added.extend)

    assert [entity._dev_id for entity in added] == [456]


@pytest.mark.asyncio
async def test_identify_action_rejects_bridge_defense_in_depth() -> None:
    _, bridge, _ = _bridge_and_switch()
    bridge_data = bridge["bridge_123"]
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"decora_devices": bridge}
    coordinator.hass.async_add_executor_job = AsyncMock()
    entity = DecoraIdentifyButton(coordinator, bridge_data)

    await entity.async_press()

    coordinator.hass.async_add_executor_job.assert_not_awaited()


def test_bridges_without_mac_have_distinct_unique_ids() -> None:
    service = LDATAService("", "", None)
    bridges = service.parse_bridge_devices(
        [
            {"id": 123, "name": "Bridge 1", "connected": True},
            {"id": 456, "name": "Bridge 2", "connected": True},
        ]
    )
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"decora_devices": bridges}

    unique_ids = {
        DecoraEntity(data, coordinator).unique_id for data in bridges.values()
    }

    assert len(unique_ids) == 2
    assert "test-user-None" not in unique_ids
