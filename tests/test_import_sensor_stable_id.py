"""Import-sensor cleanup finds the entities by their stable-id unique ids.

Since Leviton's firmware 2.2.0, breaker ids carry the panel's serial suffix
("4C45565275C6_A65E"). Entities are keyed by the stable id without it, but
sensor setup looked them up by the raw id, so on those panels a load
breaker's spurious import sensors were never removed.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from custom_components.ldata import sensor

PANEL = "1000_A65E"
RAW = "4C45565275C6_A65E"
STABLE = "4C45565275C6"
DAILY_UID = f"test-user-ldata_{STABLE}_todaymw_import"
LIFETIME_UID = f"test-user-ldata_{STABLE}__Import_kWh"
RAW_DAILY_UID = f"test-user-ldata_{RAW}_todaymw_import"


def _breaker(**over) -> dict:
    return {
        "id": RAW, "stable_id": STABLE, "name": "Dryer", "panel_id": PANEL, "poles": 2, "position": 1,
        "power": 0.0, "current": 0.0, "model": "LB250", "firmware": "2", "branch_type": "",
        "import": 0.0, "consumption": 0.0, "bleRSSI": -60, **over,
    }


async def _setup(breaker: dict, registry: MagicMock, options: dict | None = None):
    coordinator = MagicMock()
    coordinator.unique_id_prefix = "test-user"
    coordinator.data = {"breakers": {RAW: breaker}, "panels": [], "cts": {}}
    coordinator._service.panel_has_hw_counters.return_value = False  # firmware 2.x
    config_entry = SimpleNamespace(entry_id="entry-1", data={}, options=options or {}, subentries={})
    hass = SimpleNamespace(data={"ldata": {config_entry.entry_id: coordinator}}, config_entries=MagicMock())
    entities: list = []
    with patch("custom_components.ldata.sensor.er.async_get", return_value=registry):
        await sensor.async_setup_entry(hass, config_entry, entities.extend)
    return entities, hass


def _registry(existing: dict[str, str]) -> MagicMock:
    registry = MagicMock()
    registry.async_get_entity_id.side_effect = lambda _domain, _platform, uid: existing.get(uid)
    return registry


@pytest.mark.asyncio
async def test_load_breaker_import_sensors_are_removed_by_stable_id() -> None:
    registry = _registry({DAILY_UID: "sensor.dryer_daily_import", LIFETIME_UID: "sensor.dryer_import"})
    # Import mirrors consumption: a load breaker's firmware artifact.
    entities, hass = await _setup(_breaker(**{"import": 4.0, "consumption": 4.0}), registry)

    removed = {call.args[0] for call in registry.async_remove.call_args_list}
    assert removed == {"sensor.dryer_daily_import", "sensor.dryer_import"}
    options = hass.config_entries.async_update_entry.call_args.kwargs["options"]
    assert {DAILY_UID, LIFETIME_UID} <= set(options["suppressed_import_uids"])
    assert not [e for e in entities if e.unique_id in (DAILY_UID, LIFETIME_UID)]


@pytest.mark.asyncio
async def test_solar_confirmed_under_the_raw_id_is_still_honoured() -> None:
    # Classified by an earlier version, which stored the raw-id form.
    options = {"confirmed_solar_import_uids": [RAW_DAILY_UID]}
    entities, hass = await _setup(_breaker(), _registry({}), options)

    unique_ids = {entity.unique_id for entity in entities}
    assert {DAILY_UID, LIFETIME_UID} <= unique_ids
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_new_classification_is_stored_under_the_stable_id() -> None:
    entities, hass = await _setup(_breaker(branch_type="Solar"), _registry({}))

    options = hass.config_entries.async_update_entry.call_args.kwargs["options"]
    assert set(options["confirmed_solar_import_uids"]) == {DAILY_UID, LIFETIME_UID}
