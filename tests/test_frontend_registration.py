"""The panel card's Lovelace resource is registered once, safely, and kept current."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.components.lovelace.const import LOVELACE_DATA, MODE_STORAGE

from custom_components import ldata
from custom_components.ldata.const import DOMAIN

pytestmark = pytest.mark.asyncio

CARD = "/ldata_static/ldata-panel-card.js"


class FakeResources:
    """Mimics Lovelace's lazily loaded resource storage collection."""

    def __init__(self, stored: list[dict], loaded: bool = False) -> None:
        self.loaded = loaded
        self._stored = [dict(item) for item in stored]
        self.data = {item["id"]: dict(item) for item in stored} if loaded else {}
        self.created: list[dict] = []
        self.deleted: list[str] = []
        self._next = 0

    async def async_load(self) -> None:
        for item in self._stored:
            self.data[item["id"]] = dict(item)

    def async_items(self) -> list[dict]:
        return list(self.data.values())

    async def async_create_item(self, data: dict) -> dict:
        self._next += 1
        item = {"id": f"new{self._next}", "type": data["res_type"], "url": data["url"]}
        self.data[item["id"]] = item
        self.created.append(item)
        return item

    async def async_update_item(self, item_id: str, updates: dict) -> dict:
        self.data[item_id] = {**self.data[item_id], **updates}
        return self.data[item_id]

    async def async_delete_item(self, item_id: str) -> None:
        self.data.pop(item_id)
        self.deleted.append(item_id)


def _hass(resources: FakeResources) -> MagicMock:
    hass = MagicMock()
    hass.data = {LOVELACE_DATA: SimpleNamespace(resource_mode=MODE_STORAGE, resources=resources)}
    hass.http.async_register_static_paths = AsyncMock()

    async def run(func, *args):
        return func(*args)

    hass.async_add_executor_job = run
    return hass


def _card_urls(resources: FakeResources) -> list[str]:
    return [item["url"] for item in resources.async_items() if item["url"].startswith(CARD)]


async def test_loads_collection_before_reading_it() -> None:
    other = {"id": "hacs", "type": "module", "url": "/hacsfiles/mushroom/mushroom.js"}
    resources = FakeResources([other])

    await ldata._async_register_frontend(_hass(resources))

    assert resources.loaded is True
    # The user's own resources survive, plus exactly one card entry.
    assert resources.data["hacs"] == other
    assert len(_card_urls(resources)) == 1
    assert _card_urls(resources)[0].startswith(f"{CARD}?v={ldata.VERSION}-")


async def test_existing_entry_is_pointed_at_the_current_card() -> None:
    old = {"id": "card", "type": "module", "url": f"{CARD}?v=2.0.9"}
    resources = FakeResources([old])

    await ldata._async_register_frontend(_hass(resources))

    assert resources.created == []
    assert resources.data["card"]["url"] != old["url"]
    assert resources.data["card"]["url"].startswith(f"{CARD}?v=")


async def test_duplicate_entries_are_collapsed() -> None:
    resources = FakeResources(
        [
            {"id": "a", "type": "module", "url": f"{CARD}?v=2.0.10"},
            {"id": "b", "type": "module", "url": f"{CARD}?v=2.0.12"},
            {"id": "c", "type": "module", "url": f"{CARD}?v=2.0.13"},
        ]
    )

    await ldata._async_register_frontend(_hass(resources))

    assert list(resources.data) == ["a"]
    assert resources.deleted == ["b", "c"]


async def test_current_entry_is_left_alone() -> None:
    first = FakeResources([])
    await ldata._async_register_frontend(_hass(first))
    current = first.created[0]["url"]

    resources = FakeResources([{"id": "card", "type": "module", "url": current}], loaded=True)
    resources.async_update_item = AsyncMock()
    await ldata._async_register_frontend(_hass(resources))

    resources.async_update_item.assert_not_called()
    assert resources.created == [] and resources.deleted == []


async def test_url_changes_with_the_card_contents(tmp_path) -> None:
    card = tmp_path / "card.js"
    card.write_text("one")
    first = ldata._card_digest(card)
    card.write_text("two")

    assert first and ldata._card_digest(card) != first
    assert ldata._card_digest(tmp_path / "missing.js") is None


async def test_registration_runs_once_per_process() -> None:
    resources = FakeResources([])
    hass = _hass(resources)

    await ldata._async_register_frontend(hass)
    await ldata._async_register_frontend(hass)

    assert hass.data[DOMAIN]["_frontend_registered"] is True
    assert len(resources.created) == 1
