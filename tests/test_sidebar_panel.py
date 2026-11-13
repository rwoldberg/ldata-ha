"""The sidebar panel is off by default and follows the config entries.

These run against a real Home Assistant core (its frontend panel registry,
device registry, config entries and translation loader), with only the HTTP
server stubbed out.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant import loader
from homeassistant.components import frontend
from homeassistant.config_entries import ConfigEntryDisabler
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_test_home_assistant,
)

from custom_components import ldata
from custom_components.ldata import card, sidebar
from custom_components.ldata.const import DOMAIN, PANEL_SUBENTRY_TYPE, SHOW_SIDEBAR_PANEL
from custom_components.ldata.sidebar import (
    SIDEBAR_ELEMENT,
    SIDEBAR_URL_PATH,
    async_update_sidebar_panel,
    sidebar_enabled,
)

pytestmark = pytest.mark.asyncio

TRANSLATIONS = Path(ldata.__file__).parent / "translations"


@contextlib.asynccontextmanager
async def _home_assistant():
    async with async_test_home_assistant() as hass:
        # Look for custom integrations again, so this one is found.
        hass.data.pop(loader.DATA_CUSTOM_COMPONENTS, None)
        hass.http = MagicMock()
        hass.http.async_register_static_paths = AsyncMock()
        events: list = []
        hass.bus.async_listen(frontend.EVENT_PANELS_UPDATED, events.append)
        hass.panel_events = events
        try:
            yield hass
        finally:
            await hass.async_stop(force=True)


def _entry(hass: HomeAssistant, *, options=None, data=None, panels=(), title="Home") -> MockConfigEntry:
    """Add an LDATA entry that has found these panels before (one subentry each)."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=title,
        data={"username": "user@example.com", "password": "secret", **(data or {})},
        options=options or {},
        subentries_data=[
            {"data": {}, "subentry_type": PANEL_SUBENTRY_TYPE, "title": name, "unique_id": panel_id}
            for panel_id, name in panels
        ],
    )
    entry.add_to_hass(hass)
    registry = dr.async_get(hass)
    for panel_id, name in panels:
        registry.async_get_or_create(
            config_entry_id=entry.entry_id, identifiers={(DOMAIN, panel_id)}, name=name
        )
    return entry


def _loaded(hass: HomeAssistant, entry: MockConfigEntry, panel_ids) -> None:
    """Stand in for a loaded entry: its coordinator knows the panels from Leviton."""
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = SimpleNamespace(
        data={"panels": [{"id": panel_id} for panel_id in panel_ids]}
    )


def _device_id(hass: HomeAssistant, panel_id: str) -> str:
    return dr.async_get(hass).async_get_device(identifiers={(DOMAIN, panel_id)}).id


def _panel(hass: HomeAssistant) -> dict | None:
    registered = hass.data.get(frontend.DATA_PANELS, {}).get(SIDEBAR_URL_PATH)
    return registered.to_response() if registered else None


async def _events(hass: HomeAssistant) -> int:
    await hass.async_block_till_done()
    return len(hass.panel_events)


async def test_nothing_in_the_sidebar_by_default() -> None:
    async with _home_assistant() as hass:
        entry = _entry(hass, panels=[("p1", "Main Panel")])
        _loaded(hass, entry, ["p1"])

        await async_update_sidebar_panel(hass)

        assert sidebar_enabled(entry) is False
        assert _panel(hass) is None
        assert await _events(hass) == 0


async def test_option_adds_the_panel() -> None:
    async with _home_assistant() as hass:
        entry = _entry(
            hass,
            options={SHOW_SIDEBAR_PANEL: True},
            panels=[("p1", "Main Panel"), ("p2", "Casita")],
        )
        _loaded(hass, entry, ["p1", "p2"])

        await async_update_sidebar_panel(hass)

        panel = _panel(hass)
        assert panel["component_name"] == "custom"
        assert panel["url_path"] == "ldata"
        assert panel["title"] == "Load Center"
        assert panel["icon"] == "mdi:electric-switch"
        assert panel["require_admin"] is False
        assert panel["config_panel_domain"] is None
        custom = panel["config"]["_panel_custom"]
        assert custom["name"] == SIDEBAR_ELEMENT == "ldata-sidebar-panel"
        assert custom["embed_iframe"] is False
        # Listed by name, as device registry ids.
        assert panel["config"]["panels"] == [
            {"device_id": _device_id(hass, "p2")},
            {"device_id": _device_id(hass, "p1")},
        ]
        assert await _events(hass) == 1
        # The card's folder is being served by the time a browser can ask for it.
        hass.http.async_register_static_paths.assert_awaited_once()


async def test_page_loads_the_same_file_as_the_dashboard_card() -> None:
    """One URL for both, so a browser runs the card's file once."""
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])

        await async_update_sidebar_panel(hass)

        module_url = _panel(hass)["config"]["_panel_custom"]["module_url"]
        assert module_url == await card.async_serve_card(hass)
        assert module_url.startswith(f"/ldata_static/ldata-panel-card.js?v={ldata.VERSION}-")
        assert "js_url" not in _panel(hass)["config"]["_panel_custom"]
        source = (Path(ldata.__file__).parent / "www" / "ldata-panel-card.js").read_text()
        assert f'customElements.define("{SIDEBAR_ELEMENT}"' in source


async def test_choice_made_during_setup_counts_until_the_options_say_otherwise() -> None:
    async with _home_assistant() as hass:
        entry = _entry(hass, data={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        assert sidebar_enabled(entry) is True
        await async_update_sidebar_panel(hass)
        assert _panel(hass) is not None

        hass.config_entries.async_update_entry(entry, options={SHOW_SIDEBAR_PANEL: False})
        assert sidebar_enabled(entry) is False
        await async_update_sidebar_panel(hass)
        assert _panel(hass) is None


async def test_registered_before_the_entry_has_loaded() -> None:
    """A tablet left on the page must find it as soon as Home Assistant is up."""
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])

        assert await ldata.async_setup(hass, {})

        # Nothing is loaded; the panels come from what an earlier run found.
        assert DOMAIN not in hass.config_entries.async_loaded_entries(DOMAIN)
        assert _panel(hass)["config"]["panels"] == [{"device_id": _device_id(hass, "p1")}]


async def test_reload_leaves_the_panel_alone() -> None:
    async with _home_assistant() as hass:
        entry = _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        _loaded(hass, entry, ["p1"])
        await async_update_sidebar_panel(hass)
        before = _panel(hass)
        assert await _events(hass) == 1

        # Unloaded (a reload, or the cloud is unreachable), then loaded again.
        hass.data[DOMAIN].pop(entry.entry_id)
        await async_update_sidebar_panel(hass)
        _loaded(hass, entry, ["p1"])
        await async_update_sidebar_panel(hass)

        # The frontend rebuilds the page (and sends its viewer away if the
        # panel disappears) on any change, so there must be none.
        assert _panel(hass) == before
        assert await _events(hass) == 1


async def test_new_load_center_is_added_to_the_page() -> None:
    async with _home_assistant() as hass:
        entry = _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        _loaded(hass, entry, ["p1"])
        await async_update_sidebar_panel(hass)

        dr.async_get(hass).async_get_or_create(
            config_entry_id=entry.entry_id, identifiers={(DOMAIN, "p2")}, name="Garage"
        )
        _loaded(hass, entry, ["p1", "p2"])
        await async_update_sidebar_panel(hass)

        assert _panel(hass)["config"]["panels"] == [
            {"device_id": _device_id(hass, "p2")},
            {"device_id": _device_id(hass, "p1")},
        ]


async def test_loaded_entry_lists_only_what_leviton_reports() -> None:
    """A load center that left the account is dropped once the entry is loaded."""
    async with _home_assistant() as hass:
        entry = _entry(
            hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel"), ("gone", "Old Panel")]
        )
        _loaded(hass, entry, ["p1"])

        await async_update_sidebar_panel(hass)

        assert _panel(hass)["config"]["panels"] == [{"device_id": _device_id(hass, "p1")}]


async def test_one_page_for_every_entry_that_asks() -> None:
    async with _home_assistant() as hass:
        home = _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")], title="Home")
        cabin = _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p2", "Cabin")], title="Cabin")
        _entry(hass, panels=[("p3", "Shop")], title="Shop")  # not asked for
        for entry, panel_id in ((home, "p1"), (cabin, "p2")):
            _loaded(hass, entry, [panel_id])

        await async_update_sidebar_panel(hass)

        assert _panel(hass)["config"]["panels"] == [
            {"device_id": _device_id(hass, "p2")},
            {"device_id": _device_id(hass, "p1")},
        ]

        # Turning it off for one entry keeps the page for the other.
        hass.config_entries.async_update_entry(home, options={SHOW_SIDEBAR_PANEL: False})
        await async_update_sidebar_panel(hass)
        assert _panel(hass)["config"]["panels"] == [{"device_id": _device_id(hass, "p2")}]


async def test_turning_the_option_off_removes_the_panel() -> None:
    async with _home_assistant() as hass:
        entry = _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        await async_update_sidebar_panel(hass)
        assert _panel(hass) is not None

        hass.config_entries.async_update_entry(entry, options={SHOW_SIDEBAR_PANEL: False})
        await async_update_sidebar_panel(hass)

        assert _panel(hass) is None
        assert await _events(hass) == 2
        # Nothing left to remove a second time.
        await async_update_sidebar_panel(hass)
        assert await _events(hass) == 2


async def test_disabled_or_deleted_entry_drops_out() -> None:
    async with _home_assistant() as hass:
        entry = _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        await async_update_sidebar_panel(hass)
        assert _panel(hass) is not None

        # Home Assistant still lists an entry while it is being deleted.
        await ldata.async_remove_entry(hass, entry)
        assert _panel(hass) is None

        await async_update_sidebar_panel(hass)
        assert _panel(hass) is not None
        object.__setattr__(entry, "disabled_by", ConfigEntryDisabler.USER)
        await async_update_sidebar_panel(hass)
        assert _panel(hass) is None


async def test_page_without_load_centers_is_still_offered() -> None:
    """Asked for but nothing found yet: the page explains, the item is there."""
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True})

        await async_update_sidebar_panel(hass)

        assert _panel(hass)["config"]["panels"] == []


@pytest.mark.parametrize("language", ["de", "fr", "es-419", "zh-Hans"])
async def test_title_is_in_the_servers_language(language: str) -> None:
    expected = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    title = expected["config_panel"]["sidebar"]["title"]
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        hass.config.language = language

        await async_update_sidebar_panel(hass)

        assert title != "Load Center"
        assert _panel(hass)["title"] == title


async def test_title_follows_a_change_of_language() -> None:
    title = json.loads((TRANSLATIONS / "de.json").read_text(encoding="utf-8"))["config_panel"]["sidebar"]["title"]
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        assert await ldata.async_setup(hass, {})
        assert _panel(hass)["title"] == "Load Center"

        await hass.config.async_update(language="de")
        await hass.async_block_till_done()

        assert _panel(hass)["title"] == title


async def test_language_without_a_translation_gets_english() -> None:
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        hass.config.language = "ja"

        await async_update_sidebar_panel(hass)

        assert _panel(hass)["title"] == "Load Center"


async def test_unreadable_translations_do_not_cost_the_panel() -> None:
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])

        with patch.object(sidebar.translation, "async_get_translations", AsyncMock(side_effect=OSError)):
            await async_update_sidebar_panel(hass)

        assert _panel(hass)["title"] == "Load Center"


async def test_address_taken_by_something_else_is_survived(caplog: pytest.LogCaptureFixture) -> None:
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        frontend.async_register_built_in_panel(hass, "iframe", "Theirs", frontend_url_path=SIDEBAR_URL_PATH)

        await async_update_sidebar_panel(hass)

        assert _panel(hass)["title"] == "Theirs"
        assert "another panel already uses /ldata" in caplog.text
        # ... and theirs is never removed on our behalf.
        for entry in hass.config_entries.async_entries(DOMAIN):
            hass.config_entries.async_update_entry(entry, options={SHOW_SIDEBAR_PANEL: False})
        await async_update_sidebar_panel(hass)
        assert _panel(hass)["title"] == "Theirs"


async def test_failure_never_reaches_the_caller(caplog: pytest.LogCaptureFixture) -> None:
    """Entry setup calls this; a sidebar problem must not fail the entry."""
    async with _home_assistant() as hass:
        _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])

        with patch.object(sidebar.dr, "async_get", side_effect=RuntimeError("boom")):
            await async_update_sidebar_panel(hass)

        assert _panel(hass) is None
        assert "Failed to update the LDATA sidebar panel" in caplog.text


async def test_device_is_looked_up_within_its_entry_where_home_assistant_can() -> None:
    """Newer cores deprecate finding a device by identifier alone."""
    async with _home_assistant() as hass:
        entry = _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
        device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, "p1")})
        calls: list = []

        def by_identifier(identifier, config_entry_id):
            calls.append((identifier, config_entry_id))
            return device

        newer_registry = SimpleNamespace(
            async_get_device_by_identifier=by_identifier,
            async_get_device=MagicMock(side_effect=AssertionError("deprecated lookup used")),
        )
        with patch.object(sidebar.dr, "async_get", return_value=newer_registry):
            await async_update_sidebar_panel(hass)

        assert calls == [((DOMAIN, "p1"), entry.entry_id)]
        assert _panel(hass)["config"]["panels"] == [{"device_id": device.id}]


async def test_page_keeps_clear_of_the_notch_itself_where_the_frontend_asks() -> None:
    """handle_safe_area is passed to cores that know it, and only to those."""
    passed: list[dict] = []

    async def newer(hass, *, handle_safe_area=False, **kwargs):
        passed.append({"handle_safe_area": handle_safe_area, **kwargs})

    async def older(hass, frontend_url_path, webcomponent_name, sidebar_title=None, sidebar_icon=None,
                    js_url=None, module_url=None, embed_iframe=False, trust_external=False, config=None,
                    require_admin=False, config_panel_domain=None):  # fmt: skip
        passed.append({"frontend_url_path": frontend_url_path})

    for register, expected in ((newer, True), (older, None)):
        async with _home_assistant() as hass:
            _entry(hass, options={SHOW_SIDEBAR_PANEL: True}, panels=[("p1", "Main Panel")])
            with patch.object(sidebar.panel_custom, "async_register_panel", register):
                await async_update_sidebar_panel(hass)
            assert passed.pop().get("handle_safe_area") is expected
            assert hass.data[DOMAIN]["_sidebar"]["title"] == "Load Center"


async def test_setup_unload_and_removal_all_refresh_the_sidebar() -> None:
    """The entry lifecycle hooks in __init__ call the updater."""
    from tests.test_entry_unload_cleanup import _FakeCoordinator, _entry as plain_entry, _hass

    hass = _hass()
    entry = plain_entry()
    updater = AsyncMock()
    with (
        patch.object(ldata, "async_update_sidebar_panel", updater),
        patch.object(ldata, "LDATAUpdateCoordinator", _FakeCoordinator),
        patch.object(ldata, "_async_reconcile_subentries", AsyncMock()),
        patch.object(ldata, "_async_ensure_panel_devices"),
        patch.object(ldata, "_async_purge_orphaned_devices", AsyncMock()),
        patch.object(ldata, "_async_purge_stale_breaker_duplicates", AsyncMock()),
    ):
        assert await ldata.async_setup_entry(hass, entry)
        assert updater.await_count == 1
        assert await ldata.async_unload_entry(hass, entry)
        assert updater.await_count == 2
        await ldata.async_remove_entry(hass, entry)
        assert updater.await_args.kwargs == {"removed_entry_id": entry.entry_id}
