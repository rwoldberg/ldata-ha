"""Unique ids move from the account email to the Leviton user id.

Every entity's unique id started with the account email. Home Assistant's
guidelines rule emails out as unique ids, and a reauth that stored the email
in another letter case turned every entity into a new one. The migration runs
on every setup against the real entity registry.
"""

from types import MappingProxyType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.storage import Store

from custom_components import ldata
from custom_components.ldata import sensor
from custom_components.ldata.const import DOMAIN

EMAIL = "Jane.Doe@example.com"
USERID = "5fd1c0de"
WATTS = f"{EMAIL}-ldata_B1_watts"
STATUS = f"{EMAIL}-ldata_B1"
DECORA = f"{EMAIL}-AA:BB:CC:DD:EE:FF_light"


# ── The plan ─────────────────────────────────────────────────────────


def _plan(registered, holders=None, username=EMAIL):
    holders = holders or {}
    return ldata._plan_unique_id_migration(
        registered, username, USERID, lambda domain, uid: holders.get((domain, uid))
    )


def test_plan_moves_every_unique_id_under_the_email() -> None:
    registered = [("sensor.a", "sensor", WATTS), ("binary_sensor.b", "binary_sensor", STATUS)]
    assert _plan(registered) == [
        ("sensor.a", f"{USERID}-ldata_B1_watts"),
        ("binary_sensor.b", f"{USERID}-ldata_B1"),
    ]


def test_plan_leaves_other_unique_ids_alone() -> None:
    registered = [
        ("sensor.a", "sensor", "someone.else@example.com-ldata_B1_watts"),
        ("sensor.b", "sensor", "B1_status"),
        ("sensor.c", "sensor", f"{EMAIL}ldata_no_dash"),
    ]
    assert _plan(registered) == []


def test_plan_handles_dashes_in_the_email() -> None:
    username = "jane-doe@my-example.com"
    registered = [("sensor.a", "sensor", f"{username}-ldata_B1_watts")]
    assert _plan(registered, username=username) == [("sensor.a", f"{USERID}-ldata_B1_watts")]


def test_plan_moves_the_current_casing_when_several_map_to_one_id() -> None:
    registered = [
        ("sensor.old", "sensor", f"{EMAIL.lower()}-ldata_B1_watts"),  # orphaned by a reauth
        ("sensor.live", "sensor", WATTS),
    ]
    assert _plan(registered) == [("sensor.live", f"{USERID}-ldata_B1_watts")]


def test_plan_moves_a_lone_entity_under_another_casing() -> None:
    registered = [("sensor.a", "sensor", f"{EMAIL.upper()}-ldata_B1_watts")]
    assert _plan(registered) == [("sensor.a", f"{USERID}-ldata_B1_watts")]


def test_plan_moves_none_of_several_casings_when_none_is_current() -> None:
    registered = [
        ("sensor.a", "sensor", f"{EMAIL.lower()}-ldata_B1_watts"),
        ("sensor.b", "sensor", f"{EMAIL.upper()}-ldata_B1_watts"),
    ]
    assert _plan(registered) == []


def test_plan_skips_ids_this_entry_already_has() -> None:
    registered = [("sensor.a", "sensor", WATTS), ("sensor.new", "sensor", f"{USERID}-ldata_B1_watts")]
    holders = {("sensor", f"{USERID}-ldata_B1_watts"): "sensor.new"}
    assert _plan(registered, holders) == []


def test_plan_gives_up_when_another_entry_has_a_new_id() -> None:
    registered = [("sensor.a", "sensor", WATTS), ("sensor.b", "sensor", f"{EMAIL}-ldata_B2_watts")]
    holders = {("sensor", f"{USERID}-ldata_B1_watts"): "sensor.other_entry"}
    assert _plan(registered, holders) is None


def test_plan_matches_per_entity_domain() -> None:
    # The same unique id in two domains is two registry entries.
    registered = [("sensor.a", "sensor", STATUS), ("binary_sensor.a", "binary_sensor", STATUS)]
    assert len(_plan(registered)) == 2


# ── Against the real entity registry ─────────────────────────────────


@pytest.fixture
def storage():
    with (
        patch.object(Store, "async_load", AsyncMock(return_value=None)),
        patch.object(Store, "async_delay_save", MagicMock()),
    ):
        yield


async def _hass():
    hass = MagicMock()
    hass.data = {}
    entries: dict[str, ConfigEntry] = {}
    hass.config_entries.async_get_entry.side_effect = entries.get

    def _update_entry(entry, *, data=None, options=None, **_kw):
        if data is not None:
            object.__setattr__(entry, "data", MappingProxyType(data))
        if options is not None:
            object.__setattr__(entry, "options", MappingProxyType(options))
        return True

    hass.config_entries.async_update_entry = MagicMock(side_effect=_update_entry)
    for module in (dr, er):
        if hasattr(module, "async_setup"):  # HA 2026.8+
            module.async_setup(hass)
        await module.async_load(hass)
    return hass, entries


def _entry(entries: dict, *, username=EMAIL, userid=USERID, options=None, key=CONF_USERNAME) -> ConfigEntry:
    data = {key: username, CONF_PASSWORD: "secret", "refresh_token": "t"}
    if userid is not None:
        data["userid"] = userid
    entry = ConfigEntry(
        data=data,
        discovery_keys=MappingProxyType({}),
        domain=DOMAIN,
        minor_version=1,
        options=options or {},
        source=SOURCE_USER,
        subentries_data=None,
        title="Leviton LDATA (Home)",
        unique_id=username,
        version=1,
    )
    entries[entry.entry_id] = entry
    return entry


def _register(hass, entry, domain: str, unique_id: str):
    return er.async_get(hass).async_get_or_create(domain, DOMAIN, unique_id, config_entry=entry)


def _unique_ids(hass, entry) -> set[str]:
    return {ent.unique_id for ent in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)}


async def _migrate(hass, entry):
    coordinator = SimpleNamespace(unique_id_prefix=None)
    await ldata._async_migrate_unique_id_prefix(hass, entry, coordinator)
    return coordinator.unique_id_prefix


@pytest.mark.asyncio
@pytest.mark.parametrize("key", [CONF_USERNAME, "email"])
async def test_entities_move_and_keep_their_entity_ids_and_settings(storage, key) -> None:
    hass, entries = await _hass()
    entry = _entry(entries, key=key)
    ent_reg = er.async_get(hass)
    watts = _register(hass, entry, "sensor", WATTS)
    status = _register(hass, entry, "binary_sensor", STATUS)
    light = _register(hass, entry, "light", DECORA)
    ent_reg.async_update_entity(watts.entity_id, name="Dryer power", disabled_by=er.RegistryEntryDisabler.USER)

    assert await _migrate(hass, entry) == USERID

    assert _unique_ids(hass, entry) == {
        f"{USERID}-ldata_B1_watts", f"{USERID}-ldata_B1", f"{USERID}-AA:BB:CC:DD:EE:FF_light",
    }
    moved = ent_reg.async_get(watts.entity_id)
    assert moved.unique_id == f"{USERID}-ldata_B1_watts"
    assert moved.name == "Dryer power"
    assert moved.disabled_by is er.RegistryEntryDisabler.USER
    assert ent_reg.async_get(status.entity_id).unique_id == f"{USERID}-ldata_B1"
    assert ent_reg.async_get(light.entity_id).unique_id == f"{USERID}-AA:BB:CC:DD:EE:FF_light"


@pytest.mark.asyncio
async def test_options_lists_move_too(storage) -> None:
    hass, entries = await _hass()
    options = {
        "confirmed_solar_import_uids": [f"{EMAIL}-ldata_B1_todaymw_import", f"{EMAIL}-ldata_B1__Import_kWh"],
        "suppressed_import_uids": [f"{EMAIL.lower()}-ldata_B2_todaymw_import", "unrelated"],
        "ha_inform_rate": 30.0,
    }
    entry = _entry(entries, options=options)

    await _migrate(hass, entry)

    assert entry.options["confirmed_solar_import_uids"] == [
        f"{USERID}-ldata_B1_todaymw_import", f"{USERID}-ldata_B1__Import_kWh",
    ]
    assert entry.options["suppressed_import_uids"] == [f"{USERID}-ldata_B2_todaymw_import", "unrelated"]
    assert entry.options["ha_inform_rate"] == 30.0


@pytest.mark.asyncio
async def test_a_second_run_changes_nothing(storage) -> None:
    hass, entries = await _hass()
    entry = _entry(entries, options={"suppressed_import_uids": [f"{EMAIL}-ldata_B2_todaymw_import"]})
    _register(hass, entry, "sensor", WATTS)
    await _migrate(hass, entry)
    hass.config_entries.async_update_entry.reset_mock()
    before = _unique_ids(hass, entry)

    assert await _migrate(hass, entry) == USERID

    assert _unique_ids(hass, entry) == before
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_casings_left_by_a_reauth_resolve_to_the_live_entity(storage) -> None:
    hass, entries = await _hass()
    entry = _entry(entries)
    orphan = _register(hass, entry, "sensor", f"{EMAIL.lower()}-ldata_B1_watts")  # before the reauth
    live = _register(hass, entry, "sensor", WATTS)

    await _migrate(hass, entry)

    ent_reg = er.async_get(hass)
    assert ent_reg.async_get(live.entity_id).unique_id == f"{USERID}-ldata_B1_watts"
    assert ent_reg.async_get(orphan.entity_id).unique_id == f"{EMAIL.lower()}-ldata_B1_watts"


@pytest.mark.asyncio
async def test_two_entries_of_one_account_for_different_residences_both_move(storage) -> None:
    hass, entries = await _hass()
    first = _entry(entries)
    second = _entry(entries)
    _register(hass, first, "sensor", WATTS)
    _register(hass, second, "sensor", f"{EMAIL}-ldata_B9_watts")

    assert await _migrate(hass, first) == USERID
    assert await _migrate(hass, second) == USERID

    assert _unique_ids(hass, first) == {f"{USERID}-ldata_B1_watts"}
    assert _unique_ids(hass, second) == {f"{USERID}-ldata_B9_watts"}


@pytest.mark.asyncio
async def test_an_entry_overlapping_another_of_the_same_account_keeps_the_email(storage) -> None:
    # The same account and residence set up twice with the email in two
    # letter cases: both entries have entities for the same breaker.
    hass, entries = await _hass()
    first = _entry(entries)
    second = _entry(entries, username=EMAIL.lower())
    _register(hass, first, "sensor", WATTS)
    _register(hass, second, "sensor", f"{EMAIL.lower()}-ldata_B1_watts")
    _register(hass, second, "sensor", f"{EMAIL.lower()}-ldata_B9_watts")

    assert await _migrate(hass, first) == USERID
    assert await _migrate(hass, second) == EMAIL.lower()

    assert _unique_ids(hass, first) == {f"{USERID}-ldata_B1_watts"}
    # Nothing of the second entry moved, so its entities still match.
    assert _unique_ids(hass, second) == {
        f"{EMAIL.lower()}-ldata_B1_watts", f"{EMAIL.lower()}-ldata_B9_watts",
    }


@pytest.mark.asyncio
async def test_two_accounts_sharing_a_residence_both_move(storage) -> None:
    hass, entries = await _hass()
    owner = _entry(entries)
    guest = _entry(entries, username="guest@example.com", userid="99aa")
    _register(hass, owner, "sensor", WATTS)
    _register(hass, guest, "sensor", "guest@example.com-ldata_B1_watts")

    assert await _migrate(hass, owner) == USERID
    assert await _migrate(hass, guest) == "99aa"

    assert _unique_ids(hass, owner) == {f"{USERID}-ldata_B1_watts"}
    assert _unique_ids(hass, guest) == {"99aa-ldata_B1_watts"}


@pytest.mark.asyncio
async def test_without_a_user_id_nothing_moves(storage) -> None:
    hass, entries = await _hass()
    entry = _entry(entries, userid=None)
    _register(hass, entry, "sensor", WATTS)

    assert await _migrate(hass, entry) == EMAIL
    assert _unique_ids(hass, entry) == {WATTS}


def _coordinator(prefix):
    """A stand-in coordinator for building entities, which subscribe to it."""
    return SimpleNamespace(unique_id_prefix=prefix, data={}, async_add_listener=lambda _cb: lambda: None)


@pytest.mark.asyncio
async def test_platform_unique_ids_match_the_moved_ones(storage) -> None:
    hass, entries = await _hass()
    entry = _entry(entries)
    breaker = {"id": "B1", "stable_id": "B1", "name": "Dryer", "panel_id": "P1", "poles": 1, "position": 1, "power": 1.0}
    old = sensor.LDATAOutputSensor(
        _coordinator(EMAIL), breaker, sensor.SENSOR_TYPES[sensor.POWER]
    )
    registered = _register(hass, entry, "sensor", old.unique_id)

    prefix = await _migrate(hass, entry)
    new = sensor.LDATAOutputSensor(
        _coordinator(prefix), breaker, sensor.SENSOR_TYPES[sensor.POWER]
    )

    assert er.async_get(hass).async_get_entity_id("sensor", DOMAIN, new.unique_id) == registered.entity_id
    assert EMAIL not in new.unique_id


@pytest.mark.asyncio
async def test_setup_migrates_before_the_platforms_set_up() -> None:
    order: list[str] = []
    hass = MagicMock()
    hass.data = {}
    hass.services.has_service.return_value = True
    hass.config_entries.async_forward_entry_setups = AsyncMock(side_effect=lambda *_a: order.append("platforms"))

    class _Coordinator(ldata.LDATAUpdateCoordinator):
        def __init__(self, *_args) -> None:
            self.data = {}
            self.async_config_entry_first_refresh = AsyncMock()
            self.async_add_listener = MagicMock(return_value=lambda: None)

    entries: dict = {}
    with (
        patch.object(ldata, "LDATAUpdateCoordinator", _Coordinator),
        patch.object(ldata, "_async_reconcile_subentries", AsyncMock()),
        patch.object(ldata, "_async_ensure_panel_devices"),
        patch.object(ldata, "_async_purge_orphaned_devices", AsyncMock()),
        patch.object(ldata, "_async_purge_stale_breaker_duplicates", AsyncMock()),
        patch.object(
            ldata, "_async_migrate_unique_id_prefix", AsyncMock(side_effect=lambda *_a: order.append("migrate"))
        ),
    ):
        assert await ldata.async_setup_entry(hass, _entry(entries))

    assert order == ["migrate", "platforms"]
