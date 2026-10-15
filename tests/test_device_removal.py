"""Tests for manual removal of stale devices from the HA UI."""

import copy
import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

from custom_components import ldata
from custom_components.ldata.const import DOMAIN, ENABLE_DECORA, LOGGER_NAME
from custom_components.ldata.ldata_service import LDATAService

ENTRY_ID = "entry"
PANEL_ID = "LDATA-0000-0000-0001"
SUFFIXED_PANEL_ID = "1000_0001_A65E"
BREAKER_MODEL = "BREAKER-MODEL"
DECORA_MODEL = "D215S"
BRIDGE_MODEL = "MLWSB"
INCOMPLETE = LDATAService.INCOMPLETE_FETCHES
PANELS = LDATAService.FETCH_PANELS
DECORA = LDATAService.FETCH_DECORA


def _coordinator_data(incomplete=()) -> dict:
    return {
        "panels": [
            {"id": PANEL_ID, "name": "Panel"},
            {"id": SUFFIXED_PANEL_ID, "name": "Panel 2"},
        ],
        "breakers": {
            "B1": {"id": "B1", "stable_id": "B1", "panel_id": PANEL_ID},
            "B2_A65E": {
                "id": "B2_A65E",
                "stable_id": "B2",
                "panel_id": SUFFIXED_PANEL_ID,
            },
            "B3": {"id": "B3", "panel_id": PANEL_ID},
        },
        "cts": {
            7: {"id": 7, "panel_id": PANEL_ID, "name": "CT 7"},
        },
        "decora_devices": {
            456: {"id": 456, "mac": "AABBCCDDEEFF", "name": "Switch"},
            789: {"id": 789, "mac": None, "name": "Switch without mac"},
            "bridge_9": {"id": "bridge_9", "mac": None, "name": "Bridge"},
        },
        INCOMPLETE: sorted(incomplete),
    }


class _InventoryService:
    """Stands in for LDATAService.fetch_device_inventory.

    Defaults to every re-read failing, i.e. the outage that left the
    status() fetch incomplete is still ongoing.
    """

    def __init__(self, inventory=None, failed=None, error=None):
        self.inventory = inventory or {}
        self.failed = failed
        self.error = error
        self.calls = []

    def fetch_device_inventory(self, sources):
        self.calls.append(set(sources))
        if self.error is not None:
            raise self.error
        failed = set(sources) if self.failed is None else set(self.failed)
        return self.inventory, failed


async def _run_inline(func, *args):
    return func(*args)


def _hass(data, service=None):
    coordinator = SimpleNamespace(data=data, service=service or _InventoryService())
    return SimpleNamespace(
        data={DOMAIN: {ENTRY_ID: coordinator}}, async_add_executor_job=_run_inline
    )


def _device(*identifiers, model=BREAKER_MODEL):
    return SimpleNamespace(
        id="device",
        name="Device",
        name_by_user=None,
        identifiers=set(identifiers),
        model=model,
    )


async def _removable(hass, device) -> bool:
    entry = SimpleNamespace(entry_id=ENTRY_ID)
    return await ldata.async_remove_config_entry_device(hass, entry, device)


# --- live vs stale with complete data ------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identifier", "model"),
    [
        ((DOMAIN, PANEL_ID), "PANEL-MODEL"),
        ((DOMAIN, SUFFIXED_PANEL_ID), None),
        ((DOMAIN, "B1"), BREAKER_MODEL),
        ((DOMAIN, "B2"), BREAKER_MODEL),
        ((DOMAIN, "B3"), BREAKER_MODEL),
        ((DOMAIN, PANEL_ID, "7"), None),
        ((DOMAIN, PANEL_ID, 7), None),
        ((DOMAIN, "AABBCCDDEEFF"), DECORA_MODEL),
        ((DOMAIN, "789"), DECORA_MODEL),
        ((DOMAIN, "bridge_9"), BRIDGE_MODEL),
    ],
)
async def test_live_device_is_not_removable(identifier, model) -> None:
    device = _device(identifier, model=model)

    assert await _removable(_hass(_coordinator_data()), device) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identifier", "model"),
    [
        # Legacy breaker device keyed by the old serialNumber identifier.
        ((DOMAIN, "LEGACY-SERIAL-0001"), BREAKER_MODEL),
        # Raw (suffixed) breaker id superseded by its stable_id.
        ((DOMAIN, "B2_A65E"), BREAKER_MODEL),
        # CT on a panel that is no longer reported.
        ((DOMAIN, "GONE-PANEL", "7"), None),
        # Removed Decora device and bridge.
        ((DOMAIN, "112233445566"), DECORA_MODEL),
        ((DOMAIN, "bridge_10"), BRIDGE_MODEL),
        # Unknown model, both fetches complete.
        ((DOMAIN, "UNKNOWN-0001"), None),
    ],
)
async def test_stale_device_is_removable(identifier, model) -> None:
    device = _device(identifier, model=model)

    assert await _removable(_hass(_coordinator_data()), device) is True


@pytest.mark.asyncio
async def test_device_with_any_live_identifier_is_not_removable() -> None:
    device = _device((DOMAIN, "LEGACY-SERIAL-0001"), (DOMAIN, "B1"))

    assert await _removable(_hass(_coordinator_data()), device) is False


@pytest.mark.asyncio
async def test_foreign_domain_identifier_does_not_count_as_live() -> None:
    device = _device(("other_domain", "B1"), (DOMAIN, "LEGACY-SERIAL-0001"))

    assert await _removable(_hass(_coordinator_data()), device) is True


# --- no data -------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [None, {}])
async def test_removal_refused_without_coordinator_data(data) -> None:
    device = _device((DOMAIN, "LEGACY-SERIAL-0001"))

    assert await _removable(_hass(data), device) is False


@pytest.mark.asyncio
async def test_removal_refused_when_entry_not_loaded() -> None:
    hass = SimpleNamespace(data={})
    device = _device((DOMAIN, "LEGACY-SERIAL-0001"))

    assert await _removable(hass, device) is False


@pytest.mark.asyncio
async def test_removal_refused_when_fetch_status_is_missing() -> None:
    data = _coordinator_data()
    del data[INCOMPLETE]
    service = _InventoryService()
    device = _device((DOMAIN, "LEGACY-SERIAL-0001"), model=None)

    assert await _removable(_hass(data, service), device) is False
    assert service.calls == [{PANELS, DECORA}]


@pytest.mark.asyncio
async def test_missing_fetch_status_is_verified_by_re_read() -> None:
    data = _coordinator_data()
    del data[INCOMPLETE]
    service = _InventoryService(failed=())
    device = _device((DOMAIN, "LEGACY-SERIAL-0001"), model=None)

    assert await _removable(_hass(data, service), device) is True
    assert service.calls == [{PANELS, DECORA}]


@pytest.mark.asyncio
async def test_live_device_refused_without_re_read() -> None:
    service = _InventoryService(failed=())
    data = _coordinator_data(incomplete=[PANELS, DECORA])

    assert await _removable(_hass(data, service), _device((DOMAIN, "B1"))) is False
    assert service.calls == []


@pytest.mark.asyncio
async def test_complete_fetch_does_not_re_read() -> None:
    service = _InventoryService()
    device = _device((DOMAIN, "LEGACY-SERIAL-0001"), model=None)

    assert await _removable(_hass(_coordinator_data(), service), device) is True
    assert service.calls == []


# --- refusal logging -----------------------------------------------------


@pytest.mark.asyncio
async def test_refusal_logs_incomplete_source(caplog) -> None:
    data = _coordinator_data(incomplete=[DECORA])
    device = _device((DOMAIN, "112233445566"), model=DECORA_MODEL)

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        assert await _removable(_hass(data), device) is False

    refusals = [
        r for r in caplog.records
        if r.levelno == logging.INFO and r.getMessage().startswith("Refusing")
    ]
    assert len(refusals) == 1
    assert "Device" in refusals[0].getMessage()
    assert "the decora fetch is incomplete" in refusals[0].getMessage()


@pytest.mark.asyncio
async def test_refusal_logs_re_read_exception(caplog) -> None:
    data = _coordinator_data(incomplete=[PANELS])
    service = _InventoryService(error=RuntimeError("boom"))
    device = _device((DOMAIN, "LEGACY-SERIAL-0001"))

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        assert await _removable(_hass(data, service), device) is False

    assert any(
        r.levelno == logging.INFO
        and "the panels fetch is incomplete" in r.getMessage()
        and "boom" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("loaded", [False, True])
async def test_refusal_logs_missing_data(caplog, loaded) -> None:
    hass = _hass(None) if loaded else SimpleNamespace(data={})

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        assert await _removable(hass, _device((DOMAIN, "X"))) is False

    assert any(
        r.levelno == logging.INFO and "not loaded or has no data yet" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.asyncio
async def test_refusal_logs_live_device(caplog) -> None:
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        assert await _removable(_hass(_coordinator_data()), _device((DOMAIN, "B1"))) is False

    assert any(
        r.levelno == logging.INFO and "still reports it" in r.getMessage()
        for r in caplog.records
    )


# --- incomplete fetches --------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identifier", "model"),
    [
        ((DOMAIN, "112233445566"), DECORA_MODEL),
        ((DOMAIN, "bridge_10"), BRIDGE_MODEL),
        ((DOMAIN, "UNKNOWN-0001"), None),
    ],
)
async def test_possible_decora_device_refused_after_failed_decora_fetch(
    identifier, model
) -> None:
    data = _coordinator_data(incomplete=[DECORA])
    data["decora_devices"] = {}
    device = _device(identifier, model=model)

    assert await _removable(_hass(data), device) is False


@pytest.mark.asyncio
async def test_breaker_device_still_removable_after_failed_decora_fetch() -> None:
    data = _coordinator_data(incomplete=[DECORA])
    data["decora_devices"] = {}
    device = _device((DOMAIN, "LEGACY-SERIAL-0001"), model=BREAKER_MODEL)

    assert await _removable(_hass(data), device) is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identifier", "model"),
    [
        ((DOMAIN, "LEGACY-SERIAL-0001"), BREAKER_MODEL),
        ((DOMAIN, "GONE-PANEL"), "PANEL-MODEL"),
        ((DOMAIN, "GONE-PANEL", "7"), None),
        ((DOMAIN, "UNKNOWN-0001"), None),
    ],
)
async def test_panel_device_refused_after_failed_panel_fetch(identifier, model) -> None:
    data = _coordinator_data(incomplete=[PANELS])
    device = _device(identifier, model=model)

    assert await _removable(_hass(data), device) is False


@pytest.mark.asyncio
async def test_decora_device_still_removable_after_failed_panel_fetch() -> None:
    data = _coordinator_data(incomplete=[PANELS])
    device = _device((DOMAIN, "112233445566"), model=DECORA_MODEL)

    assert await _removable(_hass(data), device) is True


# --- HTTP helpers -------------------------------------------------------


def _response(status_code=200, payload=None):
    payload = [] if payload is None else payload
    return SimpleNamespace(status_code=status_code, json=lambda: payload, text="error")


def _invalid_json_response():
    def _raise():
        raise json.JSONDecodeError("Expecting value", "<html>", 0)

    return SimpleNamespace(status_code=200, json=_raise, text="<html>")


def _status_service(responses: dict, *, enable_decora=True) -> LDATAService:
    """Service whose status() runs against canned responses keyed by URL suffix."""
    entry = SimpleNamespace(options={ENABLE_DECORA: enable_decora}, data={})
    service = LDATAService("", "", entry)
    service.auth_token = "token"
    service.account_id = "account"
    service.residence_id_list = ["res-1"]

    def _get(url, **_kwargs):
        for suffix, response in responses.items():
            if url.endswith(suffix):
                if isinstance(response, Exception):
                    raise response
                return response
        return _response()

    service.session = MagicMock()
    service.session.get.side_effect = _get
    return service


def _status(service: LDATAService) -> dict:
    with patch.object(LDATAService, "refresh_auth", return_value=True):
        return service.status()


SWITCH = {"id": 456, "name": "Switch", "model": DECORA_MODEL, "mac": "AABBCCDDEEFF"}


# --- recovery: re-reading an incomplete fetch ---------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("incomplete", "identifier", "model", "expected_sources"),
    [
        ([DECORA], (DOMAIN, "112233445566"), DECORA_MODEL, {DECORA}),
        ([DECORA], (DOMAIN, "bridge_10"), BRIDGE_MODEL, {DECORA}),
        ([PANELS], (DOMAIN, "LEGACY-SERIAL-0001"), BREAKER_MODEL, {PANELS}),
        ([PANELS], (DOMAIN, "GONE-PANEL", "7"), None, {PANELS}),
        ([PANELS, DECORA], (DOMAIN, "UNKNOWN-0001"), None, {PANELS, DECORA}),
        ([PANELS], (DOMAIN, "UNKNOWN-0001"), None, {PANELS}),
    ],
)
async def test_stale_device_removable_after_successful_re_read(
    incomplete, identifier, model, expected_sources
) -> None:
    data = _coordinator_data(incomplete=incomplete)
    service = _InventoryService(failed=())
    device = _device(identifier, model=model)

    assert await _removable(_hass(data, service), device) is True
    assert service.calls == [expected_sources]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("incomplete", "inventory", "identifier", "model"),
    [
        # Decora switch the failed startup fetch left out of the data.
        (
            [DECORA],
            {"decora_devices": {1: {"id": 1, "mac": "112233445566"}}},
            (DOMAIN, "112233445566"),
            DECORA_MODEL,
        ),
        # Breaker on a panel the failed startup fetch left out.
        (
            [PANELS],
            {"breakers": {"B9_A65E": {"id": "B9_A65E", "stable_id": "B9"}}},
            (DOMAIN, "B9"),
            BREAKER_MODEL,
        ),
        # Panel itself.
        ([PANELS], {"panels": [{"id": "GONE-PANEL"}]}, (DOMAIN, "GONE-PANEL"), None),
        # CT on that panel.
        (
            [PANELS],
            {"cts": {"x": {"id": "7", "panel_id": "GONE-PANEL"}}},
            (DOMAIN, "GONE-PANEL", 7),
            None,
        ),
    ],
)
async def test_device_found_by_re_read_is_not_removable(
    incomplete, inventory, identifier, model
) -> None:
    data = _coordinator_data(incomplete=incomplete)
    service = _InventoryService(inventory=inventory, failed=())
    device = _device(identifier, model=model)

    assert await _removable(_hass(data, service), device) is False


@pytest.mark.asyncio
async def test_partial_re_read_failure_refuses_removal() -> None:
    data = _coordinator_data(incomplete=[PANELS, DECORA])
    service = _InventoryService(failed=[DECORA])
    device = _device((DOMAIN, "UNKNOWN-0001"), model=None)

    assert await _removable(_hass(data, service), device) is False


@pytest.mark.asyncio
async def test_re_read_leaves_coordinator_data_untouched() -> None:
    data = _coordinator_data(incomplete=[DECORA])
    snapshot = copy.deepcopy(data)
    service = _InventoryService(failed=())

    await _removable(_hass(data, service), _device((DOMAIN, "112233445566"), model=DECORA_MODEL))

    assert data == snapshot


# --- service device inventory --------------------------------------------


LDATA_PANEL = {
    "id": "LDATA-1",
    "residentialBreakers": [
        {"id": "LB1", "model": "BR120"},
        {"id": "LB-EMPTY", "model": "NONE-1"},
    ],
}
WHEMS_PANEL = {"id": "1000_0001_A65E"}  # no voltage/version: status() skips it


def _inventory_responses(overrides=None):
    responses = {
        "/residentialBreakerPanels": _response(payload=[LDATA_PANEL]),
        "/Residences/res-1/iotWhems": _response(
            payload=[WHEMS_PANEL, {"id": "LDATA-1"}]
        ),
        "/IotWhems/1000_0001_A65E/residentialBreakers": _response(
            payload=[{"id": "WB1_A65E", "model": "BR240"}]
        ),
        "/IotWhems/1000_0001_A65E/iotCts": _response(
            payload=[
                {"id": 3, "usageType": "SOLAR"},
                {"id": 4, "usageType": "NOT_USED"},
            ]
        ),
        "/iotSwitches": _response(payload=[SWITCH]),
        "/iotBridges": _response(payload=[{"id": 9, "mac": "BRIDGEMAC"}]),
    }
    responses.update(overrides or {})
    return responses


def test_inventory_reports_every_listed_device() -> None:
    service = _status_service(_inventory_responses())

    inventory, failed = service.fetch_device_inventory({PANELS, DECORA})

    assert failed == set()
    assert ldata._live_device_identifiers(inventory) == {
        (DOMAIN, "LDATA-1"),
        (DOMAIN, "LB1"),
        (DOMAIN, "1000_0001_A65E"),
        (DOMAIN, "WB1"),
        (DOMAIN, "1000_0001_A65E", "3"),
        (DOMAIN, "AABBCCDDEEFF"),
        (DOMAIN, "BRIDGEMAC"),
    }
    # Read-only: GETs only (no bandwidth toggle), no status/flag changes.
    service.session.request.assert_not_called()
    service.session.put.assert_not_called()
    assert service.status_data is None
    assert service._incomplete_fetches == set()


def test_inventory_fetches_only_requested_sources() -> None:
    service = _status_service(_inventory_responses())

    inventory, failed = service.fetch_device_inventory({DECORA})

    assert failed == set()
    assert inventory["panels"] == []
    urls = [c.args[0] for c in service.session.get.call_args_list]
    assert all("/iotSwitches" in u or "/iotBridges" in u for u in urls)


@pytest.mark.parametrize(
    ("override", "failed_source"),
    [
        ({"/residentialBreakerPanels": _response(500)}, PANELS),
        ({"/Residences/res-1/iotWhems": requests.ConnectionError("boom")}, PANELS),
        ({"/IotWhems/1000_0001_A65E/residentialBreakers": _response(503)}, PANELS),
        ({"/IotWhems/1000_0001_A65E/iotCts": _response(401)}, PANELS),
        ({"/residentialBreakerPanels": _invalid_json_response()}, PANELS),
        ({"/residentialBreakerPanels": _response(payload={"error": "x"})}, PANELS),
        ({"/iotSwitches": _response(500)}, DECORA),
        ({"/iotBridges": requests.Timeout("boom")}, DECORA),
        ({"/iotSwitches": _invalid_json_response()}, DECORA),
    ],
)
def test_inventory_reports_failed_source(override, failed_source) -> None:
    service = _status_service(_inventory_responses(override))

    _inventory, failed = service.fetch_device_inventory({PANELS, DECORA})

    assert failed == {failed_source}
    assert service._incomplete_fetches == set()


def test_inventory_fails_without_auth_or_residences() -> None:
    service = _status_service(_inventory_responses())
    service.auth_token = None

    assert service.fetch_device_inventory({PANELS})[1] == {PANELS}
    service.session.get.assert_not_called()


# --- service fetch status ------------------------------------------------



def test_status_reports_complete_fetch() -> None:
    service = _status_service({"/iotSwitches": _response(payload=[SWITCH])})

    data = _status(service)

    assert data[INCOMPLETE] == []
    assert 456 in data["decora_devices"]


def test_status_reports_complete_fetch_with_decora_disabled() -> None:
    service = _status_service({}, enable_decora=False)

    data = _status(service)

    assert data[INCOMPLETE] == []
    assert data["decora_devices"] == {}


@pytest.mark.parametrize(
    "responses",
    [
        {"/iotSwitches": _response(500)},
        {"/iotSwitches": RuntimeError("boom")},
        {"/iotSwitches": _response(payload=[SWITCH]), "/iotBridges": _response(500)},
        {"/iotSwitches": _response(payload=[SWITCH]), "/iotBridges": RuntimeError("boom")},
    ],
)
def test_status_reports_failed_decora_fetch(responses) -> None:
    service = _status_service(responses)

    data = _status(service)

    assert data[INCOMPLETE] == [DECORA]


@pytest.mark.parametrize(
    "responses",
    [
        {"/residentialBreakerPanels": _response(500)},
        {"/residentialBreakerPanels": _response(403)},
        {"/iotWhems": RuntimeError("boom")},
    ],
)
def test_status_reports_failed_panel_fetch(responses) -> None:
    service = _status_service(responses, enable_decora=False)

    data = _status(service)

    assert data[INCOMPLETE] == [PANELS]


def test_status_reports_skipped_whems_panel() -> None:
    # A WHEMS panel missing its voltage/version fields is skipped this poll.
    service = _status_service(
        {"/iotWhems": _response(payload=[{"id": "WHEMS-1", "name": "Panel"}])},
        enable_decora=False,
    )

    data = _status(service)

    assert data[INCOMPLETE] == [PANELS]


def test_failed_whems_sub_resource_marks_panels_incomplete() -> None:
    service = _status_service({"/residentialBreakers": _response(500)})

    assert service.get_Whems_breakers("WHEMS-1") is None
    assert service._incomplete_fetches == {PANELS}


def test_status_resets_fetch_status_on_next_call() -> None:
    responses = {"/iotSwitches": _response(500)}
    service = _status_service(responses)
    assert _status(service)[INCOMPLETE] == [DECORA]

    responses["/iotSwitches"] = _response(payload=[SWITCH])

    assert _status(service)[INCOMPLETE] == []


@pytest.mark.parametrize("suffix", ["/residentialBreakerPanels", "/iotWhems"])
def test_status_reports_invalid_panel_json(suffix) -> None:
    service = _status_service({suffix: _invalid_json_response()}, enable_decora=False)

    data = _status(service)

    assert data[INCOMPLETE] == [PANELS]


# --- legacy residence discovery ------------------------------------------
#
# Entries without CONF_RESIDENCE_ID discover their residences in status().
# If a lookup fails, residence_id_list can be short: the dropped residence's
# devices are absent from the data although no panel/Decora fetch failed.

RESIDENCES = "/ResidentialAccounts/account/residences"
ACCOUNT = "/ResidentialAccounts/account"
PERMISSIONS = "/Person/user/residentialPermissions"
RES2_PANEL = {"id": "LDATA-2", "residentialBreakers": [{"id": "R2B1", "model": "BR120"}]}


def _legacy_responses(overrides=None):
    """Two residences, res-1 (primary) and res-2. Neither lists panels."""
    responses = {
        RESIDENCES: _response(payload=[{"id": "res-1"}, {"id": "res-2"}]),
        ACCOUNT: _response(payload={"primaryResidenceId": "res-1"}),
        PERMISSIONS: _response(
            payload=[{"residenceId": "res-1"}, {"residenceId": "res-2"}]
        ),
    }
    responses.update(overrides or {})
    return responses


def _legacy_service(responses) -> LDATAService:
    service = _status_service(responses, enable_decora=False)
    service.residence_id_list = []
    service.userid = "user"
    return service


@pytest.mark.parametrize(
    "override",
    [
        # get_residences() fails, status() falls back to the primary
        # residence and the permissions lookup fails too.
        {RESIDENCES: _response(500), PERMISSIONS: _response(500)},
        {RESIDENCES: requests.ConnectionError("boom"), PERMISSIONS: _response(503)},
        # get_residences() fails, the fallback and permissions return only
        # the primary residence.
        {
            RESIDENCES: _response(500),
            PERMISSIONS: _response(payload=[{"residenceId": "res-1"}]),
        },
        # Only the permissions lookup fails.
        {
            RESIDENCES: _response(payload=[{"id": "res-1"}]),
            PERMISSIONS: _response(500),
        },
    ],
)
def test_partial_residence_discovery_marks_both_sources_incomplete(override) -> None:
    service = _legacy_service(_legacy_responses(override))

    data = _status(service)

    assert "res-2" not in service.residence_id_list
    assert data[INCOMPLETE] == [DECORA, PANELS]


def test_partial_residence_discovery_stays_incomplete_on_later_polls() -> None:
    service = _legacy_service(
        _legacy_responses({RESIDENCES: _response(500), PERMISSIONS: _response(500)})
    )
    _status(service)

    # residence_id_list is cached, so the next poll reuses the short list.
    assert _status(service)[INCOMPLETE] == [DECORA, PANELS]


@pytest.mark.parametrize(
    "override",
    [
        {},
        # An empty account listing is a valid answer, not a failure: the
        # fallback to the primary residence is the normal path then.
        {RESIDENCES: _response(payload=[])},
    ],
)
def test_complete_residence_discovery_reports_complete_fetch(override) -> None:
    service = _legacy_service(_legacy_responses(override))

    data = _status(service)

    assert set(service.residence_id_list) == {"res-1", "res-2"}
    assert data[INCOMPLETE] == []
    urls = [c.args[0] for c in service.session.get.call_args_list]
    assert any(u.endswith("/Residences/res-2/residentialBreakerPanels") for u in urls)


def test_configured_residence_reports_complete_fetch() -> None:
    service = _legacy_service(
        _legacy_responses({RESIDENCES: _response(500), PERMISSIONS: _response(500)})
    )
    service.entry.data = {"residence_id": "res-1"}

    data = _status(service)

    assert service.residence_id_list == ["res-1"]
    assert data[INCOMPLETE] == []
    urls = [c.args[0] for c in service.session.get.call_args_list]
    assert not any(u.endswith((RESIDENCES, PERMISSIONS)) for u in urls)


def _degraded_hass(responses):
    """Run status() with a failed residence lookup, then serve the hook."""
    service = _legacy_service(responses)
    data = _status(service)
    assert service.residence_id_list == ["res-1"]
    return _hass(data, service), service


@pytest.mark.asyncio
async def test_device_of_dropped_residence_is_not_removable() -> None:
    responses = _legacy_responses({RESIDENCES: _response(500), PERMISSIONS: _response(500)})
    hass, service = _degraded_hass(responses)
    responses["/Residences/res-2/residentialBreakerPanels"] = _response(payload=[RES2_PANEL])
    # The lookups recover by the time the user removes the device; the
    # re-read must use the re-discovered residences, not the short list.
    responses[RESIDENCES] = _response(payload=[{"id": "res-1"}, {"id": "res-2"}])
    responses[PERMISSIONS] = _response(payload=[{"residenceId": "res-2"}])

    assert await _removable(hass, _device((DOMAIN, "R2B1"))) is False
    assert await _removable(hass, _device((DOMAIN, "LDATA-2"), model=None)) is False
    # Re-discovery is read-only.
    assert service.residence_id_list == ["res-1"]


@pytest.mark.asyncio
async def test_stale_device_removable_after_residence_re_discovery() -> None:
    responses = _legacy_responses({RESIDENCES: _response(500), PERMISSIONS: _response(500)})
    hass, _service = _degraded_hass(responses)
    responses[RESIDENCES] = _response(payload=[{"id": "res-1"}, {"id": "res-2"}])
    responses[PERMISSIONS] = _response(payload=[])
    responses["/iotSwitches"] = _response(payload=[])

    assert await _removable(hass, _device((DOMAIN, "LEGACY-SERIAL-0001"))) is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "still_failing",
    [
        {RESIDENCES: _response(500)},
        {PERMISSIONS: requests.Timeout("boom")},
        {RESIDENCES: _response(payload=[]), ACCOUNT: _response(500)},
        {RESIDENCES: _response(payload={"error": "x"})},
    ],
)
async def test_removal_refused_when_residence_re_discovery_fails(still_failing) -> None:
    responses = _legacy_responses({RESIDENCES: _response(500), PERMISSIONS: _response(500)})
    hass, service = _degraded_hass(responses)
    responses.update(_legacy_responses())
    responses.update(still_failing)
    calls_before = service.session.get.call_count

    assert await _removable(hass, _device((DOMAIN, "LEGACY-SERIAL-0001"))) is False
    # No listing was re-read on the short residence list.
    urls = [c.args[0] for c in service.session.get.call_args_list[calls_before:]]
    assert not any("/Residences/" in u for u in urls)


def test_inventory_does_not_re_discover_after_complete_discovery() -> None:
    service = _status_service(_inventory_responses())

    _inventory, failed = service.fetch_device_inventory({PANELS})

    assert failed == set()
    urls = [c.args[0] for c in service.session.get.call_args_list]
    assert not any(u.endswith((RESIDENCES, PERMISSIONS)) for u in urls)
