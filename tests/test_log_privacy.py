"""Logs never carry response bodies, the email, or user, account or residence ids.

Debug logs are routinely pasted into public GitHub issues, so every line the
service and coordinator write is checked against the secrets in play here.
"""

import json
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest
import requests

from custom_components.ldata import ldata_service
from custom_components.ldata.const import CONF_RESIDENCE_ID, LOGGER_NAME
from custom_components.ldata.coordinator import LDATAUpdateCoordinator
from custom_components.ldata.ldata_service import (
    LDATAAuthError,
    LDATAService,
    _endpoint,
    _response_summary,
    _safe_error,
)

EMAIL = "jane.doe@example.com"
USER_ID = "USERID-4242"
ACCOUNT_ID = "ACCOUNT-7171"
RESIDENCE_ID = "RESIDENCE-9876"
ADDRESS = "12 Elm Street"
SECRETS = (EMAIL, USER_ID, ACCOUNT_ID, RESIDENCE_ID, ADDRESS)


class _Response:
    def __init__(self, status: int, body, reason: str = "OK") -> None:
        self.status_code = status
        self.reason = reason
        self._body = body
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        if isinstance(self._body, str):
            return json.loads(self._body)
        return self._body


def _connection_error(path: str) -> requests.exceptions.ConnectionError:
    """The text requests gives a connection error: it names the URL path."""
    return requests.exceptions.ConnectionError(
        "HTTPSConnectionPool(host='my.leviton.com', port=443): Max retries exceeded "
        f"with url: {path} (Caused by NameResolutionError(\"Failed to resolve\"))"
    )


def _service(*responses) -> LDATAService:
    service = LDATAService(EMAIL, "secret", None)
    service.auth_token = "token"
    service.userid = USER_ID
    service.account_id = ACCOUNT_ID
    service.residence_id_list = [RESIDENCE_ID]
    service.session = MagicMock()
    service.session.get.side_effect = list(responses)
    service.session.post.side_effect = list(responses)
    return service


def _logged(caplog) -> str:
    return "\n".join(
        record.getMessage() for record in caplog.records if record.name == LOGGER_NAME
    )


def _assert_clean(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, secret


# ── Helpers ──────────────────────────────────────────────────────────


def test_safe_error_cuts_the_url_out_of_connection_errors() -> None:
    error = _connection_error(f"/api/Person/{USER_ID}/residentialPermissions")
    text = _safe_error(error)
    assert USER_ID not in text
    assert text.startswith("ConnectionError: ")
    assert "NameResolutionError" in text


def test_safe_error_cuts_full_urls() -> None:
    error = requests.exceptions.HTTPError(
        f"404 Client Error: Not Found for url: https://my.leviton.com/api/Residences/{RESIDENCE_ID}/iotWhems"
    )
    assert RESIDENCE_ID not in _safe_error(error)
    assert "404 Client Error" in _safe_error(error)


def test_endpoint_names_the_collection_without_ids() -> None:
    assert (
        _endpoint(f"https://my.leviton.com/api/ResidentialAccounts/{ACCOUNT_ID}/residences")
        == "ResidentialAccounts/<id>/residences"
    )
    assert _endpoint(f"https://my.leviton.com/api/ResidentialAccounts/{ACCOUNT_ID}") == "ResidentialAccounts/<id>"


def test_response_summary_keeps_status_and_error_code_only() -> None:
    body = {"error": {"statusCode": 401, "code": "LOGIN_FAILED", "message": f"no person {EMAIL}"}}
    summary = _response_summary(_Response(401, body, reason="Unauthorized"))
    assert summary == "HTTP 401 Unauthorized (LOGIN_FAILED)"


def test_response_summary_ignores_free_text_codes() -> None:
    body = {"error": {"code": f"user {EMAIL} not found"}}
    assert _response_summary(_Response(400, body, reason="Bad Request")) == "HTTP 400 Bad Request"
    assert _response_summary(_Response(502, "<html><h1>502 Bad Gateway</h1></html>", "Bad Gateway")) == "HTTP 502 Bad Gateway"


# ── Service ──────────────────────────────────────────────────────────


def test_residence_lookups_do_not_log_their_bodies(caplog) -> None:
    permissions = [{"residenceId": RESIDENCE_ID, "residentialAccountId": ACCOUNT_ID, "personId": USER_ID}]
    residences = [{"id": RESIDENCE_ID, "name": "Home", "address": ADDRESS}]
    service = _service(_Response(200, permissions), _Response(200, residences))

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service.get_residencePermissions()
        assert service._residence_api_get("https://my.leviton.com/api/x", "Residences")

    assert "HTTP 200" in _logged(caplog)
    _assert_clean(_logged(caplog))


def test_residence_lookup_error_does_not_log_the_url(caplog) -> None:
    service = _service(_connection_error(f"/api/Person/{USER_ID}/residentialPermissions"))

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service.get_residencePermissions() is False

    assert "ConnectionError" in _logged(caplog)
    _assert_clean(_logged(caplog))
    # No traceback either: it would print the same URL.
    assert all(record.exc_info is None for record in caplog.records)


def test_failed_login_does_not_log_the_body(caplog) -> None:
    body = {"error": {"code": "LOGIN_FAILED", "message": f"login failed for {EMAIL}"}}
    service = _service(_Response(401, body, reason="Unauthorized"))
    service._check_rate_limit = lambda: None

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME), pytest.raises(LDATAAuthError):
        service.auth_with_credentials()

    assert "LOGIN_FAILED" in _logged(caplog)
    _assert_clean(_logged(caplog))


def test_token_check_network_error_does_not_log_the_url(caplog, monkeypatch) -> None:
    monkeypatch.setattr(ldata_service.time, "sleep", lambda _s: None)
    service = _service(*[_connection_error(f"/api/Person/{USER_ID}/residentialPermissions")] * 3)
    service.refresh_token = "token"

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME), pytest.raises(requests.exceptions.ConnectionError):
        service.refresh_auth()

    _assert_clean(_logged(caplog))


def test_panel_and_breaker_listings_do_not_log_their_bodies(caplog, monkeypatch) -> None:
    monkeypatch.setattr(ldata_service.time, "sleep", lambda _s: None)
    panel = {
        "id": "1000_ABCD", "name": "Main", "connected": False, "residenceId": RESIDENCE_ID,
        "rmsVoltageA": 120, "rmsVoltageB": 120, "version": "2.0.0",
    }
    breakers = [{"id": "B1", "residenceId": RESIDENCE_ID, "ownerEmail": EMAIL}]
    service = _service(_Response(200, [panel]), _Response(200, breakers), _Response(200, []))

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        panels = service.get_iotWhemsPanels()

    assert panels and panels[0]["residentialBreakers"] == breakers
    assert "1 panel(s)" in _logged(caplog)
    _assert_clean(_logged(caplog))


def test_panel_listing_errors_do_not_name_the_residence(caplog) -> None:
    service = _service(
        _Response(403, {"error": {"message": RESIDENCE_ID}}, reason="Forbidden"),
        _connection_error(f"/api/Residences/{RESIDENCE_ID}/iotWhems"),
        _Response(500, f"<html>{RESIDENCE_ID} broke</html>", reason="Internal Server Error"),
    )

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        for _ in range(3):
            service.get_iotWhemsPanels()

    _assert_clean(_logged(caplog))


def test_decora_listing_errors_do_not_name_the_residence(caplog) -> None:
    service = _service(
        _Response(500, f"oops {RESIDENCE_ID}", reason="Internal Server Error"),
        _connection_error(f"/api/Residences/{RESIDENCE_ID}/iotBridges"),
        _connection_error(f"/api/Residences/{RESIDENCE_ID}/residentialRooms"),
    )

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        service.get_iot_switches()
        service.get_iot_bridges()
        service.get_residential_rooms()

    _assert_clean(_logged(caplog))


def test_failed_command_does_not_log_the_url(caplog) -> None:
    service = _service()
    service.session.request.side_effect = _connection_error(
        f"/api/Residences/{RESIDENCE_ID}/iotSwitches/5"
    )

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service.set_iot_switch(RESIDENCE_ID, 5, {"power": "ON"}) is False

    _assert_clean(_logged(caplog))
    assert all(record.exc_info is None for record in caplog.records)


def test_device_inventory_names_endpoints_without_ids(caplog) -> None:
    service = _service(_Response(500, "x", reason="Internal Server Error"))

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service._inventory_get(f"https://my.leviton.com/api/Residences/{RESIDENCE_ID}/iotWhems") is None

    assert "Residences/<id>/iotWhems" in _logged(caplog)
    _assert_clean(_logged(caplog))


def test_status_does_not_log_residence_ids(caplog) -> None:
    entry = MagicMock()
    entry.data = {CONF_RESIDENCE_ID: RESIDENCE_ID}
    entry.options = {}
    service = LDATAService(EMAIL, "secret", entry)
    service.refresh_auth = lambda: True
    service.auth_token = "token"
    service.account_id = ACCOUNT_ID
    service.get_ldata_panels = lambda *a: None
    service.get_iotWhemsPanels = lambda *a: None

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        service.status()

    assert service.residence_id_list == [RESIDENCE_ID]
    assert "configured residence: yes" in _logged(caplog)
    _assert_clean(_logged(caplog))


def test_panel_without_id_is_not_dumped(caplog) -> None:
    service = LDATAService("", "", None)

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        service.parse_panels([{"name": "Main", "residenceId": RESIDENCE_ID, "ModuleType": "WHEMS"}])

    assert "without an id" in _logged(caplog)
    _assert_clean(_logged(caplog))


# ── Coordinator ──────────────────────────────────────────────────────


def _coordinator(options: dict | None = None) -> LDATAUpdateCoordinator:
    def _no_task(_hass, coro, _name):
        coro.close()

    hass = MagicMock()
    hass.async_add_executor_job = AsyncMock(side_effect=lambda func, *args: func(*args))
    entry = MagicMock()
    entry.entry_id = "entry-1"
    entry.options = options or {}
    entry.async_create_background_task.side_effect = _no_task
    coordinator = LDATAUpdateCoordinator(hass, EMAIL, "secret", entry)
    # No stored LDATA energy ledger.
    coordinator._energy_store = MagicMock(async_load=AsyncMock(return_value=None))
    return coordinator


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        pytest.param(Exception("Could not get LDATA Account ID."), id="unexpected"),
        pytest.param(_connection_error(f"/api/Person/{USER_ID}/residentialPermissions"), id="network"),
        pytest.param(TimeoutError(), id="timeout"),
    ],
)
async def test_failed_refresh_logs_neither_email_nor_url(caplog, error) -> None:
    from homeassistant.helpers.update_coordinator import UpdateFailed

    coordinator = _coordinator()

    def _fail(*_args):
        raise error

    coordinator._service.status = _fail

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME), pytest.raises(UpdateFailed) as failed:
        await coordinator._async_update_data()

    _assert_clean(_logged(caplog))
    # Home Assistant logs this text when setup has to be retried.
    _assert_clean(str(failed.value))


def _parsed_data() -> dict:
    service = LDATAService("", "", None)
    data = service.parse_panels([{
        "id": "1000_A65E", "name": "Main", "model": "LWHEM", "ModuleType": "WHEMS",
        "connected": True, "rmsVoltage": 120.0, "rmsVoltage2": 121.0, "version": "2.2.0",
        "residentialBreakers": [{
            "id": "4C45565275C6_A65E", "model": "LB120", "currentRating": 20, "position": 1,
            "name": "Kitchen", "currentState": "ManualON", "poles": 1, "serialNumber": "SN123",
            "hwVersion": "1", "firmwareVersionMeter": "2", "canRemoteOn": True, "remoteState": "",
        }],
        "CTs": [{"id": 77, "usageType": "GRID", "channel": 1, "activePower": 5}],
    }])
    data["decora_devices"] = service.parse_decora_devices([{
        "id": 5550123, "model": "D26HD", "name": "Hall", "serial": "DSN-1", "mac": "AA:BB:CC:DD:EE:FF",
        "localIP": "192.168.1.23", "_residenceId": RESIDENCE_ID, "residentialRoomId": 31,
    }])
    data["rooms"] = {31: "Master Bedroom"}
    return data


def test_parsed_data_log_redacts_every_identifier(caplog) -> None:
    coordinator = _coordinator({"log_parsed_data": True})

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        coordinator._log_data_if_enabled(_parsed_data(), "API")

    text = _logged(caplog)
    assert "Parsed Data" in text
    for identifier in (
        "4C45565275C6", "1000_A65E", "SN123", "DSN-1", "192.168.1.23", "AA:BB", RESIDENCE_ID, "'77'", "5550123",
    ):
        assert identifier not in text, identifier
    # The readings and names that make the dump useful are still there.
    assert "Kitchen" in text and "Master Bedroom" in text and "totalPower" in text


def test_selected_fields_log_redacts_identifier_fields(caplog) -> None:
    coordinator = _coordinator(
        {"enable_specific_logging": True, "log_fields": "serialNumber, stable_id, power"}
    )

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        coordinator._log_data_if_enabled(_parsed_data(), "API")

    text = _logged(caplog)
    assert "Breaker_Kitchen_power" in text
    assert "SN123" not in text and "4C45565275C6" not in text
