"""The token is renewed when Leviton refuses it after setup.

Only status() used to fall back to the stored credentials, and after setup it
only runs on a refresh requested while the WebSocket is down. An expired or
revoked token left the WebSocket retrying it and the REST polls failing while
every entity stayed available with frozen values.
"""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.ldata import ldata_service
from custom_components.ldata.const import AUTH_RENEWAL_BACKOFF, AUTH_RENEWAL_BACKOFF_MAX
from custom_components.ldata.coordinator import LDATAUpdateCoordinator
from custom_components.ldata.ldata_service import (
    LDATAAuthError,
    LDATAConnectionError,
    LDATAService,
    TwoFactorRequired,
)

pytestmark = pytest.mark.asyncio


def _coordinator() -> LDATAUpdateCoordinator:
    def _no_task(_hass, coro, _name):
        coro.close()

    hass = MagicMock()
    hass.async_add_executor_job = AsyncMock(side_effect=lambda func, *args: func(*args))
    entry = MagicMock()
    entry.options = {}
    entry.data = {"refresh_token": "old-token", "userid": "user-1"}
    entry.async_create_background_task.side_effect = _no_task
    coordinator = LDATAUpdateCoordinator(hass, "user@example.com", "secret", entry)
    coordinator._service.auth_token = "old-token"
    coordinator._service.refresh_token = "old-token"
    coordinator._service.userid = "user-1"
    coordinator._service.status_data = {"panels": [], "breakers": {}, "cts": {}}
    return coordinator


def _login_succeeds(coordinator: LDATAUpdateCoordinator) -> MagicMock:
    service = coordinator._service

    def _login():
        service.auth_token = service.refresh_token = "new-token"
        service.userid = "user-1"
        return True

    login = MagicMock(side_effect=_login)
    service.auth_with_credentials = login
    return login


async def test_refused_token_is_renewed_and_persisted() -> None:
    coordinator = _coordinator()
    login = _login_succeeds(coordinator)

    await coordinator._async_auth_failed("REST poll")

    login.assert_called_once_with()
    update = coordinator._hass.config_entries.async_update_entry
    update.assert_called_once()
    assert update.call_args.kwargs["data"]["refresh_token"] == "new-token"
    assert coordinator.last_update_success is True
    coordinator.config_entry.async_start_reauth.assert_not_called()


async def test_reports_right_after_a_login_wait_for_the_backoff() -> None:
    coordinator = _coordinator()
    login = _login_succeeds(coordinator)

    await coordinator._async_auth_failed("REST poll")
    await coordinator._async_auth_failed("Panel status poll")
    await coordinator._async_auth_failed("WebSocket login")
    assert login.call_count == 1

    coordinator._auth_retry_at = 0.0  # the backoff has passed
    await coordinator._async_auth_failed("REST poll")
    assert login.call_count == 2


async def test_concurrent_reports_log_in_once() -> None:
    coordinator = _coordinator()
    release = asyncio.Event()
    calls = 0

    async def _slow_login(_func, *_args):
        nonlocal calls
        calls += 1
        await release.wait()
        return True

    coordinator._hass.async_add_executor_job = AsyncMock(side_effect=_slow_login)
    first = asyncio.create_task(coordinator._async_auth_failed("REST poll"))
    await asyncio.sleep(0)
    await coordinator._async_auth_failed("CT poll")
    release.set()
    await first

    assert calls == 1


@pytest.mark.parametrize("error", [LDATAAuthError("refused"), TwoFactorRequired()])
async def test_refused_credentials_start_reauth_and_stop_retrying(error) -> None:
    coordinator = _coordinator()
    coordinator._service.auth_with_credentials = MagicMock(side_effect=error)
    coordinator._websocket_connected = True  # even with the socket still open

    await coordinator._async_auth_failed("REST poll")

    coordinator.config_entry.async_start_reauth.assert_called_once_with(coordinator._hass)
    assert coordinator.last_update_success is False
    # An empty token stops the WebSocket and the polls from retrying it.
    assert coordinator._service.auth_token == ""
    service = coordinator._service
    service.status_data["panels"] = [{"id": "P1"}]
    service._fetch_panel_status_locked = MagicMock()
    assert service.fetch_panel_status() is None
    service._fetch_panel_status_locked.assert_not_called()
    service.status_data["panels"] = []

    # No further logins, and pushes from the open socket don't bring the
    # entities back before reauth reloads the entry.
    coordinator._auth_retry_at = 0.0
    await coordinator._async_auth_failed("REST poll")
    assert coordinator._service.auth_with_credentials.call_count == 1
    coordinator.async_set_updated_data = MagicMock()
    coordinator._apply_debounced_update()
    coordinator._handle_decora_websocket_update()
    coordinator.async_set_updated_data.assert_not_called()


async def test_failed_login_backs_off_and_a_later_success_restores_the_entities() -> None:
    coordinator = _coordinator()
    coordinator._service.auth_with_credentials = MagicMock(side_effect=LDATAConnectionError("HTTP 503"))

    await coordinator._async_auth_failed("REST poll")

    # The token is refused and the socket is down: no data is arriving.
    assert coordinator.last_update_success is False
    assert coordinator._auth_backoff == AUTH_RENEWAL_BACKOFF * 2
    coordinator.config_entry.async_start_reauth.assert_not_called()

    for _ in range(10):
        coordinator._auth_retry_at = 0.0
        await coordinator._async_auth_failed("REST poll")
    assert coordinator._auth_backoff == AUTH_RENEWAL_BACKOFF_MAX

    _login_succeeds(coordinator)
    coordinator._auth_retry_at = 0.0
    await coordinator._async_auth_failed("REST poll")

    assert coordinator.last_update_success is True
    assert coordinator._auth_backoff == AUTH_RENEWAL_BACKOFF


async def test_failed_login_with_the_socket_up_keeps_the_entities() -> None:
    coordinator = _coordinator()
    coordinator._websocket_connected = True
    coordinator._service.auth_with_credentials = MagicMock(side_effect=LDATAConnectionError("HTTP 503"))

    await coordinator._async_auth_failed("Panel status poll")

    assert coordinator.last_update_success is True


async def test_poll_loops_report_auth_errors(monkeypatch) -> None:
    coordinator = _coordinator()
    coordinator._async_auth_failed = AsyncMock()
    monkeypatch.setattr("custom_components.ldata.coordinator.asyncio.sleep", AsyncMock())

    def _fetch():
        coordinator._service._shutdown_requested = True
        raise LDATAAuthError("Auth token invalid (401) during panel status poll.")

    await coordinator._fallback_poll_loop(
        loop_name="Panel status poll", get_interval=lambda: 0, needs_poll=lambda: True,
        fetch=_fetch, merge=lambda _fetched: False,
    )

    coordinator._async_auth_failed.assert_awaited_once_with("Panel status poll")


async def test_websocket_rejection_schedules_a_renewal() -> None:
    coordinator = _coordinator()
    scheduled = []
    coordinator.config_entry.async_create_background_task.side_effect = (
        lambda _hass, coro, name: scheduled.append((coro, name))
    )
    coordinator._async_auth_failed = AsyncMock()

    coordinator._handle_websocket_auth_rejected()

    coro, name = scheduled[0]
    assert name == "ldata_auth_renewal"
    await coro
    coordinator._async_auth_failed.assert_awaited_once_with("WebSocket login")


# ── The WebSocket loop reports the rejection ─────────────────────────


class _Stop(BaseException):
    """Ends the loop at the next connect attempt (not caught by its handlers)."""


class _Socket:
    def __init__(self) -> None:
        self.closed = False
        self.close_code = None

    async def send_json(self, _data) -> None:
        return None

    async def receive(self):
        return SimpleNamespace(
            type=aiohttp.WSMsgType.TEXT, data=json.dumps({"error": "invalid token"}), extra=None
        )

    async def close(self) -> None:
        self.closed = True


class _Session:
    def __init__(self) -> None:
        self.connects = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc) -> None:
        return None

    async def ws_connect(self, *_args, **_kwargs):
        self.connects += 1
        if self.connects > 2:
            raise _Stop
        return _Socket()


async def test_websocket_loop_reports_each_rejected_login(monkeypatch) -> None:
    session = _Session()
    monkeypatch.setattr(ldata_service.aiohttp, "ClientSession", lambda **_kw: session)
    monkeypatch.setattr(ldata_service.asyncio, "sleep", AsyncMock())
    service = LDATAService("", "", None)
    service.auth_token = "expired"
    service.userid = "user-1"
    rejected = MagicMock()

    with pytest.raises(_Stop):
        await service.async_run_websocket(lambda: None, auth_rejected_callback=rejected)

    assert rejected.call_count == 2
