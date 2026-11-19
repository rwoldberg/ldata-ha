"""Status refreshes take the REST poll lock, skip toggles after setup, and end in time.

A refresh runs at setup and whenever something asks for one while the
WebSocket is down, as every Decora command does. It used to run alongside the
REST polls, toggle every panel's bandwidth each time, and outlast the
coordinator's 30 s timeout, after which it kept running in its thread.
"""

import threading
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import requests

from custom_components.ldata import ldata_service
from custom_components.ldata.const import STATUS_LOCK_WAIT, STATUS_TIME_BUDGET, STATUS_TIMEOUT
from custom_components.ldata.coordinator import LDATAUpdateCoordinator
from custom_components.ldata.ldata_service import (
    LDATAConnectionError,
    LDATAService,
    _DeadlineSession,
)

PANEL = "1000_ABCD"


@pytest.fixture
def sent(monkeypatch) -> list[dict]:
    """Record the keyword arguments of every request that reaches requests."""
    calls: list[dict] = []

    def _request(self, method, url, *args, **kwargs):
        calls.append(kwargs)
        return "response"

    monkeypatch.setattr(requests.Session, "request", _request)
    return calls


# ── The deadline ─────────────────────────────────────────────────────


def test_requests_outside_a_deadline_are_untouched(sent) -> None:
    session = _DeadlineSession()
    session.get("https://example.invalid/", timeout=15)
    assert sent[0]["timeout"] == 15


def test_deadline_cuts_each_timeout_to_the_time_left(sent) -> None:
    session = _DeadlineSession()
    with session.deadline(5):
        session.get("https://example.invalid/", timeout=15)
        session.get("https://example.invalid/")
    assert 0 < sent[0]["timeout"] <= 5
    assert 0 < sent[1]["timeout"] <= 5


def test_requests_fail_at_once_after_the_deadline(sent) -> None:
    session = _DeadlineSession()
    with session.deadline(0):
        with pytest.raises(requests.exceptions.Timeout):
            session.get("https://example.invalid/", timeout=15)
    assert sent == []


def test_deadline_is_per_thread(sent) -> None:
    session = _DeadlineSession()
    other: list[float | None] = []
    with session.deadline(0):
        thread = threading.Thread(target=lambda: other.append(session.time_left()))
        thread.start()
        thread.join()
        session_left = session.time_left()
    assert other == [None]
    assert session_left is not None and session_left <= 0


def test_pause_ends_at_the_deadline(monkeypatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(ldata_service.time, "sleep", slept.append)
    service = LDATAService("", "", None)
    service._pause(5)
    with service.session.deadline(1):
        service._pause(5)
    assert slept[0] == 5
    assert 0 <= slept[1] <= 1


# ── status() ─────────────────────────────────────────────────────────


class _Response:
    def __init__(self, body) -> None:
        self.status_code = 200
        self.reason = "OK"
        self.text = ""
        self._body = body

    def json(self):
        return self._body


def _service(monkeypatch) -> tuple[LDATAService, list[str]]:
    service = LDATAService("", "", None)
    service.refresh_auth = lambda: True
    service.auth_token = "token"
    service.account_id = "account"
    service.residence_id_list = ["res-1"]
    panel = {
        "id": PANEL, "name": "Main", "connected": True,
        "rmsVoltageA": 120, "rmsVoltageB": 120, "version": "2.0.0",
    }
    responses = {
        "residentialBreakerPanels": [],
        "iotWhems": [panel],
        "residentialBreakers": [],
        "iotCts": [],
    }
    service.session = MagicMock()
    service.session.get.side_effect = lambda url, **_kw: _Response(responses[url.rsplit("/", 1)[-1]])
    toggled: list[str] = []
    monkeypatch.setattr(service, "_bandwidth_toggle", lambda panel_id, *_a: toggled.append(panel_id))
    monkeypatch.setattr(ldata_service.time, "sleep", lambda _s: None)
    return service, toggled


def test_setup_refresh_toggles_connected_panels(monkeypatch) -> None:
    service, toggled = _service(monkeypatch)
    service.status()
    assert toggled == [PANEL]


def test_refresh_after_setup_does_not_toggle(monkeypatch) -> None:
    service, toggled = _service(monkeypatch)
    data = service.status(False)
    assert toggled == []
    assert [panel["id"] for panel in data["panels"]] == [PANEL]


def test_status_waits_for_a_running_rest_poll(monkeypatch) -> None:
    service, _toggled = _service(monkeypatch)
    service._rest_poll_lock.acquire()
    order: list[str] = []

    def _finish_poll() -> None:
        time.sleep(0.05)
        order.append("poll done")
        service._rest_poll_lock.release()

    thread = threading.Thread(target=_finish_poll)
    thread.start()
    service.get_iotWhemsPanels = lambda *_a: order.append("status fetch")
    service.status(False)
    thread.join()

    assert order == ["poll done", "status fetch"]


def test_status_gives_up_when_the_poll_lock_stays_taken(monkeypatch) -> None:
    service, _toggled = _service(monkeypatch)
    monkeypatch.setattr(ldata_service, "STATUS_LOCK_WAIT", 0.01)
    service._rest_poll_lock.acquire()
    try:
        with pytest.raises(LDATAConnectionError):
            service.status(False)
    finally:
        service._rest_poll_lock.release()
    service.session.get.assert_not_called()


def test_status_runs_within_its_budget(monkeypatch) -> None:
    # Out of time from the start: the token check's requests fail at once
    # instead of each waiting out its own timeout.
    monkeypatch.setattr(ldata_service, "STATUS_TIME_BUDGET", 0)
    monkeypatch.setattr(ldata_service.time, "sleep", lambda _s: None)
    service = LDATAService("", "", None)
    service.refresh_token = "token"
    service.userid = "user"

    started = time.monotonic()
    with pytest.raises(requests.exceptions.Timeout):
        service.status(False)
    assert time.monotonic() - started < 1
    # The lock and the deadline are released either way.
    assert service._rest_poll_lock.acquire(blocking=False)
    service._rest_poll_lock.release()
    assert service.session.time_left() is None


def test_timeout_covers_the_lock_wait_the_budget_and_the_login_spacing() -> None:
    # The login rate limit can hold a login back up to 10 s.
    assert STATUS_TIMEOUT >= STATUS_LOCK_WAIT + STATUS_TIME_BUDGET + 10


# ── Coordinator ──────────────────────────────────────────────────────


def _coordinator() -> LDATAUpdateCoordinator:
    def _no_task(_hass, coro, _name):
        coro.close()

    hass = MagicMock()
    hass.async_add_executor_job = AsyncMock(return_value={"panels": [], "breakers": {}, "cts": {}})
    entry = MagicMock()
    entry.options = {}
    entry.data = {}
    entry.async_create_background_task.side_effect = _no_task
    coordinator = LDATAUpdateCoordinator(hass, "user@example.com", "secret", entry)
    coordinator._persist_refreshed_tokens = MagicMock()
    # No stored LDATA energy ledger.
    coordinator._energy_store = MagicMock(async_load=AsyncMock(return_value=None))
    return coordinator


@pytest.mark.asyncio
async def test_first_refresh_toggles_and_later_ones_do_not() -> None:
    coordinator = _coordinator()

    await coordinator._async_update_data()
    coordinator.data = {"panels": []}
    coordinator._websocket_connected = False
    await coordinator._async_update_data()

    calls = coordinator._hass.async_add_executor_job.await_args_list
    assert [call.args for call in calls] == [
        (coordinator._service.status, True),
        (coordinator._service.status, False),
    ]


@pytest.mark.asyncio
async def test_refresh_waits_for_status_timeout(monkeypatch) -> None:
    coordinator = _coordinator()
    seen: list[float] = []
    real_timeout = ldata_service.asyncio.timeout

    def _timeout(delay):
        seen.append(delay)
        return real_timeout(delay)

    monkeypatch.setattr("custom_components.ldata.coordinator.asyncio.timeout", _timeout)
    await coordinator._async_update_data()
    assert seen == [STATUS_TIMEOUT]
