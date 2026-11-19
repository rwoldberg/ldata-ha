"""status() and the WebSocket at startup: no partial status data, no empty subscriptions.

status() used to publish status_data from parse_panels(), before it had added
the Decora devices. The WebSocket replaces status_data with an updated copy on
every notification, so one that arrived during the Decora fetch dropped them
until the next reload. And the WebSocket, which waits for status_data before it
subscribes, gave up after 10 s: a slow first status() left that connection
without its panels, breakers and CTs, and its bandwidth keepalive without a
panel, until its proactive reconnect 55 minutes later.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.ldata import ldata_service
from custom_components.ldata.const import CONF_RESIDENCE_ID, ENABLE_DECORA
from custom_components.ldata.ldata_service import LDATAService

from test_websocket_keepalive import KEEPALIVE, _FakeClock, _FakeSession, _FakeWebSocket, _Stop

RAW_PANEL = {
    "id": "1000_ABCD", "name": "Main", "model": "LWHEM", "ModuleType": "WHEMS", "connected": True,
    "rmsVoltage": 120.0, "rmsVoltage2": 120.0, "version": "2.0.0",
    "residentialBreakers": [{"id": "B1", "model": "LB120", "name": "Dryer", "position": 1, "power": 100}],
    "CTs": [],
}
LAMP = {"id": 5, "model": "D26HD", "name": "Lamp", "canSetLevel": True}


def _service(panels) -> LDATAService:
    """A service whose status() reads the given WHEMS panels and one Decora lamp."""
    entry = SimpleNamespace(
        data={CONF_RESIDENCE_ID: "1", "refresh_token": "t", "userid": "u"},
        options={ENABLE_DECORA: True},
    )
    service = LDATAService("user", "pw", entry)
    service.auth_token, service.account_id = "t", "acct"
    service.refresh_auth = lambda: True
    service.get_ldata_panels = lambda toggle=True: None
    service.get_iotWhemsPanels = lambda toggle=True: panels
    service.get_iot_switches = lambda: [dict(LAMP)]
    service.get_iot_bridges = lambda: []
    service.get_residential_rooms = lambda: {}
    return service


def test_a_websocket_update_during_the_decora_fetch_keeps_the_decora_devices() -> None:
    service = _service([dict(RAW_PANEL)])

    def switches():
        # Meanwhile, on the event loop, the WebSocket applies a breaker
        # notification to whatever status_data it can see.
        service._update_from_websocket(
            {"modelName": "ResidentialBreaker", "data": {"id": "B1", "power": 250}}
        )
        return [dict(LAMP)]

    service.get_iot_switches = switches
    result = service.status(False)

    assert 5 in result["decora_devices"]
    assert 5 in service.status_data["decora_devices"]
    assert service.status_data[LDATAService.INCOMPLETE_FETCHES] == []


def test_status_data_is_published_only_once_complete() -> None:
    service = _service([dict(RAW_PANEL)])
    seen = []

    def switches():
        seen.append(service.status_data)
        return [dict(LAMP)]

    service.get_iot_switches = switches
    service.status(False)

    assert seen == [None]
    assert service.status_data["breakers"]


def test_an_account_without_panels_publishes_its_decora_devices() -> None:
    service = _service(None)

    service.status(False)

    # Without status_data the WebSocket drops every Decora notification.
    assert 5 in service.status_data["decora_devices"]


def test_the_websocket_subscribes_only_once_it_has_panel_data(monkeypatch) -> None:
    clock = _FakeClock()
    service = LDATAService("", "", None)
    service.auth_token, service.userid = "token", "user"
    service.residence_id_list = ["1"]
    service.status_data = None  # status() is still running when the socket is ready
    service._ws_bandwidth_put = AsyncMock()
    service._ws_apiversion_heartbeat = AsyncMock()
    panel_data = {
        "breakers": {"B1": {"id": "B1"}},
        "cts": {},
        "panels": [{"id": "1000_ABCD", "panel_type": "WHEMS"}],
    }

    def maybe_finish_status() -> None:
        if clock.now >= 12 and service.status_data is None:
            service.status_data = panel_data  # status() took 12 s

    class Socket(_FakeWebSocket):
        async def receive(self):
            maybe_finish_status()
            return await super().receive()

    keepalives = [(t, KEEPALIVE) for t in range(30, 720, 30)]
    sockets = [Socket(clock, keepalives), Socket(clock, keepalives)]
    session = _FakeSession(list(sockets))
    monkeypatch.setattr(ldata_service.aiohttp, "ClientSession", lambda **_kwargs: session)
    monkeypatch.setattr(ldata_service.asyncio, "get_event_loop", lambda: clock)

    async def _sleep(delay: float) -> None:
        clock.now += delay
        maybe_finish_status()

    monkeypatch.setattr(ldata_service.asyncio, "sleep", _sleep)

    async def _main() -> None:
        with pytest.raises(_Stop):
            await service.async_run_websocket(lambda: None)

    asyncio.run(_main())

    rounds = []
    for ws in sockets:
        models = [msg["subscription"]["modelName"] for _, msg in ws.sent if msg.get("type") == "subscribe"]
        if models:
            rounds.append(models)
    assert rounds, "nothing was ever subscribed to"
    assert all("ResidentialBreaker" in models for models in rounds), rounds
    panels_kept_alive = {p for call in service._ws_bandwidth_put.await_args_list for p in call.args[1]}
    assert ("1000_ABCD", "WHEMS") in panels_kept_alive
    assert all(call.args[1] for call in service._ws_bandwidth_put.await_args_list)
