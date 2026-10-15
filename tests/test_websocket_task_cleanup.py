"""Keepalive requests started by the WebSocket loop do not outlive it."""

import asyncio
import json
from types import SimpleNamespace

import aiohttp
import pytest

from custom_components.ldata import ldata_service
from custom_components.ldata.ldata_service import LDATAService

pytestmark = pytest.mark.asyncio


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        return self.now


class _FakeWebSocket:
    """Serves scripted frames, then blocks in receive().

    Each frame is (time, payload) or (time, payload, gate). A dict payload is
    served as a TEXT message, an aiohttp.WSMsgType as a message of that type.
    A gate is awaited before the frame is served.
    """

    def __init__(self, clock: _FakeClock, frames: list[tuple]) -> None:
        self._clock = clock
        self._frames = [(0.0, {"status": "ready"}), *frames]
        self.closed = False

    async def send_json(self, _data: dict) -> None:
        return None

    async def receive(self):
        if not self._frames:
            await asyncio.Event().wait()
        due, frame, *gate = self._frames.pop(0)
        if gate:
            await gate[0]()
        self._clock.now = max(self._clock.now, due)
        if isinstance(frame, aiohttp.WSMsgType):
            return SimpleNamespace(type=frame, data=None)
        return SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=json.dumps(frame))

    async def close(self) -> None:
        self.closed = True


class _FakeSession:
    def __init__(self, ws: _FakeWebSocket) -> None:
        self._ws = ws

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc) -> None:
        return None

    async def ws_connect(self, *_args, **_kwargs):
        return self._ws


class _SlowRequest:
    """The first call (the awaited initial request) returns; later calls hang."""

    def __init__(self) -> None:
        self.calls = 0
        self.started = asyncio.Event()
        self.cancelled = False

    async def __call__(self, *_args) -> None:
        self.calls += 1
        if self.calls == 1:
            return
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class _StubbornRequest(_SlowRequest):
    """Like _SlowRequest, but ignores cancellation until released."""

    def __init__(self) -> None:
        super().__init__()
        self.release = asyncio.Event()
        self.cancel_attempts = 0

    async def __call__(self, *_args) -> None:
        self.calls += 1
        if self.calls == 1:
            return
        self.started.set()
        while not self.release.is_set():
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.cancel_attempts += 1


NOTIFICATION = {
    "type": "notification",
    "notification": {"modelName": "ResidentialBreaker", "modelId": "breaker-1", "data": {"power": 5}},
}


def _service(monkeypatch, frames, bandwidth, heartbeat):
    """Service whose WebSocket loop runs against a fake socket and clock."""
    clock = _FakeClock()
    ws = _FakeWebSocket(clock, frames)
    monkeypatch.setattr(ldata_service.aiohttp, "ClientSession", lambda **_kwargs: _FakeSession(ws))
    monkeypatch.setattr(ldata_service.asyncio, "get_event_loop", lambda: clock)

    service = LDATAService("", "", None)
    service.auth_token = "token"
    service.userid = "user"
    service.residence_id_list = []
    service.status_data = {
        "breakers": {"breaker-1": {"id": "breaker-1"}},
        "cts": {},
        "panels": [{"id": "LDATA-1", "panel_type": "LDATA"}],
    }
    service._ws_bandwidth_put = bandwidth
    service._ws_apiversion_heartbeat = heartbeat
    return service, ws


def _keepalive_tasks() -> list[asyncio.Task]:
    return [
        task for task in asyncio.all_tasks()
        if task.get_name() in ("ldata_bandwidth_put", "ldata_heartbeat") and not task.done()
    ]


async def _both_started(bandwidth, heartbeat) -> None:
    await asyncio.wait_for(
        asyncio.gather(bandwidth.started.wait(), heartbeat.started.wait()), timeout=5
    )


async def test_cancelling_the_loop_cancels_keepalive_requests(monkeypatch) -> None:
    bandwidth, heartbeat = _SlowRequest(), _SlowRequest()
    # A frame at 51 s puts the loop past both the 10 s heartbeat and the 50 s
    # bandwidth intervals, so it starts one of each as a background request.
    service, _ws = _service(monkeypatch, [(51.0, NOTIFICATION)], bandwidth, heartbeat)

    loop_task = asyncio.create_task(service.async_run_websocket(lambda: None))
    await _both_started(bandwidth, heartbeat)

    loop_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await loop_task

    assert bandwidth.cancelled
    assert heartbeat.cancelled
    assert _keepalive_tasks() == []


async def test_cancel_resistant_keepalive_request_is_waited_for_at_most_5_s(
    monkeypatch,
) -> None:
    bandwidth, heartbeat = _StubbornRequest(), _StubbornRequest()
    service, ws = _service(monkeypatch, [(51.0, NOTIFICATION)], bandwidth, heartbeat)
    # Record the bound the loop passes to asyncio.wait, and shorten it so the
    # test does not sleep for 5 s.
    real_wait = asyncio.wait
    timeouts = []

    async def _short_wait(fs, *, timeout=None, **kwargs):
        timeouts.append(timeout)
        return await real_wait(fs, timeout=0.05 if timeout == 5 else timeout, **kwargs)

    monkeypatch.setattr(ldata_service.asyncio, "wait", _short_wait)

    loop_task = asyncio.create_task(service.async_run_websocket(lambda: None))
    try:
        await _both_started(bandwidth, heartbeat)

        loop_task.cancel()
        # Without the bound, the loop would wait for the stubborn requests
        # forever.
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(loop_task, timeout=2)

        assert timeouts == [5]
        assert bandwidth.cancel_attempts == 1
        assert heartbeat.cancel_attempts == 1
        # The loop gave up on the requests, not the other way round.
        assert len(_keepalive_tasks()) == 2
        assert ws.closed
    finally:
        # Let the stubborn requests finish so no task outlives the test.
        service._shutdown_requested = True
        bandwidth.release.set()
        heartbeat.release.set()
        loop_task.cancel()
        await asyncio.wait([loop_task, *_keepalive_tasks()], timeout=1)


async def test_connection_end_cancels_keepalive_requests_before_reconnect(
    monkeypatch,
) -> None:
    bandwidth, heartbeat = _SlowRequest(), _SlowRequest()

    async def _after_keepalives_start() -> None:
        await _both_started(bandwidth, heartbeat)

    # The server closes the socket once both keepalive requests are in
    # flight. The loop is not cancelled: it ends the connection itself and
    # waits to reconnect.
    service, ws = _service(
        monkeypatch,
        [(51.0, NOTIFICATION), (52.0, aiohttp.WSMsgType.CLOSED, _after_keepalives_start)],
        bandwidth,
        heartbeat,
    )
    connection_states = []

    loop_task = asyncio.create_task(
        service.async_run_websocket(lambda: None, connection_states.append)
    )
    try:
        await asyncio.wait_for(_until(lambda: ws.closed), timeout=5)
        # One more turn so the finally block's last steps have run.
        await asyncio.sleep(0)

        assert not loop_task.done()  # sleeping before the reconnect
        assert bandwidth.cancelled
        assert heartbeat.cancelled
        assert _keepalive_tasks() == []
        assert connection_states[-1] is False
    finally:
        service._shutdown_requested = True
        loop_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await loop_task


async def _until(condition) -> None:
    while not condition():
        await asyncio.sleep(0.01)
