"""WebSocket liveness: server keepalives count, a quiet stream is left alone."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import aiohttp
import pytest

from custom_components.ldata import ldata_service
from custom_components.ldata.ldata_service import LDATAService

KEEPALIVE = {"type": "keepalive"}


class _Stop(BaseException):
    """Ends the test once the scripted frames run out.

    A BaseException, so the loop's own ``except Exception`` handlers do not
    swallow it and retry.
    """


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        return self.now


class _FakeWebSocket:
    """Serves scripted (time, frame) pairs against the fake clock.

    A frame due more than 15 s ahead makes receive() time out after 15 s,
    the same as the real asyncio.wait_for(ws.receive(), timeout=15.0).
    """

    def __init__(self, clock: _FakeClock, frames: list[tuple[float, dict]]) -> None:
        self._clock = clock
        self._frames = [(0.0, {"status": "ready"})] + list(frames)
        self.sent: list[tuple[float, dict]] = []
        self.closed = False
        self.closed_at: float | None = None

    @property
    def unread(self) -> int:
        """Scripted frames the loop has not received yet."""
        return len(self._frames)

    async def send_json(self, data: dict) -> None:
        self.sent.append((self._clock.now, data))

    async def receive(self):
        if not self._frames:
            raise _Stop
        due, frame = self._frames[0]
        if due - self._clock.now > 15:
            self._clock.now += 15
            raise TimeoutError
        self._frames.pop(0)
        self._clock.now = max(self._clock.now, due)
        return SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=json.dumps(frame))

    async def close(self) -> None:
        if not self.closed:
            self.closed_at = self._clock.now
        self.closed = True


class _FakeSession:
    """Hands out the queued sockets; one more connect attempt ends the test.

    ``connects`` counts every attempt, including the one that finds the queue
    empty, so a reconnect is visible even when no spare socket was queued.
    """

    def __init__(self, sockets: list[_FakeWebSocket]) -> None:
        self._sockets = sockets
        self.connects = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def ws_connect(self, *_args, **_kwargs):
        self.connects += 1
        if not self._sockets:
            raise _Stop
        return self._sockets.pop(0)


def _service() -> LDATAService:
    service = LDATAService("", "", None)
    service.auth_token = "token"
    service.userid = "user"
    service.residence_id_list = []
    service.status_data = {
        "breakers": {"breaker-1": {"id": "breaker-1"}},
        "cts": {},
        "panels": [{"id": "LDATA-1", "panel_type": "LDATA"}],
    }
    service._ws_bandwidth_put = AsyncMock()
    service._ws_apiversion_heartbeat = AsyncMock()
    return service


def _run(monkeypatch, sockets: list[_FakeWebSocket], clock: _FakeClock) -> _FakeSession:
    session = _FakeSession(sockets)
    monkeypatch.setattr(ldata_service.aiohttp, "ClientSession", lambda **_kwargs: session)
    monkeypatch.setattr(ldata_service.asyncio, "get_event_loop", lambda: clock)

    async def _sleep(delay: float) -> None:
        clock.now += delay

    monkeypatch.setattr(ldata_service.asyncio, "sleep", _sleep)

    async def _main() -> None:
        with pytest.raises(_Stop):
            await _service().async_run_websocket(lambda: None)

    asyncio.run(_main())
    return session


def _subscribe_rounds(ws: _FakeWebSocket) -> int:
    """Number of times the full subscription list was sent."""
    return sum(
        1
        for _, msg in ws.sent
        if msg.get("type") == "subscribe"
        and msg["subscription"]["modelName"] == "ResidentialBreaker"
    )


def _subscribe_times(ws: _FakeWebSocket) -> list[float]:
    """Clock time of each full subscription round."""
    return [
        when
        for when, msg in ws.sent
        if msg.get("type") == "subscribe"
        and msg["subscription"]["modelName"] == "ResidentialBreaker"
    ]


NOTIFICATION = {
    "type": "notification",
    "notification": {"modelName": "ResidentialBreaker", "modelId": "breaker-1", "data": {"power": 5}},
}


def test_quiet_stream_with_keepalives_is_not_resubscribed(monkeypatch) -> None:
    clock = _FakeClock()
    # 9.5 minutes without a single notification, keepalives every 30 s.
    ws = _FakeWebSocket(clock, [(30.0 * n, KEEPALIVE) for n in range(1, 20)])

    session = _run(monkeypatch, [ws], clock)

    assert ws.unread == 0
    assert _subscribe_rounds(ws) == 1
    # Only the initial connect; the loop ended on the exhausted script, not
    # on a reconnect attempt.
    assert session.connects == 1


def test_lost_keepalives_do_not_reconnect(monkeypatch) -> None:
    clock = _FakeClock()
    # Two keepalives in a row go missing (75 s gap) a few times.
    times = [30.0, 105.0, 135.0, 210.0, 240.0, 270.0, 345.0]
    ws = _FakeWebSocket(clock, [(t, KEEPALIVE) for t in times])

    session = _run(monkeypatch, [ws], clock)

    assert ws.unread == 0
    assert _subscribe_rounds(ws) == 1
    assert session.connects == 1


def test_reconnects_when_keepalives_stop(monkeypatch) -> None:
    clock = _FakeClock()
    # Keepalives stop after 60 s; the next frame is far in the future.
    ws = _FakeWebSocket(clock, [(30.0, KEEPALIVE), (60.0, KEEPALIVE), (1000.0, KEEPALIVE)])
    reconnected = _FakeWebSocket(clock, [])

    session = _run(monkeypatch, [ws, reconnected], clock)

    # One subscribe round, no re-subscribes, then a reconnect.
    assert _subscribe_rounds(ws) == 1
    assert ws.unread == 1
    assert session.connects == 2
    # Closed no earlier than KEEPALIVE_TIMEOUT (90 s) after the last
    # keepalive, and within one 15 s receive wait after that.
    assert ws.closed_at is not None
    assert 150.0 <= ws.closed_at <= 165.0


def test_notifications_alone_still_count_after_keepalives_stop(monkeypatch) -> None:
    clock = _FakeClock()
    frames = [(30.0, KEEPALIVE)] + [(30.0 + 40.0 * n, NOTIFICATION) for n in range(1, 10)]
    ws = _FakeWebSocket(clock, frames)

    session = _run(monkeypatch, [ws], clock)

    assert ws.unread == 0
    assert _subscribe_rounds(ws) == 1
    assert session.connects == 1


def test_quiet_keepalive_stream_is_resubscribed_slowly(monkeypatch) -> None:
    clock = _FakeClock()
    # 25 minutes of keepalives without a notification. The server may have
    # dropped the subscriptions without closing the socket, so they are
    # re-sent every 600 s on the same connection.
    ws = _FakeWebSocket(clock, [(30.0 * n, KEEPALIVE) for n in range(1, 51)])

    session = _run(monkeypatch, [ws], clock)

    assert ws.unread == 0
    times = _subscribe_times(ws)
    assert len(times) == 3
    assert times[0] == 0.0
    assert 600.0 <= times[1] < 615.0
    assert 1200.0 <= times[2] < 1215.0
    assert session.connects == 1


def test_notification_postpones_keepalive_resubscribe(monkeypatch) -> None:
    clock = _FakeClock()
    # A notification at 500 s restarts the 600 s wait: the next re-subscribe
    # is due about 1100 s, not at 600 s. The loop stamps data at the start of
    # the receive wait it arrived in, up to 15 s early.
    frames = [(30.0 * n, KEEPALIVE) for n in range(1, 41)]
    frames.append((500.0, NOTIFICATION))
    frames.sort(key=lambda frame: frame[0])
    ws = _FakeWebSocket(clock, frames)

    session = _run(monkeypatch, [ws], clock)

    assert ws.unread == 0
    times = _subscribe_times(ws)
    assert len(times) == 2
    assert 1085.0 <= times[1] < 1115.0
    assert session.connects == 1


def test_server_without_keepalives_keeps_resubscribe_ladder(monkeypatch) -> None:
    clock = _FakeClock()
    # No keepalives and no notifications: the old behaviour applies,
    # re-subscribe every 60 s up to 5 times, then reconnect.
    ws = _FakeWebSocket(clock, [(1000.0, {"type": "ack"})])
    reconnected = _FakeWebSocket(clock, [])

    session = _run(monkeypatch, [ws, reconnected], clock)

    assert _subscribe_rounds(ws) == 1 + 5
    assert ws.unread == 1
    assert ws.closed
    assert session.connects == 2


def test_late_first_keepalive_switches_to_keepalive_mode(monkeypatch) -> None:
    clock = _FakeClock()
    # The first keepalive arrives late (after one re-subscribe already
    # happened); from then on the quiet stream is left alone.
    frames = [(75.0, KEEPALIVE)] + [(75.0 + 30.0 * n, KEEPALIVE) for n in range(1, 15)]
    ws = _FakeWebSocket(clock, frames)

    session = _run(monkeypatch, [ws], clock)

    assert ws.unread == 0
    assert _subscribe_rounds(ws) == 2
    assert session.connects == 1
