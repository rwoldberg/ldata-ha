"""WebSocket reconnects back off, also when a session fails before ready."""

import asyncio
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import aiohttp
import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

from custom_components.ldata import ldata_service
from custom_components.ldata.const import LOGGER_NAME
from custom_components.ldata.ldata_service import LDATAService

READY = {"status": "ready"}


class _Stop(BaseException):
    """Ends the test at the next connect attempt.

    A BaseException, so the loop's own ``except Exception`` handlers do not
    swallow it and retry.
    """


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        return self.now


def _text(payload: dict) -> SimpleNamespace:
    return SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=json.dumps(payload), extra=None)


def _close(code: int = 1008, reason: str = "Policy Violation") -> SimpleNamespace:
    """The CLOSE message aiohttp returns when the server sends a close frame."""
    return SimpleNamespace(type=aiohttp.WSMsgType.CLOSE, data=code, extra=reason)


CLOSED = SimpleNamespace(type=aiohttp.WSMsgType.CLOSED, data=None, extra=None)


class _FakeWebSocket:
    """Serves scripted (delay, message) pairs against the fake clock.

    The delay is relative to the previous message. A message that is an
    exception instance is raised instead of returned. Once the script runs
    out, receive() reports the socket as closed, like aiohttp does.
    """

    def __init__(
        self,
        clock: _FakeClock,
        script: list[tuple[float, object]],
        *,
        closed: bool = False,
        close_code: int | None = None,
        send_error_at: int | None = None,
    ) -> None:
        self._clock = clock
        self._script = list(script)
        self.closed = closed
        self.close_code = close_code
        self._send_error_at = send_error_at
        self.sent: list[dict] = []

    async def send_json(self, data: dict) -> None:
        if self._send_error_at is not None and len(self.sent) == self._send_error_at:
            raise aiohttp.ClientConnectionResetError("Cannot write to closing transport")
        self.sent.append(data)

    async def receive(self):
        if not self._script:
            self.closed = True
            return CLOSED
        delay, msg = self._script.pop(0)
        self._clock.now += delay
        if isinstance(msg, BaseException):
            raise msg
        if msg.type == aiohttp.WSMsgType.CLOSE:
            self.close_code = msg.data
            self.closed = True
        return msg

    async def close(self) -> None:
        self.closed = True


class _FakeSession:
    """Hands out the queued sockets; one more connect attempt ends the test.

    A queued exception instance is raised by ws_connect instead of returned.
    """

    def __init__(self, sockets: list[object]) -> None:
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
        socket = self._sockets.pop(0)
        if isinstance(socket, BaseException):
            raise socket
        return socket


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
    # The ws_connect failure path probes connectivity; keep it off the network.
    service._test_internet_connectivity = lambda: "UP"
    return service


def _run(monkeypatch, clock: _FakeClock, sockets: list[object]):
    """Run the loop until it asks for one socket more than queued.

    Returns the service, the session and the delays the loop slept for.
    """
    session = _FakeSession(sockets)
    monkeypatch.setattr(ldata_service.aiohttp, "ClientSession", lambda **_kwargs: session)
    monkeypatch.setattr(ldata_service.asyncio, "get_event_loop", lambda: clock)
    sleeps: list[float] = []

    async def _sleep(delay: float) -> None:
        sleeps.append(delay)
        clock.now += delay

    monkeypatch.setattr(ldata_service.asyncio, "sleep", _sleep)
    service = _service()

    async def _main() -> None:
        with pytest.raises(_Stop):
            await service.async_run_websocket(lambda: None)

    asyncio.run(_main())
    return service, session, sleeps


def _closes_before_ready(clock: _FakeClock) -> _FakeWebSocket:
    """The server accepts the socket and closes it before sending ready."""
    return _FakeWebSocket(clock, [(0.08, _close())])


def _stays_up(clock: _FakeClock, seconds: float) -> _FakeWebSocket:
    """Ready and subscribed, then the server closes after ``seconds``."""
    return _FakeWebSocket(clock, [(0.0, _text(READY)), (seconds, _close(1000, ""))])


BACKOFF = [10, 20, 40, 80, 160, 300, 300, 300]


def test_close_before_ready_backs_off(monkeypatch) -> None:
    clock = _FakeClock()
    sockets = [_closes_before_ready(clock) for _ in range(len(BACKOFF))]

    service, session, sleeps = _run(monkeypatch, clock, sockets)

    # One wait before every attempt after the first, doubling up to 300 s.
    assert session.connects == len(BACKOFF) + 1
    assert sleeps == BACKOFF
    # No tight loop: the attempts span the whole backoff.
    assert clock.now >= sum(BACKOFF)
    # A session that never became ready sends no keepalive requests.
    service._ws_bandwidth_put.assert_not_awaited()
    service._ws_apiversion_heartbeat.assert_not_awaited()


@pytest.mark.parametrize(
    "make_socket",
    [
        pytest.param(lambda clock: _FakeWebSocket(clock, [], closed=True, close_code=1006), id="closed-before-auth"),
        pytest.param(lambda clock: _FakeWebSocket(clock, [], send_error_at=0), id="reset-during-auth"),
        pytest.param(lambda clock: _FakeWebSocket(clock, [(10.0, TimeoutError())]), id="auth-timeout"),
        pytest.param(lambda clock: _FakeWebSocket(clock, [(0.0, _text({"error": "denied"}))]), id="auth-error"),
        pytest.param(lambda clock: _FakeWebSocket(clock, [(0.0, CLOSED)]), id="closed-before-ready"),
        pytest.param(
            lambda clock: _FakeWebSocket(clock, [(0.0, _text(READY))], send_error_at=1),
            id="reset-during-initial-subscribe",
        ),
    ],
)
def test_every_failed_attempt_backs_off(monkeypatch, make_socket) -> None:
    clock = _FakeClock()
    sockets = [make_socket(clock) for _ in range(5)]

    _service, session, sleeps = _run(monkeypatch, clock, sockets)

    assert session.connects == 6
    assert sleeps == [10, 20, 40, 80, 160]


def test_stable_session_resets_backoff(monkeypatch) -> None:
    clock = _FakeClock()
    sockets = [
        _closes_before_ready(clock),
        _closes_before_ready(clock),
        _stays_up(clock, 65.0),
        _closes_before_ready(clock),
        _closes_before_ready(clock),
    ]

    service, session, sleeps = _run(monkeypatch, clock, sockets)

    # Two failures (10, 20), the stable session resets the wait to 10, and
    # the failures after it start the doubling again from 20.
    assert session.connects == 6
    assert sleeps == [10, 20, 10, 20, 40]
    # Keepalive requests only for the one session that became ready.
    assert service._ws_bandwidth_put.await_count == 1
    assert service._ws_apiversion_heartbeat.await_count == 1


def test_short_ready_session_does_not_reset_backoff(monkeypatch) -> None:
    clock = _FakeClock()
    sockets = [
        _closes_before_ready(clock),
        _stays_up(clock, 5.0),
        _closes_before_ready(clock),
        _stays_up(clock, 5.0),
    ]

    _service, session, sleeps = _run(monkeypatch, clock, sockets)

    # A session that reaches ready and drops within seconds is a failure
    # too: the backoff keeps growing.
    assert session.connects == 5
    assert sleeps == [10, 20, 40, 80]


def test_close_reason_logged_once_at_warning(monkeypatch, caplog) -> None:
    clock = _FakeClock()
    sockets = [_closes_before_ready(clock) for _ in range(3)]

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        _run(monkeypatch, clock, sockets)

    failures = [r for r in caplog.records if "before ready" in r.getMessage()]
    assert [r.levelno for r in failures] == [logging.WARNING, logging.DEBUG, logging.DEBUG]
    message = failures[0].getMessage()
    assert "close code 1008" in message
    assert "Policy Violation" in message
    assert "Reconnecting in 10s" in message


def test_failure_after_stable_session_logs_at_warning_again(monkeypatch, caplog) -> None:
    clock = _FakeClock()
    sockets = [
        _closes_before_ready(clock),
        _closes_before_ready(clock),
        _stays_up(clock, 65.0),
        _closes_before_ready(clock),
    ]

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        _run(monkeypatch, clock, sockets)

    failures = [r for r in caplog.records if "before ready" in r.getMessage()]
    assert [r.levelno for r in failures] == [logging.WARNING, logging.DEBUG, logging.WARNING]


def _handshake_429() -> aiohttp.WSServerHandshakeError:
    """What ws_connect raises when the server answers the upgrade with 429."""
    url = URL("wss://socket.cloud.leviton.com/")
    request_info = aiohttp.RequestInfo(url, "GET", CIMultiDictProxy(CIMultiDict()), url)
    return aiohttp.WSServerHandshakeError(
        request_info, (), status=429, message="Invalid response status"
    )


def test_handshake_429_backs_off(monkeypatch, caplog) -> None:
    clock = _FakeClock()
    attempts = [_handshake_429() for _ in range(len(BACKOFF))]

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        service, session, sleeps = _run(monkeypatch, clock, attempts)

    # Same backoff as a socket closed before ready: one wait before every
    # attempt after the first, doubling up to 300 s.
    assert session.connects == len(BACKOFF) + 1
    assert sleeps == BACKOFF
    # No tight loop: the attempts span the whole backoff.
    assert clock.now >= sum(BACKOFF)
    # No session came up, so no keepalive requests.
    service._ws_bandwidth_put.assert_not_awaited()
    service._ws_apiversion_heartbeat.assert_not_awaited()
    assert any(
        "WS connect failed" in r.getMessage() and "429" in r.getMessage() for r in caplog.records
    )


def test_cancel_during_reconnect_wait_exits(monkeypatch) -> None:
    """Cancelling the task while it waits to reconnect ends it right away."""
    clock = _FakeClock()
    session = _FakeSession([_closes_before_ready(clock), _closes_before_ready(clock)])
    monkeypatch.setattr(ldata_service.aiohttp, "ClientSession", lambda **_kwargs: session)
    monkeypatch.setattr(ldata_service.asyncio, "get_event_loop", lambda: clock)
    sleeps: list[float] = []

    async def _main() -> None:
        waiting = asyncio.Event()
        never = asyncio.get_running_loop().create_future()

        async def _sleep(delay: float) -> None:
            sleeps.append(delay)
            if len(sleeps) > 1:
                # Reached only if the cancel did not end the loop.
                raise _Stop
            waiting.set()
            await never

        monkeypatch.setattr(ldata_service.asyncio, "sleep", _sleep)
        service = _service()
        task = asyncio.get_running_loop().create_task(service.async_run_websocket(lambda: None))
        waiter = asyncio.get_running_loop().create_task(waiting.wait())
        await asyncio.wait({task, waiter}, timeout=5, return_when=asyncio.FIRST_COMPLETED)
        waiter.cancel()

        # The first attempt failed and the loop is in the top-of-loop wait.
        assert not task.done()
        assert session.connects == 1
        assert sleeps == [10]

        task.cancel()
        done, _pending = await asyncio.wait({task}, timeout=5)
        assert task in done
        with pytest.raises(asyncio.CancelledError):
            task.result()

    asyncio.run(_main())

    # No connect attempt after the cancel.
    assert session.connects == 1
    assert sleeps == [10]
