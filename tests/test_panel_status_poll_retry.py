"""Regression tests for transient network errors in the panel status poll.

The poll reuses a pooled keep-alive connection to my.leviton.com every
PANEL_STATUS_POLL_INTERVAL. The server sometimes closes that connection
while the next request is in flight, which surfaced as a WARNING
"Panel status poll error: ('Connection aborted.', RemoteDisconnected(...))"
about once an hour.
"""

import http.client
import logging
import socket
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from custom_components.ldata.const import (
    LEVITON_KEEPALIVE_IDLE_TIMEOUT,
    LOGGER_NAME,
    PANEL_STATUS_POLL_FAILURE_WARN_THRESHOLD,
    PANEL_STATUS_POLL_INTERVAL,
)
from custom_components.ldata.ldata_service import LDATAAuthError, LDATAService

LDATA_URL = "https://my.leviton.com/api/Residences/res-1/residentialBreakerPanels"


def _remote_disconnected() -> requests.exceptions.ConnectionError:
    return requests.exceptions.ConnectionError(
        ("Connection aborted.", http.client.RemoteDisconnected("Remote end closed connection without response"))
    )


def _connection_reset() -> requests.exceptions.ConnectionError:
    return requests.exceptions.ConnectionError(
        ("Connection aborted.", ConnectionResetError(104, "Connection reset by peer"))
    )


def _listing(connected: bool):
    return SimpleNamespace(
        status_code=200,
        json=lambda: [{"id": "LDATA-1", "model": "DAU", "connected": connected}],
    )


def _service(*responses) -> LDATAService:
    """Service whose session.get returns/raises ``responses`` in order."""
    service = LDATAService("", "", None)
    service.auth_token = "token"
    service.residence_id_list = ["res-1"]
    service.status_data = {
        "breakers": {},
        "cts": {},
        "panels": [
            {"id": "LDATA-1", "name": "Panel", "panel_type": "LDATA", "connected": True},
        ],
    }
    service.session = MagicMock()
    service.session.get.side_effect = list(responses)
    return service


def _warnings(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER_NAME and r.levelno >= logging.WARNING]


def _ssl_eof() -> requests.exceptions.SSLError:
    return requests.exceptions.SSLError("EOF occurred in violation of protocol (_ssl.c:2427)")


def test_poll_interval_keeps_the_pooled_connection_alive() -> None:
    # The poll sleeps PANEL_STATUS_POLL_INTERVAL after the previous response,
    # so the connection's idle time is the interval plus scheduling latency.
    # Polling at the server's idle timeout made every poll race its close.
    assert PANEL_STATUS_POLL_INTERVAL <= LEVITON_KEEPALIVE_IDLE_TIMEOUT - 10


@pytest.mark.parametrize("error", [_remote_disconnected, _connection_reset, _ssl_eof])
def test_dropped_connection_is_retried_once(caplog, error) -> None:
    service = _service(error(), _listing(connected=False))

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service.refresh_panel_status() is True

    assert service.status_data["panels"][0]["connected"] is False
    assert [c.args[0] for c in service.session.get.call_args_list] == [LDATA_URL, LDATA_URL]
    assert _warnings(caplog) == []


def test_read_timeout_is_not_retried_and_does_not_raise(caplog) -> None:
    service = _service(
        requests.exceptions.ReadTimeout("HTTPSConnectionPool(host='my.leviton.com', port=443): Read timed out.")
    )
    before = service.status_data

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service.refresh_panel_status() is False

    assert service.session.get.call_count == 1
    assert service.status_data is before
    assert _warnings(caplog) == []


def test_connect_timeout_is_not_retried() -> None:
    service = _service(requests.exceptions.ConnectTimeout("connect timed out"))

    assert service.refresh_panel_status() is False
    assert service.session.get.call_count == 1


def test_dropped_body_is_not_retried_and_does_not_raise(caplog) -> None:
    # The server answered, so this is not a stale pooled connection.
    service = _service(requests.exceptions.ChunkedEncodingError("Connection broken: IncompleteRead"))
    before = service.status_data

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service.refresh_panel_status() is False

    assert service.session.get.call_count == 1
    assert service.status_data is before
    assert _warnings(caplog) == []


def test_non_json_body_does_not_raise(caplog) -> None:
    def bad_json():
        raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)

    service = _service(SimpleNamespace(status_code=200, json=bad_json))
    before = service.status_data

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service.refresh_panel_status() is False

    assert service.session.get.call_count == 1
    assert service.status_data is before
    assert _warnings(caplog) == []


def test_retry_that_fails_again_counts_as_one_failed_poll(caplog) -> None:
    service = _service(_remote_disconnected(), _remote_disconnected())

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        assert service.refresh_panel_status() is False

    assert service.session.get.call_count == 2
    assert _warnings(caplog) == []


def test_warns_once_after_consecutive_failures_and_logs_recovery(caplog) -> None:
    failures = PANEL_STATUS_POLL_FAILURE_WARN_THRESHOLD + 2
    service = _service(
        *[requests.exceptions.ReadTimeout("Read timed out.") for _ in range(failures)],
        _listing(connected=True),
        _listing(connected=True),
    )

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        for poll in range(1, failures + 1):
            assert service.refresh_panel_status() is False
            expected = 0 if poll < PANEL_STATUS_POLL_FAILURE_WARN_THRESHOLD else 1
            assert len(_warnings(caplog)) == expected, f"poll {poll}"

        assert service.refresh_panel_status() is False  # recovered, nothing changed
        recovered = [
            r for r in caplog.records
            if r.name == LOGGER_NAME and r.levelno == logging.INFO and "recovered" in r.getMessage()
        ]
        assert len(recovered) == 1
        assert str(failures) in recovered[0].getMessage()

        service.refresh_panel_status()

    assert len(_warnings(caplog)) == 1
    assert len([r for r in caplog.records if "recovered" in r.getMessage()]) == 1


def test_short_failure_streak_logs_no_recovery(caplog) -> None:
    service = _service(
        *[requests.exceptions.ReadTimeout("Read timed out.") for _ in range(PANEL_STATUS_POLL_FAILURE_WARN_THRESHOLD - 1)],
        _listing(connected=True),
        *[requests.exceptions.ReadTimeout("Read timed out.") for _ in range(PANEL_STATUS_POLL_FAILURE_WARN_THRESHOLD - 1)],
    )

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        for _ in range(2 * PANEL_STATUS_POLL_FAILURE_WARN_THRESHOLD - 1):
            service.refresh_panel_status()

    # A success in between resets the streak, so the threshold is never reached.
    assert [r for r in caplog.records if r.name == LOGGER_NAME] == []


def test_auth_error_still_raises() -> None:
    service = _service(SimpleNamespace(status_code=401, json=list))

    with pytest.raises(LDATAAuthError):
        service.refresh_panel_status()


class _DropReusedConnectionServer:
    """HTTP/1.1 server that answers the first request on each connection with a
    keep-alive response and closes the connection, without a response, when a
    second request arrives on it. This is what the Leviton cloud does to an
    idle pooled connection."""

    BODY = b'[{"id": "LDATA-1", "model": "DAU", "connected": false}]'

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _read_request(self, conn) -> bool:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return False
            data += chunk
        return True

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            with conn:
                if not self._read_request(conn):
                    continue
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Connection: keep-alive\r\n"
                    + f"Content-Length: {len(self.BODY)}\r\n\r\n".encode()
                    + self.BODY
                )
                # Second request on this connection: close without answering.
                self._read_request(conn)

    def close(self) -> None:
        self.sock.close()


def test_retry_uses_a_fresh_connection_with_a_real_session(caplog) -> None:
    server = _DropReusedConnectionServer()
    service = _service()
    service.session = requests.Session()
    try:
        real_get = service.session.get
        local_url = f"http://127.0.0.1:{server.port}/api"
        service.session.get = lambda _url, **kwargs: real_get(local_url, **kwargs)

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            assert service.refresh_panel_status() is True  # connection 1
            assert service.status_data["panels"][0]["connected"] is False
            service.status_data["panels"][0]["connected"] = True
            # Reuses connection 1, which the server drops; the retry opens connection 2.
            assert service.refresh_panel_status() is True

        assert service.status_data["panels"][0]["connected"] is False
        assert server.connections == 2
        assert _warnings(caplog) == []
    finally:
        service.session.close()
        server.close()
