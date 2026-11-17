"""REST poll results merge into the current data without undoing WebSocket updates.

The breaker, CT and panel status polls fetch in the executor and merge on the
event loop. WebSocket notifications keep arriving meanwhile (the CT poll alone
waits CT_BANDWIDTH_SETTLE_SECS after its bandwidth toggle). The polls used to
copy status_data before fetching and write that copy back, reverting those
notifications.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.ldata.coordinator import LDATAUpdateCoordinator
from custom_components.ldata.ldata_service import LDATAService

PANEL = "1000_ABCD"
BREAKER = "B1"
CT = "7"


def _service(monkeypatch) -> LDATAService:
    service = LDATAService("", "", None)
    service.auth_token = "token"
    service.residence_id_list = ["res-1"]
    service.status_data = {
        "panels": [{"id": PANEL, "name": "Main", "panel_type": "WHEMS", "connected": True}],
        "breakers": {
            BREAKER: {
                "id": BREAKER, "panel_id": PANEL, "leg": 1, "poles": 1,
                "power": 500.0, "power1": 500.0, "power2": 0.0,
                "current": 4.0, "current1": 4.0, "current2": 0.0,
                "state": "ManualON", "remoteState": "RemoteON",
                "consumption": 10.0, "consumption1": 10.0, "consumption2": 0.0,
            }
        },
        "cts": {
            CT: {
                "id": CT, "panel_id": PANEL, "channel": "1",
                "power": 100.0, "power1": 100.0, "power2": 0.0,
                "consumption": 1.0, "consumption1": 1.0, "consumption2": 0.0,
                "import": 0.0, "import1": 0.0, "import2": 0.0,
                "current": 1.0, "current1": 1.0, "current2": 0.0,
            }
        },
        PANEL + "totalPower": 500.0,
    }
    service._panel_needs_breaker_poll[PANEL] = True
    service._panel_needs_rest_poll[PANEL] = True
    monkeypatch.setattr(service, "_bandwidth_toggle", lambda *_a, **_k: None)
    monkeypatch.setattr("custom_components.ldata.ldata_service.time.sleep", lambda _s: None)
    return service


def _rest_breaker(**over) -> dict:
    return {
        "id": BREAKER, "model": "LB120", "currentState": "ManualON", "remoteState": "",
        "power": 520.0, "rmsCurrent": 4.2, "energyConsumption": 12.5, **over,
    }


def _rest_ct(**over) -> dict:
    return {"id": 7, "usageType": "GRID", "activePower": 150.0, "energyConsumption": 2.5, **over}


def _trip(service: LDATAService) -> None:
    """The WebSocket reports the breaker tripping."""
    assert service._update_from_websocket({
        "modelName": "ResidentialBreaker", "modelId": BREAKER,
        "data": {"id": BREAKER, "currentState": "SoftwareTrip", "power": 0, "rmsCurrent": 0},
    })


def test_trip_during_the_ct_settle_wait_survives_the_breaker_poll(monkeypatch) -> None:
    service = _service(monkeypatch)
    monkeypatch.setattr(service, "get_Whems_breakers", lambda _p: [_rest_breaker()])

    def ct_fetch(_panel_id):
        # The breaker list came back; the poll now waits for the CTs while
        # the event loop applies a WebSocket notification.
        _trip(service)
        return [_rest_ct()]

    monkeypatch.setattr(service, "get_Whems_CT", ct_fetch)

    fetched = service.fetch_breaker_poll()
    assert service.merge_rest_poll(fetched) is True

    breaker = service.status_data["breakers"][BREAKER]
    assert breaker["state"] == "SoftwareTrip"
    assert breaker["power"] == 0
    # The energy counter, which the WebSocket never sends, still comes from REST.
    assert breaker["consumption"] == 12.5
    assert service.status_data[PANEL + "totalPower"] == 0
    assert service.status_data["cts"][CT]["consumption"] == 2.5


def test_trip_between_fetch_and_merge_survives(monkeypatch) -> None:
    service = _service(monkeypatch)
    monkeypatch.setattr(service, "get_Whems_breakers", lambda _p: [_rest_breaker()])
    monkeypatch.setattr(service, "get_Whems_CT", lambda _p: [_rest_ct()])

    fetched = service.fetch_breaker_poll()
    _trip(service)
    service.merge_rest_poll(fetched)

    assert service.status_data["breakers"][BREAKER]["state"] == "SoftwareTrip"
    assert service.status_data["breakers"][BREAKER]["consumption"] == 12.5


def test_fields_the_websocket_did_not_set_still_come_from_rest(monkeypatch) -> None:
    service = _service(monkeypatch)
    monkeypatch.setattr(
        service, "get_Whems_breakers", lambda _p: [_rest_breaker(currentState="ManualOFF", power=0, rmsCurrent=0)]
    )
    monkeypatch.setattr(service, "get_Whems_CT", lambda _p: [])

    fetched = service.fetch_breaker_poll()
    # The WebSocket only reports signal strength meanwhile.
    service._update_from_websocket({
        "modelName": "ResidentialBreaker", "modelId": BREAKER,
        "data": {"id": BREAKER, "bleRSSI": -60},
    })
    service.merge_rest_poll(fetched)

    breaker = service.status_data["breakers"][BREAKER]
    assert breaker["state"] == "ManualOFF"
    assert breaker["bleRSSI"] == -60


def test_websocket_update_before_the_request_is_overwritten_by_rest(monkeypatch) -> None:
    service = _service(monkeypatch)
    _trip(service)  # older than the poll
    monkeypatch.setattr(service, "get_Whems_breakers", lambda _p: [_rest_breaker(currentState="ManualON")])
    monkeypatch.setattr(service, "get_Whems_CT", lambda _p: [])

    service.merge_rest_poll(service.fetch_breaker_poll())

    assert service.status_data["breakers"][BREAKER]["state"] == "ManualON"


def test_ct_poll_keeps_power_the_websocket_reported_meanwhile(monkeypatch) -> None:
    service = _service(monkeypatch)

    def ct_fetch(_panel_id):
        return [_rest_ct()]

    monkeypatch.setattr(service, "get_Whems_CT", ct_fetch)

    fetched = service.fetch_ct_poll()
    service._update_from_websocket({"modelName": "IotCt", "modelId": 7, "data": {"id": 7, "activePower": 900.0}})
    assert service.merge_rest_poll(fetched) is True

    ct = service.status_data["cts"][CT]
    assert ct["power"] == 900.0
    assert ct["consumption"] == 2.5


def test_merge_of_nothing_changes_nothing(monkeypatch) -> None:
    service = _service(monkeypatch)
    before = service.status_data
    assert service.merge_rest_poll(None) is False
    assert service.merge_rest_poll([]) is False
    assert service.status_data is before


def _listing(connected: bool):
    response = MagicMock(status_code=200)
    response.json.return_value = [{"id": PANEL, "connected": connected}]
    return response


def test_panel_update_from_the_websocket_wins_over_an_older_listing(monkeypatch) -> None:
    service = _service(monkeypatch)
    service.session = MagicMock()
    service.session.get.return_value = _listing(connected=True)

    fetched = service.fetch_panel_status()
    # The WebSocket reports the panel going offline after the listing was read.
    service._update_from_websocket({"modelName": "IotWhem", "modelId": PANEL, "data": {"id": PANEL, "connected": False}})
    assert service.merge_panel_status(fetched) is False

    assert service.status_data["panels"][0]["connected"] is False


def test_listing_applies_when_no_newer_websocket_update(monkeypatch) -> None:
    service = _service(monkeypatch)
    service.session = MagicMock()
    service.session.get.return_value = _listing(connected=False)

    assert service.merge_panel_status(service.fetch_panel_status()) is True
    assert service.status_data["panels"][0]["connected"] is False


@pytest.mark.asyncio
async def test_poll_loop_fetches_in_the_executor_and_merges_on_the_loop() -> None:
    def _no_task(_hass, coro, _name):
        coro.close()

    hass = MagicMock()
    hass.async_add_executor_job = AsyncMock(side_effect=lambda func, *args: func(*args))
    entry = MagicMock()
    entry.options = {}
    entry.async_create_background_task.side_effect = _no_task
    coordinator = LDATAUpdateCoordinator(hass, "user@example.com", "secret", entry)
    coordinator._handle_websocket_update = MagicMock()

    fetch = MagicMock(return_value="fetched")

    def merge(fetched):
        coordinator._service._shutdown_requested = True
        return fetched == "fetched"

    await coordinator._fallback_poll_loop(
        loop_name="test", get_interval=lambda: 0, needs_poll=lambda: True, fetch=fetch, merge=merge,
    )

    # Only the fetch goes to the executor; the merge runs on the loop.
    hass.async_add_executor_job.assert_awaited_once_with(fetch)
    coordinator._handle_websocket_update.assert_called_once_with()
