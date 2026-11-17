"""A WHEMS panel that is offline at startup is kept, not dropped until a reload.

A disconnected WHEMS panel can be listed without rmsVoltageA/rmsVoltageB and
version. status() used to skip it, and since nothing lists panels again
after setup, the panel and every breaker and CT on it stayed missing until
the entry was reloaded.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from custom_components.ldata.ldata_service import LDATAService

PANEL = "1000_ABCD"
OFFLINE_LISTING = {"id": PANEL, "name": "Garage", "model": "LWHEM", "connected": False}
BREAKER = {
    "id": "B1", "model": "LB120", "currentRating": 20, "position": 1, "name": "Freezer",
    "currentState": "ManualON", "poles": 1, "serialNumber": "S1", "hwVersion": "1",
    "firmwareVersionMeter": "2", "canRemoteOn": True, "remoteState": "",
}
CT = {"id": 7, "usageType": "GRID", "channel": 1, "activePower": 0}


def _service() -> tuple[LDATAService, list]:
    service = LDATAService("", "", None)
    service.auth_token = "token"
    service.residence_id_list = ["res-1"]
    responses = {
        "iotWhems": [OFFLINE_LISTING],
        "residentialBreakers": [BREAKER],
        "iotCts": [CT],
    }
    service.session = MagicMock()
    service.session.get.side_effect = lambda url, **_kw: SimpleNamespace(
        status_code=200, reason="OK", text="", json=lambda: responses[url.rsplit("/", 1)[-1]]
    )
    toggled: list = []
    service._bandwidth_toggle = lambda panel_id, *_a: toggled.append(panel_id)
    return service, toggled


def test_offline_panel_is_listed_with_its_breakers_and_cts() -> None:
    service, toggled = _service()

    panels = service.get_iotWhemsPanels()

    assert [panel["id"] for panel in panels] == [PANEL]
    assert panels[0]["residentialBreakers"] == [BREAKER]
    assert panels[0]["CTs"] == [CT]
    assert toggled == []  # an offline panel is never toggled
    assert service._incomplete_fetches == set()


def test_offline_panel_is_parsed_with_unknown_readings() -> None:
    service, _toggled = _service()

    data = service.parse_panels(service.get_iotWhemsPanels())

    panel = data["panels"][0]
    assert panel["connected"] is False
    assert panel["voltage"] is None
    assert panel["installed_firmware"] == "unknown"
    assert set(data["breakers"]) == {"B1"}
    assert set(data["cts"]) == {"7"}


def test_unknown_firmware_is_treated_as_current_firmware() -> None:
    # Guessing v1 would toggle the panel's bandwidth on every REST poll once
    # it connects; current firmware needs no REST polling at all.
    service, _toggled = _service()

    service.parse_panels(service.get_iotWhemsPanels())

    assert service._panel_needs_breaker_poll[PANEL] is False
    assert service._panel_needs_rest_poll[PANEL] is False
    assert service.panel_has_hw_counters(PANEL) is False


def test_offline_panel_is_subscribed_and_filled_in_when_it_connects() -> None:
    service, _toggled = _service()
    service.parse_panels(service.get_iotWhemsPanels())

    subscribed = {sub["subscription"]["modelId"] for sub in service._ws_build_subscriptions()}
    assert {PANEL, "B1", 7} <= subscribed

    assert service._update_from_websocket({
        "modelName": "IotWhem", "modelId": PANEL,
        "data": {"id": PANEL, "connected": True, "rmsVoltageA": 121.0, "rmsVoltageB": 119.0, "version": "2.1.4"},
    })
    panel = service.status_data["panels"][0]
    assert panel["connected"] is True
    assert panel["voltage1"] == 121.0 and panel["voltage2"] == 119.0
    assert panel["installed_firmware"] == "2.1.4"
