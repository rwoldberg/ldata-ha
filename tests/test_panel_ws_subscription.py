"""LDATA panels are subscribed and handled under their own WebSocket model name."""

from custom_components.ldata.ldata_service import LDATAService


def _service() -> LDATAService:
    service = LDATAService("", "", None)
    service.residence_id_list = []
    service.status_data = {
        "breakers": {
            "breaker-1": {
                "id": "breaker-1",
                "panel_id": "LDATA-1",
                "poles": 1,
                "leg": 1,
                "power": 0.0,
                "power1": 0.0,
                "power2": 0.0,
                "current": 0.0,
            },
        },
        "cts": {},
        "panels": [
            {"id": "LDATA-1", "panel_type": "LDATA", "connected": True},
            {"id": "1000_ABCD", "panel_type": "WHEMS", "connected": True},
        ],
    }
    return service


def _panel_subscriptions(service: LDATAService) -> dict[str, str]:
    return {
        sub["subscription"]["modelId"]: sub["subscription"]["modelName"]
        for sub in service._ws_build_subscriptions()
        if sub["subscription"]["modelName"] in ("IotWhem", "ResidentialBreakerPanel")
    }


def test_ldata_panel_subscribes_as_residential_breaker_panel() -> None:
    assert _panel_subscriptions(_service()) == {
        "LDATA-1": "ResidentialBreakerPanel",
        "1000_ABCD": "IotWhem",
    }


def test_breakers_are_still_subscribed_individually() -> None:
    subscriptions = _service()._ws_build_subscriptions()

    assert {
        "type": "subscribe",
        "subscription": {"modelName": "ResidentialBreaker", "modelId": "breaker-1"},
    } in subscriptions


def test_residential_breaker_panel_notification_applies_embedded_breakers() -> None:
    service = _service()
    before = service.status_data

    updated = service._update_from_websocket(
        {
            "modelName": "ResidentialBreakerPanel",
            "modelId": "LDATA-1",
            "data": {
                "id": "LDATA-1",
                "ResidentialBreaker": [{"id": "breaker-1", "power": 42.0, "rmsCurrent": 0.4}],
            },
        }
    )

    assert updated is True
    assert service.status_data is not before
    assert service.status_data["breakers"]["breaker-1"]["power"] == 42.0
    assert service.status_data["LDATA-1totalPower"] == 42.0


def test_residential_breaker_panel_notification_updates_panel_fields() -> None:
    service = _service()

    service._update_from_websocket(
        {
            "modelName": "ResidentialBreakerPanel",
            "modelId": "LDATA-1",
            "data": {"id": "LDATA-1", "rssi": -61, "connected": False},
        }
    )

    panel = service.status_data["panels"][0]
    assert panel["rssi"] == -61.0
    assert panel["connected"] is False
    # The WHEMS panel is untouched.
    assert service.status_data["panels"][1] == {
        "id": "1000_ABCD",
        "panel_type": "WHEMS",
        "connected": True,
    }


def _notify(service: LDATAService, model_name: str, panel_id: str, data: dict) -> dict:
    service._update_from_websocket(
        {"modelName": model_name, "modelId": panel_id, "data": {"id": panel_id, **data}}
    )
    return next(p for p in service.status_data["panels"] if p["id"] == panel_id)


def _dau_service() -> LDATAService:
    service = _service()
    service.status_data["panels"][0]["model"] = "DAU"
    return service


def test_dau_raw_connected_false_without_status_keeps_connected() -> None:
    # REST treats a DAU with status READY as connected even though its
    # connected flag is false; a WS frame with only connected: false must not
    # flip Cloud Connected off.
    panel = _notify(_dau_service(), "ResidentialBreakerPanel", "LDATA-1", {"connected": False, "rssi": -61})

    assert panel["connected"] is True
    assert panel["rssi"] == -61.0


def test_dau_status_ready_is_connected() -> None:
    service = _dau_service()
    service.status_data["panels"][0]["connected"] = False

    panel = _notify(service, "ResidentialBreakerPanel", "LDATA-1", {"connected": False, "status": "READY"})

    assert panel["connected"] is True


def test_dau_status_not_ready_is_disconnected() -> None:
    panel = _notify(_dau_service(), "ResidentialBreakerPanel", "LDATA-1", {"connected": False, "status": "OFFLINE"})

    assert panel["connected"] is False


def test_iotwhem_connected_is_copied_unchanged() -> None:
    panel = _notify(_service(), "IotWhem", "1000_ABCD", {"connected": False})

    assert panel["connected"] is False


def test_residential_breaker_panel_applies_real_zero_voltage() -> None:
    service = _service()
    service.status_data["panels"][0].update(voltage1=120.0, voltage2=121.0, voltage=240.5)

    panel = _notify(
        service, "ResidentialBreakerPanel", "LDATA-1", {"rmsVoltage": 0.0, "rmsVoltage2": 0.0}
    )

    assert panel["voltage1"] == 0.0
    assert panel["voltage2"] == 0.0
    assert panel["voltage"] == 0.0


def test_residential_breaker_panel_ignores_zero_frequency() -> None:
    service = _service()
    service.status_data["panels"][0].update(frequency1=60.0, frequency2=60.0, frequency=60.0)

    panel = _notify(
        service, "ResidentialBreakerPanel", "LDATA-1", {"frequencyA": 0, "frequencyB": 0}
    )

    assert panel["frequency1"] == 60.0
    assert panel["frequency2"] == 60.0
    assert panel["frequency"] == 60.0


def test_residential_breaker_panel_applies_nonzero_frequency() -> None:
    service = _service()
    service.status_data["panels"][0].update(frequency1=60.0, frequency2=60.0, frequency=60.0)

    panel = _notify(
        service, "ResidentialBreakerPanel", "LDATA-1", {"frequencyA": 59.9, "frequencyB": 0}
    )

    assert panel["frequency1"] == 59.9
    assert panel["frequency2"] == 60.0


def test_iotwhem_still_applies_zero_frequency() -> None:
    service = _service()
    service.status_data["panels"][1].update(frequency1=60.0, frequency2=60.0, frequency=60.0)

    panel = _notify(service, "IotWhem", "1000_ABCD", {"frequencyA": 0, "frequencyB": 0})

    assert panel["frequency"] == 0.0


def test_residential_breaker_panel_null_rssi_clears_rssi() -> None:
    service = _service()
    service.status_data["panels"][0]["rssi"] = -61.0

    panel = _notify(service, "ResidentialBreakerPanel", "LDATA-1", {"rssi": None})

    assert panel["rssi"] is None


def test_residential_breaker_panel_without_rssi_keeps_rssi() -> None:
    service = _service()
    service.status_data["panels"][0]["rssi"] = -61.0

    panel = _notify(service, "ResidentialBreakerPanel", "LDATA-1", {"connected": True})

    assert panel["rssi"] == -61.0


def test_iotwhem_null_rssi_keeps_rssi() -> None:
    service = _service()
    service.status_data["panels"][1]["rssi"] = -55.0

    panel = _notify(service, "IotWhem", "1000_ABCD", {"rssi": None})

    assert panel["rssi"] == -55.0
