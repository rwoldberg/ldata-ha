"""Regression tests for panel connection state going stale while a panel is offline."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from custom_components.ldata.coordinator import LDATAUpdateCoordinator
from custom_components.ldata.ldata_service import LDATAService


def _service(listings: dict[str, list[dict]]) -> LDATAService:
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

    def _get(url, **_kwargs):
        key = "LDATA" if url.endswith("residentialBreakerPanels") else "WHEMS"
        return SimpleNamespace(status_code=200, json=lambda: listings.get(key, []))

    service.session = MagicMock()
    service.session.get.side_effect = _get
    return service


def test_refresh_panel_status_reports_panel_going_offline() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "model": "DAU", "connected": False}]})
    before = service.status_data

    assert service.refresh_panel_status() is True
    assert service.status_data["panels"][0]["connected"] is False
    # Copy-on-write, so the coordinator sees a new object.
    assert service.status_data is not before
    assert before["panels"][0]["connected"] is True


def test_refresh_panel_status_unchanged_returns_false() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "model": "DAU", "status": "READY"}]})
    before = service.status_data

    assert service.refresh_panel_status() is False
    assert service.status_data is before


def test_refresh_panel_status_only_queries_known_panel_types() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "connected": True}]})

    service.refresh_panel_status()

    urls = [call.args[0] for call in service.session.get.call_args_list]
    assert urls == ["https://my.leviton.com/api/Residences/res-1/residentialBreakerPanels"]


def test_refresh_panel_status_updates_voltage_with_connection_unchanged() -> None:
    service = _service(
        {"LDATA": [{"id": "LDATA-1", "connected": True, "rmsVoltage": 121.0, "rmsVoltage2": 119.0}]}
    )
    service.status_data["panels"][0].update(voltage1=0.0, voltage2=119.0, voltage=59.5)
    before = service.status_data

    assert service.refresh_panel_status() is True
    panel = service.status_data["panels"][0]
    assert panel["connected"] is True
    assert panel["voltage1"] == 121.0
    assert panel["voltage2"] == 119.0
    assert panel["voltage"] == 120.0
    assert service.status_data is not before
    assert before["panels"][0]["voltage1"] == 0.0


def test_refresh_panel_status_missing_voltage_keeps_cached_values() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "connected": True, "rmsVoltage": None}]})
    service.status_data["panels"][0].update(voltage1=120.0, voltage2=121.0, voltage=120.5)
    before = service.status_data

    assert service.refresh_panel_status() is False
    assert service.status_data is before
    panel = service.status_data["panels"][0]
    assert (panel["voltage1"], panel["voltage2"], panel["voltage"]) == (120.0, 121.0, 120.5)


def _coordinator() -> LDATAUpdateCoordinator:
    coordinator = LDATAUpdateCoordinator.__new__(LDATAUpdateCoordinator)
    coordinator._hass = SimpleNamespace(loop=MagicMock())
    coordinator._service = SimpleNamespace(version="test", _shutdown_requested=False)
    coordinator.config_entry = SimpleNamespace(options={})
    coordinator._debounce_timer = None
    coordinator._websocket_connected = False
    coordinator._websocket_ever_connected = False
    return coordinator


def test_reconnect_rearms_update_timer_cancelled_by_disconnect() -> None:
    coordinator = _coordinator()

    coordinator._handle_connection_change(True)
    first_timer = coordinator._debounce_timer
    assert first_timer is not None

    coordinator._handle_connection_change(False)
    first_timer.cancel.assert_called_once()
    assert coordinator._debounce_timer is None

    coordinator._handle_connection_change(True)
    assert coordinator._debounce_timer is not None
    assert coordinator._hass.loop.call_later.call_count == 2
